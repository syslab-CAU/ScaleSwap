/*
 * Resizable virtual memory filesystem for Linux.
 *
 * Copyright (C) 2000 Linus Torvalds.
 *		 2000 Transmeta Corp.
 *		 2000-2001 Christoph Rohland
 *		 2000-2001 SAP AG
 *		 2002 Red Hat Inc.
 * Copyright (C) 2002-2011 Hugh Dickins.
 * Copyright (C) 2011 Google Inc.
 * Copyright (C) 2002-2005 VERITAS Software Corporation.
 * Copyright (C) 2004 Andi Kleen, SuSE Labs
 *
 * Extended attribute support for tmpfs:
 * Copyright (c) 2004, Luke Kenneth Casson Leighton <lkcl@lkcl.net>
 * Copyright (c) 2004 Red Hat, Inc., James Morris <jmorris@redhat.com>
 *
 * tiny-shmem:
 * Copyright (c) 2004, 2008 Matt Mackall <mpm@selenic.com>
 *
 * This file is released under the GPL.
 */

#include <linux/quotaops.h>
#include <linux/mman.h>

#include <linux/fs.h>
#include <linux/init.h>
#include <linux/vfs.h>
#include <linux/mount.h>
#include <linux/ramfs.h>
#include <linux/pagemap.h>
#include <linux/file.h>
#include <linux/fileattr.h>
#include <linux/mm.h>
#include <linux/random.h>
#include <linux/sched/signal.h>
#include <linux/export.h>
#include <linux/shmem_fs.h>
#include <linux/swap.h>
#include <linux/uio.h>
#include <linux/hugetlb.h>
#include <linux/fs_parser.h>
#include <linux/swapfile.h>
#include <linux/iversion.h>
#include "swap.h"


#define VM_ACCT(size)    (PAGE_ALIGN(size) >> PAGE_SHIFT)

struct shmem_falloc {
	wait_queue_head_t *waitq; /* faults into hole wait for punch to end */
	pgoff_t start;		/* start of range currently being fallocated */
	pgoff_t next;		/* the next page offset to be fallocated */
	pgoff_t nr_falloced;	/* how many new pages have been fallocated */
	pgoff_t nr_unswapped;	/* how often writepage refused to swap out */
};

/*
 * Replace item expected in xarray by a new item, while holding xa_lock.
 */
static int shmem_replace_entry(struct address_space *mapping,
			pgoff_t index, void *expected, void *replacement)
{
	XA_STATE(xas, &mapping->i_pages, index);
	void *item;

	VM_BUG_ON(!expected);
	VM_BUG_ON(!replacement);
	item = xas_load(&xas);
	if (item != expected)
		return -ENOENT;
	xas_store(&xas, replacement);
	return 0;
}

/*
 * Like delete_from_page_cache, but substitutes swap for @folio.
 */
static void shmem_delete_from_page_cache(struct folio *folio, void *radswap)
{
	struct address_space *mapping = folio->mapping;
	long nr = folio_nr_pages(folio);
	int error;

	xa_lock_irq(&mapping->i_pages);
	error = shmem_replace_entry(mapping, folio->index, folio, radswap);
	folio->mapping = NULL;
	mapping->nrpages -= nr;
	__lruvec_stat_mod_folio(folio, NR_FILE_PAGES, -nr);
	__lruvec_stat_mod_folio(folio, NR_SHMEM, -nr);
	xa_unlock_irq(&mapping->i_pages);
	folio_put(folio);
	BUG_ON(error);
}

static inline struct shmem_sb_info *SHMEM_SB(struct super_block *sb)
{
	return sb->s_fs_info;
}

static inline void shmem_unacct_blocks(unsigned long flags, long pages)
{
	if (flags & VM_NORESERVE)
		vm_unacct_memory(pages * VM_ACCT(PAGE_SIZE));
}

static void shmem_inode_unacct_blocks(struct inode *inode, long pages)
{
	struct shmem_inode_info *info = SHMEM_I(inode);
	struct shmem_sb_info *sbinfo = SHMEM_SB(inode->i_sb);

	might_sleep();	/* when quotas */
	dquot_free_block_nodirty(inode, pages);

	if (sbinfo->max_blocks)
		percpu_counter_sub(&sbinfo->used_blocks, pages);
	shmem_unacct_blocks(info->flags, pages);
}

/**
 * shmem_recalc_inode - recalculate the block usage of an inode
 * @inode: inode to recalc
 * @alloced: the change in number of pages allocated to inode
 * @swapped: the change in number of pages swapped from inode
 *
 * We have to calculate the free blocks since the mm can drop
 * undirtied hole pages behind our back.
 *
 * But normally   info->alloced == inode->i_mapping->nrpages + info->swapped
 * So mm freed is info->alloced - (inode->i_mapping->nrpages + info->swapped)
 */
static void shmem_recalc_inode(struct inode *inode, long alloced, long swapped)
{
	struct shmem_inode_info *info = SHMEM_I(inode);
	long freed;

	spin_lock(&info->lock);
	info->alloced += alloced;
	info->swapped += swapped;
	freed = info->alloced - info->swapped -
		READ_ONCE(inode->i_mapping->nrpages);
	/*
	 * Special case: whereas normally shmem_recalc_inode() is called
	 * after i_mapping->nrpages has already been adjusted (up or down),
	 * shmem_writepage() has to raise swapped before nrpages is lowered -
	 * to stop a racing shmem_recalc_inode() from thinking that a page has
	 * been freed.  Compensate here, to avoid the need for a followup call.
	 */
	if (swapped > 0)
		freed += swapped;
	if (freed > 0)
		info->alloced -= freed;
	spin_unlock(&info->lock);

	/* The quota case may block */
	if (freed > 0)
		shmem_inode_unacct_blocks(inode, freed);
}

static LIST_HEAD(shmem_swaplist);
static DEFINE_MUTEX(shmem_swaplist_mutex);

extern void _k_put_swap_folio(struct folio *folio, swp_entry_t entry);
extern int _k_swap_writepage(struct page *page, struct writeback_control *wbc);
int _k_shmem_writepage(struct page *page, struct writeback_control *wbc)
{
	struct folio *folio = page_folio(page);
	struct address_space *mapping = folio->mapping;
	struct inode *inode = mapping->host;
	struct shmem_inode_info *info = SHMEM_I(inode);
	struct shmem_sb_info *sbinfo = SHMEM_SB(inode->i_sb);
	swp_entry_t swap;
	pgoff_t index;

	/*
	 * Our capabilities prevent regular writeback or sync from ever calling
	 * shmem_writepage; but a stacking filesystem might use ->writepage of
	 * its underlying filesystem, in which case tmpfs should write out to
	 * swap only in response to memory pressure, and not for the writeback
	 * threads or sync.
	 */
	if (WARN_ON_ONCE(!wbc->for_reclaim))
		goto redirty;

	if (WARN_ON_ONCE((info->flags & VM_LOCKED) || sbinfo->noswap))
		goto redirty;

	if (!total_swap_pages)
		goto redirty;

	/*
	 * If /sys/kernel/mm/transparent_hugepage/shmem_enabled is "always" or
	 * "force", drivers/gpu/drm/i915/gem/i915_gem_shmem.c gets huge pages,
	 * and its shmem_writeback() needs them to be split when swapping.
	 */
	if (folio_test_large(folio)) {
		/* Ensure the subpages are still dirty */
		folio_test_set_dirty(folio);
		if (split_huge_page(page) < 0)
			goto redirty;
		folio = page_folio(page);
		folio_clear_dirty(folio);
	}

	index = folio->index;

	/*
	 * This is somewhat ridiculous, but without plumbing a SWAP_MAP_FALLOC
	 * value into swapfile.c, the only way we can correctly account for a
	 * fallocated folio arriving here is now to initialize it and write it.
	 *
	 * That's okay for a folio already fallocated earlier, but if we have
	 * not yet completed the fallocation, then (a) we want to keep track
	 * of this folio in case we have to undo it, and (b) it may not be a
	 * good idea to continue anyway, once we're pushing into swap.  So
	 * reactivate the folio, and let shmem_fallocate() quit when too many.
	 */
	if (!folio_test_uptodate(folio)) {
		if (inode->i_private) {
			struct shmem_falloc *shmem_falloc;
			spin_lock(&inode->i_lock);
			shmem_falloc = inode->i_private;
			if (shmem_falloc &&
			    !shmem_falloc->waitq &&
			    index >= shmem_falloc->start &&
			    index < shmem_falloc->next)
				shmem_falloc->nr_unswapped++;
			else
				shmem_falloc = NULL;
			spin_unlock(&inode->i_lock);
			if (shmem_falloc)
				goto redirty;
		}
		folio_zero_range(folio, 0, folio_size(folio));
		flush_dcache_folio(folio);
		folio_mark_uptodate(folio);
	}

	printk("[%s]: ==>warning! (shmem.c)\n", __func__);
	swap = folio_alloc_swap(folio);
	if (!swap.val)
		goto redirty;

	/*
	 * Add inode to shmem_unuse()'s list of swapped-out inodes,
	 * if it's not already there.  Do it now before the folio is
	 * moved to swap cache, when its pagelock no longer protects
	 * the inode from eviction.  But don't unlock the mutex until
	 * we've incremented swapped, because shmem_unuse_inode() will
	 * prune a !swapped inode from the swaplist under this mutex.
	 */
	mutex_lock(&shmem_swaplist_mutex);
	if (list_empty(&info->swaplist))
		list_add(&info->swaplist, &shmem_swaplist);

	if (add_to_swap_cache(folio, swap,
			__GFP_HIGH | __GFP_NOMEMALLOC | __GFP_NOWARN,
			NULL) == 0) {
		shmem_recalc_inode(inode, 0, 1);
		swap_shmem_alloc(swap);
		shmem_delete_from_page_cache(folio, swp_to_radix_entry(swap));

		mutex_unlock(&shmem_swaplist_mutex);
		BUG_ON(folio_mapped(folio));
		_k_swap_writepage(&folio->page, wbc);
		return 0;
	}

	mutex_unlock(&shmem_swaplist_mutex);
	_k_put_swap_folio(folio, swap);
redirty:
	folio_mark_dirty(folio);
	if (wbc->for_reclaim)
		return AOP_WRITEPAGE_ACTIVATE;	/* Return with folio locked */
	folio_unlock(folio);
	return 0;
}