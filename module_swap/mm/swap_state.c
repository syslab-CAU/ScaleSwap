// SPDX-License-Identifier: GPL-2.0
/*
 *  linux/mm/swap_state.c
 *
 *  Copyright (C) 1991, 1992, 1993, 1994  Linus Torvalds
 *  Swap reorganised 29.12.95, Stephen Tweedie
 *
 *  Rewritten to use page cache, (C) 1998 Stephen Tweedie
 */
#include <linux/mm.h>
#include <linux/gfp.h>
#include <linux/kernel_stat.h>
// #include <linux/swap.h>
#include "linux/swap.h"
#include <linux/swapops.h>
#include <linux/init.h>
// #include <linux/pagemap.h>
#include "linux/pagemap.h"
#include <linux/backing-dev.h>
#include <linux/blkdev.h>
#include <linux/migrate.h>
#include <linux/vmalloc.h>
#include <linux/swap_slots.h>
#include <linux/huge_mm.h>
#include <linux/shmem_fs.h>
#include "internal.h"
#include "swap.h"

#include <linux/calclock.h>

#define SWAP_RA_WIN_SHIFT	(PAGE_SHIFT / 2)
#define SWAP_RA_HITS_MASK	((1UL << SWAP_RA_WIN_SHIFT) - 1)

#define SWAP_RA_HITS(v)		((v) & SWAP_RA_HITS_MASK)
#define SWAP_RA_WIN(v)		(((v) & SWAP_RA_WIN_MASK) >> SWAP_RA_WIN_SHIFT)
#define SWAP_RA_WIN_MASK	(~PAGE_MASK & ~SWAP_RA_HITS_MASK)
#define SWAP_RA_ADDR(v)		((v) & PAGE_MASK)

/* Initial readahead hits is 4 to start up with a small window */
#define GET_SWAP_RA_VAL(vma)					\
	(atomic_long_read(&(vma)->swap_readahead_info) ? : 4)

#define SWAP_RA_VAL(addr, win, hits)				\
	(((addr) & PAGE_MASK) |					\
	 (((win) << SWAP_RA_WIN_SHIFT) & SWAP_RA_WIN_MASK) |	\
	 ((hits) & SWAP_RA_HITS_MASK))

#define SWAP_RA_ORDER_CEILING	5

static bool enable_vma_readahead __read_mostly = true;

struct vma_swap_readahead {
	unsigned short win;
	unsigned short offset;
	unsigned short nr_pte;
};

extern const struct address_space_operations swap_aops;
extern unsigned int nr_swapper_spaces[MAX_SWAPFILES] __read_mostly;

static atomic_t swapin_readahead_hits = ATOMIC_INIT(4);



/**
 * add_to_swap - allocate swap space for a folio
 * @folio: folio we want to move to swap
 *
 * Allocate swap space for the folio and add the folio to the
 * swap cache.
 *
 * Context: Caller needs to hold the folio lock.
 * Return: Whether the folio was added to the swap cache.
 */
extern void _k_put_swap_folio(struct folio *folio, swp_entry_t entry);
KTDEF(folio_alloc_swap);
KTDEF(add_to_swap_cache);
KTDEF(put_swap_folio__);
atomic_t tmp_cnt;
bool add_to_swap(struct folio *folio)
{
	ktime_t put_swap_folio___watch[2];
	swp_entry_t entry;
	int err;

	VM_BUG_ON_FOLIO(!folio_test_locked(folio), folio);
	VM_BUG_ON_FOLIO(!folio_test_uptodate(folio), folio);

#ifdef __PROFILING
#endif 
	entry = folio_alloc_swap(folio);
#ifdef __PROFILING
#endif 
	if (!entry.val)
		return false;

	/*
		* XArray node allocations from PF_MEMALLOC contexts could
		* completely exhaust the page allocator. __GFP_NOMEMALLOC
		* stops emergency reserves from being allocated.
		*
		* TODO: this could cause a theoretical memory reclaim
		* deadlock in the swap out path.
		*/
	/*
		* Add it to the swap cache.
		*/
#ifdef __PROFILING
#endif 
	err = add_to_swap_cache(folio, entry,
			__GFP_HIGH|__GFP_NOMEMALLOC|__GFP_NOWARN, NULL);
#ifdef __PROFILING
#endif 
	if (err)
		/*
			* add_to_swap_cache() doesn't return -EEXIST, so we can safely
			* clear SWAP_HAS_CACHE flag.
			*/
		goto fail;
	/*
		* Normally the folio will be dirtied in unmap because its
		* pte should be dirty. A special case is MADV_FREE page. The
		* page's pte could have dirty bit cleared but the folio's
		* SwapBacked flag is still set because clearing the dirty bit
		* and SwapBacked flag has no lock protected. For such folio,
		* unmap will not set dirty bit for it, so folio reclaim will
		* not write the folio out. This can cause data corruption when
		* the folio is swapped in later. Always setting the dirty flag
		* for the folio solves the problem.
		*/
	folio_mark_dirty(folio);

	return true;
fail:
#ifdef __PROFILING
#endif 
	_k_put_swap_folio(folio, entry);
#ifdef __PROFILING
#endif 
	return false;
}

#include "kswapd_percpu.h"

KTDEF(add_to_swap_insert_task);

#ifdef __KSWAPD_PERCPU

/**
 * add_to_swap_work - allocate swap space for a folio
 * @data: 'struct folio *folio' folio we want to move to swap
 *
 * Allocate swap space for the folio and add the folio to the
 * swap cache.
 *
 * Context: Caller needs to hold the folio lock.
 * Return: Whether the folio was added to the swap cache.
 */
void add_to_swap_work(struct swap_task_item *task) {
	struct folio *folio = (struct folio *)task->data;
	bool ret;
	
#ifdef __PROFILING
#endif 
	this_cpu_add(p_nr_swap_pages, folio_nr_pages(folio));
	ret = add_to_swap(folio);
#ifdef __PROFILING
#endif 

	memcpy(task->result, &ret, sizeof(bool));
}

#endif

static inline bool swap_use_vma_readahead(void)
{
	return READ_ONCE(enable_vma_readahead) && !atomic_read(&nr_rotate_swap);
}

extern struct folio *_k_vma_alloc_folio(gfp_t gfp, int order, struct vm_area_struct *vma,
		unsigned long addr, bool hugepage);
extern struct folio *_m_vma_alloc_folio(gfp_t gfp, int order, struct vm_area_struct *vma,
		unsigned long addr, bool hugepage);
KTDEF(swapcache_prepare);
KTDEF(_k_put_swap_folio);
KTDEF(filemap_get_folio);
KTDEF(folio_file_page);
struct page *__read_swap_cache_async(swp_entry_t entry, gfp_t gfp_mask,
			struct vm_area_struct *vma, unsigned long addr,
			bool *new_page_allocated)
{
	struct swap_info_struct *si;
	struct folio *folio;
	struct page *page;
	void *shadow = NULL;

	*new_page_allocated = false;
	si = get_swap_device(entry);
	if (!si) {
		return NULL;
	}

	for (;;) {
		int err;
		/*
		 * First check the swap cache.  Since this is normally
		 * called after swap_cache_get_folio() failed, re-calling
		 * that would confuse statistics.
		 */
#ifdef __PROFILING
#endif 		
		folio = filemap_get_folio(swap_address_space(entry),
						swp_offset(entry));
#ifdef __PROFILING
#endif 
		if (!IS_ERR(folio)) {
#ifdef __PROFILING
#endif 
			page = folio_file_page(folio, swp_offset(entry));
#ifdef __PROFILING
#endif 
			goto got_page;
		}

		/*
		 * Just skip read ahead for unused swap slot.
		 * During swap_off when swap_slot_cache is disabled,
		 * we have to handle the race between putting
		 * swap entry in swap cache and marking swap slot
		 * as SWAP_HAS_CACHE.  That's done in later part of code or
		 * else swap_off will be aborted if we return NULL.
		 */
		if (!swap_swapcount(si, entry) && swap_slot_cache_enabled)
			goto fail_put_swap;

		/*
		 * Get a new page to read into from swap.  Allocate it now,
		 * before marking swap_map SWAP_HAS_CACHE, when -EEXIST will
		 * cause any racers to loop around until we add it to cache.
		 */
		folio = vma_alloc_folio(gfp_mask, 0, vma, addr, false);
		if (!folio)
                        goto fail_put_swap;

		/*
		 * Swap entry may have been freed since our caller observed it.
		 */
#ifdef __PROFILING
#endif 
		err = swapcache_prepare(entry);
#ifdef __PROFILING
#endif 
		if (!err)
			break;

		folio_put(folio);
		if (err != -EEXIST)
			goto fail_put_swap;

		/*
		 * We might race against __delete_from_swap_cache(), and
		 * stumble across a swap_map entry whose SWAP_HAS_CACHE
		 * has not yet been cleared.  Or race against another
		 * __read_swap_cache_async(), which has set SWAP_HAS_CACHE
		 * in swap_map, but not yet added its page to swap cache.
		 */
		schedule_timeout_uninterruptible(1);
	}

	/*
	 * The swap entry is ours to swap in. Prepare the new page.
	 */

	__folio_set_locked(folio);
	__folio_set_swapbacked(folio);

	if (mem_cgroup_swapin_charge_folio(folio, NULL, gfp_mask, entry))
		goto fail_unlock;

	/* May fail (-ENOMEM) if XArray node allocation failed. */
	if (add_to_swap_cache(folio, entry, gfp_mask & GFP_RECLAIM_MASK, &shadow))
		goto fail_unlock;

	mem_cgroup_swapin_uncharge_swap(entry);

	if (shadow)
		workingset_refault(folio, shadow);

	/* Caller will initiate read into locked folio */
	folio_add_lru(folio);
	*new_page_allocated = true;
	page = &folio->page;
got_page:
	put_swap_device(si);
	return page;

fail_unlock:
	_k_put_swap_folio(folio, entry);
	folio_unlock(folio);
	folio_put(folio);
fail_put_swap:
	put_swap_device(si);
	return NULL;
}

#ifdef CONFIG_MEMCG
extern void _m_mem_cgroup_swapin_uncharge_swap(swp_entry_t entry);
#endif

static inline int folio_is_file_lru(struct folio *folio)
{                                                                                                                                                                                                                                                                                                          return !folio_test_swapbacked(folio);
}

/**
 * workingset_refault - Evaluate the refault of a previously evicted folio.
 * @folio: The freshly allocated replacement folio.
 * @shadow: Shadow entry of the evicted folio.
 *
 * Calculates and evaluates the refault distance of the previously
 * evicted folio in the context of the node and the memcg whose memory
 * pressure caused the eviction.
 */
void workingset_refault(struct folio *folio, void *shadow)
{
	bool file = folio_is_file_lru(folio);
	struct pglist_data *pgdat;
	struct mem_cgroup *memcg;
	struct lruvec *lruvec;
	bool workingset;
	long nr;

	/* Flush stats (and potentially sleep) before holding RCU read lock */
	mem_cgroup_flush_stats_ratelimited();

	rcu_read_lock();

	/*
	 * The activation decision for this folio is made at the level
	 * where the eviction occurred, as that is where the LRU order
	 * during folio reclaim is being determined.
	 *
	 * However, the cgroup that will own the folio is the one that
	 * is actually experiencing the refault event.
	 */
	nr = folio_nr_pages(folio);
	memcg = folio_memcg(folio);
	pgdat = folio_pgdat(folio);
//	lruvec = mem_cgroup_lruvec(memcg, pgdat, folio_to_cpu(folio));
	lruvec = my_mem_cgroup_lruvec(memcg, pgdat, folio_to_cpu(folio));

	mod_lruvec_state(lruvec, WORKINGSET_REFAULT_BASE + file, nr);

	if (!workingset_test_recent(shadow, file, &workingset))
		goto out;

	folio_set_active(folio);
	workingset_age_nonresident(lruvec, nr);
	mod_lruvec_state(lruvec, WORKINGSET_ACTIVATE_BASE + file, nr);

	/* Folio was active prior to eviction */
	if (workingset) {
		folio_set_workingset(folio);
		/*
		 * XXX: Move to folio_add_lru() when it supports new vs
		 * putback
		 */
		lru_note_cost_refault(folio);
		mod_lruvec_state(lruvec, WORKINGSET_RESTORE_BASE + file, nr);
	}
out:
	rcu_read_unlock();
}

KTDEF(_m_vma_alloc_folio);
KTDEF(mem_cgroup_swapin_charge_folio);
KTDEF(_m_mem_cgroup_swapin_uncharge_swap);
KTDEF(_m_get_swap_device);
KTDEF(_m_put_swap_device);
KTDEF(_m_add_to_swap_cache);
KTDEF(_m_filemap_get_folio);
KTDEF(_m_swapcache_prepare);
KTDEF(_m_workingset_refault);
struct page *__m_read_swap_cache_async(swp_entry_t entry, gfp_t gfp_mask,
			struct vm_area_struct *vma, unsigned long addr,
			bool *new_page_allocated)
{
	ktime_t _m_put_swap_device_watch[2];
	struct swap_info_struct *si;
	struct folio *folio;
	struct page *page;
	void *shadow = NULL;

	*new_page_allocated = false;
	si = get_swap_device(entry);
	if (!si) {
		return NULL;
	}

	for (;;) {
		int err;
		/*
		 * First check the swap cache.  Since this is normally
		 * called after swap_cache_get_folio() failed, re-calling
		 * that would confuse statistics.
		 */
		folio = filemap_get_folio(swap_address_space(entry),
						swp_offset(entry));
		if (!IS_ERR(folio)) {
			page = folio_file_page(folio, swp_offset(entry));
			goto got_page;
		}

		/*
		 * Just skip read ahead for unused swap slot.
		 * During swap_off when swap_slot_cache is disabled,
		 * we have to handle the race between putting
		 * swap entry in swap cache and marking swap slot
		 * as SWAP_HAS_CACHE.  That's done in later part of code or
		 * else swap_off will be aborted if we return NULL.
		 */
		if (!swap_swapcount(si, entry) && swap_slot_cache_enabled)
			goto fail_put_swap;

		/*
		 * Get a new page to read into from swap.  Allocate it now,
		 * before marking swap_map SWAP_HAS_CACHE, when -EEXIST will
		 * cause any racers to loop around until we add it to cache.
		 */
		folio = _m_vma_alloc_folio(gfp_mask, 0, vma, addr, false);
		if (!folio)
                        goto fail_put_swap;

		/*
		 * Swap entry may have been freed since our caller observed it.
		 */
		err = swapcache_prepare(entry);
		if (!err)
			break;

		folio_put(folio);
		if (err != -EEXIST)
			goto fail_put_swap;

		/*
		 * We might race against __delete_from_swap_cache(), and
		 * stumble across a swap_map entry whose SWAP_HAS_CACHE
		 * has not yet been cleared.  Or race against another
		 * __read_swap_cache_async(), which has set SWAP_HAS_CACHE
		 * in swap_map, but not yet added its page to swap cache.
		 */
		schedule_timeout_uninterruptible(1);
	}

	/*
	 * The swap entry is ours to swap in. Prepare the new page.
	 */

	__folio_set_locked(folio);
	__folio_set_swapbacked(folio);

	if (mem_cgroup_swapin_charge_folio(folio, NULL, gfp_mask, entry)) {
		goto fail_unlock;
	}

	/* May fail (-ENOMEM) if XArray node allocation failed. */
	if (add_to_swap_cache(folio, entry, gfp_mask & GFP_RECLAIM_MASK, &shadow)) {
		goto fail_unlock;
	}

	_m_mem_cgroup_swapin_uncharge_swap(entry);

	if (shadow) {
		workingset_refault(folio, shadow);
	}

	/* Caller will initiate read into locked folio */
	folio_add_lru(folio);
	*new_page_allocated = true;
	page = &folio->page;
got_page:
	put_swap_device(si);
	return page;

fail_unlock:
	_k_put_swap_folio(folio, entry);
	folio_unlock(folio);
	folio_put(folio);
fail_put_swap:
	put_swap_device(si);
	return NULL;
}

/*
 * Locate a page of swap in physical memory, reserving swap cache space
 * and reading the disk if it is not already cached.
 * A failure return means that either the page allocation failed or that
 * the swap entry is no longer in use.
 *
 * get/put_swap_device() aren't needed to call this function, because
 * __read_swap_cache_async() call them and swap_readpage() holds the
 * swap cache folio lock.
 */
struct page *read_swap_cache_async(swp_entry_t entry, gfp_t gfp_mask,
				   struct vm_area_struct *vma,
				   unsigned long addr, struct swap_iocb **plug)
{
	bool page_was_allocated;
	struct page *retpage = __read_swap_cache_async(entry, gfp_mask,
			vma, addr, &page_was_allocated);

	if (page_was_allocated) {
		swap_readpage(retpage, false, plug);
	}

	return retpage;
}

static unsigned int __swapin_nr_pages(unsigned long prev_offset,
				      unsigned long offset,
				      int hits,
				      int max_pages,
				      int prev_win)
{
	unsigned int pages, last_ra;

	/*
	 * This heuristic has been found to work well on both sequential and
	 * random loads, swapping to hard disk or to SSD: please don't ask
	 * what the "+ 2" means, it just happens to work well, that's all.
	 */
	pages = hits + 2;
	if (pages == 2) {
		/*
		 * We can have no readahead hits to judge by: but must not get
		 * stuck here forever, so check for an adjacent offset instead
		 * (and don't even bother to check whether swap type is same).
		 */
		if (offset != prev_offset + 1 && offset != prev_offset - 1)
			pages = 1;
	} else {
		unsigned int roundup = 4;
		while (roundup < pages)
			roundup <<= 1;
		pages = roundup;
	}

	if (pages > max_pages)
		pages = max_pages;

	/* Don't shrink readahead too fast */
	last_ra = prev_win / 2;
	if (pages < last_ra)
		pages = last_ra;

	return pages;
}

static void swap_ra_info(struct vm_fault *vmf,
			 struct vma_swap_readahead *ra_info)
{
	struct vm_area_struct *vma = vmf->vma;
	unsigned long ra_val;
	unsigned long faddr, pfn, fpfn, lpfn, rpfn;
	unsigned long start, end;
	unsigned int max_win, hits, prev_win, win;

	max_win = 1 << min_t(unsigned int, READ_ONCE(page_cluster),
			     SWAP_RA_ORDER_CEILING);
	// printk("[%s]: max_win=%d, page_cluster=%d\n", __func__, max_win, page_cluster);
	if (max_win == 1) {
		ra_info->win = 1;
		return;
	}

	faddr = vmf->address;
	fpfn = PFN_DOWN(faddr);
	ra_val = GET_SWAP_RA_VAL(vma);
	pfn = PFN_DOWN(SWAP_RA_ADDR(ra_val));
	prev_win = SWAP_RA_WIN(ra_val);
	hits = SWAP_RA_HITS(ra_val);
	ra_info->win = win = __swapin_nr_pages(pfn, fpfn, hits,
					       max_win, prev_win);
	atomic_long_set(&vma->swap_readahead_info,
			SWAP_RA_VAL(faddr, win, 0));
	if (win == 1)
		return;

	if (fpfn == pfn + 1) {
		lpfn = fpfn;
		rpfn = fpfn + win;
	} else if (pfn == fpfn + 1) {
		lpfn = fpfn - win + 1;
		rpfn = fpfn + 1;
	} else {
		unsigned int left = (win - 1) / 2;

		lpfn = fpfn - left;
		rpfn = fpfn + win - left;
	}
	start = max3(lpfn, PFN_DOWN(vma->vm_start),
		     PFN_DOWN(faddr & PMD_MASK));
	end = min3(rpfn, PFN_DOWN(vma->vm_end),
		   PFN_DOWN((faddr & PMD_MASK) + PMD_SIZE));

	ra_info->nr_pte = end - start;
	ra_info->offset = fpfn - start;
}

/**
 * swap_vma_readahead - swap in pages in hope we need them soon
 * @fentry: swap entry of this memory
 * @gfp_mask: memory allocation flags
 * @vmf: fault information
 *
 * Returns the struct page for entry and addr, after queueing swapin.
 *
 * Primitive swap readahead code. We simply read in a few pages whose
 * virtual addresses are around the fault address in the same vma.
 *
 * Caller must hold read mmap_lock if vmf->vma is not NULL.
 *
 */
KTDEF(pte_to_swp_entry);
KTDEF(put_page);
KTDEF(swap_readpage);
KTDEF(__read_swap_cache_async);
static struct page *swap_vma_readahead(swp_entry_t fentry, gfp_t gfp_mask,
				       struct vm_fault *vmf)
{
	struct blk_plug plug;
	struct swap_iocb *splug = NULL;
	struct vm_area_struct *vma = vmf->vma;
	struct page *page;
	pte_t *pte = NULL, pentry;
	unsigned long addr;
	swp_entry_t entry;
	unsigned int i;
	bool page_allocated;
	struct vma_swap_readahead ra_info = {
		.win = 1,
	};

	swap_ra_info(vmf, &ra_info);
	if (ra_info.win == 1)
		goto skip;

	addr = vmf->address - (ra_info.offset * PAGE_SIZE);

	blk_start_plug(&plug);
	for (i = 0; i < ra_info.nr_pte; i++, addr += PAGE_SIZE) {
		if (!pte++) {
			pte = pte_offset_map(vmf->pmd, addr);
			if (!pte)
				break;
		}
		pentry = ptep_get_lockless(pte);
		if (!is_swap_pte(pentry))
			continue;
		entry = pte_to_swp_entry(pentry);
		if (unlikely(non_swap_entry(entry)))
			continue;
		pte_unmap(pte);
		pte = NULL;
		page = __m_read_swap_cache_async(entry, gfp_mask, vma,
					       addr, &page_allocated);
		if (!page)
			continue;
		if (page_allocated) {
			swap_readpage(page, false, &splug);
			if (i != ra_info.offset) {
				SetPageReadahead(page);
				count_vm_event(SWAP_RA);
			}
#ifdef __PROFILING
#endif 
		}
#ifdef __PROFILING
#endif 
		put_page(page);
#ifdef __PROFILING
#endif 
	}
	if (pte)
		pte_unmap(pte);
	blk_finish_plug(&plug);
	swap_read_unplug(splug);
	lru_add_drain();
skip: ;
	/* The page was likely read above, so no need for plugging here */
	struct page *ret_page = read_swap_cache_async(fentry, gfp_mask, vma, vmf->address,
				     NULL);
	return ret_page;
}

static unsigned long swapin_nr_pages(unsigned long offset)
{
	static unsigned long prev_offset;
	unsigned int hits, pages, max_pages;
	static atomic_t last_readahead_pages;

	max_pages = 1 << READ_ONCE(page_cluster);
	if (max_pages <= 1)
		return 1;

	hits = atomic_xchg(&swapin_readahead_hits, 0);
	pages = __swapin_nr_pages(READ_ONCE(prev_offset), offset, hits,
				  max_pages,
				  atomic_read(&last_readahead_pages));
	if (!hits)
		WRITE_ONCE(prev_offset, offset);
	atomic_set(&last_readahead_pages, pages);

	return pages;
}

/**
 * swap_cluster_readahead - swap in pages in hope we need them soon
 * @entry: swap entry of this memory
 * @gfp_mask: memory allocation flags
 * @vmf: fault information
 *
 * Returns the struct page for entry and addr, after queueing swapin.
 *
 * Primitive swap readahead code. We simply read an aligned block of
 * (1 << page_cluster) entries in the swap area. This method is chosen
 * because it doesn't cost us any seek time.  We also make sure to queue
 * the 'original' request together with the readahead ones...
 *
 * This has been extended to use the NUMA policies from the mm triggering
 * the readahead.
 *
 * Caller must hold read mmap_lock if vmf->vma is not NULL.
 */
KTDEF(swap_cluster_readahead);
struct page *swap_cluster_readahead(swp_entry_t entry, gfp_t gfp_mask,
				struct vm_fault *vmf)
{
#ifdef __PROFILING
#endif 
	struct page *page;
	unsigned long entry_offset = swp_offset(entry);
	unsigned long offset = entry_offset;
	unsigned long start_offset, end_offset;
	unsigned long mask;
	struct swap_info_struct *si = swp_swap_info(entry);
	struct blk_plug plug;
	struct swap_iocb *splug = NULL;
	bool page_allocated;
	struct vm_area_struct *vma = vmf->vma;
	unsigned long addr = vmf->address;

	mask = swapin_nr_pages(offset) - 1;
	if (!mask)
		goto skip;

	/* Read a page_cluster sized and aligned cluster around offset. */
	start_offset = offset & ~mask;
	end_offset = offset | mask;
	if (!start_offset)	/* First page is swap header. */
		start_offset++;
	if (end_offset >= si->max)
		end_offset = si->max - 1;

	blk_start_plug(&plug);
	for (offset = start_offset; offset <= end_offset ; offset++) {
		/* Ok, do the async read-ahead now */
		page = __read_swap_cache_async(
			swp_entry(swp_type(entry), offset),
			gfp_mask, vma, addr, &page_allocated);
		if (!page)
			continue;
		if (page_allocated) {
			swap_readpage(page, false, &splug);
			if (offset != entry_offset) {
				SetPageReadahead(page);
				count_vm_event(SWAP_RA);
			}
		}
		put_page(page);
	}
	blk_finish_plug(&plug);
	swap_read_unplug(splug);

	lru_add_drain();	/* Push any new pages onto the LRU now */
skip: ;
	/* The page was likely read above, so no need for plugging here */
	struct page *ret_page = read_swap_cache_async(entry, gfp_mask, vma, addr, NULL);
#ifdef __PROFILING
#endif 
	return ret_page;
}

/**
 * swapin_readahead - swap in pages in hope we need them soon
 * @entry: swap entry of this memory
 * @gfp_mask: memory allocation flags
 * @vmf: fault information
 *
 * Returns the struct page for entry and addr, after queueing swapin.
 *
 * It's a main entry function for swap readahead. By the configuration,
 * it will read ahead blocks by cluster-based(ie, physical disk based)
 * or vma-based(ie, virtual address based on faulty address) readahead.
 */
struct page *_k_swapin_readahead(swp_entry_t entry, gfp_t gfp_mask,
				struct vm_fault *vmf)
{
	return swap_use_vma_readahead() ?
			swap_vma_readahead(entry, gfp_mask, vmf) :
			swap_cluster_readahead(entry, gfp_mask, vmf);
}

int init_swap_address_space(unsigned int type, unsigned long nr_pages)
{
        struct address_space *spaces, *space;
        unsigned int i, nr;

        nr = DIV_ROUND_UP(nr_pages, SWAP_ADDRESS_SPACE_PAGES);
        spaces = kvcalloc(nr, sizeof(struct address_space), GFP_KERNEL);
        if (!spaces)
                return -ENOMEM;
        for (i = 0; i < nr; i++) {
                space = spaces + i;
                xa_init_flags(&space->i_pages, XA_FLAGS_LOCK_IRQ);
                atomic_set(&space->i_mmap_writable, 0);
                space->a_ops = &swap_aops;
                /* swap cache doesn't use writeback related tags */
                mapping_set_no_writeback_tags(space);
        }
        nr_swapper_spaces[type] = nr;
        swapper_spaces[type] = spaces;

        return 0;
}
