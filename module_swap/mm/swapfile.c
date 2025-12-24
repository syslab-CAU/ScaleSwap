// SPDX-License-Identifier: GPL-2.0-only
/*
 *  linux/mm/swapfile.c
 *
 *  Copyright (C) 1991, 1992, 1993, 1994  Linus Torvalds
 *  Swap reorganised 29.12.95, Stephen Tweedie
 */

#include <linux/blkdev.h>
#include <linux/mm.h>
#include <linux/sched/mm.h>
#include <linux/sched/task.h>
#include <linux/hugetlb.h>
#include <linux/mman.h>
#include <linux/slab.h>
#include <linux/kernel_stat.h>
#include <linux/swap.h>
#include <linux/vmalloc.h>
#include <linux/pagemap.h>
#include <linux/namei.h>
#include <linux/shmem_fs.h>
#include <linux/blk-cgroup.h>
#include <linux/random.h>
#include <linux/writeback.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/init.h>
#include <linux/ksm.h>
#include <linux/rmap.h>
#include <linux/security.h>
#include <linux/backing-dev.h>
#include <linux/mutex.h>
#include <linux/capability.h>
#include <linux/syscalls.h>
#include <linux/memcontrol.h>
#include <linux/poll.h>
#include <linux/oom.h>
#include <linux/swapfile.h>
#include <linux/export.h>
#include <linux/swap_slots.h>
#include <linux/sort.h>
#include <linux/completion.h>
#include <linux/suspend.h>
#include <linux/zswap.h>

#include <asm/tlbflush.h>
#include <linux/swapops.h>
#include <linux/swap_cgroup.h>
#include "kswapd_percpu.h"
#include "internal.h"
#include "swap.h"
#include <linux/calclock.h>

KTDEF(get_nr_swap_pages);
inline long _m_get_nr_swap_pages(long over_val, bool is_bigger)
{
	long ret = 0;
	int cpu;
	for_each_online_cpu(cpu) {
		ret += per_cpu(p_nr_swap_pages, cpu);
		if (over_val != -1) {
			if (is_bigger && over_val <= ret) {
				return ret;
			}
			else if (!is_bigger && over_val > ret) {
				return ret;
			}
		}
	}
	if (over_val != -1) // 기준치에 못 미쳤으면, false를 반환
		return 0;
	// ret = atomic_long_read(&nr_swap_pages);
	return ret;
}

void _m_spin_lock(struct swap_info_struct *si) {
	// int cpu = get_cpu();
	// put_cpu();
	// if (cpu != si->type)
	// 	dump_stack();

#ifndef __DEL_SILOCK
	spin_lock(&si->lock);
#else
	preempt_disable();
#endif
}

void _m_spin_unlock(struct swap_info_struct *si) {
#ifndef __DEL_SILOCK
	spin_unlock(&si->lock);
#else
	preempt_enable();
#endif
}

void print_infos(void);

#ifdef __PERCPU
DECLARE_PER_CPU(struct swap_info_struct *, percpu_si);
#endif
// extern DEFINE_PER_CPU(struct swap_info_struct*, percpu_si);
// DECLARE_PER_CPU(struct swap_info_struct*, percpu_si);
// extern struct swap_info_struct* percpu_si;

extern struct swap_info_struct *swap_info[MAX_SWAPFILES];
extern unsigned int nr_swapfiles;

extern spinlock_t swap_lock;
extern wait_queue_head_t proc_poll_wait;
extern atomic_t proc_poll_event;
extern struct mutex swapon_mutex;
extern int least_priority;
extern struct plist_head swap_active_head;
extern unsigned long swapfile_maximum_size;

static const char Bad_file[] = "Bad swap file entry ";
static const char Unused_file[] = "Unused swap file entry ";
static const char Bad_offset[] = "Bad swap offset entry ";
static const char Unused_offset[] = "Unused swap offset entry ";
static inline unsigned char swap_count(unsigned char ent)
{
	return ent & ~SWAP_HAS_CACHE;	/* may include COUNT_CONTINUED flag */
}


/* Reclaim the swap entry anyway if possible */
#define TTRS_ANYWAY		0x1
/*
 * Reclaim the swap entry if there are no more mappings of the
 * corresponding page
 */
#define TTRS_UNMAPPED		0x2
/* Reclaim the swap entry if swap is getting full*/
#define TTRS_FULL		0x4

/* returns 1 if swap entry is freed */
static int __try_to_reclaim_swap(struct swap_info_struct *si,
				 unsigned long offset, unsigned long flags)
{
	swp_entry_t entry = swp_entry(si->type, offset);
	struct folio *folio;
	int ret = 0;

	folio = filemap_get_folio(swap_address_space(entry), offset);
	if (IS_ERR(folio))
		return 0;
	/*
	 * When this function is called from scan_swap_map_slots() and it's
	 * called by vmscan.c at reclaiming folios. So we hold a folio lock
	 * here. We have to use trylock for avoiding deadlock. This is a special
	 * case and you should use folio_free_swap() with explicit folio_lock()
	 * in usual operations.
	 */
	if (folio_trylock(folio)) {
		if ((flags & TTRS_ANYWAY) ||
		    ((flags & TTRS_UNMAPPED) && !folio_mapped(folio)) ||
		    ((flags & TTRS_FULL) && mem_cgroup_swap_full(folio)))
			ret = folio_free_swap(folio);
		folio_unlock(folio);
	}
	folio_put(folio);
	return ret;
}

static inline void unlock_cluster(struct swap_cluster_info *ci)
{
	if (ci)
		spin_unlock(&ci->lock);
}

static inline void unlock_cluster_or_swap_info(struct swap_info_struct *si,
					       struct swap_cluster_info *ci)
{
	if (ci)
		unlock_cluster(ci);
	else {
		_m_spin_unlock(si); // spin_unlock(&si->lock);
	}
}

/*
 * swap_count_continued - when the original swap_map count is incremented
 * from SWAP_MAP_MAX, check if there is already a continuation page to carry
 * into, carry if so, or else fail until a new continuation page is allocated;
 * when the original swap_map count is decremented from 0 with continuation,
 * borrow from the continuation and report whether it still holds more.
 * Called while __swap_duplicate() or swap_entry_free() holds swap or cluster
 * lock.
 */
static bool swap_count_continued(struct swap_info_struct *si,
				 pgoff_t offset, unsigned char count)
{
	struct page *head;
	struct page *page;
	unsigned char *map;
	bool ret;

	head = vmalloc_to_page(si->swap_map + offset);
	if (page_private(head) != SWP_CONTINUED) {
		BUG_ON(count & COUNT_CONTINUED);
		return false;		/* need to add count continuation */
	}

	spin_lock(&si->cont_lock);
	offset &= ~PAGE_MASK;
	page = list_next_entry(head, lru);
	map = kmap_atomic(page) + offset;

	if (count == SWAP_MAP_MAX)	/* initial increment from swap_map */
		goto init_map;		/* jump over SWAP_CONT_MAX checks */

	if (count == (SWAP_MAP_MAX | COUNT_CONTINUED)) { /* incrementing */
		/*
		 * Think of how you add 1 to 999
		 */
		while (*map == (SWAP_CONT_MAX | COUNT_CONTINUED)) {
			kunmap_atomic(map);
			page = list_next_entry(page, lru);
			BUG_ON(page == head);
			map = kmap_atomic(page) + offset;
		}
		if (*map == SWAP_CONT_MAX) {
			kunmap_atomic(map);
			page = list_next_entry(page, lru);
			if (page == head) {
				ret = false;	/* add count continuation */
				goto out;
			}
			map = kmap_atomic(page) + offset;
init_map:		*map = 0;		/* we didn't zero the page */
		}
		*map += 1;
		kunmap_atomic(map);
		while ((page = list_prev_entry(page, lru)) != head) {
			map = kmap_atomic(page) + offset;
			*map = COUNT_CONTINUED;
			kunmap_atomic(map);
		}
		ret = true;			/* incremented */

	} else {				/* decrementing */
		/*
		 * Think of how you subtract 1 from 1000
		 */
		BUG_ON(count != COUNT_CONTINUED);
		while (*map == COUNT_CONTINUED) {
			kunmap_atomic(map);
			page = list_next_entry(page, lru);
			BUG_ON(page == head);
			map = kmap_atomic(page) + offset;
		}
		BUG_ON(*map == 0);
		*map -= 1;
		if (*map == 0)
			count = 0;
		kunmap_atomic(map);
		while ((page = list_prev_entry(page, lru)) != head) {
			map = kmap_atomic(page) + offset;
			*map = SWAP_CONT_MAX | count;
			count = COUNT_CONTINUED;
			kunmap_atomic(map);
		}
		ret = count == COUNT_CONTINUED;
	}
out:
	spin_unlock(&si->cont_lock);
	return ret;
}

static unsigned char __swap_entry_free_locked(struct swap_info_struct *p,
					      unsigned long offset,
					      unsigned char usage)
{
	unsigned char count;
	unsigned char has_cache;

	count = p->swap_map[offset];

	has_cache = count & SWAP_HAS_CACHE;
	count &= ~SWAP_HAS_CACHE;

	if (usage == SWAP_HAS_CACHE) {
		VM_BUG_ON(!has_cache);
		has_cache = 0;
	} else if (count == SWAP_MAP_SHMEM) {
		/*
		 * Or we could insist on shmem.c using a special
		 * swap_shmem_free() and free_shmem_swap_and_cache()...
		 */
		count = 0;
	} else if ((count & ~COUNT_CONTINUED) <= SWAP_MAP_MAX) {
		if (count == COUNT_CONTINUED) {
			if (swap_count_continued(p, offset, count))
				count = SWAP_MAP_MAX | COUNT_CONTINUED;
			else
				count = SWAP_MAP_MAX;
		} else
			count--;
	}

	usage = count | has_cache;
	if (usage)
		WRITE_ONCE(p->swap_map[offset], usage);
	else
		WRITE_ONCE(p->swap_map[offset], SWAP_HAS_CACHE);

	return usage;
}

#ifdef CONFIG_THP_SWAP
#define SWAPFILE_CLUSTER	HPAGE_PMD_NR

#define swap_entry_size(size)	(size)
#else
#define SWAPFILE_CLUSTER	256

/*
 * Define swap_entry_size() as constant to let compiler to optimize
 * out some code if !CONFIG_THP_SWAP
 */
#define swap_entry_size(size)	1
#endif
#define LATENCY_LIMIT		256

static inline struct swap_cluster_info *lock_cluster(struct swap_info_struct *si,
						     unsigned long offset)
{
	struct swap_cluster_info *ci;

	ci = si->cluster_info;
	if (ci) {
		ci += offset / SWAPFILE_CLUSTER;
		spin_lock(&ci->lock);
	}
	return ci;
}

/*
 * Determine the locking method in use for this device.  Return
 * swap_cluster_info if SSD-style cluster-based locking is in place.
 */
static inline struct swap_cluster_info *lock_cluster_or_swap_info(
		struct swap_info_struct *si, unsigned long offset)
{
	struct swap_cluster_info *ci;

	/* Try to use fine-grained SSD-style locking if available: */
	ci = lock_cluster(si, offset);
	/* Otherwise, fall back to traditional, coarse locking: */
	if (!ci) {
		_m_spin_lock(si);
	}

	return ci;
}

struct swap_info_struct *_swap_info_get(swp_entry_t entry)
{
	struct swap_info_struct *p;
	unsigned long offset;

	if (!entry.val)
		goto out;
	p = swp_swap_info(entry);
	if (!p)
		goto bad_nofile;
	if (data_race(!(p->flags & SWP_USED)))
		goto bad_device;
	offset = swp_offset(entry);
	if (offset >= p->max)
		goto bad_offset;
	if (data_race(!p->swap_map[swp_offset(entry)]))
		goto bad_free;
	return p;

bad_free:
	pr_err("%s: %s%08lx\n", __func__, Unused_offset, entry.val);
	goto out;
bad_offset:
	pr_err("%s: %s%08lx\n", __func__, Bad_offset, entry.val);
	goto out;
bad_device:
	pr_err("%s: %s%08lx\n", __func__, Unused_file, entry.val);
	goto out;
bad_nofile:
	pr_err("%s: %s%08lx\n", __func__, Bad_file, entry.val);
out:
	return NULL;
}

extern struct plist_head *swap_avail_heads;
extern spinlock_t swap_avail_lock;

static void add_to_avail_list(struct swap_info_struct *p)
{
	int nid;

	spin_lock(&swap_avail_lock);
	for_each_node(nid)
		plist_add(&p->avail_lists[nid], &swap_avail_heads[nid]);
	spin_unlock(&swap_avail_lock);
}

KTDEF(atomic_operation_in_swap_range_free);
static void swap_range_free(struct swap_info_struct *si, unsigned long offset,
			    unsigned int nr_entries)
{
	unsigned long begin = offset;
	unsigned long end = offset + nr_entries - 1;
	void (*swap_slot_free_notify)(struct block_device *, unsigned long);

	if (offset < si->lowest_bit)
		si->lowest_bit = offset;
	if (end > si->highest_bit) {
		bool was_full = !si->highest_bit;

		WRITE_ONCE(si->highest_bit, end);
		// if (was_full && (si->flags & SWP_WRITEOK))
		// 	add_to_avail_list(si);
	}

	// atomic_long_add(nr_entries, &nr_swap_pages);
	this_cpu_add(p_nr_swap_pages, nr_entries);
	WRITE_ONCE(si->inuse_pages, si->inuse_pages - nr_entries);
	// si->inuse_pages -= nr_entries;

	if (si->flags & SWP_BLKDEV)
		swap_slot_free_notify =
			si->bdev->bd_disk->fops->swap_slot_free_notify;
	else
		swap_slot_free_notify = NULL;
	while (offset <= end) {
		arch_swap_invalidate_page(si->type, offset);
		zswap_invalidate(si->type, offset);
		if (swap_slot_free_notify)
			swap_slot_free_notify(si->bdev, offset);
		offset++;
	}
	clear_shadow_from_swap_cache(si->type, begin, end);
}

static void set_cluster_next(struct swap_info_struct *si, unsigned long next)
{
	unsigned long prev;

	if (!(si->flags & SWP_SOLIDSTATE)) {
		si->cluster_next = next;
		return;
	}

	prev = this_cpu_read(*si->cluster_next_cpu);
	/*
	 * Cross the swap address space size aligned trunk, choose
	 * another trunk randomly to avoid lock contention on swap
	 * address space if possible.
	 */
	if ((prev >> SWAP_ADDRESS_SPACE_SHIFT) !=
	    (next >> SWAP_ADDRESS_SPACE_SHIFT)) {
		/* No free swap slots available */
		if (si->highest_bit <= si->lowest_bit)
			return;
		next = get_random_u32_inclusive(si->lowest_bit, si->highest_bit);
		next = ALIGN_DOWN(next, SWAP_ADDRESS_SPACE_PAGES);
		next = max_t(unsigned int, next, si->lowest_bit);
	}
	this_cpu_write(*si->cluster_next_cpu, next);
}

static inline void cluster_set_flag(struct swap_cluster_info *info,
	unsigned int flag)
{
	info->flags = flag;
}

static inline void cluster_set_next(struct swap_cluster_info *info,
				    unsigned int n)
{
	info->data = n;
}

static inline unsigned int cluster_next(struct swap_cluster_info *info)
{
	return info->data;
}

static inline void cluster_set_next_flag(struct swap_cluster_info *info,
					 unsigned int n, unsigned int f)
{
	info->flags = f;
	info->data = n;
}

static inline bool cluster_is_null(struct swap_cluster_info *info)
{
	return info->flags & CLUSTER_FLAG_NEXT_NULL;
}

static inline bool cluster_list_empty(struct swap_cluster_list *list)
{
	return cluster_is_null(&list->head);
}

static void cluster_list_add_tail(struct swap_cluster_list *list,
				  struct swap_cluster_info *ci,
				  unsigned int idx)
{
	if (cluster_list_empty(list)) {
		cluster_set_next_flag(&list->head, idx, 0);
		cluster_set_next_flag(&list->tail, idx, 0);
	} else {
		struct swap_cluster_info *ci_tail;
		unsigned int tail = cluster_next(&list->tail);

		/*
		 * Nested cluster lock, but both cluster locks are
		 * only acquired when we held swap_info_struct->lock
		 */
		ci_tail = ci + tail;
		spin_lock_nested(&ci_tail->lock, SINGLE_DEPTH_NESTING);
		cluster_set_next(ci_tail, idx);
		spin_unlock(&ci_tail->lock);
		cluster_set_next_flag(&list->tail, idx, 0);
	}
}

static void __free_cluster(struct swap_info_struct *si, unsigned long idx)
{
	struct swap_cluster_info *ci = si->cluster_info;

	cluster_set_flag(ci + idx, CLUSTER_FLAG_FREE);
	cluster_list_add_tail(&si->free_clusters, ci, idx);
}

#ifdef CONFIG_THP_SWAP
#define SWAPFILE_CLUSTER	HPAGE_PMD_NR

#define swap_entry_size(size)	(size)
#else
#define SWAPFILE_CLUSTER	256
#define swap_entry_size(size)	1
#endif

/* Add a cluster to discard list and schedule it to do discard */
static void swap_cluster_schedule_discard(struct swap_info_struct *si,
		unsigned int idx)
{
	/*
	 * If scan_swap_map_slots() can't find a free cluster, it will check
	 * si->swap_map directly. To make sure the discarding cluster isn't
	 * taken by scan_swap_map_slots(), mark the swap entries bad (occupied).
	 * It will be cleared after discard
	 */
	memset(si->swap_map + idx * SWAPFILE_CLUSTER,
			SWAP_MAP_BAD, SWAPFILE_CLUSTER);

	cluster_list_add_tail(&si->discard_clusters, si->cluster_info, idx);

	schedule_work(&si->discard_work);
}

static inline unsigned int cluster_count(struct swap_cluster_info *info)
{
	return info->data;
}


static inline void cluster_set_null(struct swap_cluster_info *info)
{
	info->flags = CLUSTER_FLAG_NEXT_NULL;
	info->data = 0;
}

static void free_cluster(struct swap_info_struct *si, unsigned long idx)
{
	struct swap_cluster_info *ci = si->cluster_info + idx;

	VM_BUG_ON(cluster_count(ci) != 0);
	/*
	 * If the swap is discardable, prepare discard the cluster
	 * instead of free it immediately. The cluster will be freed
	 * after discard.
	 */
	if ((si->flags & (SWP_WRITEOK | SWP_PAGE_DISCARD)) ==
	    (SWP_WRITEOK | SWP_PAGE_DISCARD)) {
		swap_cluster_schedule_discard(si, idx);
		return;
	}

	__free_cluster(si, idx);
}

static inline void cluster_set_count_flag(struct swap_cluster_info *info,
					 unsigned int c, unsigned int f)
{
	info->flags = f;
	info->data = c;
}

#ifdef CONFIG_THP_SWAP
#define SWAPFILE_CLUSTER	HPAGE_PMD_NR

#define swap_entry_size(size)	(size)
#else
#define SWAPFILE_CLUSTER	256

/*
 * Define swap_entry_size() as constant to let compiler to optimize
 * out some code if !CONFIG_THP_SWAP
 */
#define swap_entry_size(size)	1
#endif

static inline struct swap_extent *next_se(struct swap_extent *se)
{
	struct rb_node *rb = rb_next(&se->rb_node);
	return rb ? rb_entry(rb, struct swap_extent, rb_node) : NULL;
}

static struct swap_extent *
offset_to_swap_extent(struct swap_info_struct *sis, unsigned long offset)
{
	struct swap_extent *se;
	struct rb_node *rb;

	rb = sis->swap_extent_root.rb_node;
	while (rb) {
		se = rb_entry(rb, struct swap_extent, rb_node);
		if (offset < se->start_page)
			rb = rb->rb_left;
		else if (offset >= se->start_page + se->nr_pages)
			rb = rb->rb_right;
		else
			return se;
	}
	/* It *must* be present */
	BUG();
}

/*
 * swap allocation tell device that a cluster of swap can now be discarded,
 * to allow the swap device to optimize its wear-levelling.
 */
static void discard_swap_cluster(struct swap_info_struct *si,
				 pgoff_t start_page, pgoff_t nr_pages)
{
	struct swap_extent *se = offset_to_swap_extent(si, start_page);

	while (nr_pages) {
		pgoff_t offset = start_page - se->start_page;
		sector_t start_block = se->start_block + offset;
		sector_t nr_blocks = se->nr_pages - offset;

		if (nr_blocks > nr_pages)
			nr_blocks = nr_pages;
		start_page += nr_blocks;
		nr_pages -= nr_blocks;

		start_block <<= PAGE_SHIFT - 9;
		nr_blocks <<= PAGE_SHIFT - 9;
		if (blkdev_issue_discard(si->bdev, start_block,
					nr_blocks, GFP_NOIO))
			break;

		se = next_se(se);
	}
}

static unsigned int cluster_list_del_first(struct swap_cluster_list *list,
					   struct swap_cluster_info *ci)
{
	unsigned int idx;

	idx = cluster_next(&list->head);
	if (cluster_next(&list->tail) == idx) {
		cluster_set_null(&list->head);
		cluster_set_null(&list->tail);
	} else
		cluster_set_next_flag(&list->head,
				      cluster_next(&ci[idx]), 0);

	return idx;
}


/*
 * Doing discard actually. After a cluster discard is finished, the cluster
 * will be added to free cluster list. caller should hold si->lock.
*/
static void swap_do_scheduled_discard(struct swap_info_struct *si)
{
	struct swap_cluster_info *info, *ci;
	unsigned int idx;

	info = si->cluster_info;
	printk("[swap_do_scheduled_discard]: it work!\n");

	while (!cluster_list_empty(&si->discard_clusters)) {
		idx = cluster_list_del_first(&si->discard_clusters, info);
		_m_spin_unlock(si); // spin_unlock(&si->lock);
		discard_swap_cluster(si, idx * SWAPFILE_CLUSTER,
				SWAPFILE_CLUSTER);

		_m_spin_lock(si);
		ci = lock_cluster(si, idx * SWAPFILE_CLUSTER);
		__free_cluster(si, idx);
		memset(si->swap_map + idx * SWAPFILE_CLUSTER,
				0, SWAPFILE_CLUSTER);
		unlock_cluster(ci);
	}
}

/*
 * Try to get a swap entry from current cpu's swap entry pool (a cluster). This
 * might involve allocating a new cluster for current CPU too.
 */
static bool scan_swap_map_try_ssd_cluster(struct swap_info_struct *si,
	unsigned long *offset, unsigned long *scan_base)
{
	struct percpu_cluster *cluster;
	struct swap_cluster_info *ci;
	unsigned long tmp, max;

new_cluster:
	cluster = this_cpu_ptr(si->percpu_cluster);
	if (cluster_is_null(&cluster->index)) {
		if (!cluster_list_empty(&si->free_clusters)) {
			cluster->index = si->free_clusters.head;
			cluster->next = cluster_next(&cluster->index) *
					SWAPFILE_CLUSTER;
		} else if (!cluster_list_empty(&si->discard_clusters)) {
			/*
			 * we don't have free cluster but have some clusters in
			 * discarding, do discard now and reclaim them, then
			 * reread cluster_next_cpu since we dropped si->lock
			 */
			swap_do_scheduled_discard(si);
			*scan_base = this_cpu_read(*si->cluster_next_cpu);
			*offset = *scan_base;
			goto new_cluster;
		} else
			return false;
	}

	/*
	 * Other CPUs can use our cluster if they can't find a free cluster,
	 * check if there is still free entry in the cluster
	 */
	tmp = cluster->next;
	max = min_t(unsigned long, si->max,
		    (cluster_next(&cluster->index) + 1) * SWAPFILE_CLUSTER);
	if (tmp < max) {
		ci = lock_cluster(si, tmp);
		while (tmp < max) {
			if (!si->swap_map[tmp])
				break;
			tmp++;
		}
		unlock_cluster(ci);
	}
	if (tmp >= max) {
		cluster_set_null(&cluster->index);
		goto new_cluster;
	}
	cluster->next = tmp + 1;
	*offset = tmp;
	*scan_base = tmp;
	return true;
}

static inline bool cluster_is_free(struct swap_cluster_info *info)
{
	return info->flags & CLUSTER_FLAG_FREE;
}

static inline unsigned int cluster_list_first(struct swap_cluster_list *list)
{
	return cluster_next(&list->head);
}

static void alloc_cluster(struct swap_info_struct *si, unsigned long idx)
{
	struct swap_cluster_info *ci = si->cluster_info;

	VM_BUG_ON(cluster_list_first(&si->free_clusters) != idx);
	cluster_list_del_first(&si->free_clusters, ci);
	cluster_set_count_flag(ci + idx, 0, 0);
}

static inline void cluster_set_count(struct swap_cluster_info *info,
				     unsigned int c)
{
	info->data = c;
}

/*
 * The cluster corresponding to page_nr will be used. The cluster will be
 * removed from free cluster list and its usage counter will be increased.
 */
static void inc_cluster_info_page(struct swap_info_struct *p,
	struct swap_cluster_info *cluster_info, unsigned long page_nr)
{
	unsigned long idx = page_nr / SWAPFILE_CLUSTER;

	if (!cluster_info)
		return;
	if (cluster_is_free(&cluster_info[idx]))
		alloc_cluster(p, idx);

	VM_BUG_ON(cluster_count(&cluster_info[idx]) >= SWAPFILE_CLUSTER);
	cluster_set_count(&cluster_info[idx],
		cluster_count(&cluster_info[idx]) + 1);
}

/*
 * It's possible scan_swap_map_slots() uses a free cluster in the middle of free
 * cluster list. Avoiding such abuse to avoid list corruption.
 */
static bool
scan_swap_map_ssd_cluster_conflict(struct swap_info_struct *si,
	unsigned long offset)
{
	struct percpu_cluster *percpu_cluster;
	bool conflict;

	offset /= SWAPFILE_CLUSTER;
	conflict = !cluster_list_empty(&si->free_clusters) &&
		offset != cluster_list_first(&si->free_clusters) &&
		cluster_is_free(&si->cluster_info[offset]);

	if (!conflict)
		return false;

	percpu_cluster = this_cpu_ptr(si->percpu_cluster);
	cluster_set_null(&percpu_cluster->index);
	return true;
}

static bool swap_offset_available_and_locked(struct swap_info_struct *si,
					     unsigned long offset)
{
	if (data_race(!si->swap_map[offset])) {
		_m_spin_lock(si);
		return true;
	}

	if (READ_ONCE(si->swap_map[offset]) == SWAP_HAS_CACHE && (si->inuse_pages * 2) >= si->pages) {
		_m_spin_lock(si);
		return true;
	}

	return false;
}

static void __del_from_avail_list(struct swap_info_struct *p)
{
	int nid;

	assert_spin_locked(&p->lock);
	for_each_node(nid)
		plist_del(&p->avail_lists[nid], &swap_avail_heads[nid]);
}

static void del_from_avail_list(struct swap_info_struct *p)
{
	spin_lock(&swap_avail_lock);
	__del_from_avail_list(p);
	spin_unlock(&swap_avail_lock);
}

static void swap_range_alloc(struct swap_info_struct *si, unsigned long offset,
			     unsigned int nr_entries)
{
	unsigned int end = offset + nr_entries - 1;

	if (offset == si->lowest_bit)
		si->lowest_bit += nr_entries;
	if (end == si->highest_bit)
		WRITE_ONCE(si->highest_bit, si->highest_bit - nr_entries);
	WRITE_ONCE(si->inuse_pages, si->inuse_pages + nr_entries);
	if (si->inuse_pages == si->pages) {
		si->lowest_bit = si->max;
		si->highest_bit = 0;
		// del_from_avail_list(si);
	}
}

static int scan_swap_map_slots(struct swap_info_struct *si,
			       unsigned char usage, int nr,
			       swp_entry_t slots[])
{
	int cpu = get_cpu();
	put_cpu();
	// cpu와 p->type이 같지 않은 경우: worker를 통해 들어오지 않은 경우임.
	// 또는 worker를 통해 들어왔지만, 중간에 entry가 변경됨.
	if (cpu != si->type) {
		dump_stack();
	}

	struct swap_cluster_info *ci;
	unsigned long offset;
	unsigned long scan_base;
	unsigned long last_in_cluster = 0;
	int latency_ration = LATENCY_LIMIT;
	int n_ret = 0;
	bool scanned_many = false;

	/*
	 * We try to cluster swap pages by allocating them sequentially
	 * in swap.  Once we've allocated SWAPFILE_CLUSTER pages this
	 * way, however, we resort to first-free allocation, starting
	 * a new cluster.  This prevents us from scattering swap pages
	 * all over the entire swap partition, so that we reduce
	 * overall disk seek times between swap pages.  -- sct
	 * But we do now try to find an empty cluster.  -Andrea
	 * And we let swap pages go all over an SSD partition.  Hugh
	 */

	si->flags += SWP_SCANNING;
	/*
	 * Use percpu scan base for SSD to reduce lock contention on
	 * cluster and swap cache.  For HDD, sequential access is more
	 * important.
	 */
	if (si->flags & SWP_SOLIDSTATE)
		scan_base = this_cpu_read(*si->cluster_next_cpu);
	else
		scan_base = si->cluster_next;
	offset = scan_base;

	/* SSD algorithm */
	if (si->cluster_info) {
		if (!scan_swap_map_try_ssd_cluster(si, &offset, &scan_base))
			goto scan;
	} else if (unlikely(!si->cluster_nr--)) {
		if (si->pages - si->inuse_pages < SWAPFILE_CLUSTER) {
			si->cluster_nr = SWAPFILE_CLUSTER - 1;
			goto checks;
		}

		_m_spin_unlock(si); // spin_unlock(&si->lock);

		/*
		 * If seek is expensive, start searching for new cluster from
		 * start of partition, to minimize the span of allocated swap.
		 * If seek is cheap, that is the SWP_SOLIDSTATE si->cluster_info
		 * case, just handled by scan_swap_map_try_ssd_cluster() above.
		 */
		scan_base = offset = si->lowest_bit;
		last_in_cluster = offset + SWAPFILE_CLUSTER - 1;

		/* Locate the first empty (unaligned) cluster */
		for (; last_in_cluster <= si->highest_bit; offset++) {
			if (si->swap_map[offset])
				last_in_cluster = offset + SWAPFILE_CLUSTER;
			else if (offset == last_in_cluster) {
				_m_spin_lock(si);
				offset -= SWAPFILE_CLUSTER - 1;
				si->cluster_next = offset;
				si->cluster_nr = SWAPFILE_CLUSTER - 1;
				goto checks;
			}
			if (unlikely(--latency_ration < 0)) {
				cond_resched();
				latency_ration = LATENCY_LIMIT;
			}
		}

		offset = scan_base;
		_m_spin_lock(si);
		si->cluster_nr = SWAPFILE_CLUSTER - 1;
	}

checks:
	if (si->cluster_info) {
		while (scan_swap_map_ssd_cluster_conflict(si, offset)) {
		/* take a break if we already got some slots */
			if (n_ret)
				goto done;
			if (!scan_swap_map_try_ssd_cluster(si, &offset,
							&scan_base))
				goto scan;
		}
	}
	if (!(si->flags & SWP_WRITEOK))
		goto no_page;
	if (!si->highest_bit)
		goto no_page;
	if (offset > si->highest_bit)
		scan_base = offset = si->lowest_bit;

	ci = lock_cluster(si, offset);
	/* reuse swap entry of cache-only swap if not busy. */
	if (si->swap_map[offset] == SWAP_HAS_CACHE && (si->inuse_pages * 2) >= si->pages) {
		printk("[%s]: deleted swap entry in cache\n", __func__);
		int swap_was_freed;
		unlock_cluster(ci);
		_m_spin_unlock(si); // spin_unlock(&si->lock);
		swap_was_freed = __try_to_reclaim_swap(si, offset, TTRS_ANYWAY);
		_m_spin_lock(si);
		/* entry was freed successfully, try to use this again */
		if (swap_was_freed)
			goto checks;
		goto scan; /* check next one */
	}

	if (si->swap_map[offset]) {
		unlock_cluster(ci);
		if (!n_ret)
			goto scan;
		else
			goto done;
	}
	WRITE_ONCE(si->swap_map[offset], usage);
	inc_cluster_info_page(si, si->cluster_info, offset);
	unlock_cluster(ci);

	swap_range_alloc(si, offset, 1);
	slots[n_ret++] = swp_entry(si->type, offset);

	/* got enough slots or reach max slots? */
	if ((n_ret == nr) || (offset >= si->highest_bit))
		goto done;

	/* search for next available slot */

	/* time to take a break? */
	if (unlikely(--latency_ration < 0)) {
		if (n_ret)
			goto done;
		_m_spin_unlock(si); // spin_unlock(&si->lock);
		cond_resched();
		_m_spin_lock(si);
		latency_ration = LATENCY_LIMIT;
	}

	/* try to get more slots in cluster */
	if (si->cluster_info) {
		if (scan_swap_map_try_ssd_cluster(si, &offset, &scan_base))
			goto checks;
	} else if (si->cluster_nr && !si->swap_map[++offset]) {
		/* non-ssd case, still more slots in cluster? */
		--si->cluster_nr;
		goto checks;
	}

	/*
	 * Even if there's no free clusters available (fragmented),
	 * try to scan a little more quickly with lock held unless we
	 * have scanned too many slots already.
	 */
	if (!scanned_many) {
		unsigned long scan_limit;

		if (offset < scan_base)
			scan_limit = scan_base;
		else
			scan_limit = si->highest_bit;
		for (; offset <= scan_limit && --latency_ration > 0;
		     offset++) {
			if (!si->swap_map[offset])
				goto checks;
		}
	}

done:
	set_cluster_next(si, offset + 1);
	si->flags -= SWP_SCANNING;
	return n_ret;

scan:
	_m_spin_unlock(si); // spin_unlock(&si->lock);
	while (++offset <= READ_ONCE(si->highest_bit)) {
		if (unlikely(--latency_ration < 0)) {
			cond_resched();
			latency_ration = LATENCY_LIMIT;
			scanned_many = true;
		}
		if (swap_offset_available_and_locked(si, offset))
			goto checks;
	}
	offset = si->lowest_bit;
	while (offset < scan_base) {
		if (unlikely(--latency_ration < 0)) {
			cond_resched();
			latency_ration = LATENCY_LIMIT;
			scanned_many = true;
		}
		if (swap_offset_available_and_locked(si, offset))
			goto checks;
		offset++;
	}
	_m_spin_lock(si);

no_page:
	si->flags -= SWP_SCANNING;
	return n_ret;
}

static int swap_alloc_cluster(struct swap_info_struct *si, swp_entry_t *slot)
{
	unsigned long idx;
	struct swap_cluster_info *ci;
	unsigned long offset;

	/*
	 * Should not even be attempting cluster allocations when huge
	 * page swap is disabled.  Warn and fail the allocation.
	 */
	if (!IS_ENABLED(CONFIG_THP_SWAP)) {
		VM_WARN_ON_ONCE(1);
		return 0;
	}

	if (cluster_list_empty(&si->free_clusters))
		return 0;

	idx = cluster_list_first(&si->free_clusters);
	offset = idx * SWAPFILE_CLUSTER;
	ci = lock_cluster(si, offset);
	alloc_cluster(si, idx);
	cluster_set_count_flag(ci, SWAPFILE_CLUSTER, CLUSTER_FLAG_HUGE);

	memset(si->swap_map + offset, SWAP_HAS_CACHE, SWAPFILE_CLUSTER);
	unlock_cluster(ci);
	swap_range_alloc(si, offset, SWAPFILE_CLUSTER);
	*slot = swp_entry(si->type, offset);

	return 1;
}

static void swap_free_cluster(struct swap_info_struct *si, unsigned long idx)
{
	unsigned long offset = idx * SWAPFILE_CLUSTER;
	struct swap_cluster_info *ci;

	ci = lock_cluster(si, offset);
	memset(si->swap_map + offset, 0, SWAPFILE_CLUSTER);
	cluster_set_count_flag(ci, 0, 0);
	free_cluster(si, idx);
	unlock_cluster(ci);
	swap_range_free(si, offset, SWAPFILE_CLUSTER);
}

KTDEF(spin_lock);
KTDEF(swap_avail_lock);
KTDEF(scan_swap_map_slots);
KTDEF(get_swap_pages);
// using percpu swap_info
int _m_get_swap_pages(int n_goal, swp_entry_t swp_entries[], int entry_size)
{
	ktime_t get_nr_swap_pages_watch[2];
	int cpu = get_cpu();
	put_cpu();
	unsigned long size = swap_entry_size(entry_size);
	long avail_pgs;
	int n_ret = 0;

	/* Only single cluster request supported */
	WARN_ON_ONCE(n_goal > 1 && size == SWAPFILE_CLUSTER);

	// spin_lock(&swap_avail_lock);

        // avail_pgs = atomic_long_read(&nr_swap_pages) / size;
	// avail_pgs = get_nr_swap_pages() / size;
	avail_pgs = this_cpu_read(p_nr_swap_pages) / size;
	if (avail_pgs <= 0) {
		// printk("[%s]: this_cpu_read(p_nr_swap_pages) is zero\n", __func__);
		// spin_unlock(&swap_avail_lock);
		goto noswap;
	}

	n_goal = min3((long)n_goal, (long)SWAP_BATCH, avail_pgs);

	// atomic_long_sub(n_goal * size, &nr_swap_pages);
	this_cpu_sub(p_nr_swap_pages, n_goal * size);
	
	struct swap_info_struct *sis = this_cpu_read(percpu_si);
	if (sis) { 
		// spin_unlock(&swap_avail_lock);

		_m_spin_lock(sis);

		if (!sis->highest_bit || !(sis->flags & SWP_WRITEOK)) {
			WARN(!sis->highest_bit,
                             "swap_info %d in list but !highest_bit\n",
                             sis->type);
                        WARN(!(sis->flags & SWP_WRITEOK),
                             "swap_info %d in list but !SWP_WRITEOK\n",
                             sis->type);
			_m_spin_unlock(sis); // spin_unlock(&sis->lock);
			goto check_out;
		}
		if (size == SWAPFILE_CLUSTER) {
			if (sis->flags & SWP_BLKDEV)
				n_ret = swap_alloc_cluster(sis, swp_entries);
		} else {
			n_ret = scan_swap_map_slots(sis, SWAP_HAS_CACHE,
						    n_goal, swp_entries);
		}
		_m_spin_unlock(sis); // spin_unlock(&sis->lock);
		if (n_ret || size == SWAPFILE_CLUSTER) {
			goto check_out;
		}
	}

check_out:
	if (n_ret < n_goal) {
		// atomic_long_add((long)(n_goal - n_ret) * size, &nr_swap_pages);
		this_cpu_add(p_nr_swap_pages, (long)(n_goal - n_ret) * size);
	}
noswap:
	if (cpu != get_cpu()) {
		printk("[cpu] changed cpu!!! should not tjswja\n");
	}
	put_cpu();
	return n_ret;
}

static inline void cluster_clear_huge(struct swap_cluster_info *info)
{
	info->flags &= ~CLUSTER_FLAG_HUGE;
}

static inline bool cluster_is_huge(struct swap_cluster_info *info)
{
	if (IS_ENABLED(CONFIG_THP_SWAP))
		return info->flags & CLUSTER_FLAG_HUGE;
	return false;
}

#ifdef CONFIG_THP_SWAP
#define SWAPFILE_CLUSTER	HPAGE_PMD_NR

#define swap_entry_size(size)	(size)
#else
#define SWAPFILE_CLUSTER	256

/*
 * Define swap_entry_size() as constant to let compiler to optimize
 * out some code if !CONFIG_THP_SWAP
 */
#define swap_entry_size(size)	1
#endif

/*
 * Called after dropping swapcache to decrease refcnt to swap entries.
 */
void _k_put_swap_folio(struct folio *folio, swp_entry_t entry)
{
	unsigned long offset = swp_offset(entry);
	unsigned long idx = offset / SWAPFILE_CLUSTER;
	struct swap_cluster_info *ci;
	struct swap_info_struct *si;
	unsigned char *map;
	unsigned int i, free_entries = 0;
	unsigned char val;
	int size = swap_entry_size(folio_nr_pages(folio));

	si = _swap_info_get(entry);
	if (!si)
		return;

	ci = lock_cluster_or_swap_info(si, offset);
	if (size == SWAPFILE_CLUSTER) {
		VM_BUG_ON(!cluster_is_huge(ci));
		map = si->swap_map + offset;
		for (i = 0; i < SWAPFILE_CLUSTER; i++) {
			val = map[i];
			VM_BUG_ON(!(val & SWAP_HAS_CACHE));
			if (val == SWAP_HAS_CACHE)
				free_entries++;
		}
		cluster_clear_huge(ci);
		if (free_entries == SWAPFILE_CLUSTER) {
int cpu = get_cpu();
put_cpu();
// cpu와 p->type이 같지 않은 경우: worker를 통해 들어오지 않은 경우임.
// 또는 worker를 통해 들어왔지만, 중간에 entry가 변경됨.
if (cpu != si->type) {
	dump_stack();
}

			unlock_cluster_or_swap_info(si, ci);
			_m_spin_lock(si); // Spin_lock(&si->lock);
			mem_cgroup_uncharge_swap(entry, SWAPFILE_CLUSTER);
			swap_free_cluster(si, idx);
			_m_spin_unlock(si); // spin_unlock(&si->lock);
			return;
		}
	}
	for (i = 0; i < size; i++, entry.val++) {
		if (!__swap_entry_free_locked(si, offset + i, SWAP_HAS_CACHE)) {
			unlock_cluster_or_swap_info(si, ci);
			free_swap_slot(entry);
			if (i == size - 1)
				return;
			lock_cluster_or_swap_info(si, offset);
		}
	}
	unlock_cluster_or_swap_info(si, ci);
}

KTDEF(si_lock);
static struct swap_info_struct *swap_info_get_cont(swp_entry_t entry,
					struct swap_info_struct *q)
{
	struct swap_info_struct *p;


	p = _swap_info_get(entry);

	if (p != q) {
		if (q != NULL)
			_m_spin_unlock(q); // spin_unlock(&q->lock);
		if (p != NULL) {
#ifdef __PROFILING
#endif 
			_m_spin_lock(p); // spin_lock(&p->lock);
#ifdef __PROFILING
#endif 
		}
	}

	return p;
}

static bool swap_page_trans_huge_swapped(struct swap_info_struct *si,
					 swp_entry_t entry)
{
	struct swap_cluster_info *ci;
	unsigned char *map = si->swap_map;
	unsigned long roffset = swp_offset(entry);
	unsigned long offset = round_down(roffset, SWAPFILE_CLUSTER);
	int i;
	bool ret = false;

	ci = lock_cluster_or_swap_info(si, offset);
	if (!ci || !cluster_is_huge(ci)) {
		if (swap_count(map[roffset]))
			ret = true;
		goto unlock_out;
	}
	for (i = 0; i < SWAPFILE_CLUSTER; i++) {
		if (swap_count(map[offset + i])) {
			ret = true;
			break;
		}
	}
unlock_out:
	unlock_cluster_or_swap_info(si, ci);
	return ret;
}

static bool folio_swapped(struct folio *folio)
{
	swp_entry_t entry = folio->swap;
	struct swap_info_struct *si = _swap_info_get(entry);

	if (!si)
		return false;

	if (!IS_ENABLED(CONFIG_THP_SWAP) || likely(!folio_test_large(folio)))
		return swap_swapcount(si, entry) != 0;

	return swap_page_trans_huge_swapped(si, entry);
}

/**
 * folio_free_swap() - Free the swap space used for this folio.
 * @folio: The folio to remove.
 *
 * If swap is getting full, or if there are no more mappings of this folio,
 * then call folio_free_swap to free its swap space.
 *
 * Return: true if we were able to release the swap space.
 */
bool folio_free_swap(struct folio *folio)
{
	VM_BUG_ON_FOLIO(!folio_test_locked(folio), folio);

	if (!folio_test_swapcache(folio))
		return false;
	if (folio_test_writeback(folio))
		return false;
	if (folio_swapped(folio))
		return false;

	/*
	 * Once hibernation has begun to create its image of memory,
	 * there's a danger that one of the calls to folio_free_swap()
	 * - most probably a call from __try_to_reclaim_swap() while
	 * hibernation is allocating its own swap pages for the image,
	 * but conceivably even a call from memory reclaim - will free
	 * the swap from a folio which has already been recorded in the
	 * image as a clean swapcache folio, and then reuse its swap for
	 * another page of the image.  On waking from hibernation, the
	 * original folio might be freed under memory pressure, then
	 * later read back in from swap, now with the wrong data.
	 *
	 * Hibernation suspends storage while it is writing the image
	 * to disk so check that here.
	 */
	if (pm_suspended_storage())
		return false;

	delete_from_swap_cache(folio);
	folio_set_dirty(folio);
	return true;
}

void *folio_free_swap_work(void *data) {
	struct folio *folio = (struct folio *)data;
	bool *tsk_ret = kmalloc(sizeof(bool), GFP_KERNEL);

	(*tsk_ret) = folio_free_swap(folio);

	return tsk_ret;
}

struct swap_info_struct *_k_swap_info_get_cont(swp_entry_t entry,
					struct swap_info_struct *q)
{
	struct swap_info_struct *p;

	p = _swap_info_get(entry);

	if (p != q) {
		if (q != NULL)
			_m_spin_unlock(q); // spin_unlock(&q->lock);
		if (p != NULL) {
			_m_spin_lock(p); // spin_lock(&p->lock);
		}
	}
	return p;
}

/*
 * The cluster corresponding to page_nr decreases one usage. If the usage
 * counter becomes 0, which means no page in the cluster is in using, we can
 * optionally discard the cluster and add it to free cluster list.
 */
static void dec_cluster_info_page(struct swap_info_struct *p,
	struct swap_cluster_info *cluster_info, unsigned long page_nr)
{
	unsigned long idx = page_nr / SWAPFILE_CLUSTER;

	if (!cluster_info)
		return;

	VM_BUG_ON(cluster_count(&cluster_info[idx]) == 0);
	cluster_set_count(&cluster_info[idx],
		cluster_count(&cluster_info[idx]) - 1);

	if (cluster_count(&cluster_info[idx]) == 0)
		free_cluster(p, idx);
}

static unsigned char __swap_entry_free(struct swap_info_struct *p,
				       swp_entry_t entry)
{
	struct swap_cluster_info *ci;
	unsigned long offset = swp_offset(entry);
	unsigned char usage;

	ci = lock_cluster_or_swap_info(p, offset);
	usage = __swap_entry_free_locked(p, offset, 1);
	unlock_cluster_or_swap_info(p, ci);
	if (!usage)
		free_swap_slot(entry);

	return usage;
}

KTDEF(lock_cluster);
KTDEF(mem_cgroup_uncharge_swap);
KTDEF(swap_range_free);
static void swap_entry_free(struct swap_info_struct *p, swp_entry_t entry)
{
	struct swap_cluster_info *ci;
	unsigned long offset = swp_offset(entry);
	unsigned char count;

#ifdef __PROFILING
#endif 
	ci = lock_cluster(p, offset);
#ifdef __PROFILING
#endif 
	count = p->swap_map[offset];
	VM_BUG_ON(count != SWAP_HAS_CACHE);
	p->swap_map[offset] = 0;
	dec_cluster_info_page(p, p->cluster_info, offset); // 병목 지점이 아님
	unlock_cluster(ci);

#ifdef __PROFILING
#endif 
	_m_mem_cgroup_uncharge_swap(entry, 1);
#ifdef __PROFILING
#endif 

#ifdef __PROFILING
#endif 
	swap_range_free(p, offset, 1);
#ifdef __PROFILING
#endif 
}

/*
 * Caller has made sure that the swap device corresponding to entry
 * is still around or has not been recycled.
 */
void swap_free(swp_entry_t entry)
{
	struct swap_info_struct *p;

	p = _swap_info_get(entry);
	if (p)
		__swap_entry_free(p, entry);
}

void *swap_free_work(void *data)
{
	swp_entry_t *entry = (swp_entry_t *)data;

	swap_free(*entry);

	return NULL;
}

static int swp_entry_cmp(const void *ent1, const void *ent2)
{
	const swp_entry_t *e1 = ent1, *e2 = ent2;

	return (int)swp_type(*e1) - (int)swp_type(*e2);
}

KTDEF(swapcache_free_entries);
KTDEF(swap_entry_free);
void swapcache_free_entries(swp_entry_t *entries, int n)
{
	ktime_t swap_entry_free_watch[2], swapcache_free_entries_watch[2];

	bool is_current_worker = !strncmp(current->comm, "swp_worker", 10);
	struct swap_info_struct *p, *prev;
	int i;

	if (n <= 0)
		return;
	if (n > 1) {
		printk("[%s]: custom error\n", __func__);
	}

	prev = NULL;
	p = NULL;

	/*
	 * Sort swap entries by swap device, so each lock is only taken once.
	 * nr_swapfiles isn't absolutely correct, but the overhead of sort() is
	 * so low that it isn't necessary to optimize further.
	 */
	if (nr_swapfiles > 1)
		sort(entries, n, sizeof(entries[0]), swp_entry_cmp, NULL);
	for (i = 0; i < n; ++i) {
		p = swap_info_get_cont(entries[i], prev);
		if (p) {
			swap_entry_free(p, entries[i]);
#ifdef __PROFILING
#endif 
		}
		prev = p;
	}
	if (p) {
		_m_spin_unlock(p); // spin_unlock(&p->lock);
	}
#ifdef __PROFILING
#endif 
}

#ifdef __KSWAPD_PERCPU_free_swap_slot
KTDEF(swapcache_free_entries_insert_task);
void swapcache_free_entries_work(struct swap_task_item *task) 
{
	struct swpcache_fe_item param;
	memcpy(&param, task->async_param, sizeof(struct swpcache_fe_item));
	swapcache_free_entries(&(param.entry), param.n);
}
#endif // __KSWAPD_PERCPU

static void swap_users_ref_free(struct percpu_ref *ref);

static struct swap_info_struct *alloc_swap_info(void)
{
	struct swap_info_struct *p;
	struct swap_info_struct *defer = NULL;
	unsigned int type;
	int i;

#ifdef __PRINTDEBUG
	printk("[alloc_swap_info] nr_node_ids: %d\n", nr_node_ids);
#endif
	p = kvzalloc(struct_size(p, avail_lists, nr_node_ids), GFP_KERNEL);
	if (!p)
		return ERR_PTR(-ENOMEM);

	if (percpu_ref_init(&p->users, swap_users_ref_free,
			    PERCPU_REF_INIT_DEAD, GFP_KERNEL)) {
		kvfree(p);
		return ERR_PTR(-ENOMEM);
	}

	spin_lock(&swap_lock);
	for (type = 0; type < nr_swapfiles; type++) {
		if (!(swap_info[type]->flags & SWP_USED))
			break;
	}
#ifdef __PRINTDEBUG
	printk("[alloc_swap_info] before: nr_swapfiles - %d, type - %d\n", nr_swapfiles, type);
#endif
	if (type >= MAX_SWAPFILES) {
		spin_unlock(&swap_lock);
		percpu_ref_exit(&p->users);
		kvfree(p);
		return ERR_PTR(-EPERM);
	}
	if (type >= nr_swapfiles) {
		p->type = type;
		/*
		 * Publish the swap_info_struct after initializing it.
		 * Note that kvzalloc() above zeroes all its fields.
		 */
		smp_store_release(&swap_info[type], p); /* rcu_assign_pointer() */
		nr_swapfiles++;
	} else {
		defer = p;
		p = swap_info[type];
		/*
		 * Do not memset this entry: a racing procfs swap_next()
		 * would be relying on p->type to remain valid.
		 */
	}
	printk("[alloc_swap_info] after: nr_swapfiles - %d, type - %d\n", nr_swapfiles, type);
	p->swap_extent_root = RB_ROOT;
	plist_node_init(&p->list, 0);
	for_each_node(i)
		plist_node_init(&p->avail_lists[i], 0);
	p->flags = SWP_USED;
	spin_unlock(&swap_lock);
	if (defer) {
		percpu_ref_exit(&defer->users);
		kvfree(defer);
	}
	spin_lock_init(&p->lock);
	spin_lock_init(&p->cont_lock);
	init_completion(&p->comp);

	return p;
}

static void swap_discard_work(struct work_struct *work)
{
	struct swap_info_struct *si;

	si = container_of(work, struct swap_info_struct, discard_work);

	_m_spin_lock(si); // Spin_lock(&si->lock)
	swap_do_scheduled_discard(si);
	_m_spin_unlock(si); // spin_unlock(&si->lock);
}

static int claim_swapfile(struct swap_info_struct *p, struct inode *inode)
{
	int error;

	if (S_ISBLK(inode->i_mode)) {
		p->bdev = blkdev_get_by_dev(inode->i_rdev,
				BLK_OPEN_READ | BLK_OPEN_WRITE, p, NULL);
		if (IS_ERR(p->bdev)) {
			error = PTR_ERR(p->bdev);
			p->bdev = NULL;
			return error;
		}
		p->old_block_size = block_size(p->bdev);
		error = set_blocksize(p->bdev, PAGE_SIZE);
		if (error < 0)
			return error;
		/*
		 * Zoned block devices contain zones that have a sequential
		 * write only restriction.  Hence zoned block devices are not
		 * suitable for swapping.  Disallow them here.
		 */
		if (bdev_is_zoned(p->bdev))
			return -EINVAL;
		p->flags |= SWP_BLKDEV;
	} else if (S_ISREG(inode->i_mode)) {
		p->bdev = inode->i_sb->s_bdev;
	}

	return 0;
}

/*
 * Free all of a swapdev's extent information
 */
static void destroy_swap_extents(struct swap_info_struct *sis)
{
	while (!RB_EMPTY_ROOT(&sis->swap_extent_root)) {
		struct rb_node *rb = sis->swap_extent_root.rb_node;
		struct swap_extent *se = rb_entry(rb, struct swap_extent, rb_node);

		rb_erase(rb, &sis->swap_extent_root);
		kfree(se);
	}

	if (sis->flags & SWP_ACTIVATED) {
		struct file *swap_file = sis->swap_file;
		struct address_space *mapping = swap_file->f_mapping;

		sis->flags &= ~SWP_ACTIVATED;
		if (mapping->a_ops->swap_deactivate)
			mapping->a_ops->swap_deactivate(swap_file);
	}
}

static unsigned long read_swap_header(struct swap_info_struct *p,
					union swap_header *swap_header,
					struct inode *inode)
{
	int i;
	unsigned long maxpages;
	unsigned long swapfilepages;
	unsigned long last_page;

	if (memcmp("SWAPSPACE2", swap_header->magic.magic, 10)) {
		pr_err("Unable to find swap-space signature\n");
		return 0;
	}

	/* swap partition endianness hack... */
#ifdef __PRINTDEBUG
	printk("[read_swap_header] swap_header->info.last_page (before): %u\n", swap_header->info.last_page);
#endif
	if (swab32(swap_header->info.version) == 1) {
		swab32s(&swap_header->info.version);
		swab32s(&swap_header->info.last_page);
		swab32s(&swap_header->info.nr_badpages);
		if (swap_header->info.nr_badpages > MAX_SWAP_BADPAGES)
			return 0;
		for (i = 0; i < swap_header->info.nr_badpages; i++)
			swab32s(&swap_header->info.badpages[i]);
	}
#ifdef __PRINTDEBUG
	printk("[read_swap_header] swap_header->info.last_page (after): %u\n", swap_header->info.last_page);
#endif
	/* Check the swap header's sub-version */
	if (swap_header->info.version != 1) {
		pr_warn("Unable to handle swap header version %d\n",
			swap_header->info.version);
		return 0;
	}

	p->lowest_bit  = 1;
	p->cluster_next = 1;
	p->cluster_nr = 0;
	
	maxpages = swapfile_maximum_size;
#ifdef __PRINTDEBUG
	printk("[maxpages]: %lu\n", maxpages);
#endif
	last_page = swap_header->info.last_page;
	if (!last_page) {
		pr_warn("Empty swap-file\n");
		return 0;
	}
	if (last_page > maxpages) {
		printk("[warning!]: last_page(%lu) > maxpages(%lu)\n", last_page, maxpages);
		pr_warn("Truncating oversized swap area, only using %luk out of %luk\n",
			K(maxpages), K(last_page));
	}
	if (maxpages > last_page) {
		maxpages = last_page + 1;
		/* p->max is an unsigned int: don't overflow it */
		if ((unsigned int)maxpages == 0)
			maxpages = UINT_MAX;
	}
	p->highest_bit = maxpages - 1;

	if (!maxpages)
		return 0;
	swapfilepages = i_size_read(inode) >> PAGE_SHIFT;
	if (swapfilepages && maxpages > swapfilepages) {
		pr_warn("Swap area shorter than signature indicates\n");
		return 0;
	}
	if (swap_header->info.nr_badpages && S_ISREG(inode->i_mode))
		return 0;
	if (swap_header->info.nr_badpages > MAX_SWAP_BADPAGES)
		return 0;

	return maxpages;
}

#define SWAP_CLUSTER_INFO_COLS						\
	DIV_ROUND_UP(L1_CACHE_BYTES, sizeof(struct swap_cluster_info))
#define SWAP_CLUSTER_SPACE_COLS						\
	DIV_ROUND_UP(SWAP_ADDRESS_SPACE_PAGES, SWAPFILE_CLUSTER)
#define SWAP_CLUSTER_COLS						\
	max_t(unsigned int, SWAP_CLUSTER_INFO_COLS, SWAP_CLUSTER_SPACE_COLS)


/*
 * A `swap extent' is a simple thing which maps a contiguous range of pages
 * onto a contiguous range of disk blocks.  A rbtree of swap extents is
 * built at swapon time and is then used at swap_writepage/swap_readpage
 * time for locating where on disk a page belongs.
 *
 * If the swapfile is an S_ISBLK block device, a single extent is installed.
 * This is done so that the main operating code can treat S_ISBLK and S_ISREG
 * swap files identically.
 *
 * Whether the swapdev is an S_ISREG file or an S_ISBLK blockdev, the swap
 * extent rbtree operates in PAGE_SIZE disk blocks.  Both S_ISREG and S_ISBLK
 * swapfiles are handled *identically* after swapon time.
 *
 * For S_ISREG swapfiles, setup_swap_extents() will walk all the file's blocks
 * and will parse them into a rbtree, in PAGE_SIZE chunks.  If some stray
 * blocks are found which do not fall within the PAGE_SIZE alignment
 * requirements, they are simply tossed out - we will never use those blocks
 * for swapping.
 *
 * For all swap devices we set S_SWAPFILE across the life of the swapon.  This
 * prevents users from writing to the swap device, which will corrupt memory.
 *
 * The amount of disk space which a single swap extent represents varies.
 * Typically it is in the 1-4 megabyte range.  So we can have hundreds of
 * extents in the rbtree. - akpm.
 */
static int setup_swap_extents(struct swap_info_struct *sis, sector_t *span)
{
	struct file *swap_file = sis->swap_file;
	struct address_space *mapping = swap_file->f_mapping;
	struct inode *inode = mapping->host;
	int ret;

	if (S_ISBLK(inode->i_mode)) {
		ret = add_swap_extent(sis, 0, sis->max, 0);
		*span = sis->pages;
		return ret;
	}

	if (mapping->a_ops->swap_activate) {
		ret = mapping->a_ops->swap_activate(sis, swap_file, span);
		if (ret < 0)
			return ret;
		sis->flags |= SWP_ACTIVATED;
		if ((sis->flags & SWP_FS_OPS) &&
		    sio_pool_init() != 0) {
			destroy_swap_extents(sis);
			return -ENOMEM;
		}
		return ret;
	}

	return generic_swapfile_activate(sis, swap_file, span);
}

static void cluster_list_init(struct swap_cluster_list *list)
{
	cluster_set_null(&list->head);
	cluster_set_null(&list->tail);
}

static int setup_swap_map_and_extents(struct swap_info_struct *p,
					union swap_header *swap_header,
					unsigned char *swap_map,
					struct swap_cluster_info *cluster_info,
					unsigned long maxpages,
					sector_t *span)
{
	unsigned int j, k;
	unsigned int nr_good_pages;
	int nr_extents;
	unsigned long nr_clusters = DIV_ROUND_UP(maxpages, SWAPFILE_CLUSTER);
	unsigned long col = p->cluster_next / SWAPFILE_CLUSTER % SWAP_CLUSTER_COLS;
	unsigned long i, idx;

	nr_good_pages = maxpages - 1;	/* omit header page */

	cluster_list_init(&p->free_clusters);
	cluster_list_init(&p->discard_clusters);

	for (i = 0; i < swap_header->info.nr_badpages; i++) {
		unsigned int page_nr = swap_header->info.badpages[i];
		if (page_nr == 0 || page_nr > swap_header->info.last_page)
			return -EINVAL;
		if (page_nr < maxpages) {
			swap_map[page_nr] = SWAP_MAP_BAD;
			nr_good_pages--;
			/*
			 * Haven't marked the cluster free yet, no list
			 * operation involved
			 */
			inc_cluster_info_page(p, cluster_info, page_nr);
		}
	}

	/* Haven't marked the cluster free yet, no list operation involved */
	for (i = maxpages; i < round_up(maxpages, SWAPFILE_CLUSTER); i++)
		inc_cluster_info_page(p, cluster_info, i);

	if (nr_good_pages) {
		swap_map[0] = SWAP_MAP_BAD;
		/*
		 * Not mark the cluster free yet, no list
		 * operation involved
		 */
		inc_cluster_info_page(p, cluster_info, 0);
		p->max = maxpages;
		p->pages = nr_good_pages;
		nr_extents = setup_swap_extents(p, span);
		if (nr_extents < 0)
			return nr_extents;
		nr_good_pages = p->pages;
	}
	if (!nr_good_pages) {
		pr_warn("Empty swap-file\n");
		return -EINVAL;
	}

	if (!cluster_info)
		return nr_extents;


	/*
	 * Reduce false cache line sharing between cluster_info and
	 * sharing same address space.
	 */
#ifdef __PRINTDEBUG
	printk("[setup_swap_map_and_extents] infos: SWAP_CLUSTER_COLS = %d, col = %ld\n", SWAP_CLUSTER_COLS, col);
#endif
	unsigned long last_idx = 0;
	for (k = 0; k < SWAP_CLUSTER_COLS; k++) {
		j = (k + col) % SWAP_CLUSTER_COLS;
		for (i = 0; i < DIV_ROUND_UP(nr_clusters, SWAP_CLUSTER_COLS); i++) {
			idx = i * SWAP_CLUSTER_COLS + j;
			if (idx >= nr_clusters)
				continue;
			if (cluster_count(&cluster_info[idx])) {
				last_idx = idx;
				printk("[cluster setting] skipped: %lu\n", idx);
				continue;
			}
			cluster_set_flag(&cluster_info[idx], CLUSTER_FLAG_FREE);
			cluster_list_add_tail(&p->free_clusters, cluster_info,
					      idx);
		}
	}

#ifdef __PRINTDEBUG
	//	printk("[cluster setting] free_clusters.tail.data (=idx): %u\n", p->free_clusters.tail.data);
	printk("[free_clusters.tail] cluster_info[%d].data : %u\n", p->free_clusters.tail.data, cluster_info[p->free_clusters.tail.data].data);
	printk("[free_clsuters.tail] cluster_info[%d].flag : %u\n", p->free_clusters.tail.data, cluster_info[p->free_clusters.tail.data].flags);
	printk("[last cluster] cluster_info[%ld]: %d\n", nr_clusters - 1, cluster_count(&cluster_info[nr_clusters - 1]));
#endif	
	return nr_extents;
}

static void _enable_swap_info(struct swap_info_struct *p)
{
#ifdef __DEL_SILOCK
	printk("[DEL_SILOCK]: is_okay?\n");
#endif
#ifdef __PERCPU
	printk("[_enable_swap_info]: p->type=%u\n", p->type);
	per_cpu(percpu_si, p->type) = swap_info[p->type];
	per_cpu(p_nr_swap_pages, p->type) = p->pages;
#endif

	p->flags |= SWP_WRITEOK;
	// atomic_long_add(p->pages, &nr_swap_pages);
	total_swap_pages += p->pages;

	assert_spin_locked(&swap_lock);
	/*
	 * both lists are plists, and thus priority ordered.
	 * swap_active_head needs to be priority ordered for swapoff(),
	 * which on removal of any swap_info_struct with an auto-assigned
	 * (i.e. negative) priority increments the auto-assigned priority
	 * of any lower-priority swap_info_structs.
	 * swap_avail_head needs to be priority ordered for folio_alloc_swap(),
	 * which allocates swap pages from the highest available priority
	 * swap_info_struct.
	 */
	plist_add(&p->list, &swap_active_head);

	/* add to available list iff swap device is not full */
	if (p->highest_bit)
		add_to_avail_list(p);
/*
	if (p->type > 62) {
		print_infos();
	}
*/
}

static int swap_node(struct swap_info_struct *p)
{
	struct block_device *bdev;

	if (p->bdev)
		bdev = p->bdev;
	else
		bdev = p->swap_file->f_inode->i_sb->s_bdev;

#ifdef __PRINTDEBUG
	if (bdev)
		printk("[sawp_node]: bdev is exists\n");
#endif

	return bdev ? bdev->bd_disk->node_id : NUMA_NO_NODE;
}

static void setup_swap_info(struct swap_info_struct *p, int prio,
			    unsigned char *swap_map,
			    struct swap_cluster_info *cluster_info)
{
	int i;

	if (prio >= 0)
		p->prio = prio;
	else
		p->prio = --least_priority;
	/*
	 * the plist prio is negated because plist ordering is
	 * low-to-high, while swap ordering is high-to-low
	 */
	p->list.prio = -p->prio;
	for_each_node(i) {
		if (p->prio >= 0)
			p->avail_lists[i].prio = -p->prio;
		else {
			if (swap_node(p) == i)
				p->avail_lists[i].prio = 1;
			else
				p->avail_lists[i].prio = -p->prio;
		}
	}
	p->swap_map = swap_map;
	p->cluster_info = cluster_info;
}

static void enable_swap_info(struct swap_info_struct *p, int prio,
				unsigned char *swap_map,
				struct swap_cluster_info *cluster_info)
{
	zswap_swapon(p->type);

	spin_lock(&swap_lock);
	spin_lock(&p->lock);
	setup_swap_info(p, prio, swap_map, cluster_info);
	spin_unlock(&p->lock);
	spin_unlock(&swap_lock);
	/*
	 * Finished initializing swap device, now it's safe to reference it.
	 */
	percpu_ref_resurrect(&p->users);
	spin_lock(&swap_lock);
	spin_lock(&p->lock);
	_enable_swap_info(p);
	spin_unlock(&p->lock);
	spin_unlock(&swap_lock);
}

static inline struct swap_extent *first_se(struct swap_info_struct *sis)
{
	struct rb_node *rb = rb_first(&sis->swap_extent_root);
	return rb_entry(rb, struct swap_extent, rb_node);
}

/*
 * swapon tell device that all the old swap contents can be discarded,
 * to allow the swap device to optimize its wear-levelling.
 */
static int discard_swap(struct swap_info_struct *si)
{
	struct swap_extent *se;
	sector_t start_block;
	sector_t nr_blocks;
	int err = 0;

	/* Do not discard the swap header page! */
	se = first_se(si);
	start_block = (se->start_block + 1) << (PAGE_SHIFT - 9);
	nr_blocks = ((sector_t)se->nr_pages - 1) << (PAGE_SHIFT - 9);
	if (nr_blocks) {
		err = blkdev_issue_discard(si->bdev, start_block,
				nr_blocks, GFP_KERNEL);
		if (err)
			return err;
		cond_resched();
	}

	for (se = next_se(se); se; se = next_se(se)) {
		start_block = se->start_block << (PAGE_SHIFT - 9);
		nr_blocks = (sector_t)se->nr_pages << (PAGE_SHIFT - 9);

		err = blkdev_issue_discard(si->bdev, start_block,
				nr_blocks, GFP_KERNEL);
		if (err)
			break;

		cond_resched();
	}
	return err;		/* That will often be -EOPNOTSUPP */
}

void print_extent(struct swap_info_struct* cur) {
// [ extent! ]
struct rb_node *rb = cur->swap_extent_root.rb_node;
struct swap_extent *se;
while (rb->rb_left) {
	rb = rb->rb_left;
}

while (rb) {
	se = rb_entry(rb, struct swap_extent, rb_node);
	printk("[node]: start_page = %lu, nr_pages = %lu, start_block = %llu\n", se->start_page, se->nr_pages, se->start_block);

	rb = rb_next(rb);
}
}

int k_swapon(const char __user *specialfile, int swap_flags)
{
	struct swap_info_struct *p;
	struct filename *name;
	struct file *swap_file = NULL;
	struct address_space *mapping;
	struct dentry *dentry;
	int prio;
	int error;
	union swap_header *swap_header;
	int nr_extents;
	sector_t span;
	unsigned long maxpages;
	unsigned char *swap_map = NULL;
	struct swap_cluster_info *cluster_info = NULL;
	struct page *page = NULL;
	struct inode *inode = NULL;
	bool inced_nr_rotate_swap = false;
	
	if (swap_flags & ~SWAP_FLAGS_VALID)
		return -EINVAL;

	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;

	if (!swap_avail_heads)
		return -ENOMEM;

	// print_infos();
	printk("[alloc_swap_info]: start\n");
	p = alloc_swap_info();
	if (IS_ERR(p))
		return PTR_ERR(p);

	INIT_WORK(&p->discard_work, swap_discard_work);

	name = getname(specialfile);
	printk("[getname] end: %s\n", name->name);
	if (IS_ERR(name)) {
		error = PTR_ERR(name);
		name = NULL;
		goto bad_swap;
	}
	swap_file = file_open_name(name, O_RDWR|O_LARGEFILE, 0);
	if (IS_ERR(swap_file)) {
		error = PTR_ERR(swap_file);
		swap_file = NULL;
		goto bad_swap;
	}

	p->swap_file = swap_file;
	mapping = swap_file->f_mapping;
	dentry = swap_file->f_path.dentry;
	inode = mapping->host;

	error = claim_swapfile(p, inode);
	if (unlikely(error))
		goto bad_swap;

	inode_lock(inode);
	if (d_unlinked(dentry) || cant_mount(dentry)) {
		error = -ENOENT;
		goto bad_swap_unlock_inode;
	}
	if (IS_SWAPFILE(inode)) {
		error = -EBUSY;
		goto bad_swap_unlock_inode;
	}

	/*
	 * Read the swap header.
	 */
	if (!mapping->a_ops->read_folio) {
		error = -EINVAL;
		goto bad_swap_unlock_inode;
	}
	page = read_mapping_page(mapping, 0, swap_file);
	if (IS_ERR(page)) {
		error = PTR_ERR(page);
		goto bad_swap_unlock_inode;
	}
	swap_header = kmap(page);

	maxpages = read_swap_header(p, swap_header, inode);
	printk("[max_pages] %lu\n", maxpages);
	if (unlikely(!maxpages)) {
		error = -EINVAL;
		goto bad_swap_unlock_inode;
	}

	/* OK, set up the swap map and apply the bad block list */
	swap_map = vzalloc(maxpages);
	if (!swap_map) {
		error = -ENOMEM;
		goto bad_swap_unlock_inode;
	}

	if (p->bdev && bdev_stable_writes(p->bdev))
		p->flags |= SWP_STABLE_WRITES;

	if (p->bdev && bdev_synchronous(p->bdev)) {
		printk("bdev_synchronous\n");
		p->flags |= SWP_SYNCHRONOUS_IO;
	}

	if (p->bdev && bdev_nonrot(p->bdev)) {
		int cpu;
		unsigned long ci, nr_cluster;

		p->flags |= SWP_SOLIDSTATE;
		p->cluster_next_cpu = alloc_percpu(unsigned int);
		if (!p->cluster_next_cpu) {
			error = -ENOMEM;
			goto bad_swap_unlock_inode;
		}
		/*
		 * select a random position to start with to help wear leveling
		 * SSD
		 */
		for_each_online_cpu(cpu) {
			per_cpu(*p->cluster_next_cpu, cpu) =
				get_random_u32_inclusive(1, p->highest_bit);
		}
		nr_cluster = DIV_ROUND_UP(maxpages, SWAPFILE_CLUSTER);
#ifdef __PRINTDEBUG
		printk("[SWAPFILE_CLUSTER] %d\n", SWAPFILE_CLUSTER);
		printk("[nr_cluster] %ld = DIV_ROUND_UP(%ld, %d)\n", nr_cluster, maxpages, SWAPFILE_CLUSTER);
#endif

		cluster_info = kvcalloc(nr_cluster, sizeof(*cluster_info),
					GFP_KERNEL);
		if (!cluster_info) {
			error = -ENOMEM;
			goto bad_swap_unlock_inode;
		}

		for (ci = 0; ci < nr_cluster; ci++)
			spin_lock_init(&((cluster_info + ci)->lock));

		p->percpu_cluster = alloc_percpu(struct percpu_cluster);
		if (!p->percpu_cluster) {
			error = -ENOMEM;
			goto bad_swap_unlock_inode;
		}
		for_each_online_cpu(cpu) {
			struct percpu_cluster *cluster;
			cluster = per_cpu_ptr(p->percpu_cluster, cpu);
			cluster_set_null(&cluster->index);
		}
	} else {
		atomic_inc(&nr_rotate_swap);
		inced_nr_rotate_swap = true;
	}

	error = swap_cgroup_swapon(p->type, maxpages);
	if (error)
		goto bad_swap_unlock_inode;

	nr_extents = setup_swap_map_and_extents(p, swap_header, swap_map,
		cluster_info, maxpages, &span);
	if (unlikely(nr_extents < 0)) {
		error = nr_extents;
		goto bad_swap_unlock_inode;
	}

	if ((swap_flags & SWAP_FLAG_DISCARD) &&
	    p->bdev && bdev_max_discard_sectors(p->bdev)) {
		printk("[discard]: discard it on!\n");
		/*
		 * When discard is enabled for swap with no particular
		 * policy flagged, we set all swap discard flags here in
		 * order to sustain backward compatibility with older
		 * swapon(8) releases.
		 */
		p->flags |= (SWP_DISCARDABLE | SWP_AREA_DISCARD |
			     SWP_PAGE_DISCARD);

		/*
		 * By flagging sys_swapon, a sysadmin can tell us to
		 * either do single-time area discards only, or to just
		 * perform discards for released swap page-clusters.
		 * Now it's time to adjust the p->flags accordingly.
		 */
		if (swap_flags & SWAP_FLAG_DISCARD_ONCE)
			p->flags &= ~SWP_PAGE_DISCARD;
		else if (swap_flags & SWAP_FLAG_DISCARD_PAGES)
			p->flags &= ~SWP_AREA_DISCARD;

		/* issue a swapon-time discard if it's still required */
		if (p->flags & SWP_AREA_DISCARD) {
			int err = discard_swap(p);
			if (unlikely(err))
				pr_err("swapon: discard_swap(%p): %d\n",
					p, err);
		}
	}

	error = init_swap_address_space(p->type, maxpages);
	if (error)
		goto bad_swap_unlock_inode;

	/*
	 * Flush any pending IO and dirty mappings before we start using this
	 * swap device.
	 */
	inode->i_flags |= S_SWAPFILE;
	error = inode_drain_writes(inode);
	if (error) {
		inode->i_flags &= ~S_SWAPFILE;
		goto free_swap_address_space;
	}

	mutex_lock(&swapon_mutex);
	prio = -1;
	if (swap_flags & SWAP_FLAG_PREFER)
		prio =
		  (swap_flags & SWAP_FLAG_PRIO_MASK) >> SWAP_FLAG_PRIO_SHIFT;
	enable_swap_info(p, prio, swap_map, cluster_info);

	pr_info("Adding %uk swap on %s.  Priority:%d extents:%d across:%lluk %s%s%s%s\n",
		K(p->pages), name->name, p->prio, nr_extents,
		K((unsigned long long)span),
		(p->flags & SWP_SOLIDSTATE) ? "SS" : "",
		(p->flags & SWP_DISCARDABLE) ? "D" : "",
		(p->flags & SWP_AREA_DISCARD) ? "s" : "",
		(p->flags & SWP_PAGE_DISCARD) ? "c" : "");

	mutex_unlock(&swapon_mutex);
	atomic_inc(&proc_poll_event);
	wake_up_interruptible(&proc_poll_wait);
/*	
	printk("[cluster setting] free_clusters->tail.idx: %u\n", p->cluster_info[p->free_clusters.tail.data].flags);
	for (long cl_i = 0; cl_i < DIV_ROUND_UP(maxpages, SWAPFILE_CLUSTER); cl_i++) {
		if (p->cluster_info[cl_i].flags != 0 && p->cluster_info[cl_i].flags != 1) {
			printk("NEXT_NULL: %ld\n", cl_i);
		}
	}
*/
	error = 0;
	goto out;
free_swap_address_space:
	exit_swap_address_space(p->type);
bad_swap_unlock_inode:
	inode_unlock(inode);
bad_swap:
	free_percpu(p->percpu_cluster);
	p->percpu_cluster = NULL;
	free_percpu(p->cluster_next_cpu);
	p->cluster_next_cpu = NULL;
	if (inode && S_ISBLK(inode->i_mode) && p->bdev) {
		set_blocksize(p->bdev, p->old_block_size);
		blkdev_put(p->bdev, p);
	}
	inode = NULL;
	destroy_swap_extents(p);
	swap_cgroup_swapoff(p->type);
	spin_lock(&swap_lock);
	p->swap_file = NULL;
	p->flags = 0;
	spin_unlock(&swap_lock);
	vfree(swap_map);
	kvfree(cluster_info);
	if (inced_nr_rotate_swap)
		atomic_dec(&nr_rotate_swap);
	if (swap_file)
		filp_close(swap_file, NULL);
out:
	if (page && !IS_ERR(page)) {
		kunmap(page);
		put_page(page);
	}
	if (name)
		putname(name);
	if (inode)
		inode_unlock(inode);
	if (!error)
		enable_swap_slots_cache();
	return error;
}

static struct swap_info_struct *swap_type_to_swap_info(int type)
{
	if (type >= MAX_SWAPFILES)
		return NULL;

	return READ_ONCE(swap_info[type]); /* rcu_dereference() */
}

swp_entry_t _m_get_swap_page_of_type(int type)
{	
	struct swap_info_struct *si = swap_type_to_swap_info(type);
	swp_entry_t entry = {0};

	if (!si)
		goto fail;

	int cpu = get_cpu();
	put_cpu();
	// cpu와 p->type이 같지 않은 경우: worker를 통해 들어오지 않은 경우임.
	// 또는 worker를 통해 들어왔지만, 중간에 entry가 변경됨.
	if (cpu != si->type) {
		dump_stack();
	}

	/* This is called for allocating swap entry, not cache */
	_m_spin_lock(si); // Spin_lock(&si->lock);
	if ((si->flags & SWP_WRITEOK) && scan_swap_map_slots(si, 1, 1, &entry)) {
#ifdef __PROFILING
#endif 
		this_cpu_dec(p_nr_swap_pages);
		// atomic_long_dec(&nr_swap_pages);
#ifdef __PROFILING
#endif 
	}
	_m_spin_unlock(si); // spin_unlock(&si->lock);
fail:
	return entry;
}

/*
 * add_swap_count_continuation - called when a swap count is duplicated
 * beyond SWAP_MAP_MAX, it allocates a new page and links that to the entry's
 * page of the original vmalloc'ed swap_map, to hold the continuation count
 * (for that entry and for its neighbouring PAGE_SIZE swap entries).  Called
 * again when count is duplicated beyond SWAP_MAP_MAX * SWAP_CONT_MAX, etc.
 *
 * These continuation pages are seldom referenced: the common paths all work
 * on the original swap_map, only referring to a continuation page when the
 * low "digit" of a count is incremented or decremented through SWAP_MAP_MAX.
 *
 * add_swap_count_continuation(, GFP_ATOMIC) can be called while holding
 * page table locks; if it fails, add_swap_count_continuation(, GFP_KERNEL)
 * can be called after dropping locks.
 */
KTDEF(_k_si_lock);
// static bool on_off_flag = false;
int _m_add_swap_count_continuation(swp_entry_t entry, gfp_t gfp_mask)
{
        struct swap_info_struct *si;
        struct swap_cluster_info *ci;
        struct page *head;
        struct page *page;
        struct page *list_page;
        pgoff_t offset;
        unsigned char count;
        int ret = 0;

        /*
         * When debugging, it's easier to use __GFP_ZERO here; but it's better
         * for latency not to zero a page while GFP_ATOMIC and holding locks.
         */
        page = alloc_page(gfp_mask | __GFP_HIGHMEM);

        si = get_swap_device(entry);
        if (!si) {
                /*
                 * An acceptable race has occurred since the failing
                 * __swap_duplicate(): the swap device may be swapoff
                 */
                goto outer;
        }
			int cpu = get_cpu();
	put_cpu();
	// cpu와 p->type이 같지 않은 경우: worker를 통해 들어오지 않은 경우임.
	// 또는 worker를 통해 들어왔지만, 중간에 entry가 변경됨.
	if (cpu != si->type) {
		dump_stack();
	}
// bool is_current_worker = !strncmp(current->comm, "swp_worker", 10);

// if (!is_current_worker) {
// 	if (!on_off_flag) {
// 		dump_stack();
// 		on_off_flag = true;
// 	}
// }
#ifdef __PROFILING
#endif
        _m_spin_lock(si); // Spin_lock(&si->lock);
#ifdef __PROFILING
#endif

        offset = swp_offset(entry);

        ci = lock_cluster(si, offset);

        count = swap_count(si->swap_map[offset]);

        if ((count & ~COUNT_CONTINUED) != SWAP_MAP_MAX) {
                /*
                 * The higher the swap count, the more likely it is that tasks
                 * will race to add swap count continuation: we need to avoid
                 * over-provisioning.
                 */
                goto out;
        }

        if (!page) {
                ret = -ENOMEM;
                goto out;
        }

        head = vmalloc_to_page(si->swap_map + offset);
        offset &= ~PAGE_MASK;

        spin_lock(&si->cont_lock);
        /*
         * Page allocation does not initialize the page's lru field,
         * but it does always reset its private field.
         */
        if (!page_private(head)) {
                BUG_ON(count & COUNT_CONTINUED);
                INIT_LIST_HEAD(&head->lru);
                set_page_private(head, SWP_CONTINUED);
                si->flags |= SWP_CONTINUED;
        }

        list_for_each_entry(list_page, &head->lru, lru) {
                unsigned char *map;

                /*
                 * If the previous map said no continuation, but we've found
                 * a continuation page, free our allocation and use this one.
                 */
                if (!(count & COUNT_CONTINUED))
                        goto out_unlock_cont;

                map = kmap_atomic(list_page) + offset;
                count = *map;
                kunmap_atomic(map);

                /*
                 * If this continuation count now has some space in it,
                 * free our allocation and use this one.
                 */
                if ((count & ~COUNT_CONTINUED) != SWAP_CONT_MAX)
                        goto out_unlock_cont;
        }

        list_add_tail(&page->lru, &head->lru);
        page = NULL;                    /* now it's attached, don't free it */
out_unlock_cont:
        spin_unlock(&si->cont_lock);
out:
        unlock_cluster(ci);
        spin_unlock(&si->lock);
        put_swap_device(si);
outer:
        if (page)
                __free_page(page);
        return ret;
}

/*
 * Verify that a swap entry is valid and increment its swap map count.
 *
 * Returns error code in following case.
 * - success -> 0
 * - swp_entry is invalid -> EINVAL
 * - swp_entry is migration entry -> EINVAL
 * - swap-cache reference is requested but there is already one. -> EEXIST
 * - swap-cache reference is requested but the entry is not used. -> ENOENT
 * - swap-mapped reference requested but needs continued swap count. -> ENOMEM
 */
static int __m_swap_duplicate(swp_entry_t entry, unsigned char usage)
{
	struct swap_info_struct *p;
	struct swap_cluster_info *ci;
	unsigned long offset;
	unsigned char count;
	unsigned char has_cache;
	int err;

	p = swp_swap_info(entry);

	offset = swp_offset(entry);
	ci = lock_cluster_or_swap_info(p, offset);

	count = p->swap_map[offset];

	/*
	 * swapin_readahead() doesn't check if a swap entry is valid, so the
	 * swap entry could be SWAP_MAP_BAD. Check here with lock held.
	 */
	if (unlikely(swap_count(count) == SWAP_MAP_BAD)) {
		err = -ENOENT;
		goto unlock_out;
	}

	has_cache = count & SWAP_HAS_CACHE;
	count &= ~SWAP_HAS_CACHE;
	err = 0;

	if (usage == SWAP_HAS_CACHE) {

		/* set SWAP_HAS_CACHE if there is no cache and entry is used */
		if (!has_cache && count)
			has_cache = SWAP_HAS_CACHE;
		else if (has_cache)		/* someone else added cache */
			err = -EEXIST;
		else				/* no users remaining */
			err = -ENOENT;

	} else if (count || has_cache) {

		if ((count & ~COUNT_CONTINUED) < SWAP_MAP_MAX)
			count += usage;
		else if ((count & ~COUNT_CONTINUED) > SWAP_MAP_MAX)
			err = -EINVAL;
		else if (swap_count_continued(p, offset, count))
			count = COUNT_CONTINUED;
		else
			err = -ENOMEM;
	} else
		err = -ENOENT;			/* unused swap entry */

	WRITE_ONCE(p->swap_map[offset], count | has_cache);

unlock_out:
	unlock_cluster_or_swap_info(p, ci);
	return err;
}

/*
 * Help swapoff by noting that swap entry belongs to shmem/tmpfs
 * (in which case its reference count is never incremented).
 */
void swap_shmem_alloc(swp_entry_t entry)
{
        __m_swap_duplicate(entry, SWAP_MAP_SHMEM);
}

/*
 * Increase reference count of swap entry by 1.
 * Returns 0 for success, or -ENOMEM if a swap_count_continuation is required
 * but could not be atomically allocated.  Returns 0, just as if it succeeded,
 * if __swap_duplicate() fails for another reason (-EINVAL or -ENOENT), which
 * might occur if a page table entry has got corrupted.
 */
int _m_swap_duplicate(swp_entry_t entry)
{
	int err = 0;

	while (!err && __m_swap_duplicate(entry, 1) == -ENOMEM)
		err = _m_add_swap_count_continuation(entry, GFP_ATOMIC);
	return err;
}

void *_m_swap_duplicate_work(void *data)
{
	swp_entry_t *entry = (swp_entry_t *)data;
	int *tsk_ret = kmalloc(sizeof(int *), GFP_KERNEL);

// #ifdef __PROFILING
// #endif 
	(*tsk_ret) = _m_swap_duplicate(*entry);
// #ifdef __PROFILING
// #endif 

	return tsk_ret;
}
