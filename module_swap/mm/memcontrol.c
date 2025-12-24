// SPDX-License-Identifier: GPL-2.0-or-later
/* memcontrol.c - Memory Controller
 *
 * Copyright IBM Corporation, 2007
 * Author Balbir Singh <balbir@linux.vnet.ibm.com>
 *
 * Copyright 2007 OpenVZ SWsoft Inc
 * Author: Pavel Emelianov <xemul@openvz.org>
 *
 * Memory thresholds
 * Copyright (C) 2009 Nokia Corporation
 * Author: Kirill A. Shutemov
 *
 * Kernel Memory Controller
 * Copyright (C) 2012 Parallels Inc. and Google Inc.
 * Authors: Glauber Costa and Suleiman Souhlal
 *
 * Native page reclaim
 * Charge lifetime sanitation
 * Lockless page tracking & accounting
 * Unified hierarchy configuration model
 * Copyright (C) 2015 Red Hat, Inc., Johannes Weiner
 *
 * Per memcg lru locking
 * Copyright (C) 2020 Alibaba, Inc, Alex Shi
 */

#include <linux/page_counter.h>
#include <linux/memcontrol.h>
#include <linux/cgroup.h>
#include <linux/pagewalk.h>
#include <linux/sched/mm.h>
#include <linux/shmem_fs.h>
#include <linux/hugetlb.h>
#include <linux/pagemap.h>
#include <linux/vm_event_item.h>
#include <linux/smp.h>
#include <linux/page-flags.h>
#include <linux/backing-dev.h>
#include <linux/bit_spinlock.h>
#include <linux/rcupdate.h>
#include <linux/limits.h>
#include <linux/export.h>
#include <linux/mutex.h>
#include <linux/rbtree.h>
#include <linux/slab.h>
#include <linux/swap.h>
#include <linux/swapops.h>
#include <linux/spinlock.h>
#include <linux/eventfd.h>
#include <linux/poll.h>
#include <linux/sort.h>
#include <linux/fs.h>
#include <linux/seq_file.h>
#include <linux/vmpressure.h>
#include <linux/memremap.h>
#include <linux/mm_inline.h>
#include <linux/swap_cgroup.h>
#include <linux/cpu.h>
#include <linux/oom.h>
#include <linux/lockdep.h>
#include <linux/file.h>
#include <linux/resume_user_mode.h>
#include <linux/psi.h>
#include <linux/seq_buf.h>
#include <linux/sched/isolation.h>
#include "internal.h"
#include <net/sock.h>
#include <net/ip.h>
#include "slab.h"
#include "swap.h"
#include "init.h"

#include <linux/uaccess.h>

#include <trace/events/vmscan.h>

#include <linux/calclock.h>

extern struct cgroup_subsys memory_cgrp_subsys;

#define THRESHOLDS_EVENTS_TARGET 128
#define SOFTLIMIT_EVENTS_TARGET 1024
#define NR_MEMCG_EVENTS ARRAY_SIZE(memcg_vm_event_stat)

bool _m_folio_matches_lruvec(struct folio *folio,
                struct lruvec *lruvec)
{
        bool is_matched = lruvec_pgdat(lruvec) == folio_pgdat(folio) &&
                               lruvec_memcg(lruvec) == folio_memcg(folio);
        if (lruvec->mz->is_p_lruvec_use)
                return is_matched & (lruvec->cpu == folio_to_cpu(folio)); // folio_to_cpu의 값이 lruvec에 넣을 시점과 달라질 가능성이 있음.
        return is_matched;
}

/*
 * CPU를 기준으로 node를 정해야 할 듯
 */
int change_cpu_in_node(int cpu, int node)
{
        struct Node_info node_info = node_infos[node];
        int node_size = node_info.max - node_info.min + 1;
        return (cpu % node_size) + node_info.min;
}

struct lruvec *module_mem_cgroup_lruvec(struct mem_cgroup *memcg,
                                               struct pglist_data *pgdat,
                                               int cpu)
{
        struct mem_cgroup_per_node *mz;
        struct lruvec *lruvec;
        int node;
        if (mem_cgroup_disabled()) {
                lruvec = &pgdat->__lruvec;
		goto out;
	}
        if (!memcg)
                memcg = root_mem_cgroup;
        mz = memcg->nodeinfo[pgdat->node_id];
        // (cpu == -1)
        // 만약, 현재 cpu가 node에 속하면 문제는 없으나
        // 그렇지 않을 경우, node에 속하는 다른 cpu 값을 읽어야 함.
        if (cpu == -1) {
                cpu = smp_processor_id();
                node = cpu_to_node(cpu);
                if (pgdat->node_id == node) {
                        lruvec = this_cpu_ptr(mz->p_lruvec);
                } else {
                        int change_cpu = change_cpu_in_node(cpu, pgdat->node_id);
                        lruvec = per_cpu_ptr(mz->p_lruvec, change_cpu);
                }
        } else {
                node = cpu_to_node(cpu);
                if (pgdat->node_id == node) {
                        lruvec = per_cpu_ptr(mz->p_lruvec, cpu);
                } else {
                        int change_cpu = change_cpu_in_node(cpu, pgdat->node_id);
                        lruvec = per_cpu_ptr(mz->p_lruvec, change_cpu);
                }
        }
out:
        /*
         * Since a node can be onlined after the mem_cgroup was created,
         * we have to be prepared to initialize lruvec->pgdat here;
         * and if offlined then reonlined, we need to reinitialize it.
         */
        if (unlikely(lruvec->pgdat != pgdat)) {
		printk("[%s] hwan-need to check\n", __func__);
		lruvec->pgdat = pgdat;
	}
        return lruvec;
}

/*
 * Cgroups above their limits are maintained in a RB-Tree, independent of
 * their hierarchy representation
 */

struct mem_cgroup_tree_per_node {
	struct rb_root rb_root;
	struct rb_node *rb_rightmost;
	spinlock_t lock;
};

/* Subset of vm_event_item to report for memcg event stats */
static const unsigned int memcg_vm_event_stat[] = {
	PGPGIN,
	PGPGOUT,
	PGSCAN_KSWAPD,
	PGSCAN_DIRECT,
	PGSCAN_KHUGEPAGED,
	PGSTEAL_KSWAPD,
	PGSTEAL_DIRECT,
	PGSTEAL_KHUGEPAGED,
	PGFAULT,
	PGMAJFAULT,
	PGREFILL,
	PGACTIVATE,
	PGDEACTIVATE,
	PGLAZYFREE,
	PGLAZYFREED,
#if defined(CONFIG_MEMCG_KMEM) && defined(CONFIG_ZSWAP)
	ZSWPIN,
	ZSWPOUT,
#endif
#ifdef CONFIG_TRANSPARENT_HUGEPAGE
	THP_FAULT_ALLOC,
	THP_COLLAPSE_ALLOC,
#endif
};

enum {
	RES_USAGE,
	RES_LIMIT,
	RES_MAX_USAGE,
	RES_FAILCNT,
	RES_SOFT_LIMIT,
};

struct memcg_vmstats_percpu {
	/* Local (CPU and cgroup) page state & events */
	long			state[MEMCG_NR_STAT];
	unsigned long		events[NR_MEMCG_EVENTS];

	/* Delta calculation for lockless upward propagation */
	long			state_prev[MEMCG_NR_STAT];
	unsigned long		events_prev[NR_MEMCG_EVENTS];

	/* Cgroup1: threshold notifications & softlimit tree updates */
	unsigned long		nr_page_events;
	unsigned long		targets[MEM_CGROUP_NTARGETS];
};

struct memcg_vmstats {
	/* Aggregated (CPU and subtree) page state & events */
	long			state[MEMCG_NR_STAT];
	unsigned long		events[NR_MEMCG_EVENTS];

	/* Non-hierarchical (CPU aggregated) page state & events */
	long			state_local[MEMCG_NR_STAT];
	unsigned long		events_local[NR_MEMCG_EVENTS];

	/* Pending child counts during tree propagation */
	long			state_pending[MEMCG_NR_STAT];
	unsigned long		events_pending[NR_MEMCG_EVENTS];
};

/* Whether legacy memory+swap accounting is active */
static bool do_memsw_account(void)
{
	return !cgroup_subsys_on_dfl(memory_cgrp_subsys);
}

static unsigned long mem_cgroup_usage(struct mem_cgroup *memcg, bool swap)
{
	unsigned long val;

	if (mem_cgroup_is_root(memcg)) {
		/*
		 * Approximate root's usage from global state. This isn't
		 * perfect, but the root usage was always an approximation.
		 */
		val = global_node_page_state(NR_FILE_PAGES) +
			global_node_page_state(NR_ANON_MAPPED);
		if (swap) {
			printk("[%s]: called get_nr_swap_pages() in root\n", __func__);
			val += total_swap_pages - get_nr_swap_pages(-1, false);
		}
	} else {
		if (!swap)
			val = page_counter_read(&memcg->memory);
		else
			val = page_counter_read(&memcg->memsw);
	}
	return val;
}

static void __mem_cgroup_threshold(struct mem_cgroup *memcg, bool swap)
{
	struct mem_cgroup_threshold_ary *t;
	unsigned long usage;
	int i;

	rcu_read_lock();
	if (!swap)
		t = rcu_dereference(memcg->thresholds.primary);
	else
		t = rcu_dereference(memcg->memsw_thresholds.primary);

	if (!t)
		goto unlock;

	usage = mem_cgroup_usage(memcg, swap);

	/*
	 * current_threshold points to threshold just below or equal to usage.
	 * If it's not true, a threshold was crossed after last
	 * call of __mem_cgroup_threshold().
	 */
	i = t->current_threshold;

	/*
	 * Iterate backward over array of thresholds starting from
	 * current_threshold and check if a threshold is crossed.
	 * If none of thresholds below usage is crossed, we read
	 * only one element of the array here.
	 */
	for (; i >= 0 && unlikely(t->entries[i].threshold > usage); i--)
		eventfd_signal(t->entries[i].eventfd, 1);

	/* i = current_threshold + 1 */
	i++;

	/*
	 * Iterate forward over array of thresholds starting from
	 * current_threshold+1 and check if a threshold is crossed.
	 * If none of thresholds above usage is crossed, we read
	 * only one element of the array here.
	 */
	for (; i < t->size && unlikely(t->entries[i].threshold <= usage); i++)
		eventfd_signal(t->entries[i].eventfd, 1);

	/* Update current_threshold */
	t->current_threshold = i - 1;
unlock:
	rcu_read_unlock();
}

static void mem_cgroup_threshold(struct mem_cgroup *memcg)
{
	while (memcg) {
		__mem_cgroup_threshold(memcg, false);
		if (do_memsw_account())
			__mem_cgroup_threshold(memcg, true);

		memcg = parent_mem_cgroup(memcg);
	}
}

static unsigned long soft_limit_excess(struct mem_cgroup *memcg)
{
	unsigned long nr_pages = page_counter_read(&memcg->memory);
	unsigned long soft_limit = READ_ONCE(memcg->soft_limit);
	unsigned long excess = 0;

	if (nr_pages > soft_limit)
		excess = nr_pages - soft_limit;

	return excess;
}

struct mem_cgroup_tree {
	struct mem_cgroup_tree_per_node *rb_tree_per_node[MAX_NUMNODES];
};
extern struct mem_cgroup_tree soft_limit_tree __read_mostly;

static void __mem_cgroup_remove_exceeded(struct mem_cgroup_per_node *mz,
					 struct mem_cgroup_tree_per_node *mctz)
{
	if (!mz->on_tree)
		return;

	if (&mz->tree_node == mctz->rb_rightmost)
		mctz->rb_rightmost = rb_prev(&mz->tree_node);

	rb_erase(&mz->tree_node, &mctz->rb_root);
	mz->on_tree = false;
}

static void __mem_cgroup_insert_exceeded(struct mem_cgroup_per_node *mz,
					 struct mem_cgroup_tree_per_node *mctz,
					 unsigned long new_usage_in_excess)
{
	struct rb_node **p = &mctz->rb_root.rb_node;
	struct rb_node *parent = NULL;
	struct mem_cgroup_per_node *mz_node;
	bool rightmost = true;

	if (mz->on_tree)
		return;

	mz->usage_in_excess = new_usage_in_excess;
	if (!mz->usage_in_excess)
		return;
	while (*p) {
		parent = *p;
		mz_node = rb_entry(parent, struct mem_cgroup_per_node,
					tree_node);
		if (mz->usage_in_excess < mz_node->usage_in_excess) {
			p = &(*p)->rb_left;
			rightmost = false;
		} else {
			p = &(*p)->rb_right;
		}
	}

	if (rightmost)
		mctz->rb_rightmost = &mz->tree_node;

	rb_link_node(&mz->tree_node, parent, p);
	rb_insert_color(&mz->tree_node, &mctz->rb_root);
	mz->on_tree = true;
}

static void mem_cgroup_update_tree(struct mem_cgroup *memcg, int nid)
{
	unsigned long excess;
	struct mem_cgroup_per_node *mz;
	struct mem_cgroup_tree_per_node *mctz;

	if (lru_gen_enabled()) {
		if (soft_limit_excess(memcg))
			lru_gen_soft_reclaim(memcg, nid);
		return;
	}

	mctz = soft_limit_tree.rb_tree_per_node[nid];
	if (!mctz)
		return;
	/*
	 * Necessary to update all ancestors when hierarchy is used.
	 * because their event counter is not touched.
	 */
	for (; memcg; memcg = parent_mem_cgroup(memcg)) {
		mz = memcg->nodeinfo[nid];
		excess = soft_limit_excess(memcg);
		/*
		 * We have to update the tree if mz is on RB-tree or
		 * mem is over its softlimit.
		 */
		if (excess || mz->on_tree) {
			unsigned long flags;

			spin_lock_irqsave(&mctz->lock, flags);
			/* if on-tree, remove it */
			if (mz->on_tree)
				__mem_cgroup_remove_exceeded(mz, mctz);
			/*
			 * Insert again. mz->usage_in_excess will be updated.
			 * If excess is 0, no tree ops.
			 */
			__mem_cgroup_insert_exceeded(mz, mctz, excess);
			spin_unlock_irqrestore(&mctz->lock, flags);
		}
	}
}

static bool mem_cgroup_event_ratelimit(struct mem_cgroup *memcg,
				       enum mem_cgroup_events_target target)
{
	unsigned long val, next;

	val = __this_cpu_read(memcg->vmstats_percpu->nr_page_events);
	next = __this_cpu_read(memcg->vmstats_percpu->targets[target]);
	/* from time_after() in jiffies.h */
	if ((long)(next - val) < 0) {
		switch (target) {
		case MEM_CGROUP_TARGET_THRESH:
			next = val + THRESHOLDS_EVENTS_TARGET;
			break;
		case MEM_CGROUP_TARGET_SOFTLIMIT:
			next = val + SOFTLIMIT_EVENTS_TARGET;
			break;
		default:
			break;
		}
		__this_cpu_write(memcg->vmstats_percpu->targets[target], next);
		return true;
	}
	return false;
}

/*
 * Check events in order.
 *
 */
static void memcg_check_events(struct mem_cgroup *memcg, int nid)
{
	if (IS_ENABLED(CONFIG_PREEMPT_RT))
		return;

	/* threshold event is triggered in finer grain than soft limit */
	if (unlikely(mem_cgroup_event_ratelimit(memcg,
						MEM_CGROUP_TARGET_THRESH))) {
		bool do_softlimit;

		do_softlimit = mem_cgroup_event_ratelimit(memcg,
						MEM_CGROUP_TARGET_SOFTLIMIT);
		mem_cgroup_threshold(memcg);
		if (unlikely(do_softlimit))
			mem_cgroup_update_tree(memcg, nid);
	}
}

static void memcg_stats_unlock(void)
{
	preempt_enable_nested();
}

#ifdef CONFIG_SWAP
static struct mem_cgroup *mem_cgroup_id_get_online(struct mem_cgroup *memcg)
{
	while (!refcount_inc_not_zero(&memcg->id.ref)) {
		/*
		 * The root cgroup cannot be destroyed, so it's refcount must
		 * always be >= 1.
		 */
		if (WARN_ON_ONCE(mem_cgroup_is_root(memcg))) {
			VM_BUG_ON(1);
			break;
		}
		memcg = parent_mem_cgroup(memcg);
		if (!memcg)
			memcg = root_mem_cgroup;
	}
	return memcg;
}

static void __maybe_unused mem_cgroup_id_get_many(struct mem_cgroup *memcg,
						  unsigned int n)
{
	refcount_add(n, &memcg->id.ref);
}

/*
 * Accessors to ensure that preemption is disabled on PREEMPT_RT because it can
 * not rely on this as part of an acquired spinlock_t lock. These functions are
 * never used in hardirq context on PREEMPT_RT and therefore disabling preemtion
 * is sufficient.
 */
static void memcg_stats_lock(void)
{
	preempt_disable_nested();
	VM_WARN_ON_IRQS_ENABLED();
}

static void mem_cgroup_charge_statistics(struct mem_cgroup *memcg,
					 int nr_pages)
{
	/* pagein of a big page is an event. So, ignore page size */
	if (nr_pages > 0)
		__count_memcg_events(memcg, PGPGIN, 1);
	else {
		__count_memcg_events(memcg, PGPGOUT, 1);
		nr_pages = -nr_pages; /* for event */
	}

	__this_cpu_add(memcg->vmstats_percpu->nr_page_events, nr_pages);
}

/**
 * mem_cgroup_swapout - transfer a memsw charge to swap
 * @folio: folio whose memsw charge to transfer
 * @entry: swap entry to move the charge to
 *
 * Transfer the memsw charge of @folio to @entry.
 */
void mem_cgroup_swapout(struct folio *folio, swp_entry_t entry)
{
	struct mem_cgroup *memcg, *swap_memcg;
	unsigned int nr_entries;
	unsigned short oldid;

	VM_BUG_ON_FOLIO(folio_test_lru(folio), folio);
	VM_BUG_ON_FOLIO(folio_ref_count(folio), folio);

	if (mem_cgroup_disabled())
		return;

	if (!do_memsw_account())
		return;

	memcg = folio_memcg(folio);

	VM_WARN_ON_ONCE_FOLIO(!memcg, folio);
	if (!memcg)
		return;

	/*
	 * In case the memcg owning these pages has been offlined and doesn't
	 * have an ID allocated to it anymore, charge the closest online
	 * ancestor for the swap instead and transfer the memory+swap charge.
	 */
	swap_memcg = mem_cgroup_id_get_online(memcg);
	nr_entries = folio_nr_pages(folio);
	/* Get references for the tail pages, too */
	if (nr_entries > 1)
		mem_cgroup_id_get_many(swap_memcg, nr_entries - 1);
	oldid = swap_cgroup_record(entry, mem_cgroup_id(swap_memcg),
				   nr_entries);
	VM_BUG_ON_FOLIO(oldid, folio);
	mod_memcg_state(swap_memcg, MEMCG_SWAP, nr_entries);

	folio->memcg_data = 0;


	if (!mem_cgroup_is_root(memcg)) {
		page_counter_uncharge(&memcg->memory, nr_entries);
	}

	if (memcg != swap_memcg) {
		if (!mem_cgroup_is_root(swap_memcg)) 
			page_counter_charge(&swap_memcg->memsw, nr_entries);
		page_counter_uncharge(&memcg->memsw, nr_entries);
	}


	/*
	 * Interrupts should be disabled here because the caller holds the
	 * i_pages lock which is taken with interrupts-off. It is
	 * important here to have the interrupts disabled because it is the
	 * only synchronisation we have for updating the per-CPU variables.
	 */
	memcg_stats_lock();
	mem_cgroup_charge_statistics(memcg, -nr_entries);
	memcg_stats_unlock();
	memcg_check_events(memcg, folio_nid(folio));

	css_put(&memcg->css);
}

// extern void _m_page_counter_uncharge(struct page_counter *counter, unsigned long nr_pages);

KTDEF(page_counter_charge_outer);
KTDEF(page_counter_uncharge_2);
void _m_mem_cgroup_swapout(struct folio *folio, swp_entry_t entry)
{
	struct mem_cgroup *memcg, *swap_memcg;
	unsigned int nr_entries;
	unsigned short oldid;

	VM_BUG_ON_FOLIO(folio_test_lru(folio), folio);
	VM_BUG_ON_FOLIO(folio_ref_count(folio), folio);

	if (mem_cgroup_disabled())
		return;

	if (!do_memsw_account())
		return;

	memcg = folio_memcg(folio);

	VM_WARN_ON_ONCE_FOLIO(!memcg, folio);
	if (!memcg)
		return;

	/*
	 * In case the memcg owning these pages has been offlined and doesn't
	 * have an ID allocated to it anymore, charge the closest online
	 * ancestor for the swap instead and transfer the memory+swap charge.
	 */
	swap_memcg = mem_cgroup_id_get_online(memcg);
	nr_entries = folio_nr_pages(folio);
	/* Get references for the tail pages, too */
	if (nr_entries > 1)
		mem_cgroup_id_get_many(swap_memcg, nr_entries - 1);
	oldid = swap_cgroup_record(entry, mem_cgroup_id(swap_memcg),
				   nr_entries);
	VM_BUG_ON_FOLIO(oldid, folio);
	mod_memcg_state(swap_memcg, MEMCG_SWAP, nr_entries);

	folio->memcg_data = 0;


	if (!mem_cgroup_is_root(memcg)) {
#ifdef __PROFILING
#endif 
		// _m_page_counter_uncharge(&memcg->memory, nr_entries);
		page_counter_uncharge(&memcg->memory, nr_entries);
#ifdef __PROFILING
#endif 
	}

	if (memcg != swap_memcg) {
		if (!mem_cgroup_is_root(swap_memcg))  {
#ifdef __PROFILING
#endif 
			page_counter_charge(&swap_memcg->memsw, nr_entries);
#ifdef __PROFILING
#endif 
		}
#ifdef __PROFILING
#endif 
		// _m_page_counter_uncharge(&memcg->memsw, nr_entries);
		page_counter_uncharge(&memcg->memory, nr_entries);
#ifdef __PROFILING
#endif 
	}


	/*
	 * Interrupts should be disabled here because the caller holds the
	 * i_pages lock which is taken with interrupts-off. It is
	 * important here to have the interrupts disabled because it is the
	 * only synchronisation we have for updating the per-CPU variables.
	 */
	memcg_stats_lock();
	mem_cgroup_charge_statistics(memcg, -nr_entries);
	memcg_stats_unlock();
	memcg_check_events(memcg, folio_nid(folio));

	css_put(&memcg->css);
}
// EXPORT_SYMBOL_GPL(mem_cgroup_swapout); // profiling

extern struct idr mem_cgroup_idr;

static void mem_cgroup_id_remove(struct mem_cgroup *memcg)
{
	if (memcg->id.id > 0) {
		idr_remove(&mem_cgroup_idr, memcg->id.id);
		memcg->id.id = 0;
	}
}

static void mem_cgroup_id_put_many(struct mem_cgroup *memcg, unsigned int n)
{
	if (refcount_sub_and_test(n, &memcg->id.ref)) {
		mem_cgroup_id_remove(memcg);

		/* Memcg ID pins CSS */
		css_put(&memcg->css);
	}
}

static inline void mem_cgroup_id_put(struct mem_cgroup *memcg)
{
	mem_cgroup_id_put_many(memcg, 1);
}

/**
 * __mem_cgroup_try_charge_swap - try charging swap space for a folio
 * @folio: folio being added to swap
 * @entry: swap entry to charge
 *
 * Try to charge @folio's memcg for the swap space at @entry.
 *
 * Returns 0 on success, -ENOMEM on failure.
 */
int __mem_cgroup_try_charge_swap(struct folio *folio, swp_entry_t entry)
{
	unsigned int nr_pages = folio_nr_pages(folio);
	struct page_counter *counter;
	struct mem_cgroup *memcg;
	unsigned short oldid;

	if (do_memsw_account())
		return 0;

	memcg = folio_memcg(folio);

	VM_WARN_ON_ONCE_FOLIO(!memcg, folio);
	if (!memcg)
		return 0;

	if (!entry.val) {
		memcg_memory_event(memcg, MEMCG_SWAP_FAIL);
		return 0;
	}

	memcg = mem_cgroup_id_get_online(memcg);

	if (!mem_cgroup_is_root(memcg) &&
	    !page_counter_try_charge(&memcg->swap, nr_pages, &counter)) {
		memcg_memory_event(memcg, MEMCG_SWAP_MAX);
		memcg_memory_event(memcg, MEMCG_SWAP_FAIL);
		mem_cgroup_id_put(memcg);
		return -ENOMEM;
	}

	/* Get references for the tail pages, too */
	if (nr_pages > 1)
		mem_cgroup_id_get_many(memcg, nr_pages - 1);
	oldid = swap_cgroup_record(entry, mem_cgroup_id(memcg), nr_pages);
	VM_BUG_ON_FOLIO(oldid, folio);
	mod_memcg_state(memcg, MEMCG_SWAP, nr_pages);

	return 0;
}

/**
 * __mem_cgroup_uncharge_swap - uncharge swap space
 * @entry: swap entry to uncharge
 * @nr_pages: the amount of swap space to uncharge
 */
void __mem_cgroup_uncharge_swap(swp_entry_t entry, unsigned int nr_pages)
{
	struct mem_cgroup *memcg;
	unsigned short id;

	id = swap_cgroup_record(entry, 0, nr_pages);
	rcu_read_lock();
	memcg = mem_cgroup_from_id(id);
	if (memcg) {
		if (!mem_cgroup_is_root(memcg)) {
			if (do_memsw_account())
				page_counter_uncharge(&memcg->memsw, nr_pages);
			else
				page_counter_uncharge(&memcg->swap, nr_pages);
		}
		mod_memcg_state(memcg, MEMCG_SWAP, -nr_pages);
		mem_cgroup_id_put_many(memcg, nr_pages);
	}
	rcu_read_unlock();
}
// EXPORT_SYMBOL_GPL(__mem_cgroup_uncharge_swap); // profiling

KTDEF(page_counter_uncharge_in_mcus);
void __m_mem_cgroup_uncharge_swap(swp_entry_t entry, unsigned int nr_pages)
{
	struct mem_cgroup *memcg;
	unsigned short id;

	id = swap_cgroup_record(entry, 0, nr_pages);
	rcu_read_lock();
	memcg = mem_cgroup_from_id(id);
	if (memcg) {
		if (!mem_cgroup_is_root(memcg)) {
			if (do_memsw_account())
				page_counter_uncharge(&memcg->memsw, nr_pages);
			else
				page_counter_uncharge(&memcg->swap, nr_pages);
		}
		mod_memcg_state(memcg, MEMCG_SWAP, -nr_pages);
		mem_cgroup_id_put_many(memcg, nr_pages);
	}
	rcu_read_unlock();
}

KTDEF(page_counter_read_in_protection);
static unsigned long _m_effective_protection(unsigned long usage,
                                          unsigned long *parent_usage,
                                          unsigned long setting,
                                          unsigned long parent_effective,
                                          unsigned long siblings_protected)
{
        unsigned long protected;
        unsigned long ep;

        protected = min(usage, setting);
        /*
         * If all cgroups at this level combined claim and use more
         * protection than what the parent affords them, distribute
         * shares in proportion to utilization.
         *
         * We are using actual utilization rather than the statically
         * claimed protection in order to be work-conserving: claimed
         * but unused protection is available to siblings that would
         * otherwise get a smaller chunk than what they claimed.
         */
        if (siblings_protected > parent_effective)
                return protected * parent_effective / siblings_protected;

        /*
         * Ok, utilized protection of all children is within what the
         * parent affords them, so we know whatever this child claims
         * and utilizes is effectively protected.
         *
         * If there is unprotected usage beyond this value, reclaim
         * will apply pressure in proportion to that amount.
         *
         * If there is unutilized protection, the cgroup will be fully
         * shielded from reclaim, but we do return a smaller value for
         * protection than what the group could enjoy in theory. This
         * is okay. With the overcommit distribution above, effective
         * protection is always dependent on how memory is actually
         * consumed among the siblings anyway.
         */
        ep = protected;

        /*
         * If the children aren't claiming (all of) the protection
         * afforded to them by the parent, distribute the remainder in
         * proportion to the (unprotected) memory of each cgroup. That
         * way, cgroups that aren't explicitly prioritized wrt each
         * other compete freely over the allowance, but they are
         * collectively protected from neighboring trees.
         *
         * We're using unprotected memory for the weight so that if
         * some cgroups DO claim explicit protection, we don't protect
         * the same bytes twice.
         *
         * Check both usage and parent_usage against the respective                                                                                                                                                                                   * protected values. One should imply the other, but they
         * aren't read atomically - make sure the division is sane.
         */
        if (!(cgrp_dfl_root.flags & CGRP_ROOT_MEMORY_RECURSIVE_PROT))
                return ep;

	if (parent_effective > siblings_protected &&
	    parent_usage > siblings_protected &&
            usage > protected) {
		unsigned long unclaimed;

		unclaimed = parent_effective - siblings_protected;
		unclaimed *= usage - protected;
		unclaimed /= *parent_usage - siblings_protected;

		ep += unclaimed;
        }

        return ep;
}

/*
 * Internal helper.  Don't use outside percpu-refcount proper.  The
 * function doesn't return the pointer and let the caller test it for NULL
 * because doing so forces the compiler to generate two conditional
 * branches as it can't assume that @ref->percpu_count is not NULL.
 */
KTDEF(READ_ONCE_in_is_percpu);
static inline bool __m_ref_is_percpu(struct percpu_ref *ref,
                                          unsigned long __percpu **percpu_countp)
{
        unsigned long percpu_ptr;

        /*
         * The value of @ref->percpu_count_ptr is tested for
         * !__PERCPU_REF_ATOMIC, which may be set asynchronously, and then
         * used as a pointer.  If the compiler generates a separate fetch
         * when using it as a pointer, __PERCPU_REF_ATOMIC may be set in
         * between contaminating the pointer value, meaning that
         * READ_ONCE() is required when fetching it.
         *
         * The dependency ordering from the READ_ONCE() pairs
         * with smp_store_release() in __percpu_ref_switch_to_percpu().
         */
        percpu_ptr = READ_ONCE(ref->percpu_count_ptr);

        /*
         * Theoretically, the following could test just ATOMIC; however,
         * then we'd have to mask off DEAD separately as DEAD may be
         * visible without ATOMIC if we race with percpu_ref_kill().  DEAD
         * implies ATOMIC anyway.  Test them together.
         */
        if (unlikely(percpu_ptr & __PERCPU_REF_ATOMIC_DEAD))
                return false;

        *percpu_countp = (unsigned long __percpu *)percpu_ptr;
        return true;
}

/**
 * percpu_ref_put_many - decrement a percpu refcount
 * @ref: percpu_ref to put
 * @nr: number of references to put
 *
 * Decrement the refcount, and if 0, call the release function (which was passed
 * to percpu_ref_init())
 *
 * This function is safe to call as long as @ref is between init and exit.
 */
KTDEF(rcu_read_lock_in_put_many);
KTDEF(__ref_is_percpu_in_put_many);
KTDEF(this_cpu_sub_in_put_many);
KTDEF(rcu_read_unlock_in_put_many);
static inline void _m_percpu_ref_put_many(struct percpu_ref *ref, unsigned long nr)
{
        unsigned long __percpu *percpu_count;

        rcu_read_lock();

	bool is_percpu_ref = __m_ref_is_percpu(ref, &percpu_count);

        if (is_percpu_ref) {
                this_cpu_sub(*percpu_count, nr);
	}
        else if (unlikely(atomic_long_sub_and_test(nr, &ref->data->count))) {
                ref->data->release(ref);
	}

        rcu_read_unlock();
}


/**
 * percpu_ref_put - decrement a percpu refcount
 * @ref: percpu_ref to put
 *
 * Decrement the refcount, and if 0, call the release function (which was passed
 * to percpu_ref_init())
 *
 * This function is safe to call as long as @ref is between init and exit.
 */
static inline void _m_percpu_ref_put(struct percpu_ref *ref)
{
        _m_percpu_ref_put_many(ref, 1);
}

/**
 * css_put - put a css reference
 * @css: target css
 *
 * Put a reference obtained via css_get() and css_tryget_online().
 */
CGROUP_REF_FN_ATTRS
void _m_css_put(struct cgroup_subsys_state *css)
{
        if (!(css->flags & CSS_NO_REF))
                _m_percpu_ref_put(&css->refcnt);
}

int lru_zone_size(struct mem_cgroup_per_node *pn)
{
        int i, j;
        int size = 0;
        for (i = 0; i < MAX_NR_ZONES; i++) {
                for (j = 0; j < NR_LRU_LISTS; j++) {
                        if (pn->is_p_lruvec_use) {
                                size += this_cpu_ptr(pn->p_lruvec)->p_lru_zone_size[i][j];
                        } else {
                                size += pn->lru_zone_size[i][j];
                        }
                }
        }
        return size;
}

/**
 * mem_cgroup_iter - iterateover memory cgroup hierarchy
 * @root: hierarchy root
 * @prev: previously returned memcg, NULL on first invocation
 * @reclaim: cookie for shared reclaim walks, NULL for full walks
 *
 * Returns references to children of the hierarchy below @root, or
 * @root itself, or %NULL after a full round-trip.
 *
 * Caller must pass the return value in @prev on subsequent
 * invocations for reference counting, or use mem_cgroup_iter_break()
 * to cancel a hierarchy walk before the round-trip is complete.
 *
 * Reclaimers can specify a node in @reclaim to divide up the memcgs
 * in the hierarchy among all concurrent reclaimers operating on the
 * same node.
 */
#include <linux/printk.h>

KTDEF(rcu_read_lock);
KTDEF(css_next_descendant_pre);
KTDEF(mem_cgroup_from_css);
KTDEF(css_put);
struct mem_cgroup *_m_mem_cgroup_iter(struct mem_cgroup *root,
                                   struct mem_cgroup *prev,
                                   struct mem_cgroup_reclaim_cookie *reclaim, int node)
{
        struct mem_cgroup_reclaim_iter *iter;
        struct cgroup_subsys_state *css = NULL;
        struct mem_cgroup *memcg = NULL;
        struct mem_cgroup *pos = NULL;
	int zone_size = 0;
	int patient = 0;

        if (mem_cgroup_disabled())
                return NULL;

        if (!root)
                root = root_mem_cgroup;

        rcu_read_lock();

        if (reclaim) {
                struct mem_cgroup_per_node *mz;

                mz = root->nodeinfo[reclaim->pgdat->node_id];
                iter = &mz->iter;

                /*
                 * On start, join the current reclaim iteration cycle.
                 * Exit when a concurrent walker completes it.
                 */
                if (!prev)
                        reclaim->generation = iter->generation;
                else if (reclaim->generation != iter->generation)
                        goto out_unlock;

                while (1) {
                        pos = READ_ONCE(iter->position);
                        if (!pos || css_tryget(&pos->css))
                                break;
                        /*
                         * css reference reached zero, so iter->position will
                         * be cleared by ->css_released. However, we should not
                         * rely on this happening soon, because ->css_released
                         * is called from a work queue, and by busy-waiting we
                         * might block it. So we clear iter->position right
                         * away.
                         */
                        (void)cmpxchg(&iter->position, pos, NULL);
                }
        } else if (prev) {
                pos = prev;
        }

        if (pos)
                css = &pos->css;

        for (;;) {
                css = css_next_descendant_pre(css, &root->css);
                if (!css) {
                        /*
                         * Reclaimers share the hierarchy walk, and a
                         * new one might jump in right at the end of
                         * the hierarchy - make sure they see at least
                         * one group and restart from the beginning.
                         */
                        if (!prev)
                                continue;
                        break;
                }


		memcg = mem_cgroup_from_css(css);

#if 0
		if (patient < 10) {
			zone_size = lru_zone_size(memcg->nodeinfo[node]);
			if (zone_size < 100) {
				patient++;
				continue;
			}
		}
#endif

                /*
                 * Verify the css and acquire a reference.  The root
                 * is provided by the caller, so we know it's alive
                 * and kicking, and don't take an extra reference.
                 */
                if (css == &root->css || css_tryget(css)) {
                        break;
                }
        }

        if (reclaim) {
                /*
                 * The position could have already been updated by a competing
                 * thread, so check that the value hasn't changed since we read
                 * it to avoid reclaiming from the same cgroup twice.
                 */
                (void)cmpxchg(&iter->position, pos, memcg);

                if (pos)
                        css_put(&pos->css);

                if (!memcg)
                        iter->generation++;
        }

out_unlock:
        rcu_read_unlock();
        if (prev && prev != root) {
                _m_css_put(&prev->css);
	}

        return memcg;
}

void mem_cgroup_calculate_protection(struct mem_cgroup *root,
                                     struct mem_cgroup *memcg)
{
        unsigned long usage, parent_usage;
        struct mem_cgroup *parent;

        if (mem_cgroup_disabled())
                return;

        if (!root)
                root = root_mem_cgroup;

        /*
         * Effective values of the reclaim targets are ignored so they
         * can be stale. Have a look at mem_cgroup_protection for more
         * details.
         * TODO: calculation should be more robust so that we do not need
         * that special casing.
         */
        if (memcg == root)
                return;

        usage = page_counter_read(&memcg->memory);
        if (!usage)
                return;

        parent = parent_mem_cgroup(memcg);

        if (parent == root) {
                memcg->memory.emin = READ_ONCE(memcg->memory.min);
                memcg->memory.elow = READ_ONCE(memcg->memory.low);
                return;
        }

        parent_usage = page_counter_read(&memcg->memory);

        WRITE_ONCE(memcg->memory.emin, _m_effective_protection(usage, &parent_usage,
                        READ_ONCE(memcg->memory.min),
                        READ_ONCE(parent->memory.emin),
                        atomic_long_read(&parent->memory.children_min_usage)));

        WRITE_ONCE(memcg->memory.elow, _m_effective_protection(usage, &parent_usage,
                        READ_ONCE(memcg->memory.low),
                        READ_ONCE(parent->memory.elow),
                        atomic_long_read(&parent->memory.children_low_usage)));
}

/*
 * mem_cgroup_swapin_uncharge_swap - uncharge swap slot
 * @entry: swap entry for which the page is charged
 *
 * Call this function after successfully adding the charged page to swapcache.
 *
 * Note: This function assumes the page for which swap slot is being uncharged
 * is order 0 page.
 */
void mem_cgroup_swapin_uncharge_swap(swp_entry_t entry)
{
	/*
	 * Cgroup1's unified memory+swap counter has been charged with the
	 * new swapcache page, finish the transfer by uncharging the swap
	 * slot. The swap slot would also get uncharged when it dies, but
	 * it can stick around indefinitely and we'd count the page twice
	 * the entire time.
	 *
	 * Cgroup2 has separate resource counters for memory and swap,
	 * so this is a non-issue here. Memory and swap charge lifetimes
	 * correspond 1:1 to page and swap slot lifetimes: we charge the
	 * page to memory here, and uncharge swap when the slot is freed.
	 */
	if (!mem_cgroup_disabled() && do_memsw_account()) {
		/*
		 * The swap entry might not get freed for a long time,
		 * let's not wait for it.  The page already received a
		 * memory+swap charge, drop the swap entry duplicate.
		 */
		mem_cgroup_uncharge_swap(entry, 1);
	}
}

void _m_mem_cgroup_swapin_uncharge_swap(swp_entry_t entry)
{
	/*
	 * Cgroup1's unified memory+swap counter has been charged with the
	 * new swapcache page, finish the transfer by uncharging the swap
	 * slot. The swap slot would also get uncharged when it dies, but
	 * it can stick around indefinitely and we'd count the page twice
	 * the entire time.
	 *
	 * Cgroup2 has separate resource counters for memory and swap,
	 * so this is a non-issue here. Memory and swap charge lifetimes
	 * correspond 1:1 to page and swap slot lifetimes: we charge the
	 * page to memory here, and uncharge swap when the slot is freed.
	 */
	if (!mem_cgroup_disabled() && do_memsw_account()) {
		/*
		 * The swap entry might not get freed for a long time,
		 * let's not wait for it.  The page already received a
		 * memory+swap charge, drop the swap entry duplicate.
		 */
		_m_mem_cgroup_uncharge_swap(entry, 1);
	}
}

long mem_cgroup_get_nr_swap_pages(struct mem_cgroup *memcg)
{
	long nr_swap_pages = get_nr_swap_pages(-1, false);

	if (mem_cgroup_disabled() || do_memsw_account())
		return nr_swap_pages;
	for (; !mem_cgroup_is_root(memcg); memcg = parent_mem_cgroup(memcg))
		nr_swap_pages = min_t(long, nr_swap_pages,
				      READ_ONCE(memcg->swap.max) -
				      page_counter_read(&memcg->swap));
	return nr_swap_pages;
}
// EXPORT_SYMBOL_GPL(mem_cgroup_get_nr_swap_pages); // profiling

long compare_mem_cgroup_get_nr_swap_pages(struct mem_cgroup *memcg)                                                                                                                                                                                  
{
        long nr_swap_pages = LONG_MAX;

        if (mem_cgroup_disabled() || do_memsw_account()) {
		printk("AMD3 machine turn off the memsw_account\n");
                nr_swap_pages = get_nr_swap_pages(1, true);
                return nr_swap_pages;
        }    

        long tmp = get_nr_swap_pages(1, true);
	if (tmp == 0) {
		for (; !mem_cgroup_is_root(memcg); memcg = parent_mem_cgroup(memcg))
			nr_swap_pages = min_t(long, nr_swap_pages,
					      READ_ONCE(memcg->swap.max) -
					      page_counter_read(&memcg->swap));
	}
        nr_swap_pages = min_t(long, nr_swap_pages, tmp);
        return nr_swap_pages;
}

bool mem_cgroup_swap_full(struct folio *folio)
{
	struct mem_cgroup *memcg;

	VM_BUG_ON_FOLIO(!folio_test_locked(folio), folio);

	if (vm_swap_full())
		return true;
	if (do_memsw_account())
		return false;

	memcg = folio_memcg(folio);
	if (!memcg)
		return false;

        for (; !mem_cgroup_is_root(memcg); memcg = parent_mem_cgroup(memcg)) {
                unsigned long usage = page_counter_read(&memcg->swap);

                if (usage * 2 >= READ_ONCE(memcg->swap.high) ||
                    usage * 2 >= READ_ONCE(memcg->swap.max))
                        return true;
        }

	return false;
}

static int __init setup_swap_account(char *s)
{
	pr_warn_once("The swapaccount= commandline option is deprecated. "
		     "Please report your usecase to linux-mm@kvack.org if you "
		     "depend on this functionality.\n");
	return 1;
}
__setup("swapaccount=", setup_swap_account);

static u64 swap_current_read(struct cgroup_subsys_state *css,
			     struct cftype *cft)
{
	struct mem_cgroup *memcg = mem_cgroup_from_css(css);

	return (u64)page_counter_read(&memcg->swap) * PAGE_SIZE;
}

static u64 swap_peak_read(struct cgroup_subsys_state *css,
			  struct cftype *cft)
{
	struct mem_cgroup *memcg = mem_cgroup_from_css(css);

	return (u64)memcg->swap.watermark * PAGE_SIZE;
}

static int seq_puts_memcg_tunable(struct seq_file *m, unsigned long value)
{
	if (value == PAGE_COUNTER_MAX)
		seq_puts(m, "max\n");
	else
		seq_printf(m, "%llu\n", (u64)value * PAGE_SIZE);

	return 0;
}

static int swap_high_show(struct seq_file *m, void *v)
{
	return seq_puts_memcg_tunable(m,
		READ_ONCE(mem_cgroup_from_seq(m)->swap.high));
}

static ssize_t swap_high_write(struct kernfs_open_file *of,
			       char *buf, size_t nbytes, loff_t off)
{
	struct mem_cgroup *memcg = mem_cgroup_from_css(of_css(of));
	unsigned long high;
	int err;

	buf = strstrip(buf);
	err = page_counter_memparse(buf, "max", &high);
	if (err)
		return err;

	page_counter_set_high(&memcg->swap, high);

	return nbytes;
}

static int swap_max_show(struct seq_file *m, void *v)
{
	return seq_puts_memcg_tunable(m,
		READ_ONCE(mem_cgroup_from_seq(m)->swap.max));
}

static ssize_t swap_max_write(struct kernfs_open_file *of,
			      char *buf, size_t nbytes, loff_t off)
{
	struct mem_cgroup *memcg = mem_cgroup_from_css(of_css(of));
	unsigned long max;
	int err;

	buf = strstrip(buf);
	err = page_counter_memparse(buf, "max", &max);
	if (err)
		return err;

	xchg(&memcg->swap.max, max);

	return nbytes;
}

static int swap_events_show(struct seq_file *m, void *v)
{
	struct mem_cgroup *memcg = mem_cgroup_from_seq(m);

	seq_printf(m, "high %lu\n",
		   atomic_long_read(&memcg->memory_events[MEMCG_SWAP_HIGH]));
	seq_printf(m, "max %lu\n",
		   atomic_long_read(&memcg->memory_events[MEMCG_SWAP_MAX]));
	seq_printf(m, "fail %lu\n",
		   atomic_long_read(&memcg->memory_events[MEMCG_SWAP_FAIL]));

	return 0;
}

static struct cftype swap_files[] = {
	{
		.name = "swap.current",
		.flags = CFTYPE_NOT_ON_ROOT,
		.read_u64 = swap_current_read,
	},
	{
		.name = "swap.high",
		.flags = CFTYPE_NOT_ON_ROOT,
		.seq_show = swap_high_show,
		.write = swap_high_write,
	},
	{
		.name = "swap.max",
		.flags = CFTYPE_NOT_ON_ROOT,
		.seq_show = swap_max_show,
		.write = swap_max_write,
	},
	{
		.name = "swap.peak",
		.flags = CFTYPE_NOT_ON_ROOT,
		.read_u64 = swap_peak_read,
	},
	{
		.name = "swap.events",
		.flags = CFTYPE_NOT_ON_ROOT,
		.file_offset = offsetof(struct mem_cgroup, swap_events_file),
		.seq_show = swap_events_show,
	},
	{ }	/* terminate */
};

#define MEMFILE_PRIVATE(x, val)	((x) << 16 | (val))
#define MEMFILE_TYPE(val)	((val) >> 16 & 0xffff)
#define MEMFILE_ATTR(val)	((val) & 0xffff)

/* for encoding cft->private value on file */
enum res_type {
	_MEM,
	_MEMSWAP,
	_KMEM,
	_TCP,
};

static u64 mem_cgroup_read_u64(struct cgroup_subsys_state *css,
			       struct cftype *cft)
{
	struct mem_cgroup *memcg = mem_cgroup_from_css(css);
	struct page_counter *counter;

	switch (MEMFILE_TYPE(cft->private)) {
	case _MEM:
		counter = &memcg->memory;
		break;
	case _MEMSWAP:
		counter = &memcg->memsw;
		break;
	case _KMEM:
		counter = &memcg->kmem;
		break;
	case _TCP:
		counter = &memcg->tcpmem;
		break;
	default:
		BUG();
	}

	switch (MEMFILE_ATTR(cft->private)) {
	case RES_USAGE:
		if (counter == &memcg->memory)
			return (u64)mem_cgroup_usage(memcg, false) * PAGE_SIZE;
		if (counter == &memcg->memsw)
			return (u64)mem_cgroup_usage(memcg, true) * PAGE_SIZE;
		return (u64)page_counter_read(counter) * PAGE_SIZE;
	case RES_LIMIT:
		return (u64)counter->max * PAGE_SIZE;
	case RES_MAX_USAGE:
		return (u64)counter->watermark * PAGE_SIZE;
	case RES_FAILCNT:
		return counter->failcnt;
	case RES_SOFT_LIMIT:
		return (u64)READ_ONCE(memcg->soft_limit) * PAGE_SIZE;
	default:
		BUG();
	}
}

static ssize_t mem_cgroup_reset(struct kernfs_open_file *of, char *buf,
				size_t nbytes, loff_t off)
{
	struct mem_cgroup *memcg = mem_cgroup_from_css(of_css(of));
	struct page_counter *counter;

	switch (MEMFILE_TYPE(of_cft(of)->private)) {
	case _MEM:
		counter = &memcg->memory;
		break;
	case _MEMSWAP:
		counter = &memcg->memsw;
		break;
	case _KMEM:
		counter = &memcg->kmem;
		break;
	case _TCP:
		counter = &memcg->tcpmem;
		break;
	default:
		BUG();
	}

	switch (MEMFILE_ATTR(of_cft(of)->private)) {
	case RES_MAX_USAGE:
		page_counter_reset_watermark(counter);
		break;
	case RES_FAILCNT:
		counter->failcnt = 0;
		break;
	default:
		BUG();
	}

	return nbytes;
}

struct memcg_stock_pcp {
	local_lock_t stock_lock;
	struct mem_cgroup *cached; /* this never be root cgroup */
	unsigned int nr_pages;

#ifdef CONFIG_MEMCG_KMEM
	struct obj_cgroup *cached_objcg;
	struct pglist_data *cached_pgdat;
	unsigned int nr_bytes;
	int nr_slab_reclaimable_b;
	int nr_slab_unreclaimable_b;
#endif

	struct work_struct work;
	unsigned long flags;
#define FLUSHING_CACHED_CHARGE	0
};

extern struct mutex memcg_max_mutex;
extern struct mutex percpu_charge_mutex;
DECLARE_PER_CPU(struct memcg_stock_pcp, memcg_stock);

#ifdef CONFIG_MEMCG_KMEM
static struct obj_cgroup *drain_obj_stock(struct memcg_stock_pcp *stock);
static bool obj_stock_flush_required(struct memcg_stock_pcp *stock,
				     struct mem_cgroup *root_memcg);
static void memcg_account_kmem(struct mem_cgroup *memcg, int nr_pages);

#else
static inline struct obj_cgroup *drain_obj_stock(struct memcg_stock_pcp *stock)
{
	return NULL;
}
static bool obj_stock_flush_required(struct memcg_stock_pcp *stock,
				     struct mem_cgroup *root_memcg)
{
	return false;
}
static void memcg_account_kmem(struct mem_cgroup *memcg, int nr_pages)
{
}
#endif

/*
 * Returns stocks cached in percpu and reset cached information.
 */
static void drain_stock(struct memcg_stock_pcp *stock)
{
	struct mem_cgroup *old = READ_ONCE(stock->cached);

	if (!old)
		return;

	if (stock->nr_pages) {
		page_counter_uncharge(&old->memory, stock->nr_pages);
		if (do_memsw_account())
			page_counter_uncharge(&old->memsw, stock->nr_pages);
		stock->nr_pages = 0;
	}

	css_put(&old->css);
	WRITE_ONCE(stock->cached, NULL);
}

static void drain_local_stock(struct work_struct *dummy)
{
	struct memcg_stock_pcp *stock;
	struct obj_cgroup *old = NULL;
	unsigned long flags;

	/*
	 * The only protection from cpu hotplug (memcg_hotplug_cpu_dead) vs.
	 * drain_stock races is that we always operate on local CPU stock
	 * here with IRQ disabled
	 */
	local_lock_irqsave(&memcg_stock.stock_lock, flags);

	stock = this_cpu_ptr(&memcg_stock);
	old = drain_obj_stock(stock);
	drain_stock(stock);
	clear_bit(FLUSHING_CACHED_CHARGE, &stock->flags);

	local_unlock_irqrestore(&memcg_stock.stock_lock, flags);
	if (old)
		obj_cgroup_put(old);
}

/*
 * Drains all per-CPU charge caches for given root_memcg resp. subtree
 * of the hierarchy under it.
 */
static void drain_all_stock(struct mem_cgroup *root_memcg)
{
	int cpu, curcpu;

	/* If someone's already draining, avoid adding running more workers. */
	if (!mutex_trylock(&percpu_charge_mutex))
		return;
	/*
	 * Notify other cpus that system-wide "drain" is running
	 * We do not care about races with the cpu hotplug because cpu down
	 * as well as workers from this path always operate on the local
	 * per-cpu data. CPU up doesn't touch memcg_stock at all.
	 */
	migrate_disable();
	curcpu = smp_processor_id();
	for_each_online_cpu(cpu) {
		struct memcg_stock_pcp *stock = &per_cpu(memcg_stock, cpu);
		struct mem_cgroup *memcg;
		bool flush = false;

		rcu_read_lock();
		memcg = READ_ONCE(stock->cached);
		if (memcg && stock->nr_pages &&
		    mem_cgroup_is_descendant(memcg, root_memcg))
			flush = true;
		else if (obj_stock_flush_required(stock, root_memcg))
			flush = true;
		rcu_read_unlock();

		if (flush &&
		    !test_and_set_bit(FLUSHING_CACHED_CHARGE, &stock->flags)) {
			if (cpu == curcpu)
				drain_local_stock(&stock->work);
			else if (!cpu_is_isolated(cpu))
				schedule_work_on(cpu, &stock->work);
		}
	}
	migrate_enable();
	mutex_unlock(&percpu_charge_mutex);
}

DECLARE_WAIT_QUEUE_HEAD(memcg_oom_waitq);

static void memcg_oom_recover(struct mem_cgroup *memcg)
{
	/*
	 * For the following lockless ->under_oom test, the only required
	 * guarantee is that it must see the state asserted by an OOM when
	 * this function is called as a result of userland actions
	 * triggered by the notification of the OOM.  This is trivially
	 * achieved by invoking mem_cgroup_mark_under_oom() before
	 * triggering notification.
	 */
	if (memcg && memcg->under_oom)
		__wake_up(&memcg_oom_waitq, TASK_NORMAL, 0, memcg);
}

static int mem_cgroup_resize_max(struct mem_cgroup *memcg,
				 unsigned long max, bool memsw)
{
	bool enlarge = false;
	bool drained = false;
	int ret;
	bool limits_invariant;
	struct page_counter *counter = memsw ? &memcg->memsw : &memcg->memory;

	do {
		if (signal_pending(current)) {
			ret = -EINTR;
			break;
		}

		mutex_lock(&memcg_max_mutex);
		/*
		 * Make sure that the new limit (memsw or memory limit) doesn't
		 * break our basic invariant rule memory.max <= memsw.max.
		 */
		limits_invariant = memsw ? max >= READ_ONCE(memcg->memory.max) :
					   max <= memcg->memsw.max;
		if (!limits_invariant) {
			mutex_unlock(&memcg_max_mutex);
			ret = -EINVAL;
			break;
		}
		if (max > counter->max)
			enlarge = true;
		ret = page_counter_set_max(counter, max);
		mutex_unlock(&memcg_max_mutex);

		if (!ret)
			break;

		if (!drained) {
			drain_all_stock(memcg);
			drained = true;
			continue;
		}

		if (!try_to_free_mem_cgroup_pages(memcg, 1, GFP_KERNEL,
					memsw ? 0 : MEMCG_RECLAIM_MAY_SWAP)) {
			ret = -EBUSY;
			break;
		}
	} while (true);

	if (!ret && enlarge)
		memcg_oom_recover(memcg);

	return ret;
}

static int memcg_update_tcp_max(struct mem_cgroup *memcg, unsigned long max)
{
	int ret;

	mutex_lock(&memcg_max_mutex);

	ret = page_counter_set_max(&memcg->tcpmem, max);
	if (ret)
		goto out;

	if (!memcg->tcpmem_active) {
		/*
		 * The active flag needs to be written after the static_key
		 * update. This is what guarantees that the socket activation
		 * function is the last one to run. See mem_cgroup_sk_alloc()
		 * for details, and note that we don't mark any socket as
		 * belonging to this memcg until that flag is up.
		 *
		 * We need to do this, because static_keys will span multiple
		 * sites, but we can't control their order. If we mark a socket
		 * as accounted, but the accounting functions are not patched in
		 * yet, we'll lose accounting.
		 *
		 * We never race with the readers in mem_cgroup_sk_alloc(),
		 * because when this value change, the code to process it is not
		 * patched in yet.
		 */
		static_branch_inc(&memcg_sockets_enabled_key);
		memcg->tcpmem_active = true;
	}
out:
	mutex_unlock(&memcg_max_mutex);
	return ret;
}

/*
 * The user of this function is...
 * RES_LIMIT.
 */
static ssize_t mem_cgroup_write(struct kernfs_open_file *of,
				char *buf, size_t nbytes, loff_t off)
{
	struct mem_cgroup *memcg = mem_cgroup_from_css(of_css(of));
	unsigned long nr_pages;
	int ret;

	buf = strstrip(buf);
	ret = page_counter_memparse(buf, "-1", &nr_pages);
	if (ret)
		return ret;

	switch (MEMFILE_ATTR(of_cft(of)->private)) {
	case RES_LIMIT:
		if (mem_cgroup_is_root(memcg)) { /* Can't set limit on root */
			ret = -EINVAL;
			break;
		}
		switch (MEMFILE_TYPE(of_cft(of)->private)) {
		case _MEM:
			ret = mem_cgroup_resize_max(memcg, nr_pages, false);
			break;
		case _MEMSWAP:
			ret = mem_cgroup_resize_max(memcg, nr_pages, true);
			break;
		case _KMEM:
			pr_warn_once("kmem.limit_in_bytes is deprecated and will be removed. "
				     "Writing any value to this file has no effect. "
				     "Please report your usecase to linux-mm@kvack.org if you "
				     "depend on this functionality.\n");
			ret = 0;
			break;
		case _TCP:
			ret = memcg_update_tcp_max(memcg, nr_pages);
			break;
		}
		break;
	case RES_SOFT_LIMIT:
		if (IS_ENABLED(CONFIG_PREEMPT_RT)) {
			ret = -EOPNOTSUPP;
		} else {
			WRITE_ONCE(memcg->soft_limit, nr_pages);
			ret = 0;
		}
		break;
	}
	return ret ?: nbytes;
}

static struct cftype memsw_files[] = {
	{
		.name = "memsw.usage_in_bytes",
		.private = MEMFILE_PRIVATE(_MEMSWAP, RES_USAGE),
		.read_u64 = mem_cgroup_read_u64,
	},
	{
		.name = "memsw.max_usage_in_bytes",
		.private = MEMFILE_PRIVATE(_MEMSWAP, RES_MAX_USAGE),
		.write = mem_cgroup_reset,
		.read_u64 = mem_cgroup_read_u64,
	},
	{
		.name = "memsw.limit_in_bytes",
		.private = MEMFILE_PRIVATE(_MEMSWAP, RES_LIMIT),
		.write = mem_cgroup_write,
		.read_u64 = mem_cgroup_read_u64,
	},
	{
		.name = "memsw.failcnt",
		.private = MEMFILE_PRIVATE(_MEMSWAP, RES_FAILCNT),
		.write = mem_cgroup_reset,
		.read_u64 = mem_cgroup_read_u64,
	},
	{ },	/* terminate */
};

#if defined(CONFIG_MEMCG_KMEM) && defined(CONFIG_ZSWAP)
/**
 * obj_cgroup_may_zswap - check if this cgroup can zswap
 * @objcg: the object cgroup
 *
 * Check if the hierarchical zswap limit has been reached.
 *
 * This doesn't check for specific headroom, and it is not atomic
 * either. But with zswap, the size of the allocation is only known
 * once compression has occured, and this optimistic pre-check avoids
 * spending cycles on compression when there is already no room left
 * or zswap is disabled altogether somewhere in the hierarchy.
 */
bool obj_cgroup_may_zswap(struct obj_cgroup *objcg)
{
	struct mem_cgroup *memcg, *original_memcg;
	bool ret = true;

	if (!cgroup_subsys_on_dfl(memory_cgrp_subsys))
		return true;

	original_memcg = get_mem_cgroup_from_objcg(objcg);
	for (memcg = original_memcg; !mem_cgroup_is_root(memcg);
	     memcg = parent_mem_cgroup(memcg)) {
		unsigned long max = READ_ONCE(memcg->zswap_max);
		unsigned long pages;

		if (max == PAGE_COUNTER_MAX)
			continue;
		if (max == 0) {
			ret = false;
			break;
		}

		cgroup_rstat_flush(memcg->css.cgroup);
		pages = memcg_page_state(memcg, MEMCG_ZSWAP_B) / PAGE_SIZE;
		if (pages < max)
			continue;
		ret = false;
		break;
	}
	mem_cgroup_put(original_memcg);
	return ret;
}

/**
 * obj_cgroup_charge_zswap - charge compression backend memory
 * @objcg: the object cgroup
 * @size: size of compressed object
 *
 * This forces the charge after obj_cgroup_may_zswap() allowed
 * compression and storage in zwap for this cgroup to go ahead.
 */
void obj_cgroup_charge_zswap(struct obj_cgroup *objcg, size_t size)
{
	struct mem_cgroup *memcg;

	if (!cgroup_subsys_on_dfl(memory_cgrp_subsys))
		return;

	VM_WARN_ON_ONCE(!(current->flags & PF_MEMALLOC));

	/* PF_MEMALLOC context, charging must succeed */
	if (obj_cgroup_charge(objcg, GFP_KERNEL, size))
		VM_WARN_ON_ONCE(1);

	rcu_read_lock();
	memcg = obj_cgroup_memcg(objcg);
	mod_memcg_state(memcg, MEMCG_ZSWAP_B, size);
	mod_memcg_state(memcg, MEMCG_ZSWAPPED, 1);
	rcu_read_unlock();
}

/**
 * obj_cgroup_uncharge_zswap - uncharge compression backend memory
 * @objcg: the object cgroup
 * @size: size of compressed object
 *
 * Uncharges zswap memory on page in.
 */
void obj_cgroup_uncharge_zswap(struct obj_cgroup *objcg, size_t size)
{
	struct mem_cgroup *memcg;

	if (!cgroup_subsys_on_dfl(memory_cgrp_subsys))
		return;

	obj_cgroup_uncharge(objcg, size);

	rcu_read_lock();
	memcg = obj_cgroup_memcg(objcg);
	mod_memcg_state(memcg, MEMCG_ZSWAP_B, -size);
	mod_memcg_state(memcg, MEMCG_ZSWAPPED, -1);
	rcu_read_unlock();
}

static u64 zswap_current_read(struct cgroup_subsys_state *css,
			      struct cftype *cft)
{
	cgroup_rstat_flush(css->cgroup);
	return memcg_page_state(mem_cgroup_from_css(css), MEMCG_ZSWAP_B);
}

static int zswap_max_show(struct seq_file *m, void *v)
{
	return seq_puts_memcg_tunable(m,
		READ_ONCE(mem_cgroup_from_seq(m)->zswap_max));
}

static ssize_t zswap_max_write(struct kernfs_open_file *of,
			       char *buf, size_t nbytes, loff_t off)
{
	struct mem_cgroup *memcg = mem_cgroup_from_css(of_css(of));
	unsigned long max;
	int err;

	buf = strstrip(buf);
	err = page_counter_memparse(buf, "max", &max);
	if (err)
		return err;

	xchg(&memcg->zswap_max, max);

	return nbytes;
}

static struct cftype zswap_files[] = {
	{
		.name = "zswap.current",
		.flags = CFTYPE_NOT_ON_ROOT,
		.read_u64 = zswap_current_read,
	},
	{
		.name = "zswap.max",
		.flags = CFTYPE_NOT_ON_ROOT,
		.seq_show = zswap_max_show,
		.write = zswap_max_write,
	},
	{ }	/* terminate */
};
#endif /* CONFIG_MEMCG_KMEM && CONFIG_ZSWAP */

#endif /* CONFIG_SWAP */
