// SPDX-License-Identifier: GPL-2.0-only
/*
 * Simple NUMA memory policy for the Linux kernel.
 *
 * Copyright 2003,2004 Andi Kleen, SuSE Labs.
 * (C) Copyright 2005 Christoph Lameter, Silicon Graphics, Inc.
 *
 * NUMA policy allows the user to give hints in which node(s) memory should
 * be allocated.
 *
 * Support four policies per VMA and per process:
 *
 * The VMA policy has priority over the process policy for a page fault.
 *
 * interleave     Allocate memory interleaved over a set of nodes,
 *                with normal fallback if it fails.
 *                For VMA based allocations this interleaves based on the
 *                offset into the backing object or offset into the mapping
 *                for anonymous memory. For process policy an process counter
 *                is used.
 *
 * bind           Only allocate memory on a specific set of nodes,
 *                no fallback.
 *                FIXME: memory is allocated starting with the first node
 *                to the last. It would be better if bind would truly restrict
 *                the allocation to memory nodes instead
 *
 * preferred       Try a specific node first before normal fallback.
 *                As a special case NUMA_NO_NODE here means do the allocation
 *                on the local CPU. This is normally identical to default,
 *                but useful to set in a VMA when you have a non default
 *                process policy.
 *
 * preferred many Try a set of nodes first before normal fallback. This is
 *                similar to preferred without the special case.
 *
 * default        Allocate on the local node first, or when on a VMA
 *                use the process policy. This is what Linux always did
 *		  in a NUMA aware kernel and still does by, ahem, default.
 *
 * The process policy is applied for most non interrupt memory allocations
 * in that process' context. Interrupts ignore the policies and always
 * try to allocate on the local CPU. The VMA policy is only applied for memory
 * allocations for a VMA in the VM.
 *
 * Currently there are a few corner cases in swapping where the policy
 * is not applied, but the majority should be handled. When process policy
 * is used it is not remembered over swap outs/swap ins.
 *
 * Only the highest zone in the zone hierarchy gets policied. Allocations
 * requesting a lower zone just use default policy. This implies that
 * on systems with highmem kernel lowmem allocation don't get policied.
 * Same with GFP_DMA allocations.
 *
 * For shmfs/tmpfs/hugetlbfs shared memory the policy is shared between
 * all users and remembered even when nobody has memory mapped.
 */

/* Notebook:
   fix mmap readahead to honour policy and enable policy for any page cache
   object
   statistics for bigpages
   global policy for page cache? currently it uses process policy. Requires
   first item above.
   handle mremap for shared memory (currently ignored for the policy)
   grows down?
   make bind policy root only? It can trigger oom much faster and the
   kernel is not always grateful with that.
*/


#include <linux/mempolicy.h>
#include <linux/pagewalk.h>
#include <linux/highmem.h>
#include <linux/hugetlb.h>
#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/sched/mm.h>
#include <linux/sched/numa_balancing.h>
#include <linux/sched/task.h>
#include <linux/nodemask.h>
#include <linux/cpuset.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/export.h>
#include <linux/nsproxy.h>
#include <linux/interrupt.h>
#include <linux/init.h>
#include <linux/compat.h>
#include <linux/ptrace.h>
// #include <linux/swap.h>
#include "linux/swap.h"
#include <linux/seq_file.h>
#include <linux/proc_fs.h>
#include <linux/migrate.h>
#include <linux/ksm.h>
#include <linux/rmap.h>
#include <linux/security.h>
#include <linux/syscalls.h>
#include <linux/ctype.h>
#include <linux/mm_inline.h>
#include <linux/mmu_notifier.h>
#include <linux/printk.h>
#include <linux/swapops.h>

#include <asm/tlbflush.h>
#include <asm/tlb.h>
#include <linux/uaccess.h>

#include "internal.h"
#include <linux/calclock.h>

/*
 * run-time system-wide default policy => local allocation
 */
static struct mempolicy default_policy = {
	.refcnt = ATOMIC_INIT(1), /* never free it */
	.mode = MPOL_LOCAL,
};

/* Allocate a page in interleaved policy.
   Own path because it needs to do special accounting. */
static struct page *alloc_page_interleave(gfp_t gfp, unsigned order,
					unsigned nid)
{
	struct page *page;

	page = __alloc_pages(gfp, order, nid, NULL);
	/* skip NUMA_INTERLEAVE_HIT counter update if numa stats is disabled */
	if (!static_branch_likely(&vm_numa_stat_key))
		return page;
	if (page && page_to_nid(page) == nid) {
		preempt_disable();
		__count_numa_event(page_zone(page), NUMA_INTERLEAVE_HIT);
		preempt_enable();
	}
	return page;
}

/* Do dynamic interleaving for a process */
static unsigned interleave_nodes(struct mempolicy *policy)
{
	unsigned next;
	struct task_struct *me = current;

	next = next_node_in(me->il_prev, policy->nodes);
	if (next < MAX_NUMNODES)
		me->il_prev = next;
	return next;
}

static struct page *alloc_pages_preferred_many(gfp_t gfp, unsigned int order,
						int nid, struct mempolicy *pol)
{
	struct page *page;
	gfp_t preferred_gfp;

	/*
	 * This is a two pass approach. The first pass will only try the
	 * preferred nodes but skip the direct reclaim and allow the
	 * allocation to fail, while the second pass will try all the
	 * nodes in system.
	 */
	preferred_gfp = gfp | __GFP_NOWARN;
	preferred_gfp &= ~(__GFP_DIRECT_RECLAIM | __GFP_NOFAIL);
	page = __alloc_pages(preferred_gfp, order, nid, &pol->nodes);
	if (!page)
		page = __alloc_pages(gfp, order, nid, NULL);

	return page;
}

/*
 * Return the  preferred node id for 'prefer' mempolicy, and return
 * the given id for all other policies.
 *
 * policy_node() is always coupled with policy_nodemask(), which
 * secures the nodemask limit for 'bind' and 'prefer-many' policy.
 */
static int policy_node(gfp_t gfp, struct mempolicy *policy, int nd)
{
	if (policy->mode == MPOL_PREFERRED) {
		nd = first_node(policy->nodes);
	} else {
		/*
		 * __GFP_THISNODE shouldn't even be used with the bind policy
		 * because we might easily break the expectation to stay on the
		 * requested node and not break the policy.
		 */
		WARN_ON_ONCE(policy->mode == MPOL_BIND && (gfp & __GFP_THISNODE));
	}

	if ((policy->mode == MPOL_BIND ||
	     policy->mode == MPOL_PREFERRED_MANY) &&
	    policy->home_node != NUMA_NO_NODE)
		return policy->home_node;

	return nd;
}


/*
 * get_vma_policy(@vma, @addr)
 * @vma: virtual memory area whose policy is sought
 * @addr: address in @vma for shared policy lookup
 *
 * Returns effective policy for a VMA at specified address.
 * Falls back to current->mempolicy or system default policy, as necessary.
 * Shared policies [those marked as MPOL_F_SHARED] require an extra reference
 * count--added by the get_policy() vm_op, as appropriate--to protect against
 * freeing by another task.  It is the caller's responsibility to free the
 * extra reference for shared policies.
 */
static struct mempolicy *get_vma_policy(struct vm_area_struct *vma,
						unsigned long addr)
{
	struct mempolicy *pol = __get_vma_policy(vma, addr);

	if (!pol)
		pol = get_task_policy(current);

	return pol;
}

/*
 * Do static interleaving for a VMA with known offset @n.  Returns the n'th
 * node in pol->nodes (starting from n=0), wrapping around if n exceeds the
 * number of present nodes.
 */
static unsigned offset_il_node(struct mempolicy *pol, unsigned long n)
{
	nodemask_t nodemask = pol->nodes;
	unsigned int target, nnodes;
	int i;
	int nid;
	/*
	 * The barrier will stabilize the nodemask in a register or on
	 * the stack so that it will stop changing under the code.
	 *
	 * Between first_node() and next_node(), pol->nodes could be changed
	 * by other threads. So we put pol->nodes in a local stack.
	 */
	barrier();

	nnodes = nodes_weight(nodemask);
	if (!nnodes)
		return numa_node_id();
	target = (unsigned int)n % nnodes;
	nid = first_node(nodemask);
	for (i = 0; i < target; i++)
		nid = next_node(nid, nodemask);
	return nid;
}

/* Determine a node number for interleave */
static inline unsigned interleave_nid(struct mempolicy *pol,
		 struct vm_area_struct *vma, unsigned long addr, int shift)
{
	if (vma) {
		unsigned long off;

		/*
		 * for small pages, there is no difference between
		 * shift and PAGE_SHIFT, so the bit-shift is safe.
		 * for huge pages, since vm_pgoff is in units of small
		 * pages, we need to shift off the always 0 bits to get
		 * a useful offset.
		 */
		BUG_ON(shift < PAGE_SHIFT);
		off = vma->vm_pgoff >> (shift - PAGE_SHIFT);
		off += (addr - vma->vm_start) >> shift;
		return offset_il_node(pol, off);
	} else
		return interleave_nodes(pol);
}

/**
 * vma_alloc_folio - Allocate a folio for a VMA.
 * @gfp: GFP flags.
 * @order: Order of the folio.
 * @vma: Pointer to VMA or NULL if not available.
 * @addr: Virtual address of the allocation.  Must be inside @vma.
 * @hugepage: For hugepages try only the preferred node if possible.
 *
 * Allocate a folio for a specific address in @vma, using the appropriate
 * NUMA policy.  When @vma is not NULL the caller must hold the mmap_lock
 * of the mm_struct of the VMA to prevent it from going away.  Should be
 * used for all allocations for folios that will be mapped into user space.
 *
 * Return: The folio on success or NULL if allocation fails.
 */
extern struct folio *__m_folio_alloc(gfp_t gfp, unsigned int order, int preferred_nid,
                nodemask_t *nodemask);

struct folio *_m_vma_alloc_folio(gfp_t gfp, int order, struct vm_area_struct *vma,
		unsigned long addr, bool hugepage)
{
	struct mempolicy *pol;
	int node = numa_node_id();
	struct folio *folio;
	int preferred_nid;
	nodemask_t *nmask;

	pol = get_vma_policy(vma, addr);

	if (pol->mode == MPOL_INTERLEAVE) {
		struct page *page;
		unsigned nid;

		nid = interleave_nid(pol, vma, addr, PAGE_SHIFT + order);
		mpol_cond_put(pol);
		gfp |= __GFP_COMP;
		page = alloc_page_interleave(gfp, order, nid);
		folio = (struct folio *)page;
		if (folio && order > 1)
			folio_prep_large_rmappable(folio);
		goto out;
	}

	if (pol->mode == MPOL_PREFERRED_MANY) {
		struct page *page;

		node = policy_node(gfp, pol, node);
		gfp |= __GFP_COMP;
		page = alloc_pages_preferred_many(gfp, order, node, pol);
		mpol_cond_put(pol);
		folio = (struct folio *)page;
		if (folio && order > 1)
			folio_prep_large_rmappable(folio);
		goto out;
	}

	if (unlikely(IS_ENABLED(CONFIG_TRANSPARENT_HUGEPAGE) && hugepage)) {
		int hpage_node = node;

		/*
		 * For hugepage allocation and non-interleave policy which
		 * allows the current node (or other explicitly preferred
		 * node) we only try to allocate from the current/preferred
		 * node and don't fall back to other nodes, as the cost of
		 * remote accesses would likely offset THP benefits.
		 *
		 * If the policy is interleave or does not allow the current
		 * node in its nodemask, we allocate the standard way.
		 */
		if (pol->mode == MPOL_PREFERRED)
			hpage_node = first_node(pol->nodes);

		nmask = policy_nodemask(gfp, pol);
		if (!nmask || node_isset(hpage_node, *nmask)) {
			mpol_cond_put(pol);
			/*
			 * First, try to allocate THP only on local node, but
			 * don't reclaim unnecessarily, just compact.
			 */
			folio = __folio_alloc_node(gfp | __GFP_THISNODE |
					__GFP_NORETRY, order, hpage_node);

			/*
			 * If hugepage allocations are configured to always
			 * synchronous compact or the vma has been madvised
			 * to prefer hugepage backing, retry allowing remote
			 * memory with both reclaim and compact as well.
			 */
			if (!folio && (gfp & __GFP_DIRECT_RECLAIM)) {
				folio = __m_folio_alloc(gfp, order, hpage_node,
						      nmask);
			}

			goto out;
		}
	}

	nmask = policy_nodemask(gfp, pol);
	preferred_nid = policy_node(gfp, pol, node);
	folio = __m_folio_alloc(gfp, order, preferred_nid, nmask);
	mpol_cond_put(pol);
out:
	return folio;
}


struct folio *_k_vma_alloc_folio(gfp_t gfp, int order, struct vm_area_struct *vma,
		unsigned long addr, bool hugepage)
{
	struct mempolicy *pol;
	int node = numa_node_id();
	struct folio *folio;
	int preferred_nid;
	nodemask_t *nmask;

	pol = get_vma_policy(vma, addr);

	if (pol->mode == MPOL_INTERLEAVE) {
		struct page *page;
		unsigned nid;

		nid = interleave_nid(pol, vma, addr, PAGE_SHIFT + order);
		mpol_cond_put(pol);
		gfp |= __GFP_COMP;
		page = alloc_page_interleave(gfp, order, nid);
		folio = (struct folio *)page;
		if (folio && order > 1)
			folio_prep_large_rmappable(folio);
		goto out;
	}

	if (pol->mode == MPOL_PREFERRED_MANY) {
		struct page *page;

		node = policy_node(gfp, pol, node);
		gfp |= __GFP_COMP;
		page = alloc_pages_preferred_many(gfp, order, node, pol);
		mpol_cond_put(pol);
		folio = (struct folio *)page;
		if (folio && order > 1)
			folio_prep_large_rmappable(folio);
		goto out;
	}

	if (unlikely(IS_ENABLED(CONFIG_TRANSPARENT_HUGEPAGE) && hugepage)) {
		int hpage_node = node;

		/*
		 * For hugepage allocation and non-interleave policy which
		 * allows the current node (or other explicitly preferred
		 * node) we only try to allocate from the current/preferred
		 * node and don't fall back to other nodes, as the cost of
		 * remote accesses would likely offset THP benefits.
		 *
		 * If the policy is interleave or does not allow the current
		 * node in its nodemask, we allocate the standard way.
		 */
		if (pol->mode == MPOL_PREFERRED)
			hpage_node = first_node(pol->nodes);

		nmask = policy_nodemask(gfp, pol);
		if (!nmask || node_isset(hpage_node, *nmask)) {
			mpol_cond_put(pol);
			/*
			 * First, try to allocate THP only on local node, but
			 * don't reclaim unnecessarily, just compact.
			 */
			folio = __folio_alloc_node(gfp | __GFP_THISNODE |
					__GFP_NORETRY, order, hpage_node);

			/*
			 * If hugepage allocations are configured to always
			 * synchronous compact or the vma has been madvised
			 * to prefer hugepage backing, retry allowing remote
			 * memory with both reclaim and compact as well.
			 */
			if (!folio && (gfp & __GFP_DIRECT_RECLAIM)) {
				folio = __folio_alloc(gfp, order, hpage_node,
						      nmask);
			}

			goto out;
		}
	}

	nmask = policy_nodemask(gfp, pol);
	preferred_nid = policy_node(gfp, pol, node);
	folio = __folio_alloc(gfp, order, preferred_nid, nmask);
	mpol_cond_put(pol);
out:
	return folio;
}

/**
 * alloc_pages - Allocate pages.
 * @gfp: GFP flags.
 * @order: Power of two of number of pages to allocate.
 *
 * Allocate 1 << @order contiguous pages.  The physical address of the
 * first page is naturally aligned (eg an order-3 allocation will be aligned
 * to a multiple of 8 * PAGE_SIZE bytes).  The NUMA policy of the current
 * process is honoured when in process context.
 *
 * Context: Can be called from any context, providing the appropriate GFP
 * flags are used.
 * Return: The page on success or NULL if allocation fails.
 */
extern struct page *_k__alloc_pages(gfp_t gfp, unsigned int order, int preferred_nid,
							nodemask_t *nodemask);
struct page *_k_alloc_pages(gfp_t gfp, unsigned order)
{
	struct mempolicy *pol = &default_policy;
	struct page *page;

	if (!in_interrupt() && !(gfp & __GFP_THISNODE))
		pol = get_task_policy(current);

	/*
	 * No reference counting needed for current->mempolicy
	 * nor system default_policy
	 */
	if (pol->mode == MPOL_INTERLEAVE)
		page = alloc_page_interleave(gfp, order, interleave_nodes(pol));
	else if (pol->mode == MPOL_PREFERRED_MANY)
		page = alloc_pages_preferred_many(gfp, order,
				  policy_node(gfp, pol, numa_node_id()), pol);
	else
		page = __alloc_pages(gfp, order,
				policy_node(gfp, pol, numa_node_id()),
				policy_nodemask(gfp, pol));

	return page;
}
