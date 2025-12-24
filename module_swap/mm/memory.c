// SPDX-License-Identifier: GPL-2.0-only
/*
 *  linux/mm/memory.c
 *
 *  Copyright (C) 1991, 1992, 1993, 1994  Linus Torvalds
 */

/*
 * demand-loading started 01.12.91 - seems it is high on the list of
 * things wanted, and it should be easy to implement. - Linus
 */

/*
 * Ok, demand-loading was easy, shared pages a little bit tricker. Shared
 * pages started 02.12.91, seems to work. - Linus.
 *
 * Tested sharing by executing about 30 /bin/sh: under the old kernel it
 * would have taken more than the 6M I have free, but it worked well as
 * far as I could see.
 *
 * Also corrected some "invalidate()"s - I wasn't doing enough of them.
 */

/*
 * Real VM (paging to/from disk) started 18.12.91. Much more work and
 * thought has to go into this. Oh, well..
 * 19.12.91  -  works, somewhat. Sometimes I get faults, don't know why.
 *		Found it. Everything seems to work now.
 * 20.12.91  -  Ok, making the swap-device changeable like the root.
 */

/*
 * 05.04.94  -  Multi-page memory management added for v1.1.
 *              Idea by Alex Bligh (alex@cconcepts.co.uk)
 *
 * 16.07.99  -  Support of BIGMEM added by Gerhard Wichert, Siemens AG
 *		(Gerhard.Wichert@pdb.siemens.de)
 *
 * Aug/Sep 2004 Changed to four level page tables (Andi Kleen)
 */

#include <linux/kernel_stat.h>
#include <linux/mm.h>
#include <linux/mm_inline.h>
#include <linux/sched/mm.h>
#include <linux/sched/coredump.h>
#include <linux/sched/numa_balancing.h>
#include <linux/sched/task.h>
#include <linux/hugetlb.h>
#include <linux/mman.h>
// #include <linux/swap.h>
#include "linux/swap.h"
#include <linux/highmem.h>
// #include <linux/pagemap.h>
#include "linux/pagemap.h"
#include <linux/memremap.h>
#include <linux/kmsan.h>
#include <linux/ksm.h>
#include <linux/rmap.h>
#include <linux/export.h>
#include <linux/delayacct.h>
#include <linux/init.h>
#include <linux/pfn_t.h>
#include <linux/writeback.h>
#include <linux/memcontrol.h>
#include <linux/mmu_notifier.h>
#include <linux/swapops.h>
#include <linux/elf.h>
#include <linux/gfp.h>
#include <linux/migrate.h>
#include <linux/string.h>
#include <linux/memory-tiers.h>
#include <linux/debugfs.h>
#include <linux/userfaultfd_k.h>
#include <linux/dax.h>
#include <linux/oom.h>
#include <linux/numa.h>
#include <linux/perf_event.h>
#include <linux/ptrace.h>
#include <linux/vmalloc.h>
#include <linux/sched.h>
#include <linux/sched/sysctl.h>


#include <trace/events/kmem.h>

#include <asm/io.h>
#include <asm/mmu_context.h>
#include <asm/pgalloc.h>
#include <linux/uaccess.h>
#include <asm/tlb.h>
#include <asm/tlbflush.h>

#include "pgalloc-track.h"
#include "internal.h"
#include "swap.h"
#include <linux/calclock.h>
#include <linux/calclock2.h>

#include "../lock_folio_counter.h"

static inline void flush_tlb_page(struct vm_area_struct *vma, unsigned long a)
{
	flush_tlb_mm_range(vma->vm_mm, a, a + PAGE_SIZE, PAGE_SHIFT, false);
}

#ifndef __PAGETABLE_PMD_FOLDED
/*
 * Allocate page middle directory.
 * We've already handled the fast-path in-line.
 */
int __pmd_alloc(struct mm_struct *mm, pud_t *pud, unsigned long address)
{
        spinlock_t *ptl;
        pmd_t *new = pmd_alloc_one(mm, address);
        if (!new)
                return -ENOMEM;

        ptl = pud_lock(mm, pud);
        if (!pud_present(*pud)) {
                mm_inc_nr_pmds(mm);
                smp_wmb(); /* See comment in pmd_install() */
                pud_populate(mm, pud, new);
        } else {        /* Another has populated it */
                pmd_free(mm, new);
        }
        spin_unlock(ptl);
        return 0;
}
#endif /* __PAGETABLE_PMD_FOLDED */


/*
 * Handle write page faults for pages that can be reused in the current vma
 *
 * This can happen either due to the mapping being with the VM_SHARED flag,
 * or due to us being the last reference standing to the page. In either
 * case, all we need to do here is to mark the page as writable and update
 * any related book-keeping.
 */
static inline void wp_page_reuse(struct vm_fault *vmf)
	__releases(vmf->ptl)
{
	struct vm_area_struct *vma = vmf->vma;
	struct page *page = vmf->page;
	pte_t entry;

	VM_BUG_ON(!(vmf->flags & FAULT_FLAG_WRITE));
	VM_BUG_ON(page && PageAnon(page) && !PageAnonExclusive(page));

	/*
	 * Clear the pages cpupid information as the existing
	 * information potentially belongs to a now completely
	 * unrelated process.
	 */
	if (page)
		page_cpupid_xchg_last(page, (1 << LAST_CPUPID_SHIFT) - 1);

	flush_cache_page(vma, vmf->address, pte_pfn(vmf->orig_pte));
	entry = pte_mkyoung(vmf->orig_pte);
	entry = maybe_mkwrite(pte_mkdirty(entry), vma);
	if (ptep_set_access_flags(vma, vmf->address, vmf->pte, entry, 1))
		update_mmu_cache_range(vmf, vma, vmf->address, vmf->pte, 1);
	pte_unmap_unlock(vmf->pte, vmf->ptl);
	count_vm_event(PGREUSE);
}


/**
 * finish_mkwrite_fault - finish page fault for a shared mapping, making PTE
 *			  writeable once the page is prepared
 *
 * @vmf: structure describing the fault
 *
 * This function handles all that is needed to finish a write page fault in a
 * shared mapping due to PTE being read-only once the mapped page is prepared.
 * It handles locking of PTE and modifying it.
 *
 * The function expects the page to be locked or other protection against
 * concurrent faults / writeback (such as DAX radix tree locks).
 *
 * Return: %0 on success, %VM_FAULT_NOPAGE when PTE got changed before
 * we acquired PTE lock.
 */
vm_fault_t finish_mkwrite_fault(struct vm_fault *vmf)
{
	WARN_ON_ONCE(!(vmf->vma->vm_flags & VM_SHARED));
	vmf->pte = pte_offset_map_lock(vmf->vma->vm_mm, vmf->pmd, vmf->address,
				       &vmf->ptl);
	if (!vmf->pte)
		return VM_FAULT_NOPAGE;
	/*
	 * We might have raced with another page fault while we released the
	 * pte_offset_map_lock.
	 */
	if (!pte_same(ptep_get(vmf->pte), vmf->orig_pte)) {
		update_mmu_tlb(vmf->vma, vmf->address, vmf->pte);
		pte_unmap_unlock(vmf->pte, vmf->ptl);
		return VM_FAULT_NOPAGE;
	}
	wp_page_reuse(vmf);
	return 0;
}


/*
 * Handle write page faults for VM_MIXEDMAP or VM_PFNMAP for a VM_SHARED
 * mapping
 */
static vm_fault_t wp_pfn_shared(struct vm_fault *vmf)
{
	struct vm_area_struct *vma = vmf->vma;

	if (vma->vm_ops && vma->vm_ops->pfn_mkwrite) {
		vm_fault_t ret;

		pte_unmap_unlock(vmf->pte, vmf->ptl);
		if (vmf->flags & FAULT_FLAG_VMA_LOCK) {
			vma_end_read(vmf->vma);
			return VM_FAULT_RETRY;
		}

		vmf->flags |= FAULT_FLAG_MKWRITE;
		ret = vma->vm_ops->pfn_mkwrite(vmf);
		if (ret & (VM_FAULT_ERROR | VM_FAULT_NOPAGE))
			return ret;
		return finish_mkwrite_fault(vmf);
	}
	wp_page_reuse(vmf);
	return 0;
}


/*
 * Notify the address space that the page is about to become writable so that
 * it can prohibit this or wait for the page to get into an appropriate state.
 *
 * We do this without the lock held, so that it can sleep if it needs to.
 */
static vm_fault_t do_page_mkwrite(struct vm_fault *vmf, struct folio *folio)
{
	vm_fault_t ret;
	unsigned int old_flags = vmf->flags;

	vmf->flags = FAULT_FLAG_WRITE|FAULT_FLAG_MKWRITE;

	if (vmf->vma->vm_file &&
	    IS_SWAPFILE(vmf->vma->vm_file->f_mapping->host))
		return VM_FAULT_SIGBUS;

	ret = vmf->vma->vm_ops->page_mkwrite(vmf);
	/* Restore original flags so that caller is not surprised */
	vmf->flags = old_flags;
	if (unlikely(ret & (VM_FAULT_ERROR | VM_FAULT_NOPAGE)))
		return ret;
	if (unlikely(!(ret & VM_FAULT_LOCKED))) {
		folio_lock(folio);
		if (!folio->mapping) {
			folio_unlock(folio);
			return 0; /* retry */
		}
		ret |= VM_FAULT_LOCKED;
	} else
		VM_BUG_ON_FOLIO(!folio_test_locked(folio), folio);
	return ret;
}


/*
 * Handle dirtying of a page in shared file mapping on a write fault.
 *
 * The function expects the page to be locked and unlocks it.
 */
static vm_fault_t fault_dirty_shared_page(struct vm_fault *vmf)
{
	struct vm_area_struct *vma = vmf->vma;
	struct address_space *mapping;
	struct folio *folio = page_folio(vmf->page);
	bool dirtied;
	bool page_mkwrite = vma->vm_ops && vma->vm_ops->page_mkwrite;

	dirtied = folio_mark_dirty(folio);
	VM_BUG_ON_FOLIO(folio_test_anon(folio), folio);
	/*
	 * Take a local copy of the address_space - folio.mapping may be zeroed
	 * by truncate after folio_unlock().   The address_space itself remains
	 * pinned by vma->vm_file's reference.  We rely on folio_unlock()'s
	 * release semantics to prevent the compiler from undoing this copying.
	 */
	mapping = folio_raw_mapping(folio);
	folio_unlock(folio);

	if (!page_mkwrite)
		file_update_time(vma->vm_file);

	/*
	 * Throttle page dirtying rate down to writeback speed.
	 *
	 * mapping may be NULL here because some device drivers do not
	 * set page.mapping but still dirty their pages
	 *
	 * Drop the mmap_lock before waiting on IO, if we can. The file
	 * is pinning the mapping, as per above.
	 */
	if ((dirtied || page_mkwrite) && mapping) {
		struct file *fpin;

		fpin = maybe_unlock_mmap_for_io(vmf, NULL);
		balance_dirty_pages_ratelimited(mapping);
		if (fpin) {
			fput(fpin);
			return VM_FAULT_COMPLETED;
		}
	}

	return 0;
}


static vm_fault_t wp_page_shared(struct vm_fault *vmf, struct folio *folio)
	__releases(vmf->ptl)
{
	struct vm_area_struct *vma = vmf->vma;
	vm_fault_t ret = 0;

	folio_get(folio);

	if (vma->vm_ops && vma->vm_ops->page_mkwrite) {
		vm_fault_t tmp;

		pte_unmap_unlock(vmf->pte, vmf->ptl);
		if (vmf->flags & FAULT_FLAG_VMA_LOCK) {
			folio_put(folio);
			vma_end_read(vmf->vma);
			return VM_FAULT_RETRY;
		}

		tmp = do_page_mkwrite(vmf, folio);
		if (unlikely(!tmp || (tmp &
				      (VM_FAULT_ERROR | VM_FAULT_NOPAGE)))) {
			folio_put(folio);
			return tmp;
		}
		tmp = finish_mkwrite_fault(vmf);
		if (unlikely(tmp & (VM_FAULT_ERROR | VM_FAULT_NOPAGE))) {
			folio_unlock(folio);
			folio_put(folio);
			return tmp;
		}
	} else {
		wp_page_reuse(vmf);
		folio_lock(folio);
	}
	ret |= fault_dirty_shared_page(vmf);
	folio_put(folio);

	return ret;
}


/*
 * Return:
 *	0:		copied succeeded
 *	-EHWPOISON:	copy failed due to hwpoison in source page
 *	-EAGAIN:	copied failed (some other reason)
 */
static inline int __wp_page_copy_user(struct page *dst, struct page *src,
				      struct vm_fault *vmf)
{
	int ret;
	void *kaddr;
	void __user *uaddr;
	struct vm_area_struct *vma = vmf->vma;
	struct mm_struct *mm = vma->vm_mm;
	unsigned long addr = vmf->address;

	if (likely(src)) {
		if (copy_mc_user_highpage(dst, src, addr, vma)) {
			memory_failure_queue(page_to_pfn(src), 0);
			return -EHWPOISON;
		}
		return 0;
	}

	/*
	 * If the source page was a PFN mapping, we don't have
	 * a "struct page" for it. We do a best-effort copy by
	 * just copying from the original user address. If that
	 * fails, we just zero-fill it. Live with it.
	 */
	kaddr = kmap_atomic(dst);
	uaddr = (void __user *)(addr & PAGE_MASK);

	/*
	 * On architectures with software "accessed" bits, we would
	 * take a double page fault, so mark it accessed here.
	 */
	vmf->pte = NULL;
	if (!arch_has_hw_pte_young() && !pte_young(vmf->orig_pte)) {
		pte_t entry;

		vmf->pte = pte_offset_map_lock(mm, vmf->pmd, addr, &vmf->ptl);
		if (unlikely(!vmf->pte || !pte_same(ptep_get(vmf->pte), vmf->orig_pte))) {
			/*
			 * Other thread has already handled the fault
			 * and update local tlb only
			 */
			if (vmf->pte)
				update_mmu_tlb(vma, addr, vmf->pte);
			ret = -EAGAIN;
			goto pte_unlock;
		}

		entry = pte_mkyoung(vmf->orig_pte);
		if (ptep_set_access_flags(vma, addr, vmf->pte, entry, 0))
			update_mmu_cache_range(vmf, vma, addr, vmf->pte, 1);
	}

	/*
	 * This really shouldn't fail, because the page is there
	 * in the page tables. But it might just be unreadable,
	 * in which case we just give up and fill the result with
	 * zeroes.
	 */
	if (__copy_from_user_inatomic(kaddr, uaddr, PAGE_SIZE)) {
		if (vmf->pte)
			goto warn;

		/* Re-validate under PTL if the page is still mapped */
		vmf->pte = pte_offset_map_lock(mm, vmf->pmd, addr, &vmf->ptl);
		if (unlikely(!vmf->pte || !pte_same(ptep_get(vmf->pte), vmf->orig_pte))) {
			/* The PTE changed under us, update local tlb */
			if (vmf->pte)
				update_mmu_tlb(vma, addr, vmf->pte);
			ret = -EAGAIN;
			goto pte_unlock;
		}

		/*
		 * The same page can be mapped back since last copy attempt.
		 * Try to copy again under PTL.
		 */
		if (__copy_from_user_inatomic(kaddr, uaddr, PAGE_SIZE)) {
			/*
			 * Give a warn in case there can be some obscure
			 * use-case
			 */
warn:
			WARN_ON_ONCE(1);
			clear_page(kaddr);
		}
	}

	ret = 0;

pte_unlock:
	if (vmf->pte)
		pte_unmap_unlock(vmf->pte, vmf->ptl);
	kunmap_atomic(kaddr);
	flush_dcache_page(dst);

	return ret;
}


/**
 * vma_alloc_zeroed_movable_folio - Allocate a zeroed page for a VMA.
 * @vma: The VMA the page is to be allocated for.
 * @vaddr: The virtual address the page will be inserted into.
 *
 * This function will allocate a page suitable for inserting into this
 * VMA at this virtual address.  It may be allocated from highmem or
 * the movable zone.  An architecture may provide its own implementation.
 *
 * Return: A folio containing one allocated and zeroed page or NULL if
 * we are out of memory.
 */
extern struct folio *_k_vma_alloc_folio(gfp_t gfp, int order, struct vm_area_struct *vma,
		unsigned long addr, bool hugepage);

KTDEF(__vma_folio_alloc);

static inline
struct folio *vma_alloc_zeroed_movable_folio_internal(struct vm_area_struct *vma,
                                   unsigned long vaddr)
{
	struct folio *folio;
	// folio = vma_alloc_folio(GFP_HIGHUSER_MOVABLE, 0, vma, vaddr, false);
	folio = _k_vma_alloc_folio(GFP_HIGHUSER_MOVABLE, 0, vma, vaddr, false);

	if (folio) {
		clear_user_highpage(&folio->page, vaddr);
	}


	return folio;
}

/*
 * Handle the case of a page which we actually need to copy to a new page,
 * either due to COW or unsharing.
 *
 * Called with mmap_lock locked and the old page referenced, but
 * without the ptl held.
 *
 * High level logic flow:
 *
 * - Allocate a page, copy the content of the old page to the new one.
 * - Handle book keeping and accounting - cgroups, mmu-notifiers, etc.
 * - Take the PTL. If the pte changed, bail out and release the allocated page
 * - If the pte is still the way we remember it, update the page table and all
 *   relevant references. This includes dropping the reference the page-table
 *   held to the old page, as well as updating the rmap.
 * - In any case, unlock the PTL and drop the reference we took to the old page.
 */
static vm_fault_t wp_page_copy(struct vm_fault *vmf)
{
	const bool unshare = vmf->flags & FAULT_FLAG_UNSHARE;
	struct vm_area_struct *vma = vmf->vma;
	struct mm_struct *mm = vma->vm_mm;
	struct folio *old_folio = NULL;
	struct folio *new_folio = NULL;
	pte_t entry;
	int page_copied = 0;
	struct mmu_notifier_range range;
	int ret;

	delayacct_wpcopy_start();

	if (vmf->page)
		old_folio = page_folio(vmf->page);
	if (unlikely(anon_vma_prepare(vma)))
		goto oom;

	if (is_zero_pfn(pte_pfn(vmf->orig_pte))) {
		new_folio = vma_alloc_zeroed_movable_folio(vma, vmf->address);
		if (!new_folio)
			goto oom;
	} else {
		new_folio = vma_alloc_folio(GFP_HIGHUSER_MOVABLE, 0, vma,
				vmf->address, false);
		if (!new_folio)
			goto oom;

		ret = __wp_page_copy_user(&new_folio->page, vmf->page, vmf);
		if (ret) {
			/*
			 * COW failed, if the fault was solved by other,
			 * it's fine. If not, userspace would re-fault on
			 * the same address and we will handle the fault
			 * from the second attempt.
			 * The -EHWPOISON case will not be retried.
			 */
			folio_put(new_folio);
			if (old_folio)
				folio_put(old_folio);

			delayacct_wpcopy_end();
			return ret == -EHWPOISON ? VM_FAULT_HWPOISON : 0;
		}
		kmsan_copy_page_meta(&new_folio->page, vmf->page);
	}

	if (mem_cgroup_charge(new_folio, mm, GFP_KERNEL))
		goto oom_free_new;
	folio_throttle_swaprate(new_folio, GFP_KERNEL);

	__folio_mark_uptodate(new_folio);

	mmu_notifier_range_init(&range, MMU_NOTIFY_CLEAR, 0, mm,
				vmf->address & PAGE_MASK,
				(vmf->address & PAGE_MASK) + PAGE_SIZE);
	mmu_notifier_invalidate_range_start(&range);

	/*
	 * Re-check the pte - we dropped the lock
	 */
	vmf->pte = pte_offset_map_lock(mm, vmf->pmd, vmf->address, &vmf->ptl);
	if (likely(vmf->pte && pte_same(ptep_get(vmf->pte), vmf->orig_pte))) {
		if (old_folio) {
			if (!folio_test_anon(old_folio)) {
				dec_mm_counter(mm, mm_counter_file(&old_folio->page));
				inc_mm_counter(mm, MM_ANONPAGES);
			}
		} else {
			ksm_might_unmap_zero_page(mm, vmf->orig_pte);
			inc_mm_counter(mm, MM_ANONPAGES);
		}
		flush_cache_page(vma, vmf->address, pte_pfn(vmf->orig_pte));
		entry = mk_pte(&new_folio->page, vma->vm_page_prot);
		entry = pte_sw_mkyoung(entry);
		if (unlikely(unshare)) {
			if (pte_soft_dirty(vmf->orig_pte))
				entry = pte_mksoft_dirty(entry);
			if (pte_uffd_wp(vmf->orig_pte))
				entry = pte_mkuffd_wp(entry);
		} else {
			entry = maybe_mkwrite(pte_mkdirty(entry), vma);
		}

		/*
		 * Clear the pte entry and flush it first, before updating the
		 * pte with the new entry, to keep TLBs on different CPUs in
		 * sync. This code used to set the new PTE then flush TLBs, but
		 * that left a window where the new PTE could be loaded into
		 * some TLBs while the old PTE remains in others.
		 */
		ptep_clear_flush(vma, vmf->address, vmf->pte);
		folio_add_new_anon_rmap(new_folio, vma, vmf->address);
		folio_add_lru_vma(new_folio, vma);
		/*
		 * We call the notify macro here because, when using secondary
		 * mmu page tables (such as kvm shadow page tables), we want the
		 * new page to be mapped directly into the secondary page table.
		 */
		BUG_ON(unshare && pte_write(entry));
		set_pte_at_notify(mm, vmf->address, vmf->pte, entry);
		update_mmu_cache_range(vmf, vma, vmf->address, vmf->pte, 1);
		if (old_folio) {
			/*
			 * Only after switching the pte to the new page may
			 * we remove the mapcount here. Otherwise another
			 * process may come and find the rmap count decremented
			 * before the pte is switched to the new page, and
			 * "reuse" the old page writing into it while our pte
			 * here still points into it and can be read by other
			 * threads.
			 *
			 * The critical issue is to order this
			 * page_remove_rmap with the ptp_clear_flush above.
			 * Those stores are ordered by (if nothing else,)
			 * the barrier present in the atomic_add_negative
			 * in page_remove_rmap.
			 *
			 * Then the TLB flush in ptep_clear_flush ensures that
			 * no process can access the old page before the
			 * decremented mapcount is visible. And the old page
			 * cannot be reused until after the decremented
			 * mapcount is visible. So transitively, TLBs to
			 * old page will be flushed before it can be reused.
			 */
			page_remove_rmap(vmf->page, vma, false);
		}

		/* Free the old page.. */
		new_folio = old_folio;
		page_copied = 1;
		pte_unmap_unlock(vmf->pte, vmf->ptl);
	} else if (vmf->pte) {
		update_mmu_tlb(vma, vmf->address, vmf->pte);
		pte_unmap_unlock(vmf->pte, vmf->ptl);
	}

	mmu_notifier_invalidate_range_end(&range);

	if (new_folio)
		folio_put(new_folio);
	if (old_folio) {
		if (page_copied)
			free_swap_cache(&old_folio->page);
		folio_put(old_folio);
	}

	delayacct_wpcopy_end();
	return 0;
oom_free_new:
	folio_put(new_folio);
oom:
	if (old_folio)
		folio_put(old_folio);

	delayacct_wpcopy_end();
	return VM_FAULT_OOM;
}


/*
 * This routine handles present pages, when
 * * users try to write to a shared page (FAULT_FLAG_WRITE)
 * * GUP wants to take a R/O pin on a possibly shared anonymous page
 *   (FAULT_FLAG_UNSHARE)
 *
 * It is done by copying the page to a new address and decrementing the
 * shared-page counter for the old page.
 *
 * Note that this routine assumes that the protection checks have been
 * done by the caller (the low-level page fault routine in most cases).
 * Thus, with FAULT_FLAG_WRITE, we can safely just mark it writable once we've
 * done any necessary COW.
 *
 * In case of FAULT_FLAG_WRITE, we also mark the page dirty at this point even
 * though the page will change only once the write actually happens. This
 * avoids a few races, and potentially makes it more efficient.
 *
 * We enter with non-exclusive mmap_lock (to exclude vma changes,
 * but allow concurrent faults), with pte both mapped and locked.
 * We return with mmap_lock still held, but pte unmapped and unlocked.
 */
static vm_fault_t do_wp_page(struct vm_fault *vmf)
	__releases(vmf->ptl)
{
	const bool unshare = vmf->flags & FAULT_FLAG_UNSHARE;
	struct vm_area_struct *vma = vmf->vma;
	struct folio *folio = NULL;

	if (likely(!unshare)) {
		if (userfaultfd_pte_wp(vma, ptep_get(vmf->pte))) {
			pte_unmap_unlock(vmf->pte, vmf->ptl);
			return handle_userfault(vmf, VM_UFFD_WP);
		}

		/*
		 * Userfaultfd write-protect can defer flushes. Ensure the TLB
		 * is flushed in this case before copying.
		 */
		if (unlikely(userfaultfd_wp(vmf->vma) &&
			     mm_tlb_flush_pending(vmf->vma->vm_mm)))
			flush_tlb_page(vmf->vma, vmf->address);
	}

	vmf->page = vm_normal_page(vma, vmf->address, vmf->orig_pte);

	if (vmf->page)
		folio = page_folio(vmf->page);

	/*
	 * Shared mapping: we are guaranteed to have VM_WRITE and
	 * FAULT_FLAG_WRITE set at this point.
	 */
	if (vma->vm_flags & (VM_SHARED | VM_MAYSHARE)) {
		/*
		 * VM_MIXEDMAP !pfn_valid() case, or VM_SOFTDIRTY clear on a
		 * VM_PFNMAP VMA.
		 *
		 * We should not cow pages in a shared writeable mapping.
		 * Just mark the pages writable and/or call ops->pfn_mkwrite.
		 */
		if (!vmf->page)
			return wp_pfn_shared(vmf);
		return wp_page_shared(vmf, folio);
	}

	/*
	 * Private mapping: create an exclusive anonymous page copy if reuse
	 * is impossible. We might miss VM_WRITE for FOLL_FORCE handling.
	 */
	if (folio && folio_test_anon(folio)) {
		/*
		 * If the page is exclusive to this process we must reuse the
		 * page without further checks.
		 */
		if (PageAnonExclusive(vmf->page))
			goto reuse;

		/*
		 * We have to verify under folio lock: these early checks are
		 * just an optimization to avoid locking the folio and freeing
		 * the swapcache if there is little hope that we can reuse.
		 *
		 * KSM doesn't necessarily raise the folio refcount.
		 */
		if (folio_test_ksm(folio) || folio_ref_count(folio) > 3)
			goto copy;
		if (!folio_test_lru(folio))
			/*
			 * We cannot easily detect+handle references from
			 * remote LRU caches or references to LRU folios.
			 */
			lru_add_drain();
		if (folio_ref_count(folio) > 1 + folio_test_swapcache(folio))
			goto copy;
		if (!folio_trylock(folio))
			goto copy;
		if (folio_test_swapcache(folio))
			folio_free_swap(folio);
		if (folio_test_ksm(folio) || folio_ref_count(folio) != 1) {
			folio_unlock(folio);
			goto copy;
		}
		/*
		 * Ok, we've got the only folio reference from our mapping
		 * and the folio is locked, it's dark out, and we're wearing
		 * sunglasses. Hit it.
		 */
		page_move_anon_rmap(vmf->page, vma);
		folio_unlock(folio);
reuse:
		if (unlikely(unshare)) {
			pte_unmap_unlock(vmf->pte, vmf->ptl);
			return 0;
		}
		wp_page_reuse(vmf);
		return 0;
	}
copy:
	if ((vmf->flags & FAULT_FLAG_VMA_LOCK) && !vma->anon_vma) {
		pte_unmap_unlock(vmf->pte, vmf->ptl);
		vma_end_read(vmf->vma);
		return VM_FAULT_RETRY;
	}

	/*
	 * Ok, we need to copy. Oh, well..
	 */
	if (folio)
		folio_get(folio);

	pte_unmap_unlock(vmf->pte, vmf->ptl);
#ifdef CONFIG_KSM
	if (folio && folio_test_ksm(folio))
		count_vm_event(COW_KSM);
#endif
	return wp_page_copy(vmf);
}


/*
 * Return true if the original pte was a uffd-wp pte marker (so the pte was
 * wr-protected).
 */
static bool vmf_orig_pte_uffd_wp(struct vm_fault *vmf)
{
	if (!(vmf->flags & FAULT_FLAG_ORIG_PTE_VALID))
		return false;

	return pte_marker_uffd_wp(vmf->orig_pte);
}


static bool vmf_pte_changed(struct vm_fault *vmf)
{
	if (vmf->flags & FAULT_FLAG_ORIG_PTE_VALID)
		return !pte_same(ptep_get(vmf->pte), vmf->orig_pte);

	return !pte_none(ptep_get(vmf->pte));
}

void pmd_install(struct mm_struct *mm, pmd_t *pmd, pgtable_t *pte)
{
	spinlock_t *ptl = pmd_lock(mm, pmd);

	if (likely(pmd_none(*pmd))) {	/* Has another populated it ? */
		mm_inc_nr_ptes(mm);
		/*
		 * Ensure all pte setup (eg. pte page lock and page clearing) are
		 * visible before the pte is made visible to other CPUs by being
		 * put into page tables.
		 *
		 * The other side of the story is the pointer chasing in the page
		 * table walking code (when walking the page table without locking;
		 * ie. most of the time). Fortunately, these data accesses consist
		 * of a chain of data-dependent loads, meaning most CPUs (alpha
		 * being the notable exception) will already guarantee loads are
		 * seen in-order. See the alpha page table accessors for the
		 * smp_rmb() barriers in page table walking code.
		 */
		smp_wmb(); /* Could be smp_wmb__xxx(before|after)_spin_lock */
		pmd_populate(mm, pmd, *pte);
		*pte = NULL;
	}
	spin_unlock(ptl);
}

extern struct page *_k_alloc_pages(gfp_t gfp, unsigned order);
static inline struct ptdesc *_k_pagetable_alloc(gfp_t gfp, unsigned int order)
{       
        struct page *page = _k_alloc_pages(gfp | __GFP_COMP, order);
                
        return page_ptdesc(page);
} 

static inline pgtable_t _k___pte_alloc_one(struct mm_struct *mm, gfp_t gfp)
{
        struct ptdesc *ptdesc;

        ptdesc = _k_pagetable_alloc(gfp, 0);
        if (!ptdesc)
                return NULL;
        if (!pagetable_pte_ctor(ptdesc)) {
                pagetable_free(ptdesc);
                return NULL;
        }

        return ptdesc_page(ptdesc);
}

pgtable_t _k_pte_alloc_one(struct mm_struct *mm)
{       
        return _k___pte_alloc_one(mm, __userpte_alloc_gfp);
}

KTDEF(pte_alloc_one);
int _k__pte_alloc(struct mm_struct *mm, pmd_t *pmd)
{ 
        pgtable_t new = _k_pte_alloc_one(mm);
        if (!new) {
			return -ENOMEM;
		}

        pmd_install(mm, pmd, &new);
        if (new) 
                pte_free(mm, new);

        return 0;
}


/*
 * We enter with non-exclusive mmap_lock (to exclude vma changes,
 * but allow concurrent faults), and pte mapped but not yet locked.
 * We return with mmap_lock still held, but pte unmapped and unlocked.
 */
KTDEF(vma_alloc_zeroed_movable_folio);
KTDEF(__pte_alloc);
static vm_fault_t do_anonymous_page(struct vm_fault *vmf)
{
	ktime_t __pte_alloc_watch[2];
	bool uffd_wp = vmf_orig_pte_uffd_wp(vmf);
	struct vm_area_struct *vma = vmf->vma;
	struct folio *folio;
	vm_fault_t ret = 0;
	pte_t entry;

	/* File mapping without ->vm_ops ? */
	if (vma->vm_flags & VM_SHARED) {
		return VM_FAULT_SIGBUS;
	}

	/*
	 * Use pte_alloc() instead of pte_alloc_map(), so that OOM can
	 * be distinguished from a transient failure of pte_offset_map().
	 */
	if (_k__pte_alloc(vma->vm_mm, vmf->pmd)) {
		return VM_FAULT_OOM;
	}

	/* Use the zero-page for reads */

	if (!(vmf->flags & FAULT_FLAG_WRITE) &&
			!mm_forbids_zeropage(vma->vm_mm)) {
// 일단 이 영역은 아님. (=> 해당 if문)
		entry = pte_mkspecial(pfn_pte(my_zero_pfn(vmf->address),
						vma->vm_page_prot));
		vmf->pte = pte_offset_map_lock(vma->vm_mm, vmf->pmd,
				vmf->address, &vmf->ptl);
		if (!vmf->pte) {

			goto unlock;
		}
		if (vmf_pte_changed(vmf)) {
			update_mmu_tlb(vma, vmf->address, vmf->pte);
			goto unlock;
		}
		ret = check_stable_address_space(vma->vm_mm);
		if (ret) {
			goto unlock;
		}
		/* Deliver the page fault to userland, check inside PT lock */
		if (userfaultfd_missing(vma)) {
			pte_unmap_unlock(vmf->pte, vmf->ptl);
			vm_fault_t cur_ret = handle_userfault(vmf, VM_UFFD_MISSING);
			return cur_ret;
		}
		goto setpte;
	}

	/* Allocate our own private page. */
	if (unlikely(anon_vma_prepare(vma)))  {
		goto oom;
	} 


	folio = vma_alloc_zeroed_movable_folio_internal(vma, vmf->address); // 유력 후보

	if (!folio)
		goto oom;

	if (mem_cgroup_charge(folio, vma->vm_mm, GFP_KERNEL)) {
		goto oom_free_page;
	}
		
	folio_throttle_swaprate(folio, GFP_KERNEL);

	/*
	 * The memory barrier inside __folio_mark_uptodate makes sure that
	 * preceding stores to the page contents become visible before
	 * the set_pte_at() write.
	 */
	__folio_mark_uptodate(folio);

	entry = mk_pte(&folio->page, vma->vm_page_prot);
	entry = pte_sw_mkyoung(entry);
	if (vma->vm_flags & VM_WRITE)
		entry = pte_mkwrite(pte_mkdirty(entry), vma);
	vmf->pte = pte_offset_map_lock(vma->vm_mm, vmf->pmd, vmf->address,
			&vmf->ptl);
	if (!vmf->pte) {
		goto release;
	}
	if (vmf_pte_changed(vmf)) {
		update_mmu_tlb(vma, vmf->address, vmf->pte);
		goto release;
	}

	ret = check_stable_address_space(vma->vm_mm);
	if (ret) {
		goto release;
	}

	/* Deliver the page fault to userland, check inside PT lock */
	if (userfaultfd_missing(vma)) {
		pte_unmap_unlock(vmf->pte, vmf->ptl);
		folio_put(folio);
		vm_fault_t ret_handle_userfault = handle_userfault(vmf, VM_UFFD_MISSING);
		return ret_handle_userfault;
	}

// 여긴 3~4퍼
	inc_mm_counter(vma->vm_mm, MM_ANONPAGES);
	folio_add_new_anon_rmap(folio, vma, vmf->address);
	folio_add_lru_vma(folio, vma);
// ===
setpte:
	if (uffd_wp)
		entry = pte_mkuffd_wp(entry);
	set_pte_at(vma->vm_mm, vmf->address, vmf->pte, entry);

	/* No need to invalidate - it was non-present before */
	update_mmu_cache_range(vmf, vma, vmf->address, vmf->pte, 1);
unlock:
	if (vmf->pte)
		pte_unmap_unlock(vmf->pte, vmf->ptl);
	return ret;
release:
	folio_put(folio);
	goto unlock;
oom_free_page:
	folio_put(folio);
oom:
	return VM_FAULT_OOM;
}


/*
 * The mmap_lock must have been held on entry, and may have been
 * released depending on flags and vma->vm_ops->fault() return value.
 * See filemap_fault() and __lock_page_retry().
 */
static vm_fault_t __do_fault(struct vm_fault *vmf)
{
	struct vm_area_struct *vma = vmf->vma;
	vm_fault_t ret;

	/*
	 * Preallocate pte before we take page_lock because this might lead to
	 * deadlocks for memcg reclaim which waits for pages under writeback:
	 *				lock_page(A)
	 *				SetPageWriteback(A)
	 *				unlock_page(A)
	 * lock_page(B)
	 *				lock_page(B)
	 * pte_alloc_one
	 *   shrink_page_list
	 *     wait_on_page_writeback(A)
	 *				SetPageWriteback(B)
	 *				unlock_page(B)
	 *				# flush A, B to clear the writeback
	 */
	if (pmd_none(*vmf->pmd) && !vmf->prealloc_pte) {
		vmf->prealloc_pte = pte_alloc_one(vma->vm_mm);
		if (!vmf->prealloc_pte)
			return VM_FAULT_OOM;
	}

	ret = vma->vm_ops->fault(vmf);
	if (unlikely(ret & (VM_FAULT_ERROR | VM_FAULT_NOPAGE | VM_FAULT_RETRY |
			    VM_FAULT_DONE_COW)))
		return ret;

	if (unlikely(PageHWPoison(vmf->page))) {
		struct page *page = vmf->page;
		vm_fault_t poisonret = VM_FAULT_HWPOISON;
		if (ret & VM_FAULT_LOCKED) {
			if (page_mapped(page))
				unmap_mapping_pages(page_mapping(page),
						    page->index, 1, false);
			/* Retry if a clean page was removed from the cache. */
			if (invalidate_inode_page(page))
				poisonret = VM_FAULT_NOPAGE;
			unlock_page(page);
		}
		put_page(page);
		vmf->page = NULL;
		return poisonret;
	}

	if (unlikely(!(ret & VM_FAULT_LOCKED)))
		lock_page(vmf->page);
	else
		VM_BUG_ON_PAGE(!PageLocked(vmf->page), vmf->page);

	return ret;
}


static unsigned long fault_around_pages __read_mostly =
	65536 >> PAGE_SHIFT;


/* Return true if we should do read fault-around, false otherwise */
static inline bool should_fault_around(struct vm_fault *vmf)
{
	/* No ->map_pages?  No way to fault around... */
	if (!vmf->vma->vm_ops->map_pages)
		return false;

	if (uffd_disable_fault_around(vmf->vma))
		return false;

	/* A single page implies no faulting 'around' at all. */
	return fault_around_pages > 1;
}


/*
 * do_fault_around() tries to map few pages around the fault address. The hope
 * is that the pages will be needed soon and this will lower the number of
 * faults to handle.
 *
 * It uses vm_ops->map_pages() to map the pages, which skips the page if it's
 * not ready to be mapped: not up-to-date, locked, etc.
 *
 * This function doesn't cross VMA or page table boundaries, in order to call
 * map_pages() and acquire a PTE lock only once.
 *
 * fault_around_pages defines how many pages we'll try to map.
 * do_fault_around() expects it to be set to a power of two less than or equal
 * to PTRS_PER_PTE.
 *
 * The virtual address of the area that we map is naturally aligned to
 * fault_around_pages * PAGE_SIZE rounded down to the machine page size
 * (and therefore to page order).  This way it's easier to guarantee
 * that we don't cross page table boundaries.
 */
static vm_fault_t do_fault_around(struct vm_fault *vmf)
{
	pgoff_t nr_pages = READ_ONCE(fault_around_pages);
	pgoff_t pte_off = pte_index(vmf->address);
	/* The page offset of vmf->address within the VMA. */
	pgoff_t vma_off = vmf->pgoff - vmf->vma->vm_pgoff;
	pgoff_t from_pte, to_pte;
	vm_fault_t ret;

	/* The PTE offset of the start address, clamped to the VMA. */
	from_pte = max(ALIGN_DOWN(pte_off, nr_pages),
		       pte_off - min(pte_off, vma_off));

	/* The PTE offset of the end address, clamped to the VMA and PTE. */
	to_pte = min3(from_pte + nr_pages, (pgoff_t)PTRS_PER_PTE,
		      pte_off + vma_pages(vmf->vma) - vma_off) - 1;

	if (pmd_none(*vmf->pmd)) {
		vmf->prealloc_pte = pte_alloc_one(vmf->vma->vm_mm);
		if (!vmf->prealloc_pte)
			return VM_FAULT_OOM;
	}

	rcu_read_lock();
	ret = vmf->vma->vm_ops->map_pages(vmf,
			vmf->pgoff + from_pte - pte_off,
			vmf->pgoff + to_pte - pte_off);
	rcu_read_unlock();

	return ret;
}



static vm_fault_t do_read_fault(struct vm_fault *vmf)
{
	vm_fault_t ret = 0;
	struct folio *folio;

	/*
	 * Let's call ->map_pages() first and use ->fault() as fallback
	 * if page by the offset is not ready to be mapped (cold cache or
	 * something).
	 */
	if (should_fault_around(vmf)) {
		ret = do_fault_around(vmf);
		if (ret)
			return ret;
	}

	if (vmf->flags & FAULT_FLAG_VMA_LOCK) {
		vma_end_read(vmf->vma);
		return VM_FAULT_RETRY;
	}

	ret = __do_fault(vmf);
	if (unlikely(ret & (VM_FAULT_ERROR | VM_FAULT_NOPAGE | VM_FAULT_RETRY)))
		return ret;

	ret |= finish_fault(vmf);
	folio = page_folio(vmf->page);
	folio_unlock(folio);
	if (unlikely(ret & (VM_FAULT_ERROR | VM_FAULT_NOPAGE | VM_FAULT_RETRY)))
		folio_put(folio);
	return ret;
}


static vm_fault_t do_cow_fault(struct vm_fault *vmf)
{
	struct vm_area_struct *vma = vmf->vma;
	vm_fault_t ret;

	if (vmf->flags & FAULT_FLAG_VMA_LOCK) {
		vma_end_read(vma);
		return VM_FAULT_RETRY;
	}

	if (unlikely(anon_vma_prepare(vma)))
		return VM_FAULT_OOM;

	vmf->cow_page = alloc_page_vma(GFP_HIGHUSER_MOVABLE, vma, vmf->address);
	if (!vmf->cow_page)
		return VM_FAULT_OOM;

	if (mem_cgroup_charge(page_folio(vmf->cow_page), vma->vm_mm,
				GFP_KERNEL)) {
		put_page(vmf->cow_page);
		return VM_FAULT_OOM;
	}
	folio_throttle_swaprate(page_folio(vmf->cow_page), GFP_KERNEL);

	ret = __do_fault(vmf);
	if (unlikely(ret & (VM_FAULT_ERROR | VM_FAULT_NOPAGE | VM_FAULT_RETRY)))
		goto uncharge_out;
	if (ret & VM_FAULT_DONE_COW)
		return ret;

	copy_user_highpage(vmf->cow_page, vmf->page, vmf->address, vma);
	__SetPageUptodate(vmf->cow_page);

	ret |= finish_fault(vmf);
	unlock_page(vmf->page);
	put_page(vmf->page);
	if (unlikely(ret & (VM_FAULT_ERROR | VM_FAULT_NOPAGE | VM_FAULT_RETRY)))
		goto uncharge_out;
	return ret;
uncharge_out:
	put_page(vmf->cow_page);
	return ret;
}


static vm_fault_t do_shared_fault(struct vm_fault *vmf)
{
	struct vm_area_struct *vma = vmf->vma;
	vm_fault_t ret, tmp;
	struct folio *folio;

	if (vmf->flags & FAULT_FLAG_VMA_LOCK) {
		vma_end_read(vma);
		return VM_FAULT_RETRY;
	}

	ret = __do_fault(vmf);
	if (unlikely(ret & (VM_FAULT_ERROR | VM_FAULT_NOPAGE | VM_FAULT_RETRY)))
		return ret;

	folio = page_folio(vmf->page);

	/*
	 * Check if the backing address space wants to know that the page is
	 * about to become writable
	 */
	if (vma->vm_ops->page_mkwrite) {
		folio_unlock(folio);
		tmp = do_page_mkwrite(vmf, folio);
		if (unlikely(!tmp ||
				(tmp & (VM_FAULT_ERROR | VM_FAULT_NOPAGE)))) {
			folio_put(folio);
			return tmp;
		}
	}

	ret |= finish_fault(vmf);
	if (unlikely(ret & (VM_FAULT_ERROR | VM_FAULT_NOPAGE |
					VM_FAULT_RETRY))) {
		folio_unlock(folio);
		folio_put(folio);
		return ret;
	}

	ret |= fault_dirty_shared_page(vmf);
	return ret;
}


/*
 * We enter with non-exclusive mmap_lock (to exclude vma changes,
 * but allow concurrent faults).
 * The mmap_lock may have been released depending on flags and our
 * return value.  See filemap_fault() and __folio_lock_or_retry().
 * If mmap_lock is released, vma may become invalid (for example
 * by other thread calling munmap()).
 */
static vm_fault_t do_fault(struct vm_fault *vmf)
{
	struct vm_area_struct *vma = vmf->vma;
	struct mm_struct *vm_mm = vma->vm_mm;
	vm_fault_t ret;

	/*
	 * The VMA was not fully populated on mmap() or missing VM_DONTEXPAND
	 */
	if (!vma->vm_ops->fault) {
		vmf->pte = pte_offset_map_lock(vmf->vma->vm_mm, vmf->pmd,
					       vmf->address, &vmf->ptl);
		if (unlikely(!vmf->pte))
			ret = VM_FAULT_SIGBUS;
		else {
			/*
			 * Make sure this is not a temporary clearing of pte
			 * by holding ptl and checking again. A R/M/W update
			 * of pte involves: take ptl, clearing the pte so that
			 * we don't have concurrent modification by hardware
			 * followed by an update.
			 */
			if (unlikely(pte_none(ptep_get(vmf->pte))))
				ret = VM_FAULT_SIGBUS;
			else
				ret = VM_FAULT_NOPAGE;

			pte_unmap_unlock(vmf->pte, vmf->ptl);
		}
	} else if (!(vmf->flags & FAULT_FLAG_WRITE))
		ret = do_read_fault(vmf);
	else if (!(vma->vm_flags & VM_SHARED))
		ret = do_cow_fault(vmf);
	else
		ret = do_shared_fault(vmf);

	/* preallocated pagetable is unused: free it */
	if (vmf->prealloc_pte) {
		pte_free(vm_mm, vmf->prealloc_pte);
		vmf->prealloc_pte = NULL;
	}
	return ret;
}

KTDEF(do_anonymous_page);
static vm_fault_t do_pte_missing_internal(struct vm_fault *vmf)
{
	vm_fault_t ret;

	if (vma_is_anonymous(vmf->vma)) {
		ret = do_anonymous_page(vmf);
	}
	else 
		ret = do_fault(vmf);

	return ret;
}

KTDEF(do_pte_missing);
static vm_fault_t do_pte_missing(struct vm_fault *vmf)
{
	vm_fault_t ret;


	ret = do_pte_missing_internal(vmf);


	return ret;
}


static gfp_t __get_fault_gfp_mask(struct vm_area_struct *vma)
{
	struct file *vm_file = vma->vm_file;

	if (vm_file)
		return mapping_gfp_mask(vm_file->f_mapping) | __GFP_FS | __GFP_IO;

	/*
	 * Special mappings (e.g. VDSO) do not have any file so fake
	 * a default GFP_KERNEL for them.
	 */
	return GFP_KERNEL;
}

int numa_migrate_prep(struct page *page, struct vm_area_struct *vma,
		      unsigned long addr, int page_nid, int *flags)
{
	get_page(page);

	/* Record the current PID acceesing VMA */
	vma_set_access_pid_bit(vma);

	count_vm_numa_event(NUMA_HINT_FAULTS);
	if (page_nid == numa_node_id()) {
		count_vm_numa_event(NUMA_HINT_FAULTS_LOCAL);
		*flags |= TNF_FAULT_LOCAL;
	}

	return mpol_misplaced(page, vma, addr);
}


static vm_fault_t do_numa_page(struct vm_fault *vmf)
{
	struct vm_area_struct *vma = vmf->vma;
	struct page *page = NULL;
	int page_nid = NUMA_NO_NODE;
	bool writable = false;
	int last_cpupid;
	int target_nid;
	pte_t pte, old_pte;
	int flags = 0;

	/*
	 * The "pte" at this point cannot be used safely without
	 * validation through pte_unmap_same(). It's of NUMA type but
	 * the pfn may be screwed if the read is non atomic.
	 */
	spin_lock(vmf->ptl);
	if (unlikely(!pte_same(ptep_get(vmf->pte), vmf->orig_pte))) {
		pte_unmap_unlock(vmf->pte, vmf->ptl);
		goto out;
	}

	/* Get the normal PTE  */
	old_pte = ptep_get(vmf->pte);
	pte = pte_modify(old_pte, vma->vm_page_prot);

	/*
	 * Detect now whether the PTE could be writable; this information
	 * is only valid while holding the PT lock.
	 */
	writable = pte_write(pte);
	if (!writable && vma_wants_manual_pte_write_upgrade(vma) &&
	    can_change_pte_writable(vma, vmf->address, pte))
		writable = true;

	page = vm_normal_page(vma, vmf->address, pte);
	if (!page || is_zone_device_page(page))
		goto out_map;

	/* TODO: handle PTE-mapped THP */
	if (PageCompound(page))
		goto out_map;

	/*
	 * Avoid grouping on RO pages in general. RO pages shouldn't hurt as
	 * much anyway since they can be in shared cache state. This misses
	 * the case where a mapping is writable but the process never writes
	 * to it but pte_write gets cleared during protection updates and
	 * pte_dirty has unpredictable behaviour between PTE scan updates,
	 * background writeback, dirty balancing and application behaviour.
	 */
	if (!writable)
		flags |= TNF_NO_GROUP;

	/*
	 * Flag if the page is shared between multiple address spaces. This
	 * is later used when determining whether to group tasks together
	 */
	if (page_mapcount(page) > 1 && (vma->vm_flags & VM_SHARED))
		flags |= TNF_SHARED;

	page_nid = page_to_nid(page);
	/*
	 * For memory tiering mode, cpupid of slow memory page is used
	 * to record page access time.  So use default value.
	 */
	if ((sysctl_numa_balancing_mode & NUMA_BALANCING_MEMORY_TIERING) &&
	    !node_is_toptier(page_nid))
		last_cpupid = (-1 & LAST_CPUPID_MASK);
	else
		last_cpupid = page_cpupid_last(page);
	target_nid = numa_migrate_prep(page, vma, vmf->address, page_nid,
			&flags);
	if (target_nid == NUMA_NO_NODE) {
		put_page(page);
		goto out_map;
	}
	pte_unmap_unlock(vmf->pte, vmf->ptl);
	writable = false;

	/* Migrate to the requested node */
	if (migrate_misplaced_page(page, vma, target_nid)) {
		page_nid = target_nid;
		flags |= TNF_MIGRATED;
	} else {
		flags |= TNF_MIGRATE_FAIL;
		vmf->pte = pte_offset_map_lock(vma->vm_mm, vmf->pmd,
					       vmf->address, &vmf->ptl);
		if (unlikely(!vmf->pte))
			goto out;
		if (unlikely(!pte_same(ptep_get(vmf->pte), vmf->orig_pte))) {
			pte_unmap_unlock(vmf->pte, vmf->ptl);
			goto out;
		}
		goto out_map;
	}

out:
	if (page_nid != NUMA_NO_NODE)
		task_numa_fault(last_cpupid, page_nid, 1, flags);
	return 0;
out_map:
	/*
	 * Make it present again, depending on how arch implements
	 * non-accessible ptes, some can allow access by kernel mode.
	 */
	old_pte = ptep_modify_prot_start(vma, vmf->address, vmf->pte);
	pte = pte_modify(old_pte, vma->vm_page_prot);
	pte = pte_mkyoung(pte);
	if (writable)
		pte = pte_mkwrite(pte, vma);
	ptep_modify_prot_commit(vma, vmf->address, vmf->pte, old_pte, pte);
	update_mmu_cache_range(vmf, vma, vmf->address, vmf->pte, 1);
	pte_unmap_unlock(vmf->pte, vmf->ptl);
	goto out;
}


static vm_fault_t create_huge_pud(struct vm_fault *vmf)
{
#if defined(CONFIG_TRANSPARENT_HUGEPAGE) &&			\
	defined(CONFIG_HAVE_ARCH_TRANSPARENT_HUGEPAGE_PUD)
	struct vm_area_struct *vma = vmf->vma;
	/* No support for anonymous transparent PUD pages yet */
	if (vma_is_anonymous(vma))
		return VM_FAULT_FALLBACK;
	if (vma->vm_ops->huge_fault)
		return vma->vm_ops->huge_fault(vmf, PUD_ORDER);
#endif /* CONFIG_TRANSPARENT_HUGEPAGE */
	return VM_FAULT_FALLBACK;
}

/* `inline' is required to avoid gcc 4.1.2 build error */
static inline vm_fault_t wp_huge_pmd(struct vm_fault *vmf)
{
	struct vm_area_struct *vma = vmf->vma;
	const bool unshare = vmf->flags & FAULT_FLAG_UNSHARE;
	vm_fault_t ret;

	if (vma_is_anonymous(vma)) {
		if (likely(!unshare) &&
		    userfaultfd_huge_pmd_wp(vma, vmf->orig_pmd))
			return handle_userfault(vmf, VM_UFFD_WP);
		return do_huge_pmd_wp_page(vmf);
	}

	if (vma->vm_flags & (VM_SHARED | VM_MAYSHARE)) {
		if (vma->vm_ops->huge_fault) {
			ret = vma->vm_ops->huge_fault(vmf, PMD_ORDER);
			if (!(ret & VM_FAULT_FALLBACK))
				return ret;
		}
	}

	/* COW or write-notify handled on pte level: split pmd. */
	__split_huge_pmd(vma, vmf->pmd, vmf->address, false, NULL);

	return VM_FAULT_FALLBACK;
}

static inline bool should_try_to_free_swap(struct folio *folio,
					   struct vm_area_struct *vma,
					   unsigned int fault_flags)
{
	if (!folio_test_swapcache(folio))
		return false;
	if ((vma->vm_flags & VM_LOCKED) || folio_test_mlocked(folio) ||
	    mem_cgroup_swap_full(folio)) 
		return true;
	/*
	 * If we want to map a page that's in the swapcache writable, we
	 * have to detect via the refcount if we're really the exclusive
	 * user. Try freeing the swapcache to get rid of the swapcache
	 * reference only in case it's likely that we'll be the exlusive user.
	 */
	return (fault_flags & FAULT_FLAG_WRITE) && !folio_test_ksm(folio) &&
		folio_ref_count(folio) == 2;
}

/*
 * This function is called to print an error when a bad pte
 * is found. For example, we might have a PFN-mapped pte in
 * a region that doesn't allow it.
 *
 * The calling function must still handle the error.
 */
static void print_bad_pte(struct vm_area_struct *vma, unsigned long addr,
			  pte_t pte, struct page *page)
{
	pgd_t *pgd = pgd_offset(vma->vm_mm, addr);
	p4d_t *p4d = p4d_offset(pgd, addr);
	pud_t *pud = pud_offset(p4d, addr);
	pmd_t *pmd = pmd_offset(pud, addr);
	struct address_space *mapping;
	pgoff_t index;
	static unsigned long resume;
	static unsigned long nr_shown;
	static unsigned long nr_unshown;

	/*
	 * Allow a burst of 60 reports, then keep quiet for that minute;
	 * or allow a steady drip of one report per second.
	 */
	if (nr_shown == 60) {
		if (time_before(jiffies, resume)) {
			nr_unshown++;
			return;
		}
		if (nr_unshown) {
			pr_alert("BUG: Bad page map: %lu messages suppressed\n",
				 nr_unshown);
			nr_unshown = 0;
		}
		nr_shown = 0;
	}
	if (nr_shown++ == 0)
		resume = jiffies + 60 * HZ;

	mapping = vma->vm_file ? vma->vm_file->f_mapping : NULL;
	index = linear_page_index(vma, addr);

	pr_alert("BUG: Bad page map in process %s  pte:%08llx pmd:%08llx\n",
		 current->comm,
		 (long long)pte_val(pte), (long long)pmd_val(*pmd));
	if (page)
		dump_page(page, "bad pte");
	pr_alert("addr:%px vm_flags:%08lx anon_vma:%px mapping:%px index:%lx\n",
		 (void *)addr, vma->vm_flags, vma->anon_vma, mapping, index);
	pr_alert("file:%pD fault:%ps mmap:%ps read_folio:%ps\n",
		 vma->vm_file,
		 vma->vm_ops ? vma->vm_ops->fault : NULL,
		 vma->vm_file ? vma->vm_file->f_op->mmap : NULL,
		 mapping ? mapping->a_ops->read_folio : NULL);
	dump_stack();
	add_taint(TAINT_BAD_PAGE, LOCKDEP_NOW_UNRELIABLE);
}

static vm_fault_t pte_marker_clear(struct vm_fault *vmf)
{
	vmf->pte = pte_offset_map_lock(vmf->vma->vm_mm, vmf->pmd,
				       vmf->address, &vmf->ptl);
	if (!vmf->pte)
		return 0;
	/*
	 * Be careful so that we will only recover a special uffd-wp pte into a
	 * none pte.  Otherwise it means the pte could have changed, so retry.
	 *
	 * This should also cover the case where e.g. the pte changed
	 * quickly from a PTE_MARKER_UFFD_WP into PTE_MARKER_POISONED.
	 * So is_pte_marker() check is not enough to safely drop the pte.
	 */
	if (pte_same(vmf->orig_pte, ptep_get(vmf->pte)))
		pte_clear(vmf->vma->vm_mm, vmf->address, vmf->pte);
	pte_unmap_unlock(vmf->pte, vmf->ptl);
	return 0;
}

/*
 * This is actually a page-missing access, but with uffd-wp special pte
 * installed.  It means this pte was wr-protected before being unmapped.
 */
static vm_fault_t pte_marker_handle_uffd_wp(struct vm_fault *vmf)
{
	/*
	 * Just in case there're leftover special ptes even after the region
	 * got unregistered - we can simply clear them.
	 */
	if (unlikely(!userfaultfd_wp(vmf->vma)))
		return pte_marker_clear(vmf);

	return do_pte_missing(vmf);
}

static vm_fault_t handle_pte_marker(struct vm_fault *vmf)
{
	swp_entry_t entry = pte_to_swp_entry(vmf->orig_pte);
	unsigned long marker = pte_marker_get(entry);

	/*
	 * PTE markers should never be empty.  If anything weird happened,
	 * the best thing to do is to kill the process along with its mm.
	 */
	if (WARN_ON_ONCE(!marker))
		return VM_FAULT_SIGBUS;

	/* Higher priority than uffd-wp when data corrupted */
	if (marker & PTE_MARKER_POISONED)
		return VM_FAULT_HWPOISON;

	if (pte_marker_entry_uffd_wp(entry))
		return pte_marker_handle_uffd_wp(vmf);

	/* This is an unknown pte marker */
	return VM_FAULT_SIGBUS;
}

static void restore_exclusive_pte(struct vm_area_struct *vma,
				  struct page *page, unsigned long address,
				  pte_t *ptep)
{
	pte_t orig_pte;
	pte_t pte;
	swp_entry_t entry;

	orig_pte = ptep_get(ptep);
	pte = pte_mkold(mk_pte(page, READ_ONCE(vma->vm_page_prot)));
	if (pte_swp_soft_dirty(orig_pte))
		pte = pte_mksoft_dirty(pte);

	entry = pte_to_swp_entry(orig_pte);
	if (pte_swp_uffd_wp(orig_pte))
		pte = pte_mkuffd_wp(pte);
	else if (is_writable_device_exclusive_entry(entry))
		pte = maybe_mkwrite(pte_mkdirty(pte), vma);

	VM_BUG_ON(pte_write(pte) && !(PageAnon(page) && PageAnonExclusive(page)));

	/*
	 * No need to take a page reference as one was already
	 * created when the swap entry was made.
	 */
	if (PageAnon(page))
		page_add_anon_rmap(page, vma, address, RMAP_NONE);
	else
		/*
		 * Currently device exclusive access only supports anonymous
		 * memory so the entry shouldn't point to a filebacked page.
		 */
		WARN_ON_ONCE(1);

	set_pte_at(vma->vm_mm, address, ptep, pte);

	/*
	 * No need to invalidate - it was non-present before. However
	 * secondary CPUs may have mappings that need invalidating.
	 */
	update_mmu_cache(vma, address, ptep);
}

/*
 * Restore a potential device exclusive pte to a working pte entry
 */
static vm_fault_t remove_device_exclusive_entry(struct vm_fault *vmf)
{
	struct folio *folio = page_folio(vmf->page);
	struct vm_area_struct *vma = vmf->vma;
	struct mmu_notifier_range range;
	vm_fault_t ret;

	/*
	 * We need a reference to lock the folio because we don't hold
	 * the PTL so a racing thread can remove the device-exclusive
	 * entry and unmap it. If the folio is free the entry must
	 * have been removed already. If it happens to have already
	 * been re-allocated after being freed all we do is lock and
	 * unlock it.
	 */
	if (!folio_try_get(folio))
		return 0;

	ret = folio_lock_or_retry(folio, vmf);
	if (ret) {
		folio_put(folio);
		return ret;
	}
	mmu_notifier_range_init_owner(&range, MMU_NOTIFY_EXCLUSIVE, 0,
				vma->vm_mm, vmf->address & PAGE_MASK,
				(vmf->address & PAGE_MASK) + PAGE_SIZE, NULL);
	mmu_notifier_invalidate_range_start(&range);

	vmf->pte = pte_offset_map_lock(vma->vm_mm, vmf->pmd, vmf->address,
				&vmf->ptl);
	if (likely(vmf->pte && pte_same(ptep_get(vmf->pte), vmf->orig_pte)))
		restore_exclusive_pte(vma, vmf->page, vmf->address, vmf->pte);

	if (vmf->pte)
		pte_unmap_unlock(vmf->pte, vmf->ptl);
	folio_unlock(folio);
	folio_put(folio);

	mmu_notifier_invalidate_range_end(&range);
	return 0;
}

/*
 * handle_pte_fault chooses page fault handler according to an entry which was
 * read non-atomically.  Before making any commitment, on those architectures
 * or configurations (e.g. i386 with PAE) which might give a mix of unmatched
 * parts, do_swap_page must check under lock before unmapping the pte and
 * proceeding (but do_wp_page is only called after already making such a check;
 * and do_anonymous_page can safely check later on).
 */
static inline int pte_unmap_same(struct vm_fault *vmf)
{
	int same = 1;
#if defined(CONFIG_SMP) || defined(CONFIG_PREEMPTION)
	if (sizeof(pte_t) > sizeof(unsigned long)) {
		spin_lock(vmf->ptl);
		same = pte_same(ptep_get(vmf->pte), vmf->orig_pte);
		spin_unlock(vmf->ptl);
	}
#endif
	pte_unmap(vmf->pte);
	vmf->pte = NULL;
	return same;
}

/*
 * We enter with non-exclusive mmap_lock (to exclude vma changes,
 * but allow concurrent faults), and pte mapped but not yet locked.
 * We return with pte unmapped and unlocked.
 *
 * We return with the mmap_lock locked or unlocked in the same cases
 * as does filemap_fault().
 */
extern struct page *_k_swapin_readahead(swp_entry_t entry, gfp_t gfp_mask,
				struct vm_fault *vmf);

KTDEF(folio_lock_or_retry);
KTDEF(swapin_readahead);
KTDEF(swap_free_in_do_swap_page);
KTDEF(do_wp_page_in_do_swap_page);
KTDEF(SWP_SYNCHRONOUS_IO);
KTDEF(do_swap_page_bottom);
KTDEF(ksm_might_need_to_copy);
KTDEF(folio_throttle_swaprate);
KTDEF(update_mmu_cache_range);
KTDEF(arch_swap_restore);
KTDEF(pte_offset_map_lock);

#include "kswapd_percpu.h"

vm_fault_t do_swap_page_internal(struct vm_fault *vmf, struct swap_info_struct *si, 
								swp_entry_t entry, struct folio *folio, struct page *page,
								struct folio *swapcache)
{
	struct vm_area_struct *vma = vmf->vma;
	bool exclusive = false;
	vm_fault_t ret = 0;
	pte_t pte;
	rmap_t rmap_flags = RMAP_NONE;

	/*
	 * Back out if somebody else already faulted in this pte.
	 */
	vmf->pte = pte_offset_map_lock(vma->vm_mm, vmf->pmd, vmf->address,
			&vmf->ptl);
	if (unlikely(!vmf->pte || !pte_same(ptep_get(vmf->pte), vmf->orig_pte)))
		goto out_nomap;

	if (unlikely(!folio_test_uptodate(folio))) {
		ret = VM_FAULT_SIGBUS;
		goto out_nomap;
	}

	/*
	 * PG_anon_exclusive reuses PG_mappedtodisk for anon pages. A swap pte
	 * must never point at an anonymous page in the swapcache that is
	 * PG_anon_exclusive. Sanity check that this holds and especially, that
	 * no filesystem set PG_mappedtodisk on a page in the swapcache. Sanity
	 * check after taking the PT lock and making sure that nobody
	 * concurrently faulted in this page and set PG_anon_exclusive.
	 */
	BUG_ON(!folio_test_anon(folio) && folio_test_mappedtodisk(folio));
	BUG_ON(folio_test_anon(folio) && PageAnonExclusive(page));

	/*
	 * Check under PT lock (to protect against concurrent fork() sharing
	 * the swap entry concurrently) for certainly exclusive pages.
	 */
	if (!folio_test_ksm(folio)) {
		exclusive = pte_swp_exclusive(vmf->orig_pte);
		if (folio != swapcache) {
			/*
			 * We have a fresh page that is not exposed to the
			 * swapcache -> certainly exclusive.
			 */
			exclusive = true;
		} else if (exclusive && folio_test_writeback(folio) &&
			  data_race(si->flags & SWP_STABLE_WRITES)) {
			/*
			 * This is tricky: not all swap backends support
			 * concurrent page modifications while under writeback.
			 *
			 * So if we stumble over such a page in the swapcache
			 * we must not set the page exclusive, otherwise we can
			 * map it writable without further checks and modify it
			 * while still under writeback.
			 *
			 * For these problematic swap backends, simply drop the
			 * exclusive marker: this is perfectly fine as we start
			 * writeback only if we fully unmapped the page and
			 * there are no unexpected references on the page after
			 * unmapping succeeded. After fully unmapped, no
			 * further GUP references (FOLL_GET and FOLL_PIN) can
			 * appear, so dropping the exclusive marker and mapping
			 * it only R/O is fine.
			 */
			exclusive = false;
		}
	}

	/*
	 * Some architectures may have to restore extra metadata to the page
	 * when reading from swap. This metadata may be indexed by swap entry
	 * so this must be called before swap_free().
	 */
	arch_swap_restore(entry, folio);

	/*
	 * Remove the swap entry and conditionally try to free up the swapcache.
	 * We're already holding a reference on the page but haven't mapped it
	 * yet.
	 */
	swap_free(entry);

	if (should_try_to_free_swap(folio, vma, vmf->flags)) {
		folio_free_swap(folio);
	}

	inc_mm_counter(vma->vm_mm, MM_ANONPAGES);
	dec_mm_counter(vma->vm_mm, MM_SWAPENTS);
	pte = mk_pte(page, vma->vm_page_prot);

	/*
	 * Same logic as in do_wp_page(); however, optimize for pages that are
	 * certainly not shared either because we just allocated them without
	 * exposing them to the swapcache or because the swap entry indicates
	 * exclusivity.
	 */
	if (!folio_test_ksm(folio) &&
	    (exclusive || folio_ref_count(folio) == 1)) {
		if (vmf->flags & FAULT_FLAG_WRITE) {
			pte = maybe_mkwrite(pte_mkdirty(pte), vma);
			vmf->flags &= ~FAULT_FLAG_WRITE;
		}
		rmap_flags |= RMAP_EXCLUSIVE;
	}
	flush_icache_page(vma, page);
	if (pte_swp_soft_dirty(vmf->orig_pte))
		pte = pte_mksoft_dirty(pte);
	if (pte_swp_uffd_wp(vmf->orig_pte))
		pte = pte_mkuffd_wp(pte);
	vmf->orig_pte = pte;

	/* ksm created a completely new copy */
	if (unlikely(folio != swapcache && swapcache)) {
		page_add_new_anon_rmap(page, vma, vmf->address);
		folio_add_lru_vma(folio, vma);
	} else {
		page_add_anon_rmap(page, vma, vmf->address, rmap_flags);
	}

	VM_BUG_ON(!folio_test_anon(folio) ||
			(pte_write(pte) && !PageAnonExclusive(page)));
	set_pte_at(vma->vm_mm, vmf->address, vmf->pte, pte);
	arch_do_swap_page(vma->vm_mm, vma, vmf->address, pte, vmf->orig_pte);

	folio_unlock(folio);
	if (folio != swapcache && swapcache) {
		/*
		 * Hold the lock to avoid the swap entry to be reused
		 * until we take the PT lock for the pte_same() check
		 * (to avoid false positives from pte_same). For
		 * further safety release the lock after the swap_free
		 * so that the swap count won't change under a
		 * parallel locked swapcache.
		 */
		folio_unlock(swapcache);
		folio_put(swapcache);
	}

	if (vmf->flags & FAULT_FLAG_WRITE) {
		ret |= do_wp_page(vmf);
		if (ret & VM_FAULT_ERROR)
			ret &= VM_FAULT_ERROR;
		goto out;
	}

	/* No need to invalidate - it was non-present before */
	update_mmu_cache_range(vmf, vma, vmf->address, vmf->pte, 1);

// unlock:
	if (vmf->pte)
		pte_unmap_unlock(vmf->pte, vmf->ptl);
out:
	if (si)
		put_swap_device(si);
	return ret;
out_nomap:
	if (vmf->pte)
		pte_unmap_unlock(vmf->pte, vmf->ptl);
// out_page
	folio_unlock(folio);
// out_release
	folio_put(folio);
	if (folio != swapcache && swapcache) {
		folio_unlock(swapcache);
		folio_put(swapcache);
	}
	if (si)
		put_swap_device(si);
	return ret;
}

KTDEF(do_swap_page_insert_task);
#ifdef __KSWAPD_PERCPU

struct do_swap_page_item {
	struct vm_fault *vmf;
	struct swap_info_struct *si;
	swp_entry_t entry;
	struct folio *folio;
	struct page *page;
	struct folio *swapcache;
};

void *do_swap_page_work(void *data)
{
	struct do_swap_page_item *dsp_item = (struct do_swap_page_item*)data;
	vm_fault_t *tsk_ret = kmalloc(sizeof(vm_fault_t), GFP_KERNEL);

	(*tsk_ret) = do_swap_page_internal(dsp_item->vmf, dsp_item->si, dsp_item->entry, dsp_item->folio, dsp_item->page, dsp_item->swapcache);

	return tsk_ret;
}

#endif

extern struct folio *_m_vma_alloc_folio(gfp_t gfp, int order, struct vm_area_struct *vma,
		unsigned long addr, bool hugepage);
		
KTDEF(folio_lock_wait_swapin);
KTDEC(_m_vma_alloc_folio);
KTDEC(swap_readpage);
vm_fault_t do_swap_page(struct vm_fault *vmf)
{
	ktime_t folio_lock_wait_swapin_watch[2];
	struct folio *swapcache, *folio = NULL;
	struct page *page;
	struct vm_area_struct *vma = vmf->vma;
	struct swap_info_struct *si = NULL;
	swp_entry_t entry;
	vm_fault_t ret = 0;
	void *shadow = NULL;

	if (!pte_unmap_same(vmf))
		goto out;

	entry = pte_to_swp_entry(vmf->orig_pte);
	if (unlikely(non_swap_entry(entry))) {
		if (is_migration_entry(entry)) {
			migration_entry_wait(vma->vm_mm, vmf->pmd,
					     vmf->address);
		} else if (is_device_exclusive_entry(entry)) {
			vmf->page = pfn_swap_entry_to_page(entry);
			ret = remove_device_exclusive_entry(vmf);
		} else if (is_device_private_entry(entry)) {
			if (vmf->flags & FAULT_FLAG_VMA_LOCK) {
				/*
				 * migrate_to_ram is not yet ready to operate
				 * under VMA lock.
				 */
				vma_end_read(vma);
				ret = VM_FAULT_RETRY;
				goto out;
			}

			vmf->page = pfn_swap_entry_to_page(entry);
			vmf->pte = pte_offset_map_lock(vma->vm_mm, vmf->pmd,
					vmf->address, &vmf->ptl);
			if (unlikely(!vmf->pte ||
				     !pte_same(ptep_get(vmf->pte),
							vmf->orig_pte)))
				goto unlock;

			/*
			 * Get a page reference while we know the page can't be
			 * freed.
			 */
			get_page(vmf->page);
			pte_unmap_unlock(vmf->pte, vmf->ptl);
			ret = vmf->page->pgmap->ops->migrate_to_ram(vmf);
			put_page(vmf->page);
		} else if (is_hwpoison_entry(entry)) {
			ret = VM_FAULT_HWPOISON;
		} else if (is_pte_marker_entry(entry)) {
			ret = handle_pte_marker(vmf);
		} else {
			print_bad_pte(vma, vmf->address, vmf->orig_pte, NULL);
			ret = VM_FAULT_SIGBUS;
		}
		goto out;
	}

	/* Prevent swapoff from happening to us. */
	si = get_swap_device(entry);
	if (unlikely(!si))
		goto out;

	folio = swap_cache_get_folio(entry, vma, vmf->address);
	if (folio)
		page = folio_file_page(folio, swp_offset(entry));
	swapcache = folio;
	bool is_swap_in = false;

	if (!folio) {
		if (data_race(si->flags & SWP_SYNCHRONOUS_IO) &&
		    __swap_count(entry) == 1) {
		// if (__swap_count(entry) == 1) {
			/* skip swapcache */
			folio = _m_vma_alloc_folio(GFP_HIGHUSER_MOVABLE, 0,
						vma, vmf->address, false);
			page = &folio->page;
			if (folio) {
				__folio_set_locked(folio);
				__folio_set_swapbacked(folio);

				if (mem_cgroup_swapin_charge_folio(folio,
							vma->vm_mm, GFP_KERNEL,
							entry)) {
					ret = VM_FAULT_OOM;
					goto out_page;
				}
				mem_cgroup_swapin_uncharge_swap(entry);

				shadow = get_shadow_from_swap_cache(entry);
				if (shadow)
					workingset_refault(folio, shadow);

				folio_add_lru(folio);

				/* To provide entry to swap_readpage() */
				folio->swap = entry;
				swap_readpage(page, true, NULL);
				folio->private = NULL;
			}
		} else {
			page = _k_swapin_readahead(entry, GFP_HIGHUSER_MOVABLE,
						vmf);
			if (page)
				folio = page_folio(page);
			swapcache = folio;
			is_swap_in = true;
		}

		if (!folio) {
			/*
			 * Back out if somebody else faulted in this pte
			 * while we released the pte lock.
			 */
			vmf->pte = pte_offset_map_lock(vma->vm_mm, vmf->pmd,
					vmf->address, &vmf->ptl);
			if (likely(vmf->pte &&
				   pte_same(ptep_get(vmf->pte), vmf->orig_pte)))
				ret = VM_FAULT_OOM;
			goto unlock;
		}

		/* Had to read the page from swap area: Major fault */
		ret = VM_FAULT_MAJOR;
		count_vm_event(PGMAJFAULT);
		count_memcg_event_mm(vma->vm_mm, PGMAJFAULT);
	} else if (PageHWPoison(page)) {
		/*
		 * hwpoisoned dirty swapcache pages are kept for killing
		 * owner processes (which may be unknown at hwpoison time)
		 */
		ret = VM_FAULT_HWPOISON;
		goto out_release;
	}

	ret |= folio_lock_or_retry(folio, vmf);
	if (ret & VM_FAULT_RETRY)
		goto out_release;

	if (swapcache) {
		/*
		 * Make sure folio_free_swap() or swapoff did not release the
		 * swapcache from under us.  The page pin, and pte_same test
		 * below, are not enough to exclude that.  Even if it is still
		 * swapcache, we need to check that the page's swap has not
		 * changed.
		 */
		if (unlikely(!folio_test_swapcache(folio) ||
			     page_swap_entry(page).val != entry.val))
			goto out_page;

		/*
		 * KSM sometimes has to copy on read faults, for example, if
		 * page->index of !PageKSM() pages would be nonlinear inside the
		 * anon VMA -- PageKSM() is lost on actual swapout.
		 */
		page = ksm_might_need_to_copy(page, vma, vmf->address);
		if (unlikely(!page)) {
			ret = VM_FAULT_OOM;
			goto out_page;
		} else if (unlikely(PTR_ERR(page) == -EHWPOISON)) {
			ret = VM_FAULT_HWPOISON;
			goto out_page;
		}
		folio = page_folio(page);

		/*
		 * If we want to map a page that's in the swapcache writable, we
		 * have to detect via the refcount if we're really the exclusive
		 * owner. Try removing the extra reference from the local LRU
		 * caches if required.
		 */
		if ((vmf->flags & FAULT_FLAG_WRITE) && folio == swapcache &&
		    !folio_test_ksm(folio) && !folio_test_lru(folio))
			lru_add_drain();
	}

	folio_throttle_swaprate(folio, GFP_KERNEL);


#ifdef __KSWAPD_PERCPU_do_swap_page

	struct do_swap_page_item param;
	param.vmf = vmf;
	param.si = si;
	param.entry = entry;
	param.folio = folio;
	param.page = page;
	param.swapcache = swapcache;
	printk(KERN_ERR "[%s] hwan-need to check\n", __func__);
	insert_task(do_swap_page_work, &param, &ret, sizeof(vm_fault_t), si->type, true);

#else

	ret = do_swap_page_internal(vmf, si, entry, folio, page, swapcache);

#endif

	goto done;

unlock:
	if (vmf->pte)
		pte_unmap_unlock(vmf->pte, vmf->ptl);
out:
	if (si)
		put_swap_device(si);
	return ret;
out_nomap:
	if (vmf->pte)
		pte_unmap_unlock(vmf->pte, vmf->ptl);
out_page:
	folio_unlock(folio);
out_release:
	folio_put(folio);
	if (folio != swapcache && swapcache) {
		folio_unlock(swapcache);
		folio_put(swapcache);
	}
	if (si)
		put_swap_device(si);
	return ret;
done:
	return ret;
}

/*
 * These routines also need to handle stuff like marking pages dirty
 * and/or accessed for architectures that don't do it in hardware (most
 * RISC architectures).  The early dirtying is also good on the i386.
 *
 * There is also a hook called "update_mmu_cache()" that architectures
 * with external mmu caches can use to update those (ie the Sparc or
 * PowerPC hashed page tables that act as extended TLBs).
 *
 * We enter with non-exclusive mmap_lock (to exclude vma changes, but allow
 * concurrent faults).
 *
 * The mmap_lock may have been released depending on flags and our return value.
 * See filemap_fault() and __folio_lock_or_retry().
 */
KTDEF(do_swap_page);
static vm_fault_t handle_pte_fault_internal(struct vm_fault *vmf)
{
	pte_t entry;

	if (unlikely(pmd_none(*vmf->pmd))) {
		/*
		 * Leave __pte_alloc() until later: because vm_ops->fault may
		 * want to allocate huge page, and if we expose page table
		 * for an instant, it will be difficult to retract from
		 * concurrent faults and from rmap lookups.
		 */
		vmf->pte = NULL;
		vmf->flags &= ~FAULT_FLAG_ORIG_PTE_VALID;
	} else {
		/*
		 * A regular pmd is established and it can't morph into a huge
		 * pmd by anon khugepaged, since that takes mmap_lock in write
		 * mode; but shmem or file collapse to THP could still morph
		 * it into a huge pmd: just retry later if so.
		 */
		vmf->pte = pte_offset_map_nolock(vmf->vma->vm_mm, vmf->pmd,
						 vmf->address, &vmf->ptl);
		if (unlikely(!vmf->pte))
			return 0;
		vmf->orig_pte = ptep_get_lockless(vmf->pte);
		vmf->flags |= FAULT_FLAG_ORIG_PTE_VALID;

		if (pte_none(vmf->orig_pte)) {
			pte_unmap(vmf->pte);
			vmf->pte = NULL;
		}
	}

	if (!vmf->pte) 
		return do_pte_missing(vmf);

	if (!pte_present(vmf->orig_pte))  {
		vm_fault_t ret;
		ret = do_swap_page(vmf);
		return ret;
	}

	if (pte_protnone(vmf->orig_pte) && vma_is_accessible(vmf->vma))
		return do_numa_page(vmf);

	spin_lock(vmf->ptl);
	entry = vmf->orig_pte;
	if (unlikely(!pte_same(ptep_get(vmf->pte), entry))) {
		update_mmu_tlb(vmf->vma, vmf->address, vmf->pte);
		goto unlock;
	}
	if (vmf->flags & (FAULT_FLAG_WRITE|FAULT_FLAG_UNSHARE)) {
		if (!pte_write(entry))
			return do_wp_page(vmf);
		else if (likely(vmf->flags & FAULT_FLAG_WRITE))
			entry = pte_mkdirty(entry);
	}
	entry = pte_mkyoung(entry);
	if (ptep_set_access_flags(vmf->vma, vmf->address, vmf->pte, entry,
				vmf->flags & FAULT_FLAG_WRITE)) {
		update_mmu_cache_range(vmf, vmf->vma, vmf->address,
				vmf->pte, 1);
	} else {
		/* Skip spurious TLB flush for retried page fault */
		if (vmf->flags & FAULT_FLAG_TRIED)
			goto unlock;
		/*
		 * This is needed only for protection faults but the arch code
		 * is not yet telling us if this is a protection fault or not.
		 * This still avoids useless tlb flushes for .text page faults
		 * with threads.
		 */
		if (vmf->flags & FAULT_FLAG_WRITE)
			flush_tlb_fix_spurious_fault(vmf->vma, vmf->address,
						     vmf->pte);
	}
unlock:
	pte_unmap_unlock(vmf->pte, vmf->ptl);
	return 0;
}

KTDEF(handle_pte_fault);
static vm_fault_t handle_pte_fault(struct vm_fault *vmf) {
	vm_fault_t ret = handle_pte_fault_internal(vmf);
	return ret;
}


static vm_fault_t sanitize_fault_flags(struct vm_area_struct *vma,
				       unsigned int *flags)
{
	if (unlikely(*flags & FAULT_FLAG_UNSHARE)) {
		if (WARN_ON_ONCE(*flags & FAULT_FLAG_WRITE))
			return VM_FAULT_SIGSEGV;
		/*
		 * FAULT_FLAG_UNSHARE only applies to COW mappings. Let's
		 * just treat it like an ordinary read-fault otherwise.
		 */
		if (!is_cow_mapping(vma->vm_flags))
			*flags &= ~FAULT_FLAG_UNSHARE;
	} else if (*flags & FAULT_FLAG_WRITE) {
		/* Write faults on read-only mappings are impossible ... */
		if (WARN_ON_ONCE(!(vma->vm_flags & VM_MAYWRITE)))
			return VM_FAULT_SIGSEGV;
		/* ... and FOLL_FORCE only applies to COW mappings. */
		if (WARN_ON_ONCE(!(vma->vm_flags & VM_WRITE) &&
				 !is_cow_mapping(vma->vm_flags)))
			return VM_FAULT_SIGSEGV;
	}
#ifdef CONFIG_PER_VMA_LOCK
	/*
	 * Per-VMA locks can't be used with FAULT_FLAG_RETRY_NOWAIT because of
	 * the assumption that lock is dropped on VM_FAULT_RETRY.
	 */
	if (WARN_ON_ONCE((*flags &
			(FAULT_FLAG_VMA_LOCK | FAULT_FLAG_RETRY_NOWAIT)) ==
			(FAULT_FLAG_VMA_LOCK | FAULT_FLAG_RETRY_NOWAIT)))
		return VM_FAULT_SIGSEGV;
#endif

	return 0;
}


static vm_fault_t wp_huge_pud(struct vm_fault *vmf, pud_t orig_pud)
{
#if defined(CONFIG_TRANSPARENT_HUGEPAGE) &&			\
	defined(CONFIG_HAVE_ARCH_TRANSPARENT_HUGEPAGE_PUD)
	struct vm_area_struct *vma = vmf->vma;
	vm_fault_t ret;

	/* No support for anonymous transparent PUD pages yet */
	if (vma_is_anonymous(vma))
		goto split;
	if (vma->vm_flags & (VM_SHARED | VM_MAYSHARE)) {
		if (vma->vm_ops->huge_fault) {
			ret = vma->vm_ops->huge_fault(vmf, PUD_ORDER);
			if (!(ret & VM_FAULT_FALLBACK))
				return ret;
		}
	}
split:
	/* COW or write-notify not handled on PUD level: split pud.*/
	__split_huge_pud(vma, vmf->pud, vmf->address);
#endif /* CONFIG_TRANSPARENT_HUGEPAGE && CONFIG_HAVE_ARCH_TRANSPARENT_HUGEPAGE_PUD */
	return VM_FAULT_FALLBACK;
}


static inline vm_fault_t create_huge_pmd(struct vm_fault *vmf)
{
	struct vm_area_struct *vma = vmf->vma;
	if (vma_is_anonymous(vma))
		return do_huge_pmd_anonymous_page(vmf);
	if (vma->vm_ops->huge_fault)
		return vma->vm_ops->huge_fault(vmf, PMD_ORDER);
	return VM_FAULT_FALLBACK;
}


#ifdef CONFIG_LRU_GEN
static void lru_gen_enter_fault(struct vm_area_struct *vma)
{
	/* the LRU algorithm only applies to accesses with recency */
	current->in_lru_fault = vma_has_recency(vma);
}

static void lru_gen_exit_fault(void)
{
	current->in_lru_fault = false;
}
#else
static void lru_gen_enter_fault(struct vm_area_struct *vma)
{
}

static void lru_gen_exit_fault(void)
{
}
#endif /* CONFIG_LRU_GEN */


/**
 * mm_account_fault - Do page fault accounting
 * @mm: mm from which memcg should be extracted. It can be NULL.
 * @regs: the pt_regs struct pointer.  When set to NULL, will skip accounting
 *        of perf event counters, but we'll still do the per-task accounting to
 *        the task who triggered this page fault.
 * @address: the faulted address.
 * @flags: the fault flags.
 * @ret: the fault retcode.
 *
 * This will take care of most of the page fault accounting.  Meanwhile, it
 * will also include the PERF_COUNT_SW_PAGE_FAULTS_[MAJ|MIN] perf counter
 * updates.  However, note that the handling of PERF_COUNT_SW_PAGE_FAULTS should
 * still be in per-arch page fault handlers at the entry of page fault.
 */
static inline void mm_account_fault(struct mm_struct *mm, struct pt_regs *regs,
				    unsigned long address, unsigned int flags,
				    vm_fault_t ret)
{
	bool major;

	/* Incomplete faults will be accounted upon completion. */
	if (ret & VM_FAULT_RETRY)
		return;

	/*
	 * To preserve the behavior of older kernels, PGFAULT counters record
	 * both successful and failed faults, as opposed to perf counters,
	 * which ignore failed cases.
	 */
	count_vm_event(PGFAULT);
	count_memcg_event_mm(mm, PGFAULT);

	/*
	 * Do not account for unsuccessful faults (e.g. when the address wasn't
	 * valid).  That includes arch_vma_access_permitted() failing before
	 * reaching here. So this is not a "this many hardware page faults"
	 * counter.  We should use the hw profiling for that.
	 */
	if (ret & VM_FAULT_ERROR)
		return;

	/*
	 * We define the fault as a major fault when the final successful fault
	 * is VM_FAULT_MAJOR, or if it retried (which implies that we couldn't
	 * handle it immediately previously).
	 */
	major = (ret & VM_FAULT_MAJOR) || (flags & FAULT_FLAG_TRIED);

	if (major)
		current->maj_flt++;
	else
		current->min_flt++;

	/*
	 * If the fault is done for GUP, regs will be NULL.  We only do the
	 * accounting for the per thread fault counters who triggered the
	 * fault, and we skip the perf event updates.
	 */
	if (!regs)
		return;

	if (major)
		perf_sw_event(PERF_COUNT_SW_PAGE_FAULTS_MAJ, 1, regs, address);
	else
		perf_sw_event(PERF_COUNT_SW_PAGE_FAULTS_MIN, 1, regs, address);
}


/*
 * On entry, we hold either the VMA lock or the mmap_lock
 * (FAULT_FLAG_VMA_LOCK tells you which).  If VM_FAULT_RETRY is set in
 * the result, the mmap_lock is not held on exit.  See filemap_fault()
 * and __folio_lock_or_retry().
 */
static vm_fault_t __handle_mm_fault_internal(struct vm_area_struct *vma,
		unsigned long address, unsigned int flags)
{
	struct vm_fault vmf = {
		.vma = vma,
		.address = address & PAGE_MASK,
		.real_address = address,
		.flags = flags,
		.pgoff = linear_page_index(vma, address),
		.gfp_mask = __get_fault_gfp_mask(vma),
	};
	struct mm_struct *mm = vma->vm_mm;
	unsigned long vm_flags = vma->vm_flags;
	pgd_t *pgd;
	p4d_t *p4d;
	vm_fault_t ret;

	pgd = pgd_offset(mm, address);
	p4d = p4d_alloc(mm, pgd, address);
	if (!p4d)
		return VM_FAULT_OOM;

	vmf.pud = pud_alloc(mm, p4d, address);
	if (!vmf.pud)
		return VM_FAULT_OOM;
retry_pud:
	if (pud_none(*vmf.pud) &&
	    hugepage_vma_check(vma, vm_flags, false, true, true)) {
		ret = create_huge_pud(&vmf);
		if (!(ret & VM_FAULT_FALLBACK))
			return ret;
	} else {
		pud_t orig_pud = *vmf.pud;

		barrier();
		if (pud_trans_huge(orig_pud) || pud_devmap(orig_pud)) {

			/*
			 * TODO once we support anonymous PUDs: NUMA case and
			 * FAULT_FLAG_UNSHARE handling.
			 */
			if ((flags & FAULT_FLAG_WRITE) && !pud_write(orig_pud)) {
				ret = wp_huge_pud(&vmf, orig_pud);
				if (!(ret & VM_FAULT_FALLBACK))
					return ret;
			} else {
				huge_pud_set_accessed(&vmf, orig_pud);
				return 0;
			}
		}
	}

	vmf.pmd = pmd_alloc(mm, vmf.pud, address);
	if (!vmf.pmd)
		return VM_FAULT_OOM;

	/* Huge pud page fault raced with pmd_alloc? */
	if (pud_trans_unstable(vmf.pud))
		goto retry_pud;

	if (pmd_none(*vmf.pmd) &&
	    hugepage_vma_check(vma, vm_flags, false, true, true)) {
		ret = create_huge_pmd(&vmf);
		if (!(ret & VM_FAULT_FALLBACK))
			return ret;
	} else {
		vmf.orig_pmd = pmdp_get_lockless(vmf.pmd);

		if (unlikely(is_swap_pmd(vmf.orig_pmd))) {
			VM_BUG_ON(thp_migration_supported() &&
					  !is_pmd_migration_entry(vmf.orig_pmd));
			if (is_pmd_migration_entry(vmf.orig_pmd))
				pmd_migration_entry_wait(mm, vmf.pmd);
			return 0;
		}
		if (pmd_trans_huge(vmf.orig_pmd) || pmd_devmap(vmf.orig_pmd)) {
			if (pmd_protnone(vmf.orig_pmd) && vma_is_accessible(vma))
				return do_huge_pmd_numa_page(&vmf);

			if ((flags & (FAULT_FLAG_WRITE|FAULT_FLAG_UNSHARE)) &&
			    !pmd_write(vmf.orig_pmd)) {
				ret = wp_huge_pmd(&vmf);
				if (!(ret & VM_FAULT_FALLBACK))
					return ret;
			} else {
				huge_pmd_set_accessed(&vmf);
				return 0;
			}
		}
	}

	return handle_pte_fault(&vmf);
}


KTDEF(__handle_mm_fault);
KTDEF2(__handle_mm_fault);
static vm_fault_t __handle_mm_fault(struct vm_area_struct *vma,
		unsigned long address, unsigned int flags) 
{
	ktime_t stopwatch[2];
	vm_fault_t ret;


	ktget2(&stopwatch[0]);
CLOCK_START(__handle_mm_fault);
	ret = __handle_mm_fault_internal(vma, address, flags);
CLOCK_STOP(__handle_mm_fault);
	ktget2(&stopwatch[1]);
	ktput2(stopwatch, __handle_mm_fault);

	return ret;
}


vm_fault_t k_handle_mm_fault(struct vm_area_struct *vma, unsigned long address,
			   unsigned int flags, struct pt_regs *regs)
{
	/* If the fault handler drops the mmap_lock, vma may be freed */
	struct mm_struct *mm = vma->vm_mm;
	vm_fault_t ret;

	__set_current_state(TASK_RUNNING);

	ret = sanitize_fault_flags(vma, &flags);
	if (ret)
		goto out;

	if (!arch_vma_access_permitted(vma, flags & FAULT_FLAG_WRITE,
					    flags & FAULT_FLAG_INSTRUCTION,
					    flags & FAULT_FLAG_REMOTE)) {
		ret = VM_FAULT_SIGSEGV;
		goto out;
	}

	/*
	 * Enable the memcg OOM handling for faults triggered in user
	 * space.  Kernel faults are handled more gracefully.
	 */
	if (flags & FAULT_FLAG_USER)
		mem_cgroup_enter_user_fault();

	lru_gen_enter_fault(vma);

	if (unlikely(is_vm_hugetlb_page(vma)))
		ret = hugetlb_fault(vma->vm_mm, vma, address, flags);
	else
		ret = __handle_mm_fault(vma, address, flags);

	lru_gen_exit_fault();

	if (flags & FAULT_FLAG_USER) {
		mem_cgroup_exit_user_fault();
		/*
		 * The task may have entered a memcg OOM situation but
		 * if the allocation error was handled gracefully (no
		 * VM_FAULT_OOM), there is no need to kill anything.
		 * Just clean up the OOM state peacefully.
		 */
		if (task_in_memcg_oom(current) && !(ret & VM_FAULT_OOM))
			mem_cgroup_oom_synchronize(false);
	}
out:
	mm_account_fault(mm, regs, address, flags, ret);
	return ret;
}



enum fault_flags {
        FAULT_NOWARN =  1 << 0,
};

#define FAULT_ATTR_INITIALIZER {                                        \
                .interval = 1,                                          \
                .times = ATOMIC_INIT(1),                                \
                .require_end = ULONG_MAX,                               \
                .stacktrace_depth = 32,                                 \
                .ratelimit_state = RATELIMIT_STATE_INIT_DISABLED,       \
                .verbose = 2,                                           \
                .dname = NULL,                                          \
        }

struct fault_attr {
        unsigned long probability;
        unsigned long interval;
        atomic_t times;
        atomic_t space;
        unsigned long verbose;
        bool task_filter;
        unsigned long stacktrace_depth;
        unsigned long require_start;
        unsigned long require_end;
        unsigned long reject_start;
        unsigned long reject_end;

        unsigned long count;
        struct ratelimit_state ratelimit_state;
        struct dentry *dname;
};

// static struct {
//         struct fault_attr attr;

//         bool ignore_gfp_highmem;
//         bool ignore_gfp_reclaim;
//         u32 min_order;
// } fail_page_alloc = {
//         .attr = FAULT_ATTR_INITIALIZER,
//         .ignore_gfp_reclaim = true,
//         .ignore_gfp_highmem = true,
//         .min_order = 1,
// };

// bool __should_fail_alloc_page(gfp_t gfp_mask, unsigned int order)
// {
//         int flags = 0;

//         if (order < fail_page_alloc.min_order)
//                 return false;
//         if (gfp_mask & __GFP_NOFAIL)
//                 return false;
//         if (fail_page_alloc.ignore_gfp_highmem && (gfp_mask & __GFP_HIGHMEM))
//                 return false;
//         if (fail_page_alloc.ignore_gfp_reclaim &&
//                         (gfp_mask & __GFP_DIRECT_RECLAIM))
//                 return false;

//         /* See comment in __should_failslab() */
//         if (gfp_mask & __GFP_NOWARN)
//                 flags |= FAULT_NOWARN;

//         return should_fail_ex(&fail_page_alloc.attr, 1 << order, flags);
// }


// KTDEF(__folio_alloc);
// /*
//  * This is the 'heart' of the zoned buddy allocator.
//  */
// struct page *_k__alloc_pages(gfp_t gfp, unsigned int order, int preferred_nid,
//                                                         nodemask_t *nodemask)
// {
//         struct page *page;
//         unsigned int alloc_flags = ALLOC_WMARK_LOW;
//         gfp_t alloc_gfp; /* The gfp_t that was actually used for allocation */
//         struct alloc_context ac = { };

//         /*
//          * There are several places where we assume that the order value is sane
//          * so bail out early if the request is out of bound.
//          */
//         if (WARN_ON_ONCE_GFP(order > MAX_ORDER, gfp))
//                 return NULL;

//         gfp &= gfp_allowed_mask;
//         /*
//          * Apply scoped allocation constraints. This is mainly about GFP_NOFS
//          * resp. GFP_NOIO which has to be inherited for all allocation requests
//          * from a particular context which has been marked by
//          * memalloc_no{fs,io}_{save,restore}. And PF_MEMALLOC_PIN which ensures
//          * movable zones are not used during allocation.
//          */
//         gfp = current_gfp_context(gfp);
//         alloc_gfp = gfp;
//         if (!prepare_alloc_pages(gfp, order, preferred_nid, nodemask, &ac,
//                         &alloc_gfp, &alloc_flags))
//                 return NULL;

//         /*
//          * Forbid the first pass from falling back to types that fragment
//          * memory until all local zones are considered.
//          */
//         alloc_flags |= alloc_flags_nofragment(ac.preferred_zoneref->zone, gfp);

//         /* First allocation attempt */
//         page = get_page_from_freelist(alloc_gfp, order, alloc_flags, &ac);
//         if (likely(page))
//                 goto out;

//         alloc_gfp = gfp;
//         ac.spread_dirty_pages = false;

//         /*
//          * Restore the original nodemask if it was potentially replaced with
//          * &cpuset_current_mems_allowed to optimize the fast-path attempt.
//          */
//         ac.nodemask = nodemask;

// #ifdef __PROFILING
// #endif 
//         page = __alloc_pages_slowpath(alloc_gfp, order, &ac);
// #ifdef __PROFILING
// #endif 

// out:
//         if (memcg_kmem_online() && (gfp & __GFP_ACCOUNT) && page &&
//             unlikely(__memcg_kmem_charge_page(page, gfp, order) != 0)) {
//                 __free_pages(page, order);
//                 page = NULL;
//         }

//         trace_mm_page_alloc(page, order, alloc_gfp, ac.migratetype);
//         kmsan_alloc_page(page, order, alloc_gfp);

//         return page;
// }


// struct folio *__k_folio_alloc(gfp_t gfp, unsigned int order, int preferred_nid,
// 		nodemask_t *nodemask)
// {
// 	struct page *page = __alloc_pages(gfp | __GFP_COMP, order,
// 			preferred_nid, nodemask);
// 	struct folio *folio = (struct folio *)page;

// 	if (folio && order > 1)
// 		folio_prep_large_rmappable(folio);
// 	return folio;
// }
