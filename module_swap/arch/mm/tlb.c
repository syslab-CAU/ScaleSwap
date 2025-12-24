// arch/x86/mm/tlb.c
// SPDX-License-Identifier: GPL-2.0-only
#include <linux/init.h>

#include <linux/mm.h>
#include <linux/spinlock.h>
#include <linux/smp.h>
#include <linux/interrupt.h>
#include <linux/export.h>
#include <linux/cpu.h>
#include <linux/debugfs.h>
#include <linux/sched/smt.h>
#include <linux/task_work.h>
#include <linux/mmu_notifier.h>

#include <asm/tlbflush.h>
// #include "tlbflush.h"
#include <asm/mmu_context.h>
#include <asm/nospec-branch.h>
#include <asm/cache.h>
#include <asm/cacheflush.h>
#include <asm/apic.h>
#include <asm/perf_event.h>

#include "mm_internal.h"


// DECLARE_PER_CPU_SHARED_ALIGNED(struct flush_tlb_info, flush_tlb_info);
// DECLARE_PER_CPU_ALIGNED(struct tlb_state, cpu_tlbstate);

void flush_tlb_multi(const struct cpumask *cpumask,
		      const struct flush_tlb_info *info)
{
	__flush_tlb_multi(cpumask, info);
}

/*
 * flush_tlb_func()'s memory ordering requirement is that any
 * TLB fills that happen after we flush the TLB are ordered after we
 * read active_mm's tlb_gen.  We don't need any explicit barriers
 * because all x86 flush operations are serializing and the
 * atomic64_read operation won't be reordered by the compiler.
 */
static void flush_tlb_func(void *info)
{
	/*
	 * We have three different tlb_gen values in here.  They are:
	 *
	 * - mm_tlb_gen:     the latest generation.
	 * - local_tlb_gen:  the generation that this CPU has already caught
	 *                   up to.
	 * - f->new_tlb_gen: the generation that the requester of the flush
	 *                   wants us to catch up to.
	 */
	const struct flush_tlb_info *f = info;
	struct mm_struct *loaded_mm = this_cpu_read(cpu_tlbstate.loaded_mm);
	u32 loaded_mm_asid = this_cpu_read(cpu_tlbstate.loaded_mm_asid);
	u64 local_tlb_gen = this_cpu_read(cpu_tlbstate.ctxs[loaded_mm_asid].tlb_gen);
	bool local = smp_processor_id() == f->initiating_cpu;
	unsigned long nr_invalidate = 0;
	u64 mm_tlb_gen;

	/* This code cannot presently handle being reentered. */
	VM_WARN_ON(!irqs_disabled());

	if (!local) {
		inc_irq_stat(irq_tlb_count);
		count_vm_tlb_event(NR_TLB_REMOTE_FLUSH_RECEIVED);

		/* Can only happen on remote CPUs */
		if (f->mm && f->mm != loaded_mm)
			return;
	}

	if (unlikely(loaded_mm == &init_mm))
		return;

	VM_WARN_ON(this_cpu_read(cpu_tlbstate.ctxs[loaded_mm_asid].ctx_id) !=
		   loaded_mm->context.ctx_id);

	if (this_cpu_read(cpu_tlbstate_shared.is_lazy)) {
		/*
		 * We're in lazy mode.  We need to at least flush our
		 * paging-structure cache to avoid speculatively reading
		 * garbage into our TLB.  Since switching to init_mm is barely
		 * slower than a minimal flush, just switch to init_mm.
		 *
		 * This should be rare, with native_flush_tlb_multi() skipping
		 * IPIs to lazy TLB mode CPUs.
		 */
		switch_mm_irqs_off(NULL, &init_mm, NULL);
		return;
	}

	if (unlikely(f->new_tlb_gen != TLB_GENERATION_INVALID &&
		     f->new_tlb_gen <= local_tlb_gen)) {
		/*
		 * The TLB is already up to date in respect to f->new_tlb_gen.
		 * While the core might be still behind mm_tlb_gen, checking
		 * mm_tlb_gen unnecessarily would have negative caching effects
		 * so avoid it.
		 */
		return;
	}

	/*
	 * Defer mm_tlb_gen reading as long as possible to avoid cache
	 * contention.
	 */
	mm_tlb_gen = atomic64_read(&loaded_mm->context.tlb_gen);

	if (unlikely(local_tlb_gen == mm_tlb_gen)) {
		/*
		 * There's nothing to do: we're already up to date.  This can
		 * happen if two concurrent flushes happen -- the first flush to
		 * be handled can catch us all the way up, leaving no work for
		 * the second flush.
		 */
		goto done;
	}

	WARN_ON_ONCE(local_tlb_gen > mm_tlb_gen);
	WARN_ON_ONCE(f->new_tlb_gen > mm_tlb_gen);

	/*
	 * If we get to this point, we know that our TLB is out of date.
	 * This does not strictly imply that we need to flush (it's
	 * possible that f->new_tlb_gen <= local_tlb_gen), but we're
	 * going to need to flush in the very near future, so we might
	 * as well get it over with.
	 *
	 * The only question is whether to do a full or partial flush.
	 *
	 * We do a partial flush if requested and two extra conditions
	 * are met:
	 *
	 * 1. f->new_tlb_gen == local_tlb_gen + 1.  We have an invariant that
	 *    we've always done all needed flushes to catch up to
	 *    local_tlb_gen.  If, for example, local_tlb_gen == 2 and
	 *    f->new_tlb_gen == 3, then we know that the flush needed to bring
	 *    us up to date for tlb_gen 3 is the partial flush we're
	 *    processing.
	 *
	 *    As an example of why this check is needed, suppose that there
	 *    are two concurrent flushes.  The first is a full flush that
	 *    changes context.tlb_gen from 1 to 2.  The second is a partial
	 *    flush that changes context.tlb_gen from 2 to 3.  If they get
	 *    processed on this CPU in reverse order, we'll see
	 *     local_tlb_gen == 1, mm_tlb_gen == 3, and end != TLB_FLUSH_ALL.
	 *    If we were to use __flush_tlb_one_user() and set local_tlb_gen to
	 *    3, we'd be break the invariant: we'd update local_tlb_gen above
	 *    1 without the full flush that's needed for tlb_gen 2.
	 *
	 * 2. f->new_tlb_gen == mm_tlb_gen.  This is purely an optimization.
	 *    Partial TLB flushes are not all that much cheaper than full TLB
	 *    flushes, so it seems unlikely that it would be a performance win
	 *    to do a partial flush if that won't bring our TLB fully up to
	 *    date.  By doing a full flush instead, we can increase
	 *    local_tlb_gen all the way to mm_tlb_gen and we can probably
	 *    avoid another flush in the very near future.
	 */
	if (f->end != TLB_FLUSH_ALL &&
	    f->new_tlb_gen == local_tlb_gen + 1 &&
	    f->new_tlb_gen == mm_tlb_gen) {
		/* Partial flush */
		unsigned long addr = f->start;

		/* Partial flush cannot have invalid generations */
		VM_WARN_ON(f->new_tlb_gen == TLB_GENERATION_INVALID);

		/* Partial flush must have valid mm */
		VM_WARN_ON(f->mm == NULL);

		nr_invalidate = (f->end - f->start) >> f->stride_shift;

		while (addr < f->end) {
			flush_tlb_one_user(addr);
			addr += 1UL << f->stride_shift;
		}
		if (local)
			count_vm_tlb_events(NR_TLB_LOCAL_FLUSH_ONE, nr_invalidate);
	} else {
		/* Full flush. */
		nr_invalidate = TLB_FLUSH_ALL;

		flush_tlb_local();
		if (local)
			count_vm_tlb_event(NR_TLB_LOCAL_FLUSH_ALL);
	}

	/* Both paths above update our state to mm_tlb_gen. */
	this_cpu_write(cpu_tlbstate.ctxs[loaded_mm_asid].tlb_gen, mm_tlb_gen);

	/* Tracing is done in a unified manner to reduce the code size */
done:
	trace_tlb_flush(!local ? TLB_REMOTE_SHOOTDOWN :
				(f->mm == NULL) ? TLB_LOCAL_SHOOTDOWN :
						  TLB_LOCAL_MM_SHOOTDOWN,
			nr_invalidate);
}

static void put_flush_tlb_info(void)
{
#ifdef CONFIG_DEBUG_VM
	/* Complete reentrancy prevention checks */
	barrier();
	this_cpu_dec(flush_tlb_info_idx);
#endif
}

// static DEFINE_PER_CPU_SHARED_ALIGNED(struct flush_tlb_info, flush_tlb_info);

static struct flush_tlb_info *get_flush_tlb_info(struct mm_struct *mm,
			unsigned long start, unsigned long end,
			unsigned int stride_shift, bool freed_tables,
			u64 new_tlb_gen)
{
	struct flush_tlb_info *info = this_cpu_ptr(&flush_tlb_info);

#ifdef CONFIG_DEBUG_VM
	/*
	 * Ensure that the following code is non-reentrant and flush_tlb_info
	 * is not overwritten. This means no TLB flushing is initiated by
	 * interrupt handlers and machine-check exception handlers.
	 */
	BUG_ON(this_cpu_inc_return(flush_tlb_info_idx) != 1);
#endif

	info->start		= start;
	info->end		= end;
	info->mm		= mm;
	info->stride_shift	= stride_shift;
	info->freed_tables	= freed_tables;
	info->new_tlb_gen	= new_tlb_gen;
	info->initiating_cpu	= smp_processor_id();

	return info;
}

void arch_tlbbatch_flush(struct arch_tlbflush_unmap_batch *batch)
{
	struct flush_tlb_info *info;

	int cpu = get_cpu();

	info = get_flush_tlb_info(NULL, 0, TLB_FLUSH_ALL, 0, false,
				  TLB_GENERATION_INVALID);
	/*
	 * flush_tlb_multi() is not optimized for the common case in which only
	 * a local TLB flush is needed. Optimize this use-case by calling
	 * flush_tlb_func_local() directly in this case.
	 */
	if (cpumask_any_but(&batch->cpumask, cpu) < nr_cpu_ids) {
		flush_tlb_multi(&batch->cpumask, info);
	} else if (cpumask_test_cpu(cpu, &batch->cpumask)) {
		lockdep_assert_irqs_enabled();
		local_irq_disable();
		flush_tlb_func(info);
		local_irq_enable();
	}

	cpumask_clear(&batch->cpumask);

	put_flush_tlb_info();
	put_cpu();
}

void _m_arch_tlbbatch_flush(struct arch_tlbflush_unmap_batch *batch)
{
	struct flush_tlb_info *info;

	int cpu = get_cpu();

	info = get_flush_tlb_info(NULL, 0, TLB_FLUSH_ALL, 0, false,
				  TLB_GENERATION_INVALID);
	/*
	 * flush_tlb_multi() is not optimized for the common case in which only
	 * a local TLB flush is needed. Optimize this use-case by calling
	 * flush_tlb_func_local() directly in this case.
	 */
	if (cpumask_any_but(&batch->cpumask, cpu) < nr_cpu_ids) {
		flush_tlb_multi(&batch->cpumask, info);
	} else if (cpumask_test_cpu(cpu, &batch->cpumask)) {
		lockdep_assert_irqs_enabled();
		local_irq_disable();
		flush_tlb_func(info);
		local_irq_enable();
	}

	cpumask_clear(&batch->cpumask);

	put_flush_tlb_info();
	put_cpu();
}