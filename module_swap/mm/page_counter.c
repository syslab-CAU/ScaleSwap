// SPDX-License-Identifier: GPL-2.0
/*
 * Lockless hierarchical page accounting & limiting
 *
 * Copyright (C) 2014 Red Hat, Inc., Johannes Weiner
 */

#include <linux/page_counter.h>
#include <linux/atomic.h>
#include <linux/kernel.h>
#include <linux/string.h>
#include <linux/sched.h>
#include <linux/bug.h>
#include <asm/page.h>

#include <linux/calclock.h>

static void propagate_protected_usage(struct page_counter *c,
				      unsigned long usage)
{
	unsigned long protected, old_protected;
	long delta;

	if (!c->parent)
		return;

	protected = min(usage, READ_ONCE(c->min));
	old_protected = atomic_long_read(&c->min_usage);
	if (protected != old_protected) {
		old_protected = atomic_long_xchg(&c->min_usage, protected);
		delta = protected - old_protected;
		if (delta)
			atomic_long_add(delta, &c->parent->children_min_usage);
	}

	protected = min(usage, READ_ONCE(c->low));
	old_protected = atomic_long_read(&c->low_usage);
	if (protected != old_protected) {
		old_protected = atomic_long_xchg(&c->low_usage, protected);
		delta = protected - old_protected;
		if (delta)
			atomic_long_add(delta, &c->parent->children_low_usage);
	}
}

KTDEF(min_usage_READ_ONCE);
KTDEF(atomic_long_read_MIN_USAGE);
KTDEF(low_usage_READ_ONCE);
KTDEF(atomic_long_read_LOW_USAGE);
static void _m_propagate_protected_usage(struct page_counter *c,
				      unsigned long usage)
{
	unsigned long protected, old_protected;
	long delta;

	if (!c->parent)
		return;

#ifdef __PROFILING
#endif 
	protected = min(usage, READ_ONCE(c->min));
#ifdef __PROFILING
#endif 
#ifdef __PROFILING
#endif 
	old_protected = atomic_long_read(&c->min_usage);
#ifdef __PROFILING
#endif 
	if (protected != old_protected) {
		old_protected = atomic_long_xchg(&c->min_usage, protected);
		delta = protected - old_protected;
		if (delta) {
			atomic_long_add(delta, &c->parent->children_min_usage);
		}
	}

#ifdef __PROFILING
#endif 
	protected = min(usage, READ_ONCE(c->low));
#ifdef __PROFILING
#endif 
#ifdef __PROFILING
#endif 
	old_protected = atomic_long_read(&c->low_usage);
#ifdef __PROFILING
#endif 
	if (protected != old_protected) {
		old_protected = atomic_long_xchg(&c->low_usage, protected);
		delta = protected - old_protected;
		if (delta) {
			atomic_long_add(delta, &c->parent->children_low_usage);
		}
	}
}

/**
 * page_counter_cancel - take pages out of the local counter
 * @counter: counter
 * @nr_pages: number of pages to cancel
 */
void page_counter_cancel(struct page_counter *counter, unsigned long nr_pages)
{
        long new;

        new = atomic_long_sub_return(nr_pages, &counter->usage);

        /* More uncharges than charges? */
        if (WARN_ONCE(new < 0, "page_counter underflow: %ld nr_pages=%lu\n",
                      new, nr_pages)) {
                new = 0;
                atomic_long_set(&counter->usage, new);
        }
        propagate_protected_usage(counter, new);
}

/**
 * page_counter_uncharge - hierarchically uncharge pages
 * @counter: counter
 * @nr_pages: number of pages to uncharge
 */
KTDEF(total_page_counter_uncharge);
void page_counter_uncharge(struct page_counter *counter, unsigned long nr_pages)
{
#ifdef __PROFILING
#endif 
	struct page_counter *c;

	for (c = counter; c; c = c->parent)
		page_counter_cancel(c, nr_pages);
#ifdef __PROFILING
#endif 
}
// EXPORT_SYMBOL(page_counter_uncharge);

KTDEF(total_page_counter_charge);
void page_counter_charge(struct page_counter *counter, unsigned long nr_pages)
{
#ifdef __PROFILING
#endif 
        struct page_counter *c;

        for (c = counter; c; c = c->parent) {
                long new;

                new = atomic_long_add_return(nr_pages, &c->usage);
                propagate_protected_usage(c, new);
                /*
                 * This is indeed racy, but we can live with some
                 * inaccuracy in the watermark.
                 */
                if (new > READ_ONCE(c->watermark))
                        WRITE_ONCE(c->watermark, new);
        }
#ifdef __PROFILING
#endif 
}
