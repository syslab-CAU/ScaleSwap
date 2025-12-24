
// ==== [not used] ====
// #define __KSWAPD_PERCPU_do_swap_page
/*
	// #define __KSWAPD_PERCPU_folio_free_swap
	// #define __KSWAPD_PERCPU_swap_free
// #define __KSWAPD_PERCPU_shrink_folio_list_insert_task
// #define __KSWAPD_PERCPU_swapcache_free_entries
*/



#define __PERCPU
#define __KSWAPD_PERCPU
	
#define __DEL_SILOCK
#define __KSWAPD_PERCPU_free_swap_slot

// === [shrink_folio_list (vmscan.c)] ===
#define __KSWAPD_PERCPU_remove_mapping
#define __KSWAPD_PERCPU_add_to_swap
#define __KSWAPD_PERCPU_try_to_unmap

// #define __PROFILING

#ifndef __CALCLOCK_H
#define __CALCLOCK_H

#include <linux/ktime.h>
#include <linux/percpu.h>


// #define CONFIG_CALCLOCK

struct calclock {
	ktime_t time;
	unsigned long long count;
};

#define KTDEF(funcname)	\
	DEFINE_PER_CPU(struct calclock, funcname##_clock) = {0, 0}

#define KTDEC(funcname)	\
	DECLARE_PER_CPU(struct calclock, funcname##_clock)

#ifdef CONFIG_CALCLOCK
static inline void ktget(ktime_t *clock)
{
	*clock = ktime_get_raw();
}

static inline void __ktput(ktime_t localclocks[], ktime_t *clock_time)
{
	ktime_t diff;

	BUG_ON(ktime_after(localclocks[0], localclocks[1]));
	diff = ktime_sub(localclocks[1], localclocks[0]);
	*clock_time = ktime_add_safe(*clock_time, diff);
}

#define ktput(localclocks, funcname)						\
do {										\
	struct calclock *clock;							\
	bool prmpt_enabled = preemptible();					\
										\
	if (prmpt_enabled)							\
		preempt_disable();						\
	clock = this_cpu_ptr(&(funcname##_clock));				\
	__ktput(localclocks, &clock->time);					\
	clock->count++; 							\
	if (prmpt_enabled)							\
		put_cpu_ptr(&(funcname##_clock));				\
} while (0)

void __ktprint(int depth, char *func_name, ktime_t time, unsigned long long count);

#define ktprint(depth, funcname)						\
do {										\
	int cpu;								\
	ktime_t timesum = 0;							\
	unsigned long long countsum = 0;					\
										\
	for_each_online_cpu(cpu) {						\
		struct calclock *clock = per_cpu_ptr(&funcname##_clock, cpu);	\
		timesum += clock->time;						\
		countsum += clock->count;					\
	}									\
	__ktprint(depth, #funcname, timesum, countsum);				\
} while (0)

#define ktreset(funcname)				\
do {								\
	int cpu;						\
	struct calclock *clock;					\
								\
	for_each_online_cpu(cpu) {				\
		clock = per_cpu_ptr(&funcname##_clock, cpu);	\
		clock->count = 0;				\
		clock->time = 0;				\
	}							\
} while (0)

#define ktprint_reset(depth, funcname)				\
do {								\
	ktprint(depth, funcname);				\
	ktreset(funcname);					\
} while (0)


#define CLOCK_START(funcname) \
	ktime_t funcname##_watch[2]; \
	ktget(&funcname##_watch[0])

#define CLOCK_STOP(funcname) \
	ktget(&funcname##_watch[1]); \
	ktput(funcname##_watch, funcname)

#else /* !CONFIG_CALCLOCK */
#define CLOCK_START(funcname) 
#define CLOCK_STOP(funcname) 
#define ktget(clock)
#define ktput(localclock, funcname)
#define ktprint(depth, funcname)
#define ktprint_reset(depth, funcname)
#define ktreset(funcname)
#endif /* CONFIG_CALCLOCK */

#define calclock(a, b, c)
#define CALCLOCK_DEF(a)

#endif /* __CALCLOCK_H */
