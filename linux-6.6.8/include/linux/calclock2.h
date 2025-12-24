#define __PERCPU
#define __KSWAPD_PERCPU
	
#define __DEL_SILOCK
#define __KSWAPD_PERCPU_free_swap_slot

// === [shrink_folio_list (vmscan.c)] ===
#define __KSWAPD_PERCPU_remove_mapping
#define __KSWAPD_PERCPU_add_to_swap
#define __KSWAPD_PERCPU_try_to_unmap

// #define __PROFILING

#ifndef __CALCLOCK2_H
#define __CALCLOCK2_H

#include <linux/ktime.h>
#include <linux/percpu.h>


//#define CONFIG_CALCLOCK2

struct calclock2 {
	ktime_t time;
	unsigned long long count;
};

#define KTDEF2(funcname)	\
	DEFINE_PER_CPU(struct calclock2, funcname##_clock2) = {0, 0}

#define KTDEC2(funcname)	\
	DECLARE_PER_CPU(struct calclock2, funcname##_clock2)

#ifdef CONFIG_CALCLOCK2
static inline void ktget2(ktime_t *clock)
{
	*clock = ktime_get_raw();
}

static inline void __ktput2(ktime_t localclocks[], ktime_t *clock_time)
{
	ktime_t diff;

	BUG_ON(ktime_after(localclocks[0], localclocks[1]));
	diff = ktime_sub(localclocks[1], localclocks[0]);
	*clock_time = ktime_add_safe(*clock_time, diff);
}

#define ktput2(localclocks, funcname)						\
do {										\
	struct calclock2 *clock;							\
	bool prmpt_enabled = preemptible();					\
										\
	if (prmpt_enabled)							\
		preempt_disable();						\
	clock = this_cpu_ptr(&(funcname##_clock2));				\
	__ktput2(localclocks, &clock->time);					\
	clock->count++; 							\
	if (prmpt_enabled)							\
		put_cpu_ptr(&(funcname##_clock2));				\
} while (0)

void __ktprint2(int depth, char *func_name, ktime_t time, unsigned long long count);

#define ktprint2(depth, funcname)						\
do {										\
	int cpu;								\
	ktime_t timesum = 0;							\
	unsigned long long countsum = 0;					\
										\
	for_each_online_cpu(cpu) {						\
		struct calclock2 *clock = per_cpu_ptr(&funcname##_clock2, cpu);	\
		timesum += clock->time;						\
		countsum += clock->count;					\
	}									\
	__ktprint2(depth, #funcname, timesum, countsum);				\
} while (0)

#define ktreset2(funcname)				\
do {								\
	int cpu;						\
	struct calclock2 *clock;					\
								\
	for_each_online_cpu(cpu) {				\
		clock = per_cpu_ptr(&funcname##_clock2, cpu);	\
		clock->count = 0;				\
		clock->time = 0;				\
	}							\
} while (0)

#define ktprint_reset2(depth, funcname)				\
do {								\
	ktprint2(depth, funcname);				\
	ktreset2(funcname);					\
} while (0)


#else /* !CONFIG_CALCLOCK2 */
#define ktget2(clock)
#define ktput2(localclock, funcname)
#define ktprint2(depth, funcname)
#define ktprint_reset2(depth, funcname)
#define ktreset2(funcname)
#endif /* CONFIG_CALCLOCK2 */

#define calclock2(a, b, c)
#define CALCLOCK2_DEF(a)

#endif /* __CALCLOCK2_H */
