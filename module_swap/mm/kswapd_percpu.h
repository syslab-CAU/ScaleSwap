#ifndef KSWAPD_PERCPU_H
#define KSWAPD_PERCPU_H

#include <linux/completion.h>
#include <linux/wait.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/percpu.h>
#include <linux/calclock.h>
#include "internal.h"

struct try_to_unmap_item {
        struct folio *folio;
        enum ttu_flags flags;
};

#ifdef __KSWAPD_PERCPU

#define NUMA_CNT 2
#define CPU_CNT 128

extern unsigned int get_cpu_to_numa_min[NUMA_CNT];
extern unsigned int get_cpu_to_numa_max[NUMA_CNT];

struct swpcache_fe_item {
        swp_entry_t entry;
        int n;
};

struct swap_task_item {
        struct list_head list;
        void (*run)(struct swap_task_item *data);
        void *data;
        struct completion comp;
        bool is_blocking;
        union {
                void *async_param; 
                void *result;
        }; // 64 bytes
        size_t param_size;
	int request_cpu;
};

struct swapper_t {
	struct task_struct *thread;
	wait_queue_head_t wq;

        // struct mutex task_queue_lock;
        struct list_head creation_tasks;
        spinlock_t creation_queue_lock;
        struct list_head runnable_tasks;
        spinlock_t runnable_queue_lock;
};

// extern struct swap_task_worker_t *swap_task_workers[CPU_CNT]; // TODO: percore variable로 바꿔야함. -> cache 문제 (or 동기화?)

extern void swap_task_worker_init(void);
extern void swap_task_worker_exit(void);
extern int swap_task_handler(void *data);
extern int swap_task_handler_inner(void);
extern void insert_task(void (*task_func)(struct swap_task_item *data), void *data, void *result, size_t ret_size, int cpu, bool is_blocking);

// extern void *swap_free_work(void *data);
extern void swapcache_free_entries_work(struct swap_task_item *task);
extern void add_to_swap_work(struct swap_task_item *task);
extern void try_to_unmap_work(struct swap_task_item *task);

#endif // __KSWAPD_PERCPU

#endif // KSWAPD_PERCPU_H
