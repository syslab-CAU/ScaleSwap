#include "kswapd_percpu.h"

KTDEF(wait_for_completion);
KTDEF(worker_queue_lock);
#ifdef __KSWAPD_PERCPU

#include <linux/slab.h>
#include <linux/kthread.h>
#include <linux/calclock2.h>

// struct swap_task_worker_t *swap_task_workers[CPU_CNT];
// DEFINE_PER_CPU(struct swapper_t, swapper);
struct swapper_t __percpu *swapper;
unsigned int get_cpu_to_numa_min[NUMA_CNT];
unsigned int get_cpu_to_numa_max[NUMA_CNT];
//#define MAX_TASK 500000
//#define MAX_TASK 250000
//#define MAX_TASK 100000
//#define MAX_TASK 50000
//#define MAX_TASK 25000
//#define MAX_TASK 10000
#define MAX_TASK 5000
//#define MAX_TASK 1500

void swap_task_worker_init(void) {
    swapper = alloc_percpu(struct swapper_t);
    struct swapper_t *worker;
    struct swap_task_item *task;
    int cpu, i;

    for_each_online_cpu(cpu) {
	// worker = kzalloc(sizeof(struct swap_task_worker_t), GFP_KERNEL);
	worker = per_cpu_ptr(swapper, cpu);

        // spin_lock_init(&worker->creation_queue_lock);
        // spin_lock_init(&worker->runnable_queue_lock);

        INIT_LIST_HEAD(&worker->creation_tasks);
        for (int i = 0; i < MAX_TASK; i++) {
            task = kzalloc(sizeof(struct swap_task_item), GFP_KERNEL);

            task->async_param = kzalloc(64, GFP_KERNEL);
	    task->request_cpu = cpu;
            list_add_tail(&task->list, &worker->creation_tasks);
        }
        INIT_LIST_HEAD(&worker->runnable_tasks);

        init_waitqueue_head(&worker->wq);

        worker->thread = kthread_create(swap_task_handler, (void *)worker, "swp_worker/%d", cpu);
        kthread_bind(worker->thread, cpu);
        wake_up_process(worker->thread);

        // swap_task_workers[cpu] = worker;
    }

    for (i = 0; i < NUMA_CNT; i++) {
        get_cpu_to_numa_min[i] = -1;
        get_cpu_to_numa_max[i] = -1;
    }

    for_each_online_cpu(cpu) {
        int node = cpu_to_node(cpu);
        if (get_cpu_to_numa_min[node] == -1) {
            get_cpu_to_numa_min[node] = cpu;
        }
        get_cpu_to_numa_max[node] = cpu;
    }

    for (i = 0; i < NUMA_CNT; i++) {
        printk("NUMA %d: min=%d, max=%d\n", i, get_cpu_to_numa_min[i], get_cpu_to_numa_max[i]);
    }
}

void swap_task_worker_exit(void) {
    int cpu;
    struct swap_task_item *cur, *tmp;
    struct swapper_t *worker;

    for_each_online_cpu(cpu) {
	worker = per_cpu_ptr(swapper, cpu);
	// kthread_stop(swap_task_workers[cpu]->thread);
	kthread_stop(worker->thread);
	
        // list_for_each_entry_safe(cur, tmp, &swap_task_workers[cpu]->creation_tasks, list) {
        list_for_each_entry_safe(cur, tmp, &worker->creation_tasks, list) {
            list_del(&cur->list);
            kfree(cur->async_param);
            kfree(cur);
        }
	// kfree(swap_task_workers[cpu]);
    }
    free_percpu(swapper);
}

bool list_empty_with_lock(const struct list_head *head, spinlock_t *lock) {
    bool ret;

#ifdef __PROFILING
#endif 
    spin_lock(lock);
#ifdef __PROFILING
#endif 
    ret = list_empty(head);
    if (!ret)
        return 0;
    spin_unlock(lock);
    return 1;
}

KTDEF(swap_task_handler_work);
int swap_task_handler(void *data) 
{
    struct swapper_t *worker = (struct swapper_t *)data;
    struct swap_task_item *task;

    bool kthread_is_stop = false;
    while (!kthread_is_stop) {
        wait_event_interruptible(worker->wq, kthread_should_stop() || !list_empty_with_lock(&worker->runnable_tasks, &worker->runnable_queue_lock));
        if (list_empty(&worker->runnable_tasks) && kthread_should_stop()) {
            kthread_is_stop = true;
            break;
        }
        task = list_first_entry(&worker->runnable_tasks, struct swap_task_item, list);
        list_del(&task->list);
        spin_unlock(&worker->runnable_queue_lock);

        if (task) {
            if (task->is_blocking) {
                task->run(task);
                complete(&task->comp);
            } else {
                task->run(task);
		struct swapper_t *target_worker = per_cpu_ptr(swapper, task->request_cpu);
                spin_lock(&target_worker->creation_queue_lock);
                list_add_tail(&task->list, &target_worker->creation_tasks);
                spin_unlock(&target_worker->creation_queue_lock);

            }
            task = NULL;
        }
    }

    return 0;
}

KTDEF(help_worker);
/*

*/
int swap_task_handler_inner(void) {
    struct swapper_t *worker;
    struct swap_task_item *task;

    worker = this_cpu_ptr(swapper);
    if (list_empty_with_lock(&worker->runnable_tasks, &worker->runnable_queue_lock))
        return 1;
    task = list_first_entry(&worker->runnable_tasks, struct swap_task_item, list);
    list_del(&task->list);
    spin_unlock(&worker->runnable_queue_lock);

    if (task) {
        if (task->is_blocking) {
            task->run(task);
            complete(&task->comp);
        } else {
            task->run(task);
	    struct swapper_t *target_worker = per_cpu_ptr(swapper, task->request_cpu);
            spin_lock(&target_worker->creation_queue_lock);
            list_add_tail(&task->list, &target_worker->creation_tasks);
            spin_unlock(&target_worker->creation_queue_lock);
        }
        task = NULL;
    }

    return 0;
}

/**
 * insert_task - insert task and wait the task function
 * @task_func: insert task function (return: void *, param: void *)
 * @data: parameter in task function
 * @result: task function result (void *)
 *
 * task function은 return type에 대해 kmalloc(sizeof(type), ...)으로 하고 이 안에 값을 담아야 함.
 *
 * Context: caller는 return type에 대해 형변환을 꼭 시켜줘야 함. 또한 result 변수에 대해서 kfree를 해줘야 함.
 * return: None
 */
KTDEF2(insert_task);
void insert_task(void (*task_func)(struct swap_task_item *data), void *data, void *result, size_t ret_size, int cpu, bool is_blocking) 
{
	ktime_t stopwatch[2];
	ktget2(&stopwatch[0]);
	struct swap_task_item *task;
	struct swapper_t *target_worker, *worker;

	worker = this_cpu_ptr(swapper);
	target_worker = per_cpu_ptr(swapper, cpu);

	for (;;) {
		spin_lock(&worker->creation_queue_lock);
		if (!list_empty(&worker->creation_tasks)) {
			break;
		}
		//printk("[%s]: list is empty!! (%d)\n", __func__, cpu);
		spin_unlock(&worker->creation_queue_lock);
		// over head가 발생할 가능성이 있는 곳.
	}
	task = list_first_entry(&worker->creation_tasks, struct swap_task_item, list);

	list_del(&task->list);
	spin_unlock(&worker->creation_queue_lock);
	task->run = task_func;
	task->is_blocking = is_blocking;
	// task->is_complete = false;
	if (is_blocking) {
		task->data = data;
	        task->param_size = 0;
	        init_completion(&task->comp);
	}
	else {
		memcpy(task->async_param, data, ret_size);
		task->param_size = ret_size;
	}

	spin_lock(&target_worker->runnable_queue_lock);
	list_add_tail(&task->list, &target_worker->runnable_tasks);
	spin_unlock(&target_worker->runnable_queue_lock);

	wake_up_process(target_worker->thread);
	if (!is_blocking) {
		ktget2(&stopwatch[1]);
		ktput2(stopwatch, insert_task);
        	return;
	}

	int patient = 0;
	while (!completion_done(&task->comp)) {
		if (patient == 10) {
			swap_task_handler_inner();
			patient = 0;
		}
		patient++;
	}
	// wait_for_completion(&task->comp);

	if (result != NULL)
		memcpy(result, task->result, ret_size);
	spin_lock(&worker->creation_queue_lock);
	list_add_tail(&task->list, &worker->creation_tasks);
	spin_unlock(&worker->creation_queue_lock);
	ktget2(&stopwatch[1]);
	ktput2(stopwatch, insert_task);

}

#endif // __KSWAPD_PERCPU
