#include "lock_folio_counter.h"
#include <linux/percpu.h>
#include <linux/slab.h>
#include <linux/delayacct.h>
#include <linux/psi.h>

struct kmem_cache *lock_folio_counter_cachep;
struct kmem_cache *counter_node_cachep;

DEFINE_PER_CPU(struct list_head, lock_folio_refs);

static struct rb_root_cached root = RB_ROOT_CACHED;

/*
 * A choice of three behaviors for wait_on_page_bit_common():
 */
enum behavior {
	EXCLUSIVE,	/* Hold ref to page and take the bit when woken, like
			 * __lock_page() waiting on then setting PG_locked.
			 */
	SHARED,		/* Hold ref to page and check the bit when woken, like
			 * wait_on_page_writeback() waiting on PG_writeback.
			 */
	DROP,		/* Drop ref to page before wait, no check when woken,
			 * like put_and_wait_on_page_locked() on PG_locked.
			 */
};

static ssize_t write_pair_to_file(struct file *file, u64 key, u64 count);
wait_queue_head_t *folio_waitqueue(struct folio *folio);
int wake_page_function(wait_queue_entry_t *wait, unsigned mode, int sync, void *arg);
inline bool folio_trylock_flag(struct folio *folio, int bit_nr,
					struct wait_queue_entry *wait);

static inline int _k_folio_wait_bit_common(struct folio *folio, int bit_nr,
		int state, enum behavior behavior)
{
	wait_queue_head_t *q = folio_waitqueue(folio);
	int unfairness = sysctl_page_lock_unfairness;
	struct wait_page_queue wait_page;
	wait_queue_entry_t *wait = &wait_page.wait;
	bool thrashing = false;
	unsigned long pflags;
	bool in_thrashing;

	if (bit_nr == PG_locked &&
	    !folio_test_uptodate(folio) && folio_test_workingset(folio)) {
		delayacct_thrashing_start(&in_thrashing);
		psi_memstall_enter(&pflags);
		thrashing = true;
	}

	init_wait(wait);
	wait->func = wake_page_function;
	wait_page.folio = folio;
	wait_page.bit_nr = bit_nr;

repeat:
	wait->flags = 0;
	if (behavior == EXCLUSIVE) {
		wait->flags = WQ_FLAG_EXCLUSIVE;
		if (--unfairness < 0)
			wait->flags |= WQ_FLAG_CUSTOM;
	}

	/*
	 * Do one last check whether we can get the
	 * page bit synchronously.
	 *
	 * Do the folio_set_waiters() marking before that
	 * to let any waker we _just_ missed know they
	 * need to wake us up (otherwise they'll never
	 * even go to the slow case that looks at the
	 * page queue), and add ourselves to the wait
	 * queue if we need to sleep.
	 *
	 * This part needs to be done under the queue
	 * lock to avoid races.
	 */
	spin_lock_irq(&q->lock);
	folio_set_waiters(folio);
	if (!folio_trylock_flag(folio, bit_nr, wait))
		__add_wait_queue_entry_tail(q, wait);
	spin_unlock_irq(&q->lock);

	/*
	 * From now on, all the logic will be based on
	 * the WQ_FLAG_WOKEN and WQ_FLAG_DONE flag, to
	 * see whether the page bit testing has already
	 * been done by the wake function.
	 *
	 * We can drop our reference to the folio.
	 */
	if (behavior == DROP)
		folio_put(folio);

	/*
	 * Note that until the "finish_wait()", or until
	 * we see the WQ_FLAG_WOKEN flag, we need to
	 * be very careful with the 'wait->flags', because
	 * we may race with a waker that sets them.
	 */
	for (;;) {
		unsigned int flags;

		set_current_state(state);

		/* Loop until we've been woken or interrupted */
		flags = smp_load_acquire(&wait->flags);
		if (!(flags & WQ_FLAG_WOKEN)) {
			if (signal_pending_state(state, current))
				break;

			create_and_insert_folio_counter(folio);
			io_schedule();
			continue;
		}

		/* If we were non-exclusive, we're done */
		if (behavior != EXCLUSIVE)
			break;

		/* If the waker got the lock for us, we're done */
		if (flags & WQ_FLAG_DONE)
			break;

		/*
		 * Otherwise, if we're getting the lock, we need to
		 * try to get it ourselves.
		 *
		 * And if that fails, we'll have to retry this all.
		 */
		if (unlikely(test_and_set_bit(bit_nr, folio_flags(folio, 0))))
			goto repeat;

		wait->flags |= WQ_FLAG_DONE;
		break;
	}

	/*
	 * If a signal happened, this 'finish_wait()' may remove the last
	 * waiter from the wait-queues, but the folio waiters bit will remain
	 * set. That's ok. The next wakeup will take care of it, and trying
	 * to do it here would be difficult and prone to races.
	 */
	finish_wait(q, wait);

	if (thrashing) {
		delayacct_thrashing_end(&in_thrashing);
		psi_memstall_leave(&pflags);
	}

	/*
	 * NOTE! The wait->flags weren't stable until we've done the
	 * 'finish_wait()', and we could have exited the loop above due
	 * to a signal, and had a wakeup event happen after the signal
	 * test but before the 'finish_wait()'.
	 *
	 * So only after the finish_wait() can we reliably determine
	 * if we got woken up or not, so we can now figure out the final
	 * return value based on that state without races.
	 *
	 * Also note that WQ_FLAG_WOKEN is sufficient for a non-exclusive
	 * waiter, but an exclusive one requires WQ_FLAG_DONE.
	 */
	if (behavior == EXCLUSIVE)
		return wait->flags & WQ_FLAG_DONE ? 0 : -EINTR;

	return wait->flags & WQ_FLAG_WOKEN ? 0 : -EINTR;
}

int _k_folio_wait_bit_killable(struct folio *folio, int bit_nr)
{       
        return _k_folio_wait_bit_common(folio, bit_nr, TASK_KILLABLE, SHARED);
}

void _k_folio_wait_bit(struct folio *folio, int bit_nr)
{
	//pr_info("join in %s\n", __func__);
	_k_folio_wait_bit_common(folio, bit_nr, TASK_UNINTERRUPTIBLE, SHARED);
}

/*
 * Return values:
 * 0 - folio is locked.
 * non-zero - folio is not locked.
 *     mmap_lock or per-VMA lock has been released (mmap_read_unlock() or
 *     vma_end_read()), unless flags had both FAULT_FLAG_ALLOW_RETRY and
 *     FAULT_FLAG_RETRY_NOWAIT set, in which case the lock is still held.
 *
 * If neither ALLOW_RETRY nor KILLABLE are set, will always return 0
 * with the folio locked and the mmap_lock/per-VMA lock is left unperturbed.
 */
vm_fault_t _k__folio_lock_or_retry(struct folio *folio, struct vm_fault *vmf)
{
	unsigned int flags = vmf->flags;
	
	// pr_info("start in _k__folio_lock_or_retry\n");
	if (fault_flag_allow_retry_first(flags)) {
		/*
		 * CAUTION! In this case, mmap_lock/per-VMA lock is not
		 * released even though returning VM_FAULT_RETRY.
		 */
		if (flags & FAULT_FLAG_RETRY_NOWAIT)
			return VM_FAULT_RETRY;

		release_fault_lock(vmf);
		if (flags & FAULT_FLAG_KILLABLE)
			//create_and_insert_folio_counter(folio);
			_k_folio_wait_locked_killable(folio);
		else {			
			//create_and_insert_folio_counter(folio);
			_k_folio_wait_locked(folio);
		}
		return VM_FAULT_RETRY;
	}
	if (flags & FAULT_FLAG_KILLABLE) {
		bool ret;

		ret = __folio_lock_killable(folio);
		if (ret) {
			release_fault_lock(vmf);
			return VM_FAULT_RETRY;
		}
	} else {
		__folio_lock(folio);
	}

	return 0;
}

/**
 * NOTE: DO NOT use this function under spin_locked!
 */
void create_and_insert_folio_counter(struct folio *folio)
{
	struct list_head *pcpu_lock_folio_refs;
	struct lock_folio_counter *counter;

	// pr_info("%s\n", __func__);
	counter = kmem_cache_alloc(lock_folio_counter_cachep, GFP_KERNEL);
	counter->foliop = folio;
	pcpu_lock_folio_refs = get_cpu_ptr(&lock_folio_refs);
	list_add_tail(&counter->list, pcpu_lock_folio_refs);
	put_cpu_ptr(&lock_folio_refs);
}

static void print_counter_node_iter_cached(struct file *file, struct rb_root_cached *root)
{
	struct rb_node *node = root->rb_leftmost, *next;

	if (!node) {
		// WARN_ON(1);
		return;
	}

	while ((next = rb_next(node))) {
		struct counter_node *entry;
		entry = rb_entry(node, struct counter_node, rb);

		/*
		if (entry->count >= 5) {
			printk("page @%px: count=%llu\n", 
					(struct page *)entry->key, 
					entry->count);
		}
		*/
		write_pair_to_file(file, entry->key, entry->count);
		rb_erase_cached(&entry->rb, root);
		kmem_cache_free(counter_node_cachep, entry);
		node = next;
	}
}

static void
get_or_create_node_cached(u64 key, struct rb_root_cached *root)
{
	struct rb_node **new = &root->rb_root.rb_node, *parent = NULL;
	bool leftmost = true;
	struct counter_node *entry;

	while (*new) {
		parent = *new;
		entry = rb_entry(parent, struct counter_node, rb);
		if (key < entry->key) {
			/* Descend to left child */
			new = &parent->rb_left;
		} else if (key == entry->key) {
			/* entry already exists */
			entry->count++;
			return;
		} else {
			/* Descend to right child */
			new = &parent->rb_right;
			leftmost = false;
		}
	}
	entry = kmem_cache_alloc(counter_node_cachep, GFP_KERNEL);
	entry->key = key;
	entry->count = 1;
	rb_link_node(&entry->rb, parent, new);
	rb_insert_color_cached(&entry->rb, root, leftmost);
}

static void lock_folio_counter_ctor(void *arg)
{
	struct lock_folio_counter *counter = arg;

	memset(counter, 0, sizeof(*counter));
	INIT_LIST_HEAD(&counter->list);
}

static int open_csv_filep(struct file **filep)
{
    struct file *file;
    static const char* filePath = "/home/syslab/workspace_cmh/swap/proposed-swap/profiling_swap/counting_page.csv";
    file = filp_open(filePath, O_CREAT|O_WRONLY|O_APPEND, 0666);
    if (IS_ERR(file) || file == NULL) {
        printk("Cannot open the file\n");
        return PTR_ERR(file);
    }
    *filep = file;
    return 0;
}

// La: write_file function
//static void write_file(char* buf, size_t size) {
static ssize_t write_pair_to_file(struct file *file, u64 key, u64 count) 
{
    //size_t res = kernel_write(file, buf, size, file->f_pos);
    char key_buffer[18], count_buffer[22];
    char *string;
    ssize_t res;

    memset(key_buffer, 0, sizeof(key_buffer));
    memset(count_buffer, 0, sizeof(count_buffer));
    sprintf(key_buffer, "%px,", (struct folio *)key);
    sprintf(count_buffer, "%llu\n", count);

    string = kmalloc(strlen(key_buffer)+1+strlen(count_buffer)+1, GFP_KERNEL);
    if (!string)
        return -ENOMEM;

    strncpy(string, key_buffer, strlen(key_buffer));
    strcat(string, count_buffer);

    //printk("%ld\n", res);
    res = kernel_write(file, string, strlen(string), &file->f_pos);
    kfree(string);
    return res;
}

void __init lock_folio_counter_init(void)
{
	int cpu;

	printk("[%s]: start\n", __func__);
	for_each_online_cpu(cpu)
		INIT_LIST_HEAD((struct list_head *)per_cpu_ptr(&lock_folio_refs, cpu));

	lock_folio_counter_cachep = kmem_cache_create("lock_folio_counter",
			sizeof(struct lock_folio_counter), 0,
			SLAB_PANIC | SLAB_RECLAIM_ACCOUNT,
			lock_folio_counter_ctor);
	counter_node_cachep = kmem_cache_create("counter_node",
			sizeof(struct counter_node), 0,
			SLAB_PANIC | SLAB_RECLAIM_ACCOUNT, NULL);
	WARN_ON(!lock_folio_counter_cachep);
	WARN_ON(!counter_node_cachep);
}

void __exit lock_folio_counter_exit(void)
{
	int cpu, ret;
	struct file *file;

	for_each_online_cpu(cpu) {
		struct list_head *pcpu_lock_folio_refs;
		struct lock_folio_counter *cur, *tmp;
		pcpu_lock_folio_refs = per_cpu_ptr(&lock_folio_refs, cpu);

		list_for_each_entry_safe(cur, tmp, pcpu_lock_folio_refs, list) {
			get_or_create_node_cached((u64)cur->foliop, &root);
			list_del(&cur->list);
			kmem_cache_free(lock_folio_counter_cachep, cur);
		}
	}
	// print_counter_node_iter_cached(&root);
	ret = open_csv_filep(&file);
	if (ret < 0)
		return;
	print_counter_node_iter_cached(file, &root);
	filp_close(file, NULL);
}
