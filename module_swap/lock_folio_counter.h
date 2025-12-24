#include <linux/list.h>
#include <linux/rbtree.h>
#include <linux/pagemap.h>

struct lock_folio_counter {
	struct folio *foliop;
	struct list_head list;
};

struct counter_node {
	u64 key;
	unsigned long long count;
	struct rb_node rb;
};

int _k_folio_wait_bit_killable(struct folio *folio, int bit_nr);

static inline int _k_folio_wait_locked_killable(struct folio *folio)
{
	if (!folio_test_locked(folio))
		return 0;
	return _k_folio_wait_bit_killable(folio, PG_locked);
}

void _k_folio_wait_bit(struct folio *folio, int bit_nr);

/* 
 * Wait for a folio to be unlocked.
 *
 * This must be called with the caller "holding" the folio,
 * ie with increased folio reference count so that the folio won't
 * go away during the wait.
 */
static inline void _k_folio_wait_locked(struct folio *folio)
{
	if (folio_test_locked(folio))
		_k_folio_wait_bit(folio, PG_locked);
}

vm_fault_t _k__folio_lock_or_retry(struct folio *folio, struct vm_fault *vmf);

/*
 * folio_lock_or_retry - Lock the folio, unless this would block and the
 * caller indicated that it can handle a retry.
 *
 * Return value and mmap_lock implications depend on flags; see
 * __folio_lock_or_retry().
 */
static inline vm_fault_t _k_folio_lock_or_retry(struct folio *folio,
					     struct vm_fault *vmf)
{
	might_sleep();
	if (!folio_trylock(folio))
		return _k__folio_lock_or_retry(folio, vmf);
	return 0;
}

void create_and_insert_folio_counter(struct folio *folio);

void __init lock_folio_counter_init(void);
void __exit lock_folio_counter_exit(void);
