#include <linux/swap_slots.h>
#include <linux/cpu.h>
#include <linux/cpumask.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>
#include <linux/mutex.h>
#include <linux/mm.h>
#include <linux/swapops.h>

#include "kswapd_percpu.h"
#include <linux/calclock.h>

// static DEFINE_PER_CPU(struct swap_slots_cache, swp_slots);
DECLARE_PER_CPU(struct swap_slots_cache, swp_slots);

// static bool	swap_slot_cache_active;
extern bool swap_slot_cache_active;
extern bool	swap_slot_cache_initialized;
extern struct mutex swap_slots_cache_mutex;
extern struct mutex swap_slots_cache_enable_mutex;
#define use_swap_slot_cache (swap_slot_cache_active && swap_slot_cache_enabled)

#define SLOTS_CACHE 0x1
#define SLOTS_CACHE_RET 0x2

extern int _m_get_swap_pages(int n_goal, swp_entry_t swp_entries[], int entry_size);
extern struct swap_info_struct *_swap_info_get(swp_entry_t entry);

KTDEF(drain_slots_cache_cpu);
static void drain_slots_cache_cpu(unsigned int cpu, unsigned int type,
				  bool free_slots)
{
#ifdef __PROFILING
#endif 
	struct swap_slots_cache *cache;
	swp_entry_t *slots = NULL;

	cache = &per_cpu(swp_slots, cpu);
	if ((type & SLOTS_CACHE) && cache->slots) {
		mutex_lock(&cache->alloc_lock);
		swapcache_free_entries(cache->slots + cache->cur, cache->nr);
		cache->cur = 0;
		cache->nr = 0;
		if (free_slots && cache->slots) {
			kvfree(cache->slots);
			cache->slots = NULL;
		}
		mutex_unlock(&cache->alloc_lock);
	}
	if ((type & SLOTS_CACHE_RET) && cache->slots_ret) {
		spin_lock_irq(&cache->free_lock);
		swapcache_free_entries(cache->slots_ret, cache->n_ret);
		cache->n_ret = 0;
		if (free_slots && cache->slots_ret) {
			slots = cache->slots_ret;
			cache->slots_ret = NULL;
		}
		spin_unlock_irq(&cache->free_lock);
		kvfree(slots);
	}
#ifdef __PROFILING
#endif 
}

static void __drain_swap_slots_cache(unsigned int type)
{
	unsigned int cpu;

	/*
	 * This function is called during
	 *	1) swapoff, when we have to make sure no
	 *	   left over slots are in cache when we remove
	 *	   a swap device;
	 *      2) disabling of swap slot cache, when we run low
	 *	   on swap slots when allocating memory and need
	 *	   to return swap slots to global pool.
	 *
	 * We cannot acquire cpu hot plug lock here as
	 * this function can be invoked in the cpu
	 * hot plug path:
	 * cpu_up -> lock cpu_hotplug -> cpu hotplug state callback
	 *   -> memory allocation -> direct reclaim -> folio_alloc_swap
	 *   -> drain_swap_slots_cache
	 *
	 * Hence the loop over current online cpu below could miss cpu that
	 * is being brought online but not yet marked as online.
	 * That is okay as we do not schedule and run anything on a
	 * cpu before it has been marked online. Hence, we will not
	 * fill any swap slots in slots cache of such cpu.
	 * There are no slots on such cpu that need to be drained.
	 */
	for_each_online_cpu(cpu)
		drain_slots_cache_cpu(cpu, type, false);
}

KTDEF(deactivate_swap_slots_cache);
static void deactivate_swap_slots_cache(void)
{
#ifdef __PROFILING
#endif 
	mutex_lock(&swap_slots_cache_mutex);
	swap_slot_cache_active = false;
	__drain_swap_slots_cache(SLOTS_CACHE|SLOTS_CACHE_RET);
	mutex_unlock(&swap_slots_cache_mutex);
#ifdef __PROFILING
#endif 	
}

static void reactivate_swap_slots_cache(void)
{
	mutex_lock(&swap_slots_cache_mutex);
	swap_slot_cache_active = true;
	mutex_unlock(&swap_slots_cache_mutex);
}

KTDEF(check_cache_active);
static bool check_cache_active(void)
{
	// long pages;
	return true;

	if (!swap_slot_cache_enabled)
		return false;

#ifdef __PROFILING
#endif 
	// pages = get_nr_swap_pages();
	if (!swap_slot_cache_active) {
		// if (pages > num_online_cpus() *
		//     THRESHOLD_ACTIVATE_SWAP_SLOTS_CACHE)
		if (get_nr_swap_pages((num_online_cpus() * 
				THRESHOLD_ACTIVATE_SWAP_SLOTS_CACHE) + 1, true))
			reactivate_swap_slots_cache();
		goto out;
	}

	/* if global pool of slot caches too low, deactivate cache */
	// if (pages < num_online_cpus() * THRESHOLD_DEACTIVATE_SWAP_SLOTS_CACHE) 
	if (get_nr_swap_pages(num_online_cpus() * 
				THRESHOLD_ACTIVATE_SWAP_SLOTS_CACHE, false))
		deactivate_swap_slots_cache();
out:
#ifdef __PROFILING
#endif 
	return swap_slot_cache_active;
}

KTDEF(free_swap_slot);
void free_swap_slot(swp_entry_t entry)
{
#ifdef __KSWAPD_PERCPU_free_swap_slot
	// swapcache_free_entries(&entry, 1);
	bool is_current_worker = !strncmp(current->comm, "swp_worker", 10);
	struct swap_info_struct *p = _swap_info_get(entry);
	int cpu = get_cpu();
	put_cpu();


	if (!p)
		return;

	// if (is_current_worker && cpu == p->type) { //  && cpu == type
	if (cpu == p->type) { //  && cpu == type
		swapcache_free_entries(&entry, 1);
	} else {
		if (is_current_worker) {
			printk("[%s]: worker is changed\n", __func__);
		}
		struct swpcache_fe_item param;
		param.entry = entry;
		param.n = 1;
		insert_task(swapcache_free_entries_work, &param, NULL, sizeof(struct swpcache_fe_item), p->type, false);

	}
#else
	struct swap_slots_cache *cache;

	cache = raw_cpu_ptr(&swp_slots);
	if (likely(use_swap_slot_cache && cache->slots_ret)) {
		spin_lock_irq(&cache->free_lock);
		/* Swap slots cache may be deactivated before acquiring lock */
		if (!use_swap_slot_cache || !cache->slots_ret) {
			spin_unlock_irq(&cache->free_lock);
			goto direct_free;
		}
		if (cache->n_ret >= SWAP_SLOTS_CACHE_SIZE) {
			/*
			 * Return slots to global pool.
			 * The current swap_map value is SWAP_HAS_CACHE.
			 * Set it to 0 to indicate it is available for
			 * allocation in global pool
			 */
			swapcache_free_entries(cache->slots_ret, cache->n_ret);
			cache->n_ret = 0;
		}
		cache->slots_ret[cache->n_ret++] = entry;
		spin_unlock_irq(&cache->free_lock);
	} else {
direct_free:
		swapcache_free_entries(&entry, 1);
	}
#endif

#ifdef __PROFILING
#endif 
}

/*
void _m_enable_swap_slots_cache(void)
{
	printk("[%s]: disable swap_slots_cache\n", __func__);
	swap_slot_cache_active = false;
	swap_slot_cache_initialized = false;
	return ;

// 	mutex_lock(&swap_slots_cache_enable_mutex);
// 	if (!swap_slot_cache_initialized) {
// 		int ret;

// 		ret = cpuhp_setup_state(CPUHP_AP_ONLINE_DYN, "swap_slots_cache",
// 					alloc_swap_slot_cache, free_slot_cache);
// 		if (WARN_ONCE(ret < 0, "Cache allocatio__n failed (%s), operating "
// 				       "without swap slots cache.\n", __func__))
// 			goto out_unlock;

// 		swap_slot_cache_initialized = true;
// 	}

// 	__reenable_swap_slots_cache();
// out_unlock:
// 	mutex_unlock(&swap_slots_cache_enable_mutex);
}
*/

/* called with swap slot cache's alloc lock held */
static int refill_swap_slots_cache(struct swap_slots_cache *cache)
{
	if (!use_swap_slot_cache)
		return 0;

	cache->cur = 0;
	if (swap_slot_cache_active)
		cache->nr = _m_get_swap_pages(SWAP_SLOTS_CACHE_SIZE,
					   cache->slots, 1);
	return cache->nr;
}

KTDEF(mem_cgroup_try_charge_swap_in_fas);
swp_entry_t folio_alloc_swap(struct folio *folio)
{
	ktime_t mem_cgroup_try_charge_swap_in_fas_watch[2];
	swp_entry_t entry;
	struct swap_slots_cache *cache;

	entry.val = 0;

	if (folio_test_large(folio)) {
		if (IS_ENABLED(CONFIG_THP_SWAP) && arch_thp_swp_supported())
			_m_get_swap_pages(1, &entry, folio_nr_pages(folio));
		goto out;
	}

	/*
	 * Preemption is allowed here, because we may sleep
	 * in refill_swap_slots_cache().  But it is safe, because
	 * accesses to the per-CPU data structure are protected by the
	 * mutex cache->alloc_lock.
	 *
	 * The alloc path here does not touch cache->slots_ret
	 * so cache->free_lock is not taken.
	 */
	cache = raw_cpu_ptr(&swp_slots);

	if (likely(check_cache_active() && cache->slots)) {
		mutex_lock(&cache->alloc_lock);
		if (cache->slots) {
repeat:
			if (cache->nr) {
				entry = cache->slots[cache->cur];
				cache->slots[cache->cur++].val = 0;
				cache->nr--;
			} else if (refill_swap_slots_cache(cache)) {
				goto repeat;
			}
		}
		mutex_unlock(&cache->alloc_lock);
		if (entry.val)
			goto out;
	}

	_m_get_swap_pages(1, &entry, 1);
out:
#ifdef __PROFILING
#endif 
	if (mem_cgroup_try_charge_swap(folio, entry)) {
		put_swap_folio(folio, entry);
		entry.val = 0;
	}
#ifdef __PROFILING
#endif 
	return entry;
}
