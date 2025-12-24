#include <linux/types.h>
#include <linux/module.h>	/* Needed by all modules */
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/writeback.h>
#include "block/blk-rq-qos.h"
#include <linux/calclock.h>
#include <linux/swap.h>
#include "mm/init.h"

#include <linux/scan_control.h>
#include "mm/kswapd_percpu.h"
#include "lock_folio_counter.h"

#include <linux/calclock.h>
#include <linux/calclock2.h>

#ifdef __PERCPU
DEFINE_PER_CPU(struct swap_info_struct *, percpu_si);
EXPORT_PER_CPU_SYMBOL(percpu_si);
#endif

#ifdef __KSWAPD_PERCPU
extern void kswapd_worker_init(void);
extern void kswapd_worker_exit(void);
#endif

/*
FUNCTION POINTER
*/

extern void print_profiling(void);

extern int (*swapon_module)(const char __user *specialfile, int swap_flags);
extern int k_swapon(const char __user *specialfile, int swap_flags);

extern vm_fault_t (*handle_mm_fault_module)(struct vm_area_struct *vma, unsigned long address,
			   unsigned int flags, struct pt_regs *regs);
extern vm_fault_t k_handle_mm_fault(struct vm_area_struct *vma, unsigned long address,
			   unsigned int flags, struct pt_regs *regs);

extern struct folio *(*__alloc_pages_module)(gfp_t gfp, unsigned int order, int preferred_nid, nodemask_t *nodemask);
extern struct folio *_k__alloc_pages(gfp_t gfp, unsigned int order, int preferred_nid, nodemask_t *nodemask);

extern int (*swap_writepage_module)(struct page *page, struct writeback_control *wbc);
extern int _k_swap_writepage(struct page *page, struct writeback_control *wbc);

extern void (*wbt_wait_module)(struct rq_qos *rqos, struct bio *bio);
extern void _k_wbt_wait(struct rq_qos *rqos, struct bio *bio);


extern struct swap_info_struct *(*swap_info_get_cont_module)(swp_entry_t entry,
					struct swap_info_struct *q);
extern struct swap_info_struct *_k_swap_info_get_cont(swp_entry_t entry,
					struct swap_info_struct *q);

extern swp_entry_t (*get_swap_page_of_type_module)(int type);
extern swp_entry_t _m_get_swap_page_of_type(int type);

extern int (*get_swap_pages_module)(int n_goal, swp_entry_t swp_entries[], int entry_size);
extern int _m_get_swap_pages(int n_goal, swp_entry_t swp_entries[], int entry_size);

extern int (*add_swap_count_continuation_module)(swp_entry_t entry, gfp_t gfp_mask);
extern int _m_add_swap_count_continuation(swp_entry_t entry, gfp_t gfp_mask);

extern unsigned long (*shrink_inactive_list_module)(unsigned long nr_to_scan,
                struct lruvec *lruvec, struct scan_control *sc,
                enum lru_list lru);
extern unsigned long shrink_inactive_list(unsigned long nr_to_scan,
                struct lruvec *lruvec, struct scan_control *sc,
                enum lru_list lru);

extern void (*shrink_node_module)(pg_data_t *pgdat, struct scan_control *sc);
extern void shrink_node(struct pglist_data *pgdat, struct scan_control *sc);

extern void (*free_swap_slot_module)(swp_entry_t entry);
extern void free_swap_slot(swp_entry_t entry);

extern void (*enable_swap_slots_cache_module)(void);
// extern void _m_enable_swap_slots_cache(void);

extern int (*shmem_writepage_module)(struct page *page, struct writeback_control *wbc);
extern int _k_shmem_writepage(struct page *page, struct writeback_control *wbc);

extern long (*get_nr_swap_pages_module)(long over_val, bool is_bigger);
extern inline long _m_get_nr_swap_pages(long over_val, bool is_bigger);

extern void (*page_counter_uncharge_module)(struct page_counter *counter, unsigned long nr_pages);
// extern void page_counter_uncharge(struct page_counter *counter, unsigned long nr_pages);

//percore LRU list
extern bool is_module_lruvec;
extern struct lruvec *(*mem_cgroup_lruvec_module)(struct mem_cgroup *memcg,
                                                               struct pglist_data *pgdat, int cpu);
extern struct lruvec *module_mem_cgroup_lruvec(struct mem_cgroup *memcg,
                                                               struct pglist_data *pgdat, int cpu);
extern bool (*folio_matches_lruvec_module)(struct folio *folio,
                                struct lruvec *lruvec);
extern bool _m_folio_matches_lruvec(struct folio *folio,
                                struct lruvec *lruvec);
extern void move_to_folios_to_percpu_lruvec(void);
extern void move_to_folios_to_original_lruvec(void);

extern int (*conn_alloc_mem_cgroup_per_node_info)(struct mem_cgroup *memcg, int node);


KTDEC(my_si_spin_lock);
KTDEC(my_lru_spin_lock);
static int __init init_swap_module(void) 
{
	printk("[combine_scheme]: init swap module\n");
/*
ASSIGN FUNCTION POINTER
*/
	ktreset(my_si_spin_lock);
	ktreset(my_lru_spin_lock);
// percore LRU scheme
        init_node_infos();
        move_to_folios_to_percpu_lruvec();
	conn_alloc_mem_cgroup_per_node_info = 1;
        folio_matches_lruvec_module = _m_folio_matches_lruvec;
        mem_cgroup_lruvec_module = module_mem_cgroup_lruvec;

// swap scheme
	swapon_module = k_swapon;
	get_swap_pages_module = _m_get_swap_pages;

	free_swap_slot_module = free_swap_slot;
	handle_mm_fault_module = k_handle_mm_fault;
	__alloc_pages_module = _k__alloc_pages;
	// swap_writepage_module = _k_swap_writepage;
	//wbt_wait_module = _k_wbt_wait;

	swap_info_get_cont_module = _k_swap_info_get_cont;
	get_swap_page_of_type_module = _m_get_swap_page_of_type;
	add_swap_count_continuation_module = _m_add_swap_count_continuation;
	
	// shrink_inactive_list_module = shrink_inactive_list;
	shrink_node_module = shrink_node; // kswapd를 이어주는 역할

	shmem_writepage_module = _k_shmem_writepage;

	// enable_swap_slots_cache_module = _m_enable_swap_slots_cache;
	enable_swap_slots_cache_module = NULL;
	get_nr_swap_pages_module = _m_get_nr_swap_pages;

#ifdef __KSWAPD_PERCPU
	swap_task_worker_init();
#endif

	// lock_folio_counter_init();
	return 0;
}

/*
DECLARE PER CORE PROFILING
*/

//unsigned long free_swap_test[128][2];
//unsigned long add_to_swap_test1[128][2];
//unsigned long add_to_swap_test2[128][2];
//unsigned long remove_mapping_test[128][2];
//unsigned long try_to_unmap_test1[128][2];
//unsigned long try_to_unmap_test2[128][2];
//ktime_t free_swap_time[128];

KTDEC2(__handle_mm_fault);
KTDEC2(insert_task);
extern unsigned long long add_cnt[128];
static void __exit exit_swap_module(void)
{
	ktprint2(0, __handle_mm_fault);
	ktprint2(1, insert_task);
//	int i, j;
//	unsigned long tmp_array[6][2] = {0};
//	printk("[%s] 1 (%lu,%lu)(%lu,%lu)(%lu,%lu)(%lu,%lu)(%lu,%lu)\n", __func__,
//			tmp_array[0][0], tmp_array[0][1],
//			tmp_array[1][0], tmp_array[1][1],
//			tmp_array[2][0], tmp_array[2][1],
//			tmp_array[3][0], tmp_array[3][1],
//			tmp_array[4][0], tmp_array[4][1],
//			tmp_array[5][0], tmp_array[5][1]);
//
//	for (i = 0; i < 128; i++) {
//		for (j = 0; j < 2; j++) {
//			tmp_array[0][j] += free_swap_test[i][j];
//			tmp_array[1][j] += add_to_swap_test1[i][j];
//			tmp_array[2][j] += add_to_swap_test2[i][j];
//			tmp_array[3][j] += remove_mapping_test[i][j];
//			tmp_array[4][j] += try_to_unmap_test1[i][j];
//			tmp_array[5][j] += try_to_unmap_test2[i][j];
//		}
//		printk("[%s] i=%d, (%llu)\n", __func__, i,
//				ktime_to_ns(free_swap_time[i]));
//	}
//
//	printk("[%s] 2 %lu %lu, %lu %lu, %lu %lu, %lu %lu, %lu %lu, %lu %lu\n", __func__,
//			tmp_array[0][0], tmp_array[0][1],
//			tmp_array[1][0], tmp_array[1][1],
//			tmp_array[2][0], tmp_array[2][1],
//			tmp_array[3][0], tmp_array[3][1],
//			tmp_array[4][0], tmp_array[4][1],
//			tmp_array[5][0], tmp_array[5][1]);

/*
 RESET FUNCTION POINTER
*/
// percore LRU scheme
        is_module_lruvec = false;
        mem_cgroup_lruvec_module = NULL;
        folio_matches_lruvec_module = NULL;
	conn_alloc_mem_cgroup_per_node_info = NULL;
        move_to_folios_to_original_lruvec();

// swap scheme
	swapon_module = NULL;

	free_swap_slot_module = NULL;
	handle_mm_fault_module = NULL;
	__alloc_pages_module = NULL;
	swap_writepage_module = NULL;
	//wbt_wait_module = NULL;
	swap_info_get_cont_module = NULL;

	// shrink_inactive_list_module = NULL;
	shrink_node_module = NULL; // kswapd를 이어주는 역할

	enable_swap_slots_cache_module = NULL;
	shmem_writepage_module = NULL;

	get_nr_swap_pages_module = NULL;

/*
 PRINT PROFILING
*/
#ifdef __KSWAPD_PERCPU
	swap_task_worker_exit();
#endif
	print_profiling();
	// lock_folio_counter_exit();
}

module_init(init_swap_module);
module_exit(exit_swap_module);
MODULE_LICENSE("GPL");
