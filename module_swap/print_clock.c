#include <linux/calclock.h>

KTDEC(__handle_mm_fault);
KTDEC(handle_pte_fault);

KTDEC(do_swap_page);
KTDEC(ksm_might_need_to_copy);
KTDEC(pte_offset_map_lock);
KTDEC(folio_lock_or_retry);
KTDEC(folio_lock_wait_swapin);
KTDEC(folio_wait_locked);
KTDEC(folio_wait_bit_common);
KTDEC(io_schedule_in_folio_wait_bit_common);

KTDEC(swapin_readahead);
KTDEC(SWP_SYNCHRONOUS_IO);
KTDEC(swap_readpage);
KTDEC(__read_swap_cache_async);
    KTDEC(_m_swapcache_prepare);
    KTDEC(_m_get_swap_device);
    KTDEC(_m_put_swap_device);
    KTDEC(_m_add_to_swap_cache);
    KTDEC(_m_filemap_get_folio);
    KTDEC(_m_workingset_refault);
KTDEC(_m_mem_cgroup_swapin_uncharge_swap);
KTDEC(page_counter_uncharge_in_mcus);

KTDEC(mem_cgroup_swapin_charge_folio);
// KTDEC(charge_memcg);

KTDEC(_m_vma_alloc_folio);
KTDEC(drain_slots_cache_cpu);
KTDEC(free_swap_slot);
KTDEC(swapcache_free_entries);
KTDEC(swap_entry_free);
KTDEC(lock_cluster);
KTDEC(mem_cgroup_uncharge_swap);
KTDEC(swap_cgroup_record);
KTDEC(mem_cgroup_from_id);
KTDEC(swap_range_free);
KTDEC(atomic_operation_in_swap_range_free);

KTDEC(si_lock);
KTDEC(_k_si_lock);
KTDEC(spin_lock);

KTDEC(get_nr_swap_pages);

KTDEC(__m_folio_alloc);
KTDEC(__m_alloc_pages_slowpath);
KTDEC(__m_perform_reclaim);
KTDEC(_m_try_to_free_pages);
KTDEC(_m_shrink_zones);
KTDEC(_m_shrink_node);
KTDEC(_m_shrink_node_memcgs);
KTDEC(_m_cond_resched);
KTDEC(_m_mem_cgroup_lruvec);
KTDEC(_m_vmpressure);
KTDEC(_m_mem_cgroup_iter);
KTDEC(_m_mem_cgroup_calculate_protection);
KTDEC(_m_shrink_slab);
KTDEC(_m_shrink_lruvec);
KTDEC(_m_get_scan_count);
KTDEC(_m_shrink_slab);
KTDEC(_m_shrink_list);
KTDEC(_m_shrink_inactive_list);
KTDEC(_m_try_to_unmap_flush_dirty);
KTDEC(_m_spin_lock_irq_in_shrink_inactive_list_top);
KTDEC(_m_spin_lock_irq_in_shrink_inactive_list_bottom);
KTDEC(_m_shrink_folio_list);
KTDEC(_m_add_to_swap);
KTDEC(folio_mapping);
KTDEC(_m_pageout);
KTDEC(_m_try_to_unmap_flush);
KTDEC(_m_arch_tlbbatch_flush);
KTDEC(_m_remove_mapping);
KTDEC(_m_mem_cgroup_swapout);
// #ifdef CONFIG_MEMCG
// KTDEC(page_counter_uncharge_2);
// #endif

// KTDEC(atomic_long_sub_return);
// KTDEC(propagate_protected_usage);

// KTDEC(min_usage_READ_ONCE);
// KTDEC(atomic_long_read_MIN_USAGE);
// KTDEC(low_usage_READ_ONCE);
// KTDEC(atomic_long_read_LOW_USAGE);

KTDEC(do_pte_missing);
KTDEC(pte_alloc);
KTDEC(do_anonymous_page);
KTDEC(vma_alloc_zeroed_movable_folio);
KTDEC(__vma_folio_alloc);
KTDEC(__pte_alloc);
KTDEC(pte_alloc_one);
KTDEC(__alloc_pages);
KTDEC(get_page_from_freelist);
KTDEC(__memcg_kmem_charge_page);
KTDEC(__alloc_pages_slowpath);
KTDEC(get_page_from_freelist_in_slowpath);
KTDEC(__alloc_pages_direct_compact);
KTDEC(__alloc_pages_direct_reclaim);
KTDEC(__perform_reclaim);
KTDEC(try_to_free_pages);
KTDEC(throttle_direct_reclaim);
KTDEC(do_try_to_free_pages);
KTDEC(shrink_zones);
KTDEC(shrink_node);
KTDEC(prepare_scan_count);
KTDEC(shrink_node_memcgs);
KTDEC(cond_resched);
KTDEC(mem_cgroup_lruvec);
KTDEC(mem_cgroup_iter);
KTDEC(vmpressure);
KTDEC(mem_cgroup_calculate_protection);
KTDEC(shrink_slab);
KTDEC(shrink_lruvec);
KTDEC(get_scan_count);
KTDEC(shrink_list);
KTDEC(shrink_inactive_list);
KTDEC(shrink_folio_list);
KTDEC(add_to_swap_lock);
KTDEC(add_to_swap);
KTDEC(__remove_mapping);
KTDEC(mem_cgroup_swapout);
KTDEC(spin_lock_irq_in_shrink_inactive_list_top);
KTDEC(spin_lock_irq_in_shrink_inactive_list_bottom);
KTDEC(try_to_unmap_flush_dirty);
KTDEC(try_to_unmap_flush);
KTDEC(arch_tlbbatch_flush);
KTDEC(pageout);
KTDEC(writepage);
KTDEC(__swap_writepage);
KTDEC(swap_writepage_fs);
KTDEC(swap_writepage_bdev_sync);
KTDEC(swap_writepage_bdev_async);
KTDEC(blk_mq_get_new_requests);
KTDEC(rq_qos_throttle);
KTDEC(__wbt_wait);
KTDEC(io_schedule);

// KTDEC(shrink_folio_list_internal);
KTDEC(help_worker);
KTDEC(swap_task_handler_work);
KTDEC(try_to_unmap_one_insert_task);
KTDEC(__m_remove_mapping_internal_work);
KTDEC(add_to_swap_insert_task);
KTDEC(do_swap_page_insert_task);
KTDEC(swapcache_free_entries_insert_task);
KTDEC(wait_for_completion);
KTDEC(worker_queue_lock);

// ==== [page_counter] ====
KTDEC(mapping_host_i_lock);
KTDEC(mapping_i_pages);
// #ifdef CONFIG_MEMCG
// KTDEC(page_counter_charge_outer);
// #endif

KTDEC(total_page_counter_charge);
KTDEC(total_page_counter_uncharge);

KTDEC(get_swap_pages);
KTDEC(swap_avail_lock);
KTDEC(scan_swap_map_slots);

KTDEC(mem_cgroup_try_charge_swap_in_fas);

KTDEC(folio_alloc_swap);
KTDEC(check_cache_active);
KTDEC(deactivate_swap_slots_cache);
KTDEC(add_to_swap_cache);
KTDEC(put_swap_folio__);

KTDEC(isolate_lru_folios_internal);
KTDEC(move_folios_to_lru);

KTDEC(rcu_read_lock);
KTDEC(css_next_descendant_pre);
KTDEC(mem_cgroup_from_css);
KTDEC(css_put);

KTDEC(rcu_read_lock_in_put_many);
KTDEC(__ref_is_percpu_in_put_many);
KTDEC(this_cpu_sub_in_put_many);
KTDEC(rcu_read_unlock_in_put_many);

KTDEC(READ_ONCE_in_is_percpu);

KTDEC(rmqueue);
KTDEC(prep_new_page);
	
KTDEC(rmqueue_buddy);
	KTDEC(post_alloc_hook);
		KTDEC(kernel_init_pages);
			KTDEC(kmap_local_page);
			KTDEC(clear_page);
			KTDEC(kunmap_local);
	KTDEC(prep_compound_page);
KTDEC(node_reclaim);
KTDEC(read_once_pcp_batch);
KTDEC(rmqueue_bulk);
	KTDEC(zone_lock);
	KTDEC(__rmqueue);

	KTDEC(my_lru_spin_lock);
void print_profiling(void) 
{
    ktprint(0, __handle_mm_fault);
        ktprint(1, handle_pte_fault);
		ktprint(2, my_lru_spin_lock);
            ktprint(2, do_swap_page);
                ktprint(3, SWP_SYNCHRONOUS_IO);
                ktprint(3, swap_readpage);
                ktprint(3, pte_offset_map_lock);
                ktprint(3, swapin_readahead);
                        ktprint(5, swap_readpage);
                        ktprint(5, __read_swap_cache_async);
			    ktprint(6, _m_workingset_refault);
			    ktprint(6, _m_swapcache_prepare);
			    ktprint(6, _m_add_to_swap_cache);
			    ktprint(6, _m_filemap_get_folio);
			    ktprint(6, _m_get_swap_device);
			    ktprint(6, _m_put_swap_device);
			    ktprint(6, _m_mem_cgroup_swapin_uncharge_swap);
			    	ktprint(7, page_counter_uncharge_in_mcus);
			    ktprint(6, mem_cgroup_swapin_charge_folio);
				// ktprint(7, charge_memcg);
                            ktprint(6, _m_vma_alloc_folio);
				    ktprint(7, __m_folio_alloc);
					ktprint(8, __m_alloc_pages_slowpath);
					    ktprint(9, __m_perform_reclaim);
						ktprint(10, _m_try_to_free_pages);
						    ktprint(11, _m_shrink_zones);
							ktprint(12, _m_shrink_node);
							    ktprint(13, _m_shrink_node_memcgs);
   							    	    ktprint(14, _m_mem_cgroup_iter);
								    ktprint(14, _m_mem_cgroup_lruvec);
								    ktprint(14, _m_cond_resched);
								    ktprint(14, _m_vmpressure);
								    ktprint(14, _m_mem_cgroup_calculate_protection);
								    ktprint(14, shrink_slab);
								    ktprint(14, _m_shrink_lruvec);
								       ktprint(15, _m_get_scan_count);
								       ktprint(15, _m_shrink_list);
									   ktprint(16, _m_shrink_inactive_list);
										ktprint(16, _m_spin_lock_irq_in_shrink_inactive_list_top);
										ktprint(16, _m_spin_lock_irq_in_shrink_inactive_list_bottom);
										ktprint(16, _m_shrink_folio_list);
										    ktprint(17, _m_add_to_swap);
										    ktprint(17, _m_try_to_unmap_flush);
										    ktprint(17, _m_try_to_unmap_flush_dirty);
											ktprint(18, _m_arch_tlbbatch_flush);
										    ktprint(17, _m_remove_mapping);
											    ktprint(18, _m_mem_cgroup_swapout);
										    ktprint(17, _m_pageout);
										    // ktprint(17, folio_mapping);
// #ifdef CONFIG_MEMCG
	//                                                                         ktprint(18, page_counter_uncharge_2);
	// #endif
// ktprint(2, atomic_long_sub_return);
// ktprint(2, propagate_protected_usage);
// ktprint(3, min_usage_READ_ONCE);
// ktprint(3, atomic_long_read_MIN_USAGE);
// ktprint(3, low_usage_READ_ONCE);
// ktprint(3, atomic_long_read_LOW_USAGE);
                                                    
                            // ktprint(6, _k_put_swap_folio);
                                // ktprint(7, spin_lock_irq);
printk("\n");
            ktprint(2, folio_lock_wait_swapin);
                ktprint(3, folio_lock_or_retry);
                        ktprint(5, folio_wait_locked);
                            ktprint(6, folio_wait_bit_common);
                                ktprint(7, io_schedule_in_folio_wait_bit_common);

printk("\n\n");
                ktprint(3, free_swap_slot);
                ktprint(3, drain_slots_cache_cpu);
            ktprint(2, swapcache_free_entries);
        ktprint(1, swap_entry_free);
    ktprint(0, si_lock);
    ktprint(0, _k_si_lock);
    ktprint(0, spin_lock);
        ktprint(1, lock_cluster);
        ktprint(1, swap_range_free);
            ktprint(2, atomic_operation_in_swap_range_free);

printk("\n\n");
ktprint(0, get_nr_swap_pages);

// ==== [ do_anonymous_page ] ====
printk("\n\n ==== [ do_anonymous_page ] ====\n");
            ktprint(2, do_pte_missing);
                    ktprint(3, do_anonymous_page);
                    ktprint(4, vma_alloc_zeroed_movable_folio);
                        ktprint(5, __vma_folio_alloc);   
printk("\n");
                    ktprint(4, __pte_alloc);
                        ktprint(5, pte_alloc_one);
                            ktprint(6, __alloc_pages);
printk("...\n");
            ktprint(2, __alloc_pages);
	    	ktprint(3, get_page_from_freelist);
		ktprint(3, __memcg_kmem_charge_page);
                ktprint(3, __alloc_pages_slowpath);
		    ktprint(4, get_page_from_freelist_in_slowpath); 
                    ktprint(4, __alloc_pages_direct_compact);
                    ktprint(4, __alloc_pages_direct_reclaim);
printk("...\n");
                        ktprint(2, __perform_reclaim);
                            ktprint(3, try_to_free_pages);
			    	ktprint(4, throttle_direct_reclaim);
				ktprint(4, do_try_to_free_pages);
                                ktprint(4, shrink_zones);
                                    ktprint(5, shrink_node);
				    	ktprint(6, prepare_scan_count);
					ktprint(6, shrink_node_memcgs);
						ktprint(7, cond_resched);
						ktprint(7, mem_cgroup_lruvec);
						ktprint(7, mem_cgroup_calculate_protection);
						ktprint(7, shrink_slab);
						ktprint(7, mem_cgroup_iter);
						ktprint(7, vmpressure);
						ktprint(7, shrink_lruvec);
						    ktprint(8, get_scan_count);
						    ktprint(8, shrink_list);
							ktprint(9, shrink_inactive_list);
							    ktprint(10, spin_lock_irq_in_shrink_inactive_list_top);
							    ktprint(10, spin_lock_irq_in_shrink_inactive_list_bottom);
							    ktprint(10, shrink_folio_list);
								    ktprint(11, add_to_swap_lock);
								    ktprint(11, add_to_swap);
									ktprint(12, mem_cgroup_try_charge_swap_in_fas);
								    ktprint(11, __remove_mapping);
									ktprint(12, mem_cgroup_swapout);
								    ktprint(11, try_to_unmap_flush);
								    ktprint(11, try_to_unmap_flush_dirty);
									ktprint(12, arch_tlbbatch_flush);
								    // ktprint(11, pageout);
								    //     ktprint(12, writepage);     
// printk("====\n");
// ktprint(7, shrink_folio_list);
            ktprint(2, pageout);
                ktprint(3, writepage);
                    ktprint(4, __swap_writepage);
                        ktprint(5, swap_writepage_fs);
                        ktprint(5, swap_writepage_bdev_sync);
                        ktprint(5, swap_writepage_bdev_async);
                                                    ktprint(11, blk_mq_get_new_requests);
                                                        ktprint(12, rq_qos_throttle);
                                                            ktprint(13, __wbt_wait);
                                                                ktprint(14, io_schedule);


    printk("\n\nmy_function\n");
    ktprint(0, help_worker);
    ktprint(0, swap_task_handler_work);
    ktprint(0, __m_remove_mapping_internal_work);
    ktprint(0, try_to_unmap_one_insert_task);
    ktprint(0, add_to_swap_insert_task);
    ktprint(0, do_swap_page_insert_task);
    ktprint(0, swapcache_free_entries_insert_task);
    ktprint(0, wait_for_completion);
    ktprint(0, worker_queue_lock);

    printk("\n\n[page counter]\n");
    ktprint(0, mapping_host_i_lock);
    ktprint(0, mapping_i_pages);

// #ifdef CONFIG_MEMCG
//     ktprint(0, page_counter_charge_outer);
// #endif
     ktprint(0, total_page_counter_charge);
     ktprint(0, total_page_counter_uncharge);

    printk("\n\n");

    ktprint(0, folio_alloc_swap);
        ktprint(1, check_cache_active);
            ktprint(2, deactivate_swap_slots_cache);
        ktprint(1, get_swap_pages);
        ktprint(2, swap_avail_lock);
        ktprint(2, scan_swap_map_slots);
    ktprint(0, add_to_swap_cache);
    ktprint(0, put_swap_folio__);

    printk("\n\n");
    ktprint(0, isolate_lru_folios_internal);
    ktprint(0, move_folios_to_lru);

    printk("\n[mem_cgroup_iter]:\n");
    ktprint(0, rcu_read_lock);
    ktprint(0, css_next_descendant_pre);
    ktprint(0, mem_cgroup_from_css);
    ktprint(0, css_put);
	    ktprint(1, rcu_read_lock_in_put_many);
	    ktprint(1, __ref_is_percpu_in_put_many);
	    ktprint(1, this_cpu_sub_in_put_many);
		    ktprint(2, READ_ONCE_in_is_percpu);
	    ktprint(1, rcu_read_unlock_in_put_many);

	printk("\n[get_page_from_freelist]:\n");
	ktprint(0, node_reclaim);
	ktprint(0, rmqueue);
		ktprint(1, rmqueue_buddy);
			ktprint(2, read_once_pcp_batch);
			ktprint(2, rmqueue_bulk);
				ktprint(3, zone_lock);
				ktprint(3, __rmqueue);
	ktprint(0, prep_new_page);
		ktprint(1, post_alloc_hook);
			ktprint(2, kernel_init_pages);
				ktprint(3, kmap_local_page);
				ktprint(3, clear_page);
				ktprint(3, kunmap_local);
		ktprint(1, prep_compound_page);
}

// pte_offset_map_lock 0.09
