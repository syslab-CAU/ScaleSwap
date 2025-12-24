#include <linux/memcontrol.h>
#include <linux/mm_inline.h>
#include "mm/init.h"

#define for_each_mem_cgroup(iter)			\
	for (iter = mem_cgroup_iter(NULL, NULL, NULL);	\
	     iter != NULL;				\
	     iter = mem_cgroup_iter(NULL, iter, NULL))

#ifdef ARCH_HAS_PREFETCHW
#define prefetchw_prev_lru_folio(_folio, _base, _field)			\
	do {								\
		if ((_folio)->lru.prev != _base) {			\
			struct folio *prev;				\
									\
			prev = lru_to_folio(&(_folio->lru));		\
			prefetchw(&prev->_field);			\
		}							\
	} while (0)
#else
#define prefetchw_prev_lru_folio(_folio, _base, _field) do { } while (0)
#endif

struct Node_info *node_infos;
void init_node_infos(void) {
	node_infos = kzalloc(sizeof(struct Node_info) * nr_node_ids, GFP_KERNEL);
	int cpu, node;
	for (node = 0; node < nr_node_ids; node++) {
		node_infos[node].min = -1;
		node_infos[node].max = -1;
		for_each_online_cpu(cpu) {
			if (node == cpu_to_node(cpu)) {
				if (node_infos[node].min == -1)
					node_infos[node].min = cpu;
				node_infos[node].max = cpu;
			}
		}
		printk("node_infos[%d]: min=%d, max=%d", node, node_infos[node].min, node_infos[node].max);
	}
}

static int get_total_cnt(int *cnts) {
	return cnts[0] + cnts[1] + cnts[2] + cnts[3];
}

static void copy_to_variable(struct lruvec *from_lruvec, struct lruvec *to_lruvec) 
{
	int i;

	to_lruvec->anon_cost = from_lruvec->anon_cost;
	to_lruvec->file_cost = from_lruvec->file_cost;

	to_lruvec->nonresident_age = from_lruvec->nonresident_age;

	for (i = 0; i < ANON_AND_FILE; i++)
		to_lruvec->refaults[i] = from_lruvec->refaults[i];

	to_lruvec->flags = from_lruvec->flags;

#ifdef CONFIG_LRU_GEN
	to_lruvec->lrugen = from_lruvec->lrugen;
	to_lruvec->mm_state = from_lruvec->mm_state;
#endif
}

void init_percpu_lruvec(struct mem_cgroup_per_node *mz, int node);

static void check_and_init_percpu_lruvec(struct mem_cgroup_per_node *mz, int node) 
{
	int cpu;
	struct lruvec *lruvec;

	for_each_cpu(cpu, cpumask_of_node(node)) {
		lruvec = per_cpu_ptr(mz->p_lruvec, cpu);
		if (!lruvec)
			goto alloc;
		else if (!lruvec->pgdat || !lruvec->mz)
			goto alloc;
//		printk("[%s](%d) flag=%d, lruvec=%x, lruvec->mz=%x, cpu=%d, pgdat=%x\n", __func__,
//				smp_processor_id(),
//				mz->is_p_lruvec_use, lruvec, lruvec->mz, lruvec->cpu, lruvec->pgdat);
	}
	return;
alloc:
	init_percpu_lruvec(mz, node);
	return;
}

extern unsigned long folio_to_cpu(struct folio *folio);
extern struct lruvec *module_mem_cgroup_lruvec(struct mem_cgroup *memcg,
					   struct pglist_data *pgdat,
					   int cpu);
void move_to_folios_to_percpu_lruvec(void) 
{
	struct mem_cgroup *memcg;
	int node_idx, cpu;
	enum lru_list lru;

	int tmp_cnt = 3;
	
	printk("[%s]: from=lruvec, to=percpu_lruvec\n", __func__);
	printk("form - to: %d - %d\n", NR_PAGEFLAGS, LRU_REFS_PGOFF); /* 26-34 */

	for_each_mem_cgroup(memcg) {
		struct folio *iter, *tmp;

		for (node_idx = 0; node_idx < nr_node_ids; node_idx++) {
			struct mem_cgroup_per_node *mz = memcg->nodeinfo[node_idx];
			check_and_init_percpu_lruvec(mz, node_idx);

			struct lruvec *from = &mz->lruvec;
			struct lruvec *to = NULL;

			spin_lock(&from->lru_lock);
			mz->is_p_lruvec_use = true;

			for_each_evictable_lru(lru) {
				list_for_each_entry_safe(iter, tmp, &from->lists[lru], lru) {
					cpu = folio_to_cpu(iter);
					if (cpu == -1)
						printk("[%s] need to check\n", __func__);

					if (tmp_cnt && cpu == 64) {
						tmp_cnt--;
						printk("[%s] node=%d, zone=%d\n", 
								__func__, 
								folio_pgdat(iter)->node_id, 
								folio_zone(iter));
						printk("[%s] %llu\n", __func__, iter->flags);
					}

					if ((iter->page.flags >> LAST_CPUPID_PGSHIFT) & LAST_CPUPID_MASK != 2097151)
					printk("[%s] page_cpupid_last=%lu\n", 
							__func__, 
							(iter->page.flags >> LAST_CPUPID_PGSHIFT) & LAST_CPUPID_MASK);

//					if (node_idx == 0 && cpu > 63)
//						printk("[%s] 0 node_idx=%d, cpu_node=%d, cpu=%d\n", 
//								__func__, node_idx, cpu_to_node(cpu), cpu);
//
//					if (node_idx == 1 && cpu <= 63) 
//						printk("[%s] 1 node_idx=%d, cpu_node=%d, cpu=%d\n", 
//								__func__, node_idx, cpu_to_node(cpu), cpu);
//
					
					to = module_mem_cgroup_lruvec(memcg, folio_pgdat(iter), cpu);
					//lruvec_del_folio(from, iter);
					default_lruvec_del_folio(from, iter);

					spin_lock(&to->lru_lock);
					lruvec_add_folio_tail(to, iter);
					spin_unlock(&to->lru_lock);
				}
			}
			spin_unlock(&from->lru_lock);
		}

	}

	printk("[%s]: sizeof(memcg)=%ld\n", __func__, sizeof(struct mem_cgroup));

}


void move_to_folios_to_original_lruvec(void) 
{
	struct mem_cgroup *memcg;
	int node_idx, cpu;
	enum lru_list lru;
	
	printk("[%s]: from=percpu_lruvec, to=lruvec\n", __func__);

	for_each_mem_cgroup(memcg) {
		struct folio *iter, *tmp;

		for (node_idx = 0; node_idx < nr_node_ids; node_idx++) {
			struct mem_cgroup_per_node *mz = memcg->nodeinfo[node_idx];

			struct lruvec *from = NULL;
			struct lruvec *to = &mz->lruvec;

			spin_lock(&to->lru_lock);
			mz->is_p_lruvec_use = false;

			for_each_evictable_lru(lru) {
				for_each_cpu(cpu, cpumask_of_node(node_idx)) {
					from = per_cpu_ptr(mz->p_lruvec, cpu);
					spin_lock(&from->lru_lock);
					list_for_each_entry_safe(iter, tmp, &from->lists[lru], lru) {
						int folio_cpu = folio_to_cpu(iter);

//						if (node_idx == 0 && folio_cpu > 63)
//							printk("[%s] 00 node_idx=%d, cpu_node=%d, cpu=%d\n", 
//								__func__, node_idx, cpu_to_node(cpu), folio_cpu);
//
//
//						if (node_idx == 1 && folio_cpu <= 63) 
//							printk("[%s] 11 node_idx=%d, cpu_node=%d, cpu=%d\n", 
//								__func__, node_idx, cpu_to_node(cpu), folio_cpu);


						module_lruvec_del_folio(from, iter);
						lruvec_add_folio_tail(to, iter);
					}
					spin_unlock(&from->lru_lock);
				}	
			}

			spin_unlock(&to->lru_lock);

		}
	}


	printk("[%s]: sizeof(memcg)=%ld\n", __func__, sizeof(struct mem_cgroup));
}
