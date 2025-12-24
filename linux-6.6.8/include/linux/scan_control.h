#ifndef SCAN_CONTROL
#define SCAN_CONTROL

struct scan_control {
        /* How many pages shrink_list() should reclaim */
        unsigned long nr_to_reclaim;

        /*
         * Nodemask of nodes allowed by the caller. If NULL, all nodes
         * are scanned.
         */
        nodemask_t      *nodemask;

        /*
         * The memory cgroup that hit its limit and as a result is the
         * primary target of this reclaim invocation.
         */
        struct mem_cgroup *target_mem_cgroup;

        /*
         * Scan pressure balancing between anon and file LRUs
         */
        unsigned long   anon_cost;
        unsigned long   file_cost;

        /* Can active folios be deactivated as part of reclaim? */
#define DEACTIVATE_ANON 1
#define DEACTIVATE_FILE 2
        unsigned int may_deactivate:2;
        unsigned int force_deactivate:1;
        unsigned int skipped_deactivate:1;

        /* Writepage batching in laptop mode; RECLAIM_WRITE */
        unsigned int may_writepage:1;

        /* Can mapped folios be reclaimed? */
        unsigned int may_unmap:1;

        /* Can folios be swapped as part of reclaim? */
        unsigned int may_swap:1;

        /* Proactive reclaim invoked by userspace through memory.reclaim */
        unsigned int proactive:1;

        /*
         * Cgroup memory below memory.low is protected as long as we
         * don't threaten to OOM. If any cgroup is reclaimed at
         * reduced force or passed over entirely due to its memory.low
         * setting (memcg_low_skipped), and nothing is reclaimed as a
         * result, then go back for one more cycle that reclaims the protected
         * memory (memcg_low_reclaim) to avert OOM.
         */
        unsigned int memcg_low_reclaim:1;
        unsigned int memcg_low_skipped:1;

        unsigned int hibernation_mode:1;

        /* One of the zones is ready for compaction */
        unsigned int compaction_ready:1;

        /* There is easily reclaimable cold cache in the current node */
        unsigned int cache_trim_mode:1;

        /* The file folios on the current node are dangerously low */
        unsigned int file_is_tiny:1;

 /* Always discard instead of demoting to lower tier memory */
        unsigned int no_demotion:1;

        /* Allocation order */
        s8 order;

        /* Scan (total_size >> priority) pages at once */
        s8 priority;

        /* The highest zone to isolate folios for reclaim from */
        s8 reclaim_idx;

        /* This context's GFP mask */
        gfp_t gfp_mask;

        /* Incremented by the number of inactive pages that were scanned */
        unsigned long nr_scanned;

        /* Number of pages freed so far during a call to shrink_zones() */
        unsigned long nr_reclaimed;

        struct {
                unsigned int dirty;
                unsigned int unqueued_dirty;
                unsigned int congested;
                unsigned int writeback;
                unsigned int immediate;
                unsigned int file_taken;
                unsigned int taken;
        } nr;

        /* for recording the reclaimed slab by now */
        struct reclaim_state reclaim_state;
};

#endif // SCAN_CONTROL
