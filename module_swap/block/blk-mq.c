// SPDX-License-Identifier: GPL-2.0
/*
 * Block multiqueue core code
 *
 * Copyright (C) 2013-2014 Jens Axboe
 * Copyright (C) 2013-2014 Christoph Hellwig
 */
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/backing-dev.h>
#include <linux/bio.h>
#include <linux/blkdev.h>
#include <linux/blk-integrity.h>
#include <linux/kmemleak.h>
#include <linux/mm.h>
#include <linux/init.h>
#include <linux/slab.h>
#include <linux/workqueue.h>
#include <linux/smp.h>
#include <linux/interrupt.h>
#include <linux/llist.h>
#include <linux/cpu.h>
#include <linux/cache.h>
#include <linux/sched/sysctl.h>
#include <linux/sched/topology.h>
#include <linux/sched/signal.h>
#include <linux/delay.h>
#include <linux/crash_dump.h>
#include <linux/prefetch.h>
#include <linux/blk-crypto.h>
#include <linux/part_stat.h>

#include <trace/events/block.h>

#include <linux/t10-pi.h>
#include "blk.h"
#include "blk-mq.h"
#include "blk-mq-debugfs.h"
#include "blk-pm.h"
#include "blk-stat.h"
#include "blk-mq-sched.h"
#include "blk-rq-qos.h"
#include "blk-ioprio.h"

#include <linux/calclock.h>

/**
 * blk_mq_request_bypass_insert - Insert a request at dispatch list.
 * @rq: Pointer to request to be inserted.
 * @flags: BLK_MQ_INSERT_*
 *
 * Should only be used carefully, when the caller knows we want to
 * bypass a potential IO scheduler on the target device.
 */
static void blk_mq_request_bypass_insert(struct request *rq, blk_insert_t flags)
{
	struct blk_mq_hw_ctx *hctx = rq->mq_hctx;

	spin_lock(&hctx->lock);
	if (flags & BLK_MQ_INSERT_AT_HEAD)
		list_add(&rq->queuelist, &hctx->dispatch);
	else
		list_add_tail(&rq->queuelist, &hctx->dispatch);
	spin_unlock(&hctx->lock);
}

static void __blk_mq_requeue_request(struct request *rq)
{
	struct request_queue *q = rq->q;

	blk_mq_put_driver_tag(rq);

	trace_block_rq_requeue(rq);
	rq_qos_requeue(q, rq);

	if (blk_mq_request_started(rq)) {
		WRITE_ONCE(rq->state, MQ_RQ_IDLE);
		rq->rq_flags &= ~RQF_TIMED_OUT;
	}
}

#define BLK_MQ_DISPATCH_BUSY_EWMA_WEIGHT  8
#define BLK_MQ_DISPATCH_BUSY_EWMA_FACTOR  4

/*
 * Update dispatch busy with the Exponential Weighted Moving Average(EWMA):
 * - EWMA is one simple way to compute running average value
 * - weight(7/8 and 1/8) is applied so that it can decrease exponentially
 * - take 4 as factor for avoiding to get too small(0) result, and this
 *   factor doesn't matter because EWMA decreases exponentially
 */
static void blk_mq_update_dispatch_busy(struct blk_mq_hw_ctx *hctx, bool busy)
{
	unsigned int ewma;

	ewma = hctx->dispatch_busy;

	if (!ewma && !busy)
		return;

	ewma *= BLK_MQ_DISPATCH_BUSY_EWMA_WEIGHT - 1;
	if (busy)
		ewma += 1 << BLK_MQ_DISPATCH_BUSY_EWMA_FACTOR;
	ewma /= BLK_MQ_DISPATCH_BUSY_EWMA_WEIGHT;

	hctx->dispatch_busy = ewma;
}

static blk_status_t __blk_mq_issue_directly(struct blk_mq_hw_ctx *hctx,
					    struct request *rq, bool last)
{
	struct request_queue *q = rq->q;
	struct blk_mq_queue_data bd = {
		.rq = rq,
		.last = last,
	};
	blk_status_t ret;

	/*
	 * For OK queue, we are done. For error, caller may kill it.
	 * Any other error (busy), just add it to our list as we
	 * previously would have done.
	 */
	ret = q->mq_ops->queue_rq(hctx, &bd);
	switch (ret) {
	case BLK_STS_OK:
		blk_mq_update_dispatch_busy(hctx, false);
		break;
	case BLK_STS_RESOURCE:
	case BLK_STS_DEV_RESOURCE:
		blk_mq_update_dispatch_busy(hctx, true);
		__blk_mq_requeue_request(rq);
		break;
	default:
		blk_mq_update_dispatch_busy(hctx, false);
		break;
	}

	return ret;
}

static bool blk_mq_get_budget_and_tag(struct request *rq)
{
	int budget_token;

	budget_token = blk_mq_get_dispatch_budget(rq->q);
	if (budget_token < 0)
		return false;
	blk_mq_set_rq_budget_token(rq, budget_token);
	if (!blk_mq_get_driver_tag(rq)) {
		blk_mq_put_dispatch_budget(rq->q, budget_token);
		return false;
	}
	return true;
}

/*
 * Mark this ctx as having pending work in this hardware queue
 */
static void blk_mq_hctx_mark_pending(struct blk_mq_hw_ctx *hctx,
				     struct blk_mq_ctx *ctx)
{
	const int bit = ctx->index_hw[hctx->type];

	if (!sbitmap_test_bit(&hctx->ctx_map, bit))
		sbitmap_set_bit(&hctx->ctx_map, bit);
}

static void blk_mq_insert_request(struct request *rq, blk_insert_t flags)
{
	struct request_queue *q = rq->q;
	struct blk_mq_ctx *ctx = rq->mq_ctx;
	struct blk_mq_hw_ctx *hctx = rq->mq_hctx;

	if (blk_rq_is_passthrough(rq)) {
		/*
		 * Passthrough request have to be added to hctx->dispatch
		 * directly.  The device may be in a situation where it can't
		 * handle FS request, and always returns BLK_STS_RESOURCE for
		 * them, which gets them added to hctx->dispatch.
		 *
		 * If a passthrough request is required to unblock the queues,
		 * and it is added to the scheduler queue, there is no chance to
		 * dispatch it given we prioritize requests in hctx->dispatch.
		 */
		blk_mq_request_bypass_insert(rq, flags);
	} else if (req_op(rq) == REQ_OP_FLUSH) {
		/*
		 * Firstly normal IO request is inserted to scheduler queue or
		 * sw queue, meantime we add flush request to dispatch queue(
		 * hctx->dispatch) directly and there is at most one in-flight
		 * flush request for each hw queue, so it doesn't matter to add
		 * flush request to tail or front of the dispatch queue.
		 *
		 * Secondly in case of NCQ, flush request belongs to non-NCQ
		 * command, and queueing it will fail when there is any
		 * in-flight normal IO request(NCQ command). When adding flush
		 * rq to the front of hctx->dispatch, it is easier to introduce
		 * extra time to flush rq's latency because of S_SCHED_RESTART
		 * compared with adding to the tail of dispatch queue, then
		 * chance of flush merge is increased, and less flush requests
		 * will be issued to controller. It is observed that ~10% time
		 * is saved in blktests block/004 on disk attached to AHCI/NCQ
		 * drive when adding flush rq to the front of hctx->dispatch.
		 *
		 * Simply queue flush rq to the front of hctx->dispatch so that
		 * intensive flush workloads can benefit in case of NCQ HW.
		 */
		blk_mq_request_bypass_insert(rq, BLK_MQ_INSERT_AT_HEAD);
	} else if (q->elevator) {
		LIST_HEAD(list);

		WARN_ON_ONCE(rq->tag != BLK_MQ_NO_TAG);

		list_add(&rq->queuelist, &list);
		q->elevator->type->ops.insert_requests(hctx, &list, flags);
	} else {
		trace_block_rq_insert(rq);

		spin_lock(&ctx->lock);
		if (flags & BLK_MQ_INSERT_AT_HEAD)
			list_add(&rq->queuelist, &ctx->rq_lists[hctx->type]);
		else
			list_add_tail(&rq->queuelist,
				      &ctx->rq_lists[hctx->type]);
		blk_mq_hctx_mark_pending(hctx, ctx);
		spin_unlock(&ctx->lock);
	}
}


/**
 * blk_mq_try_issue_directly - Try to send a request directly to device driver.
 * @hctx: Pointer of the associated hardware queue.
 * @rq: Pointer to request to be sent.
 *
 * If the device has enough resources to accept a new request now, send the
 * request directly to device driver. Else, insert at hctx->dispatch queue, so
 * we can try send it another time in the future. Requests inserted at this
 * queue have higher priority.
 */
static void blk_mq_try_issue_directly(struct blk_mq_hw_ctx *hctx,
		struct request *rq)
{
	blk_status_t ret;

	if (blk_mq_hctx_stopped(hctx) || blk_queue_quiesced(rq->q)) {
		blk_mq_insert_request(rq, 0);
		return;
	}

	if ((rq->rq_flags & RQF_USE_SCHED) || !blk_mq_get_budget_and_tag(rq)) {
		blk_mq_insert_request(rq, 0);
		blk_mq_run_hw_queue(hctx, rq->cmd_flags & REQ_NOWAIT);
		return;
	}

	ret = __blk_mq_issue_directly(hctx, rq, true);
	switch (ret) {
	case BLK_STS_OK:
		break;
	case BLK_STS_RESOURCE:
	case BLK_STS_DEV_RESOURCE:
		blk_mq_request_bypass_insert(rq, 0);
		blk_mq_run_hw_queue(hctx, false);
		break;
	default:
		blk_mq_end_request(rq, ret);
		break;
	}
}

/*
 * Allow 2x BLK_MAX_REQUEST_COUNT requests on plug queue for multiple
 * queues. This is important for md arrays to benefit from merging
 * requests.
 */
static inline unsigned short blk_plug_max_rq_count(struct blk_plug *plug)
{
	if (plug->multiple_queues)
		return BLK_MAX_REQUEST_COUNT * 2;
	return BLK_MAX_REQUEST_COUNT;
}

static void blk_add_rq_to_plug(struct blk_plug *plug, struct request *rq)
{
	struct request *last = rq_list_peek(&plug->mq_list);

	if (!plug->rq_count) {
		trace_block_plug(rq->q);
	} else if (plug->rq_count >= blk_plug_max_rq_count(plug) ||
		   (!blk_queue_nomerges(rq->q) &&
		    blk_rq_bytes(last) >= BLK_PLUG_FLUSH_SIZE)) {
		blk_mq_flush_plug_list(plug, false);
		last = NULL;
		trace_block_plug(rq->q);
	}

	if (!plug->multiple_queues && last && last->q != rq->q)
		plug->multiple_queues = true;
	/*
	 * Any request allocated from sched tags can't be issued to
	 * ->queue_rqs() directly
	 */
	if (!plug->has_elevator && (rq->rq_flags & RQF_SCHED_TAGS))
		plug->has_elevator = true;
	rq->rq_next = NULL;
	rq_list_add(&plug->mq_list, rq);
	plug->rq_count++;
}

static inline void blk_account_io_start(struct request *req)
{
	trace_block_io_start(req);

	if (blk_do_io_stat(req)) {
		/*
		 * All non-passthrough requests are created from a bio with one
		 * exception: when a flush command that is part of a flush sequence
		 * generated by the state machine in blk-flush.c is cloned onto the
		 * lower device by dm-multipath we can get here without a bio.
		 */
		if (req->bio)
			req->part = req->bio->bi_bdev;
		else
			req->part = req->q->disk->part0;

		part_stat_lock();
		update_io_ticks(req->part, jiffies, false);
		part_stat_unlock();
	}
}

static void blk_mq_bio_to_request(struct request *rq, struct bio *bio,
		unsigned int nr_segs)
{
	int err;

	if (bio->bi_opf & REQ_RAHEAD)
		rq->cmd_flags |= REQ_FAILFAST_MASK;

	rq->__sector = bio->bi_iter.bi_sector;
	blk_rq_bio_prep(rq, bio, nr_segs);

	/* This can't fail, since GFP_NOIO includes __GFP_DIRECT_RECLAIM. */
	err = blk_crypto_rq_bio_prep(rq, bio, GFP_NOIO);
	WARN_ON_ONCE(err);

	blk_account_io_start(rq);
}

/* Set start and alloc time when the allocated request is actually used */
static inline void blk_mq_rq_time_init(struct request *rq, u64 alloc_time_ns)
{
	if (blk_mq_need_time_stamp(rq))
		rq->start_time_ns = ktime_get_ns();
	else
		rq->start_time_ns = 0;

#ifdef CONFIG_BLK_RQ_ALLOC_TIME
	if (blk_queue_rq_alloc_time(rq->q))
		rq->alloc_time_ns = alloc_time_ns ?: rq->start_time_ns;
	else
		rq->alloc_time_ns = 0;
#endif
}

static struct request *blk_mq_rq_ctx_init(struct blk_mq_alloc_data *data,
		struct blk_mq_tags *tags, unsigned int tag)
{
	struct blk_mq_ctx *ctx = data->ctx;
	struct blk_mq_hw_ctx *hctx = data->hctx;
	struct request_queue *q = data->q;
	struct request *rq = tags->static_rqs[tag];

	rq->q = q;
	rq->mq_ctx = ctx;
	rq->mq_hctx = hctx;
	rq->cmd_flags = data->cmd_flags;

	if (data->flags & BLK_MQ_REQ_PM)
		data->rq_flags |= RQF_PM;
	if (blk_queue_io_stat(q))
		data->rq_flags |= RQF_IO_STAT;
	rq->rq_flags = data->rq_flags;

	if (data->rq_flags & RQF_SCHED_TAGS) {
		rq->tag = BLK_MQ_NO_TAG;
		rq->internal_tag = tag;
	} else {
		rq->tag = tag;
		rq->internal_tag = BLK_MQ_NO_TAG;
	}
	rq->timeout = 0;

	rq->part = NULL;
	rq->io_start_time_ns = 0;
	rq->stats_sectors = 0;
	rq->nr_phys_segments = 0;
#if defined(CONFIG_BLK_DEV_INTEGRITY)
	rq->nr_integrity_segments = 0;
#endif
	rq->end_io = NULL;
	rq->end_io_data = NULL;

	blk_crypto_rq_set_defaults(rq);
	INIT_LIST_HEAD(&rq->queuelist);
	/* tag was already set */
	WRITE_ONCE(rq->deadline, 0);
	req_ref_set(rq, 1);

	if (rq->rq_flags & RQF_USE_SCHED) {
		struct elevator_queue *e = data->q->elevator;

		INIT_HLIST_NODE(&rq->hash);
		RB_CLEAR_NODE(&rq->rb_node);

		if (e->type->ops.prepare_request)
			e->type->ops.prepare_request(rq);
	}

	return rq;
}

static inline struct request *
__blk_mq_alloc_requests_batch(struct blk_mq_alloc_data *data)
{
	unsigned int tag, tag_offset;
	struct blk_mq_tags *tags;
	struct request *rq;
	unsigned long tag_mask;
	int i, nr = 0;

	tag_mask = blk_mq_get_tags(data, data->nr_tags, &tag_offset);
	if (unlikely(!tag_mask))
		return NULL;

	tags = blk_mq_tags_from_data(data);
	for (i = 0; tag_mask; i++) {
		if (!(tag_mask & (1UL << i)))
			continue;
		tag = tag_offset + i;
		prefetch(tags->static_rqs[tag]);
		tag_mask &= ~(1UL << i);
		rq = blk_mq_rq_ctx_init(data, tags, tag);
		rq_list_add(data->cached_rq, rq);
		nr++;
	}
	/* caller already holds a reference, add for remainder */
	percpu_ref_get_many(&data->q->q_usage_counter, nr - 1);
	data->nr_tags -= nr;

	return rq_list_pop(data->cached_rq);
}

static struct request *__blk_mq_alloc_requests(struct blk_mq_alloc_data *data)
{
	struct request_queue *q = data->q;
	u64 alloc_time_ns = 0;
	struct request *rq;
	unsigned int tag;

	/* alloc_time includes depth and tag waits */
	if (blk_queue_rq_alloc_time(q))
		alloc_time_ns = ktime_get_ns();

	if (data->cmd_flags & REQ_NOWAIT)
		data->flags |= BLK_MQ_REQ_NOWAIT;

	if (q->elevator) {
		/*
		 * All requests use scheduler tags when an I/O scheduler is
		 * enabled for the queue.
		 */
		data->rq_flags |= RQF_SCHED_TAGS;

		/*
		 * Flush/passthrough requests are special and go directly to the
		 * dispatch list.
		 */
		if ((data->cmd_flags & REQ_OP_MASK) != REQ_OP_FLUSH &&
		    !blk_op_is_passthrough(data->cmd_flags)) {
			struct elevator_mq_ops *ops = &q->elevator->type->ops;

			WARN_ON_ONCE(data->flags & BLK_MQ_REQ_RESERVED);

			data->rq_flags |= RQF_USE_SCHED;
			if (ops->limit_depth)
				ops->limit_depth(data->cmd_flags, data);
		}
	}

retry:
	data->ctx = blk_mq_get_ctx(q);
	data->hctx = blk_mq_map_queue(q, data->cmd_flags, data->ctx);
	if (!(data->rq_flags & RQF_SCHED_TAGS))
		blk_mq_tag_busy(data->hctx);

	if (data->flags & BLK_MQ_REQ_RESERVED)
		data->rq_flags |= RQF_RESV;

	/*
	 * Try batched alloc if we want more than 1 tag.
	 */
	if (data->nr_tags > 1) {
		rq = __blk_mq_alloc_requests_batch(data);
		if (rq) {
			blk_mq_rq_time_init(rq, alloc_time_ns);
			return rq;
		}
		data->nr_tags = 1;
	}

	/*
	 * Waiting allocations only fail because of an inactive hctx.  In that
	 * case just retry the hctx assignment and tag allocation as CPU hotplug
	 * should have migrated us to an online CPU by now.
	 */
	tag = blk_mq_get_tag(data);
	if (tag == BLK_MQ_NO_TAG) {
		if (data->flags & BLK_MQ_REQ_NOWAIT)
			return NULL;
		/*
		 * Give up the CPU and sleep for a random short time to
		 * ensure that thread using a realtime scheduling class
		 * are migrated off the CPU, and thus off the hctx that
		 * is going away.
		 */
		msleep(3);
		goto retry;
	}

	rq = blk_mq_rq_ctx_init(data, blk_mq_tags_from_data(data), tag);
	blk_mq_rq_time_init(rq, alloc_time_ns);
	return rq;
}

static bool blk_mq_attempt_bio_merge(struct request_queue *q,
				     struct bio *bio, unsigned int nr_segs)
{
	if (!blk_queue_nomerges(q) && bio_mergeable(bio)) {
		if (blk_attempt_plug_merge(q, bio, nr_segs))
			return true;
		if (blk_mq_sched_bio_merge(q, bio, nr_segs))
			return true;
	}
	return false;
}

KTDEF(rq_qos_throttle);
static struct request *blk_mq_get_new_requests(struct request_queue *q,
					       struct blk_plug *plug,
					       struct bio *bio,
					       unsigned int nsegs)
{
	struct blk_mq_alloc_data data = {
		.q		= q,
		.nr_tags	= 1,
		.cmd_flags	= bio->bi_opf,
	};
	struct request *rq;

	if (blk_mq_attempt_bio_merge(q, bio, nsegs)) {
		return NULL;
	}

#ifdef __PROFILING
#endif 
	rq_qos_throttle(q, bio);
#ifdef __PROFILING
#endif 

	if (plug) {
		data.nr_tags = plug->nr_ios;
		plug->nr_ios = 1;
		data.cached_rq = &plug->cached_rq;
	}

	rq = __blk_mq_alloc_requests(&data);
	if (rq)
		return rq;
	rq_qos_cleanup(q, bio);
	if (bio->bi_opf & REQ_NOWAIT)
		bio_wouldblock_error(bio);
	return NULL;
}

/* return true if this @rq can be used for @bio */
static bool blk_mq_can_use_cached_rq(struct request *rq, struct blk_plug *plug,
		struct bio *bio)
{
	enum hctx_type type = blk_mq_get_hctx_type(bio->bi_opf);
	enum hctx_type hctx_type = rq->mq_hctx->type;

	WARN_ON_ONCE(rq_list_peek(&plug->cached_rq) != rq);

	if (type != hctx_type &&
	    !(type == HCTX_TYPE_READ && hctx_type == HCTX_TYPE_DEFAULT))
		return false;
	if (op_is_flush(rq->cmd_flags) != op_is_flush(bio->bi_opf))
		return false;

	/*
	 * If any qos ->throttle() end up blocking, we will have flushed the
	 * plug and hence killed the cached_rq list as well. Pop this entry
	 * before we throttle.
	 */
	plug->cached_rq = rq_list_next(rq);
	rq_qos_throttle(rq->q, bio);

	blk_mq_rq_time_init(rq, 0);
	rq->cmd_flags = bio->bi_opf;
	INIT_LIST_HEAD(&rq->queuelist);
	return true;
}

static void bio_set_ioprio(struct bio *bio)
{
	/* Nobody set ioprio so far? Initialize it based on task's nice value */
	if (IOPRIO_PRIO_CLASS(bio->bi_ioprio) == IOPRIO_CLASS_NONE)
		bio->bi_ioprio = get_current_ioprio();
	blkcg_set_ioprio(bio);
}


/**
 * blk_mq_submit_bio - Create and send a request to block device.
 * @bio: Bio pointer.
 *
 * Builds up a request structure from @q and @bio and send to the device. The
 * request may not be queued directly to hardware if:
 * * This request can be merged with another one
 * * We want to place request at plug queue for possible future merging
 * * There is an IO scheduler active at this queue
 *
 * It will not queue the request if there is an error with the bio, or at the
 * request creation.
 */
KTDEF(blk_mq_get_new_requests);
void blk_mq_submit_bio(struct bio *bio)
{
	struct request_queue *q = bdev_get_queue(bio->bi_bdev);
	struct blk_plug *plug = blk_mq_plug(bio);
	const int is_sync = op_is_sync(bio->bi_opf);
	struct blk_mq_hw_ctx *hctx;
	struct request *rq = NULL;
	unsigned int nr_segs = 1;
	blk_status_t ret;

	bio = blk_queue_bounce(bio, q);
	if (bio_may_exceed_limits(bio, &q->limits)) {
		bio = __bio_split_to_limits(bio, &q->limits, &nr_segs);
		if (!bio)
			return;
	}

	bio_set_ioprio(bio);

	if (plug) {
		rq = rq_list_peek(&plug->cached_rq);
		if (rq && rq->q != q)
			rq = NULL;
	}
	if (rq) {
		if (!bio_integrity_prep(bio))
			return;
		if (blk_mq_attempt_bio_merge(q, bio, nr_segs))
			return;
		if (blk_mq_can_use_cached_rq(rq, plug, bio))
			goto done;
		percpu_ref_get(&q->q_usage_counter);
	} else {
		if (unlikely(bio_queue_enter(bio)))
			return;
		if (!bio_integrity_prep(bio))
			goto fail;
	}

#ifdef __PROFILING
#endif 
	rq = blk_mq_get_new_requests(q, plug, bio, nr_segs);
#ifdef __PROFILING
#endif 
	if (unlikely(!rq)) {
fail:
		blk_queue_exit(q);
		return;
	}

done:
	trace_block_getrq(bio);

	rq_qos_track(q, rq, bio);

	blk_mq_bio_to_request(rq, bio, nr_segs);

	ret = blk_crypto_rq_get_keyslot(rq);
	if (ret != BLK_STS_OK) {
		bio->bi_status = ret;
		bio_endio(bio);
		blk_mq_free_request(rq);
		return;
	}

	if (op_is_flush(bio->bi_opf) && blk_insert_flush(rq))
		return;

	if (plug) {
		blk_add_rq_to_plug(plug, rq);
		return;
	}

	hctx = rq->mq_hctx;
	if ((rq->rq_flags & RQF_USE_SCHED) ||
	    (hctx->dispatch_busy && (q->nr_hw_queues == 1 || !is_sync))) {
		blk_mq_insert_request(rq, 0);
		blk_mq_run_hw_queue(hctx, true);
	} else {
		blk_mq_run_dispatch_ops(q, blk_mq_try_issue_directly(hctx, rq));
	}
}
