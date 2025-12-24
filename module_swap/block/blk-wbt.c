// SPDX-License-Identifier: GPL-2.0
/*
 * buffered writeback throttling. loosely based on CoDel. We can't drop
 * packets for IO scheduling, so the logic is something like this:
 *
 * - Monitor latencies in a defined window of time.
 * - If the minimum latency in the above window exceeds some target, increment
 *   scaling step and scale down queue depth by a factor of 2x. The monitoring
 *   window is then shrunk to 100 / sqrt(scaling step + 1).
 * - For any window where we don't have solid data on what the latencies
 *   look like, retain status quo.
 * - If latencies look good, decrement scaling step.
 * - If we're only doing writes, allow the scaling step to go negative. This
 *   will temporarily boost write performance, snapping back to a stable
 *   scaling step of 0 if reads show up or the heavy writers finish. Unlike
 *   positive scaling steps where we shrink the monitoring window, a negative
 *   scaling step retains the default step==0 window size.
 *
 * Copyright (C) 2016 Jens Axboe
 *
 */
#include <linux/kernel.h>
#include <linux/blk_types.h>
#include <linux/slab.h>
#include <linux/backing-dev.h>
#include <linux/swap.h>

#include "blk-stat.h"
#include "blk-wbt.h"
#include "blk-rq-qos.h"
#include "elevator.h"

#include <linux/calclock.h>

#define CREATE_TRACE_POINTS
#include <trace/events/wbt.h>


enum wbt_flags {
	WBT_TRACKED		= 1,	/* write, tracked for throttling */
	WBT_READ		= 2,	/* read */
	WBT_KSWAPD		= 4,	/* write, from kswapd */
	WBT_DISCARD		= 8,	/* discard */

	WBT_NR_BITS		= 4,	/* number of bits */
};

enum {
	WBT_RWQ_BG		= 0,
	WBT_RWQ_KSWAPD,
	WBT_RWQ_DISCARD,
	WBT_NUM_RWQ,
};

/*
 * If current state is WBT_STATE_ON/OFF_DEFAULT, it can be covered to any other
 * state, if current state is WBT_STATE_ON/OFF_MANUAL, it can only be covered
 * to WBT_STATE_OFF/ON_MANUAL.
 */
enum {
	WBT_STATE_ON_DEFAULT	= 1,	/* on by default */
	WBT_STATE_ON_MANUAL	= 2,	/* on manually by sysfs */
	WBT_STATE_OFF_DEFAULT	= 3,	/* off by default */
	WBT_STATE_OFF_MANUAL	= 4,	/* off manually by sysfs */
};

struct rq_wb {
	/*
	 * Settings that govern how we throttle
	 */
	unsigned int wb_background;		/* background writeback */
	unsigned int wb_normal;			/* normal writeback */

	short enable_state;			/* WBT_STATE_* */

	/*
	 * Number of consecutive periods where we don't have enough
	 * information to make a firm scale up/down decision.
	 */
	unsigned int unknown_cnt;

	u64 win_nsec;				/* default window size */
	u64 cur_win_nsec;			/* current window size */

	struct blk_stat_callback *cb;

	u64 sync_issue;
	void *sync_cookie;

	unsigned int wc;

	unsigned long last_issue;		/* last non-throttled issue */
	unsigned long last_comp;		/* last non-throttled comp */
	unsigned long min_lat_nsec;
	struct rq_qos rqos;
	struct rq_wait rq_wait[WBT_NUM_RWQ];
	struct rq_depth rq_depth;
};

static inline struct rq_wb *RQWB(struct rq_qos *rqos)
{
	return container_of(rqos, struct rq_wb, rqos);
}

static void rwb_arm_timer(struct rq_wb *rwb)
{
	struct rq_depth *rqd = &rwb->rq_depth;

	if (rqd->scale_step > 0) {
		/*
		 * We should speed this up, using some variant of a fast
		 * integer inverse square root calculation. Since we only do
		 * this for every window expiration, it's not a huge deal,
		 * though.
		 */
		rwb->cur_win_nsec = div_u64(rwb->win_nsec << 4,
					int_sqrt((rqd->scale_step + 1) << 8));
	} else {
		/*
		 * For step < 0, we don't want to increase/decrease the
		 * window size.
		 */
		rwb->cur_win_nsec = rwb->win_nsec;
	}

	blk_stat_activate_nsecs(rwb->cb, rwb->cur_win_nsec);
}

static inline bool rwb_enabled(struct rq_wb *rwb)
{
	return rwb && rwb->enable_state != WBT_STATE_OFF_DEFAULT &&
		      rwb->enable_state != WBT_STATE_OFF_MANUAL;
}

static void wb_timestamp(struct rq_wb *rwb, unsigned long *var)
{
	if (rwb_enabled(rwb)) {
		const unsigned long cur = jiffies;

		if (cur != *var)
			*var = cur;
	}
}

static inline bool wbt_should_throttle(struct bio *bio)
{

	switch (bio_op(bio)) {
	case REQ_OP_WRITE:
		/*
		 * Don't throttle WRITE_ODIRECT
		 */
		if ((bio->bi_opf & (REQ_SYNC | REQ_IDLE)) ==
		    (REQ_SYNC | REQ_IDLE))
			return false;
		fallthrough;
	case REQ_OP_DISCARD:
		return true;
	default:
		return false;
	}
}

static enum wbt_flags bio_to_wbt_flags(struct rq_wb *rwb, struct bio *bio)
{
	enum wbt_flags flags = 0;

	if (!rwb_enabled(rwb))
		return 0;

	if (bio_op(bio) == REQ_OP_READ) {
		flags = WBT_READ;
	} else if (wbt_should_throttle(bio)) {
		if (current_is_kswapd())
			flags |= WBT_KSWAPD;
		if (bio_op(bio) == REQ_OP_DISCARD)
			flags |= WBT_DISCARD;
		flags |= WBT_TRACKED;
	}
	return flags;
}

/*
 * If a task was rate throttled in balance_dirty_pages() within the last
 * second or so, use that to indicate a higher cleaning rate.
 */
static bool wb_recent_wait(struct rq_wb *rwb)
{
	struct bdi_writeback *wb = &rwb->rqos.disk->bdi->wb;

	return time_before(jiffies, wb->dirty_sleep + HZ);
}

static void wbt_rqw_done(struct rq_wb *rwb, struct rq_wait *rqw,
			 enum wbt_flags wb_acct)
{
	int inflight, limit;

	inflight = atomic_dec_return(&rqw->inflight);

	/*
	 * For discards, our limit is always the background. For writes, if
	 * the device does write back caching, drop further down before we
	 * wake people up.
	 */
	if (wb_acct & WBT_DISCARD)
		limit = rwb->wb_background;
	else if (rwb->wc && !wb_recent_wait(rwb))
		limit = 0;
	else
		limit = rwb->wb_normal;

	/*
	 * Don't wake anyone up if we are above the normal limit.
	 */
	if (inflight && inflight >= limit)
		return;

	if (wq_has_sleeper(&rqw->wait)) {
		int diff = limit - inflight;

		if (!inflight || diff >= rwb->wb_background / 2)
			wake_up_all(&rqw->wait);
	}
}

static inline struct rq_wait *get_rq_wait(struct rq_wb *rwb,
					  enum wbt_flags wb_acct)
{
	if (wb_acct & WBT_KSWAPD)
		return &rwb->rq_wait[WBT_RWQ_KSWAPD];
	else if (wb_acct & WBT_DISCARD)
		return &rwb->rq_wait[WBT_RWQ_DISCARD];

	return &rwb->rq_wait[WBT_RWQ_BG];
}

static bool close_io(struct rq_wb *rwb)
{
	const unsigned long now = jiffies;

	return time_before(now, rwb->last_issue + HZ / 10) ||
		time_before(now, rwb->last_comp + HZ / 10);
}

#define REQ_HIPRIO	(REQ_SYNC | REQ_META | REQ_PRIO)

static inline unsigned int get_limit(struct rq_wb *rwb, blk_opf_t opf)
{
	unsigned int limit;

	if ((opf & REQ_OP_MASK) == REQ_OP_DISCARD)
		return rwb->wb_background;

	/*
	 * At this point we know it's a buffered write. If this is
	 * kswapd trying to free memory, or REQ_SYNC is set, then
	 * it's WB_SYNC_ALL writeback, and we'll use the max limit for
	 * that. If the write is marked as a background write, then use
	 * the idle limit, or go to normal if we haven't had competing
	 * IO for a bit.
	 */
	if ((opf & REQ_HIPRIO) || wb_recent_wait(rwb) || current_is_kswapd())
		limit = rwb->rq_depth.max_depth;
	else if ((opf & REQ_BACKGROUND) || close_io(rwb)) {
		/*
		 * If less than 100ms since we completed unrelated IO,
		 * limit us to half the depth for background writeback.
		 */
		limit = rwb->wb_background;
	} else
		limit = rwb->wb_normal;

	return limit;
}

struct wbt_wait_data {
	struct rq_wb *rwb;
	enum wbt_flags wb_acct;
	blk_opf_t opf;
};

static bool wbt_inflight_cb(struct rq_wait *rqw, void *private_data)
{
	struct wbt_wait_data *data = private_data;
	return rq_wait_inc_below(rqw, get_limit(data->rwb, data->opf));
}

static void wbt_cleanup_cb(struct rq_wait *rqw, void *private_data)
{
	struct wbt_wait_data *data = private_data;
	wbt_rqw_done(data->rwb, rqw, data->wb_acct);
}

struct rq_qos_wait_data {
	struct wait_queue_entry wq;
	struct task_struct *task;
	struct rq_wait *rqw;
	acquire_inflight_cb_t *cb;
	void *private_data;
	bool got_token;
};

static int rq_qos_wake_function(struct wait_queue_entry *curr,
				unsigned int mode, int wake_flags, void *key)
{
	struct rq_qos_wait_data *data = container_of(curr,
						     struct rq_qos_wait_data,
						     wq);

	/*
	 * If we fail to get a budget, return -1 to interrupt the wake up loop
	 * in __wake_up_common.
	 */
	if (!data->cb(data->rqw, data->private_data))
		return -1;

	data->got_token = true;
	smp_wmb();
	list_del_init(&curr->entry);
	wake_up_process(data->task);
	return 1;
}

/**
 * rq_qos_wait - throttle on a rqw if we need to
 * @rqw: rqw to throttle on
 * @private_data: caller provided specific data
 * @acquire_inflight_cb: inc the rqw->inflight counter if we can
 * @cleanup_cb: the callback to cleanup in case we race with a waker
 *
 * This provides a uniform place for the rq_qos users to do their throttling.
 * Since you can end up with a lot of things sleeping at once, this manages the
 * waking up based on the resources available.  The acquire_inflight_cb should
 * inc the rqw->inflight if we have the ability to do so, or return false if not
 * and then we will sleep until the room becomes available.
 *
 * cleanup_cb is in case that we race with a waker and need to cleanup the
 * inflight count accordingly.
 */
KTDEF(io_schedule);
void rq_qos_wait(struct rq_wait *rqw, void *private_data,
		 acquire_inflight_cb_t *acquire_inflight_cb,
		 cleanup_cb_t *cleanup_cb)
{
	struct rq_qos_wait_data data = {
		.wq = {
			.func	= rq_qos_wake_function,
			.entry	= LIST_HEAD_INIT(data.wq.entry),
		},
		.task = current,
		.rqw = rqw,
		.cb = acquire_inflight_cb,
		.private_data = private_data,
	};
	bool has_sleeper;

	has_sleeper = wq_has_sleeper(&rqw->wait);
	if (!has_sleeper && acquire_inflight_cb(rqw, private_data))
		return;

	has_sleeper = !prepare_to_wait_exclusive(&rqw->wait, &data.wq,
						 TASK_UNINTERRUPTIBLE);

	do {
		/* The memory barrier in set_task_state saves us here. */
		if (data.got_token)
			break;
		if (!has_sleeper && acquire_inflight_cb(rqw, private_data)) {
			finish_wait(&rqw->wait, &data.wq);

			/*
			 * We raced with rq_qos_wake_function() getting a token,
			 * which means we now have two. Put our local token
			 * and wake anyone else potentially waiting for one.
			 */
			smp_rmb();
			if (data.got_token)
				cleanup_cb(rqw, private_data);
			break;
		}
#ifdef __PROFILING
#endif 
		io_schedule();
#ifdef __PROFILING
#endif 
		has_sleeper = true;
		set_current_state(TASK_UNINTERRUPTIBLE);
	} while (1);
	finish_wait(&rqw->wait, &data.wq);
}

/*
 * Block if we will exceed our limit, or if we are currently waiting for
 * the timer to kick off queuing again.
 */
KTDEF(__wbt_wait);
static void __wbt_wait(struct rq_wb *rwb, enum wbt_flags wb_acct,
		       blk_opf_t opf)
{
	struct rq_wait *rqw = get_rq_wait(rwb, wb_acct);
	struct wbt_wait_data data = {
		.rwb = rwb,
		.wb_acct = wb_acct,
		.opf = opf,
	};

#ifdef __PROFILING
#endif 
	rq_qos_wait(rqw, &data, wbt_inflight_cb, wbt_cleanup_cb);
#ifdef __PROFILING
#endif 
}

/*
 * May sleep, if we have exceeded the writeback limits. Caller can pass
 * in an irq held spinlock, if it holds one when calling this function.
 * If we do sleep, we'll release and re-grab it.
 */
void _k_wbt_wait(struct rq_qos *rqos, struct bio *bio)
{
	struct rq_wb *rwb = RQWB(rqos);
	enum wbt_flags flags;

	flags = bio_to_wbt_flags(rwb, bio);
	if (!(flags & WBT_TRACKED)) {
		if (flags & WBT_READ)
			wb_timestamp(rwb, &rwb->last_issue);
		return;
	}

	__wbt_wait(rwb, flags, bio->bi_opf);

	if (!blk_stat_is_active(rwb->cb))
		rwb_arm_timer(rwb);
}
