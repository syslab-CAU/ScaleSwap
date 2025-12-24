/* SPDX-License-Identifier: GPL-2.0
 *
 * IO cost model based controller.
 *
 * Copyright (C) 2019 Tejun Heo <tj@kernel.org>
 * Copyright (C) 2019 Andy Newell <newella@fb.com>
 * Copyright (C) 2019 Facebook
 *
 * One challenge of controlling IO resources is the lack of trivially
 * observable cost metric.  This is distinguished from CPU and memory where
 * wallclock time and the number of bytes can serve as accurate enough
 * approximations.
 *
 * Bandwidth and iops are the most commonly used metrics for IO devices but
 * depending on the type and specifics of the device, different IO patterns
 * easily lead to multiple orders of magnitude variations rendering them
 * useless for the purpose of IO capacity distribution.  While on-device
 * time, with a lot of clutches, could serve as a useful approximation for
 * non-queued rotational devices, this is no longer viable with modern
 * devices, even the rotational ones.
 *
 * While there is no cost metric we can trivially observe, it isn't a
 * complete mystery.  For example, on a rotational device, seek cost
 * dominates while a contiguous transfer contributes a smaller amount
 * proportional to the size.  If we can characterize at least the relative
 * costs of these different types of IOs, it should be possible to
 * implement a reasonable work-conserving proportional IO resource
 * distribution.
 *
 * 1. IO Cost Model
 *
 * IO cost model estimates the cost of an IO given its basic parameters and
 * history (e.g. the end sector of the last IO).  The cost is measured in
 * device time.  If a given IO is estimated to cost 10ms, the device should
 * be able to process ~100 of those IOs in a second.
 *
 * Currently, there's only one builtin cost model - linear.  Each IO is
 * classified as sequential or random and given a base cost accordingly.
 * On top of that, a size cost proportional to the length of the IO is
 * added.  While simple, this model captures the operational
 * characteristics of a wide varienty of devices well enough.  Default
 * parameters for several different classes of devices are provided and the
 * parameters can be configured from userspace via
 * /sys/fs/cgroup/io.cost.model.
 *
 * If needed, tools/cgroup/iocost_coef_gen.py can be used to generate
 * device-specific coefficients.
 *
 * 2. Control Strategy
 *
 * The device virtual time (vtime) is used as the primary control metric.
 * The control strategy is composed of the following three parts.
 *
 * 2-1. Vtime Distribution
 *
 * When a cgroup becomes active in terms of IOs, its hierarchical share is
 * calculated.  Please consider the following hierarchy where the numbers
 * inside parentheses denote the configured weights.
 *
 *           root
 *         /       \
 *      A (w:100)  B (w:300)
 *      /       \
 *  A0 (w:100)  A1 (w:100)
 *
 * If B is idle and only A0 and A1 are actively issuing IOs, as the two are
 * of equal weight, each gets 50% share.  If then B starts issuing IOs, B
 * gets 300/(100+300) or 75% share, and A0 and A1 equally splits the rest,
 * 12.5% each.  The distribution mechanism only cares about these flattened
 * shares.  They're called hweights (hierarchical weights) and always add
 * upto 1 (WEIGHT_ONE).
 *
 * A given cgroup's vtime runs slower in inverse proportion to its hweight.
 * For example, with 12.5% weight, A0's time runs 8 times slower (100/12.5)
 * against the device vtime - an IO which takes 10ms on the underlying
 * device is considered to take 80ms on A0.
 *
 * This constitutes the basis of IO capacity distribution.  Each cgroup's
 * vtime is running at a rate determined by its hweight.  A cgroup tracks
 * the vtime consumed by past IOs and can issue a new IO if doing so
 * wouldn't outrun the current device vtime.  Otherwise, the IO is
 * suspended until the vtime has progressed enough to cover it.
 *
 * 2-2. Vrate Adjustment
 *
 * It's unrealistic to expect the cost model to be perfect.  There are too
 * many devices and even on the same device the overall performance
 * fluctuates depending on numerous factors such as IO mixture and device
 * internal garbage collection.  The controller needs to adapt dynamically.
 *
 * This is achieved by adjusting the overall IO rate according to how busy
 * the device is.  If the device becomes overloaded, we're sending down too
 * many IOs and should generally slow down.  If there are waiting issuers
 * but the device isn't saturated, we're issuing too few and should
 * generally speed up.
 *
 * To slow down, we lower the vrate - the rate at which the device vtime
 * passes compared to the wall clock.  For example, if the vtime is running
 * at the vrate of 75%, all cgroups added up would only be able to issue
 * 750ms worth of IOs per second, and vice-versa for speeding up.
 *
 * Device business is determined using two criteria - rq wait and
 * completion latencies.
 *
 * When a device gets saturated, the on-device and then the request queues
 * fill up and a bio which is ready to be issued has to wait for a request
 * to become available.  When this delay becomes noticeable, it's a clear
 * indication that the device is saturated and we lower the vrate.  This
 * saturation signal is fairly conservative as it only triggers when both
 * hardware and software queues are filled up, and is used as the default
 * busy signal.
 *
 * As devices can have deep queues and be unfair in how the queued commands
 * are executed, solely depending on rq wait may not result in satisfactory
 * control quality.  For a better control quality, completion latency QoS
 * parameters can be configured so that the device is considered saturated
 * if N'th percentile completion latency rises above the set point.
 *
 * The completion latency requirements are a function of both the
 * underlying device characteristics and the desired IO latency quality of
 * service.  There is an inherent trade-off - the tighter the latency QoS,
 * the higher the bandwidth lossage.  Latency QoS is disabled by default
 * and can be set through /sys/fs/cgroup/io.cost.qos.
 *
 * 2-3. Work Conservation
 *
 * Imagine two cgroups A and B with equal weights.  A is issuing a small IO
 * periodically while B is sending out enough parallel IOs to saturate the
 * device on its own.  Let's say A's usage amounts to 100ms worth of IO
 * cost per second, i.e., 10% of the device capacity.  The naive
 * distribution of half and half would lead to 60% utilization of the
 * device, a significant reduction in the total amount of work done
 * compared to free-for-all competition.  This is too high a cost to pay
 * for IO control.
 *
 * To conserve the total amount of work done, we keep track of how much
 * each active cgroup is actually using and yield part of its weight if
 * there are other cgroups which can make use of it.  In the above case,
 * A's weight will be lowered so that it hovers above the actual usage and
 * B would be able to use the rest.
 *
 * As we don't want to penalize a cgroup for donating its weight, the
 * surplus weight adjustment factors in a margin and has an immediate
 * snapback mechanism in case the cgroup needs more IO vtime for itself.
 *
 * Note that adjusting down surplus weights has the same effects as
 * accelerating vtime for other cgroups and work conservation can also be
 * implemented by adjusting vrate dynamically.  However, squaring who can
 * donate and should take back how much requires hweight propagations
 * anyway making it easier to implement and understand as a separate
 * mechanism.
 *
 * 3. Monitoring
 *
 * Instead of debugfs or other clumsy monitoring mechanisms, this
 * controller uses a drgn based monitoring script -
 * tools/cgroup/iocost_monitor.py.  For details on drgn, please see
 * https://github.com/osandov/drgn.  The output looks like the following.
 *
 *  sdb RUN   per=300ms cur_per=234.218:v203.695 busy= +1 vrate= 62.12%
 *                 active      weight      hweight% inflt% dbt  delay usages%
 *  test/a              *    50/   50  33.33/ 33.33  27.65   2  0*041 033:033:033
 *  test/b              *   100/  100  66.67/ 66.67  17.56   0  0*000 066:079:077
 *
 * - per	: Timer period
 * - cur_per	: Internal wall and device vtime clock
 * - vrate	: Device virtual time rate against wall clock
 * - weight	: Surplus-adjusted and configured weights
 * - hweight	: Surplus-adjusted and configured hierarchical weights
 * - inflt	: The percentage of in-flight IO cost at the end of last period
 * - del_ms	: Deferred issuer delay induction level and duration
 * - usages	: Usage history
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/timer.h>
#include <linux/time64.h>
#include <linux/parser.h>
#include <linux/sched/signal.h>
#include <asm/local.h>
#include <asm/local64.h>
#include "blk-rq-qos.h"
#include "blk-stat.h"
#include "blk-wbt.h"
#include "blk-cgroup.h"

#include "iocost.h"
#include <linux/calclock.h>


struct iocg_pcpu_stat {
	local64_t			abs_vusage;
};

struct ioc_now {
	u64				now_ns;
	u64				now;
	u64				vnow;
};

struct iocg_stat {
	u64				usage_us;
	u64				wait_us;
	u64				indebt_us;
	u64				indelay_us;
};

struct ioc_margins {
	s64				min;
	s64				low;
	s64				target;
};

enum ioc_running {
	IOC_IDLE,
	IOC_RUNNING,
	IOC_STOP,
};

enum {
	/* if IOs end up waiting for requests, issue less */
	RQ_WAIT_BUSY_PCT	= 5,

	/* unbusy hysterisis */
	UNBUSY_THR_PCT		= 75,

	/*
	 * The effect of delay is indirect and non-linear and a huge amount of
	 * future debt can accumulate abruptly while unthrottled. Linearly scale
	 * up delay as debt is going up and then let it decay exponentially.
	 * This gives us quick ramp ups while delay is accumulating and long
	 * tails which can help reducing the frequency of debt explosions on
	 * unthrottle. The parameters are experimentally determined.
	 *
	 * The delay mechanism provides adequate protection and behavior in many
	 * cases. However, this is far from ideal and falls shorts on both
	 * fronts. The debtors are often throttled too harshly costing a
	 * significant level of fairness and possibly total work while the
	 * protection against their impacts on the system can be choppy and
	 * unreliable.
	 *
	 * The shortcoming primarily stems from the fact that, unlike for page
	 * cache, the kernel doesn't have well-defined back-pressure propagation
	 * mechanism and policies for anonymous memory. Fully addressing this
	 * issue will likely require substantial improvements in the area.
	 */
	MIN_DELAY_THR_PCT	= 500,
	MAX_DELAY_THR_PCT	= 25000,
	MIN_DELAY		= 250,
	MAX_DELAY		= 250 * USEC_PER_MSEC,

	/* halve debts if avg usage over 100ms is under 50% */
	DFGV_USAGE_PCT		= 50,
	DFGV_PERIOD		= 100 * USEC_PER_MSEC,

	/* don't let cmds which take a very long time pin lagging for too long */
	MAX_LAGGING_PERIODS	= 10,

	/*
	 * Count IO size in 4k pages.  The 12bit shift helps keeping
	 * size-proportional components of cost calculation in closer
	 * numbers of digits to per-IO cost components.
	 */
	IOC_PAGE_SHIFT		= 12,
	IOC_PAGE_SIZE		= 1 << IOC_PAGE_SHIFT,
	IOC_SECT_TO_PAGE_SHIFT	= IOC_PAGE_SHIFT - SECTOR_SHIFT,

	/* if apart further than 16M, consider randio for linear model */
	LCOEF_RANDIO_PAGES	= 4096,
};

/* io.cost.qos params */
enum {
	QOS_RPPM,
	QOS_RLAT,
	QOS_WPPM,
	QOS_WLAT,
	QOS_MIN,
	QOS_MAX,
	NR_QOS_PARAMS,
};

/* builtin linear cost model coefficients */
enum {
	I_LCOEF_RBPS,
	I_LCOEF_RSEQIOPS,
	I_LCOEF_RRANDIOPS,
	I_LCOEF_WBPS,
	I_LCOEF_WSEQIOPS,
	I_LCOEF_WRANDIOPS,
	NR_I_LCOEFS,
};

enum {
	LCOEF_RPAGE,
	LCOEF_RSEQIO,
	LCOEF_RRANDIO,
	LCOEF_WPAGE,
	LCOEF_WSEQIO,
	LCOEF_WRANDIO,
	NR_LCOEFS,
};

static const match_table_t qos_tokens = {
	{ QOS_RPPM,		"rpct=%s"	},
	{ QOS_RLAT,		"rlat=%u"	},
	{ QOS_WPPM,		"wpct=%s"	},
	{ QOS_WLAT,		"wlat=%u"	},
	{ QOS_MIN,		"min=%s"	},
	{ QOS_MAX,		"max=%s"	},
	{ NR_QOS_PARAMS,	NULL		},
};

struct ioc_params {
	u32				qos[NR_QOS_PARAMS];
	u64				i_lcoefs[NR_I_LCOEFS];
	u64				lcoefs[NR_LCOEFS];
	u32				too_fast_vrate_pct;
	u32				too_slow_vrate_pct;
};

struct iocg_wait {
	struct wait_queue_entry		wait;
	struct bio			*bio;
	u64				abs_cost;
	bool				committed;
};

/* per device-cgroup pair */
struct ioc_gq {
	struct blkg_policy_data		pd;
	struct ioc			*ioc;

	/*
	 * A iocg can get its weight from two sources - an explicit
	 * per-device-cgroup configuration or the default weight of the
	 * cgroup.  `cfg_weight` is the explicit per-device-cgroup
	 * configuration.  `weight` is the effective considering both
	 * sources.
	 *
	 * When an idle cgroup becomes active its `active` goes from 0 to
	 * `weight`.  `inuse` is the surplus adjusted active weight.
	 * `active` and `inuse` are used to calculate `hweight_active` and
	 * `hweight_inuse`.
	 *
	 * `last_inuse` remembers `inuse` while an iocg is idle to persist
	 * surplus adjustments.
	 *
	 * `inuse` may be adjusted dynamically during period. `saved_*` are used
	 * to determine and track adjustments.
	 */
	u32				cfg_weight;
	u32				weight;
	u32				active;
	u32				inuse;

	u32				last_inuse;
	s64				saved_margin;

	sector_t			cursor;		/* to detect randio */

	/*
	 * `vtime` is this iocg's vtime cursor which progresses as IOs are
	 * issued.  If lagging behind device vtime, the delta represents
	 * the currently available IO budget.  If running ahead, the
	 * overage.
	 *
	 * `vtime_done` is the same but progressed on completion rather
	 * than issue.  The delta behind `vtime` represents the cost of
	 * currently in-flight IOs.
	 */
	atomic64_t			vtime;
	atomic64_t			done_vtime;
	u64				abs_vdebt;

	/* current delay in effect and when it started */
	u64				delay;
	u64				delay_at;

	/*
	 * The period this iocg was last active in.  Used for deactivation
	 * and invalidating `vtime`.
	 */
	atomic64_t			active_period;
	struct list_head		active_list;

	/* see __propagate_weights() and current_hweight() for details */
	u64				child_active_sum;
	u64				child_inuse_sum;
	u64				child_adjusted_sum;
	int				hweight_gen;
	u32				hweight_active;
	u32				hweight_inuse;
	u32				hweight_donating;
	u32				hweight_after_donation;

	struct list_head		walk_list;
	struct list_head		surplus_list;

	struct wait_queue_head		waitq;
	struct hrtimer			waitq_timer;

	/* timestamp at the latest activation */
	u64				activated_at;

	/* statistics */
	struct iocg_pcpu_stat __percpu	*pcpu_stat;
	struct iocg_stat		stat;
	struct iocg_stat		last_stat;
	u64				last_stat_abs_vusage;
	u64				usage_delta_us;
	u64				wait_since;
	u64				indebt_since;
	u64				indelay_since;

	/* this iocg's depth in the hierarchy and ancestors including self */
	int				level;
	struct ioc_gq			*ancestors[];
};

struct iocg_wake_ctx {
	struct ioc_gq			*iocg;
	u32				hw_inuse;
	s64				vbudget;
};

/* per device */
struct ioc {
	struct rq_qos			rqos;

	bool				enabled;

	struct ioc_params		params;
	struct ioc_margins		margins;
	u32				period_us;
	u32				timer_slack_ns;
	u64				vrate_min;
	u64				vrate_max;

	spinlock_t			lock;
	struct timer_list		timer;
	struct list_head		active_iocgs;	/* active cgroups */
	struct ioc_pcpu_stat __percpu	*pcpu_stat;

	enum ioc_running		running;
	atomic64_t			vtime_rate;
	u64				vtime_base_rate;
	s64				vtime_err;

	seqcount_spinlock_t		period_seqcount;
	u64				period_at;	/* wallclock starttime */
	u64				period_at_vtime; /* vtime starttime */

	atomic64_t			cur_period;	/* inc'd each period */
	int				busy_level;	/* saturation history */

	bool				weights_updated;
	atomic_t			hweight_gen;	/* for lazy hweights */

	/* debt forgivness */
	u64				dfgv_period_at;
	u64				dfgv_period_rem;
	u64				dfgv_usage_us_sum;

	u64				autop_too_fast_at;
	u64				autop_too_slow_at;
	int				autop_idx;
	bool				user_qos_params:1;
	bool				user_cost_model:1;
};

enum {
	MILLION			= 1000000,

	/* timer period is calculated from latency requirements, bound it */
	MIN_PERIOD		= USEC_PER_MSEC,
	MAX_PERIOD		= USEC_PER_SEC,

	/*
	 * iocg->vtime is targeted at 50% behind the device vtime, which
	 * serves as its IO credit buffer.  Surplus weight adjustment is
	 * immediately canceled if the vtime margin runs below 10%.
	 */
	MARGIN_MIN_PCT		= 10,
	MARGIN_LOW_PCT		= 20,
	MARGIN_TARGET_PCT	= 50,

	INUSE_ADJ_STEP_PCT	= 25,

	/* Have some play in timer operations */
	TIMER_SLACK_PCT		= 1,

	/* 1/64k is granular enough and can easily be handled w/ u32 */
	WEIGHT_ONE		= 1 << 16,
};

#ifdef CONFIG_TRACEPOINTS

/* copied from TRACE_CGROUP_PATH, see cgroup-internal.h */
#define TRACE_IOCG_PATH_LEN 1024
static DEFINE_SPINLOCK(trace_iocg_path_lock);
static char trace_iocg_path[TRACE_IOCG_PATH_LEN];

#define TRACE_IOCG_PATH(type, iocg, ...)					\
	do {									\
		unsigned long flags;						\
		if (trace_iocost_##type##_enabled()) {				\
			spin_lock_irqsave(&trace_iocg_path_lock, flags);	\
			cgroup_path(iocg_to_blkg(iocg)->blkcg->css.cgroup,	\
				    trace_iocg_path, TRACE_IOCG_PATH_LEN);	\
			trace_iocost_##type(iocg, trace_iocg_path,		\
					      ##__VA_ARGS__);			\
			spin_unlock_irqrestore(&trace_iocg_path_lock, flags);	\
		}								\
	} while (0)

#else	/* CONFIG_TRACE_POINTS */
#define TRACE_IOCG_PATH(type, iocg, ...)	do { } while (0)
#endif	/* CONFIG_TRACE_POINTS */

static struct blkcg_gq *iocg_to_blkg(struct ioc_gq *iocg)
{
	return pd_to_blkg(&iocg->pd);
}

static void current_hweight(struct ioc_gq *iocg, u32 *hw_activep, u32 *hw_inusep)
{
	struct ioc *ioc = iocg->ioc;
	int lvl;
	u32 hwa, hwi;
	int ioc_gen;

	/* hot path - if uptodate, use cached */
	ioc_gen = atomic_read(&ioc->hweight_gen);
	if (ioc_gen == iocg->hweight_gen)
		goto out;

	/*
	 * Paired with wmb in commit_weights(). If we saw the updated
	 * hweight_gen, all the weight updates from __propagate_weights() are
	 * visible too.
	 *
	 * We can race with weight updates during calculation and get it
	 * wrong.  However, hweight_gen would have changed and a future
	 * reader will recalculate and we're guaranteed to discard the
	 * wrong result soon.
	 */
	smp_rmb();

	hwa = hwi = WEIGHT_ONE;
	for (lvl = 0; lvl <= iocg->level - 1; lvl++) {
		struct ioc_gq *parent = iocg->ancestors[lvl];
		struct ioc_gq *child = iocg->ancestors[lvl + 1];
		u64 active_sum = READ_ONCE(parent->child_active_sum);
		u64 inuse_sum = READ_ONCE(parent->child_inuse_sum);
		u32 active = READ_ONCE(child->active);
		u32 inuse = READ_ONCE(child->inuse);

		/* we can race with deactivations and either may read as zero */
		if (!active_sum || !inuse_sum)
			continue;

		active_sum = max_t(u64, active, active_sum);
		hwa = div64_u64((u64)hwa * active, active_sum);

		inuse_sum = max_t(u64, inuse, inuse_sum);
		hwi = div64_u64((u64)hwi * inuse, inuse_sum);
	}

	iocg->hweight_active = max_t(u32, hwa, 1);
	iocg->hweight_inuse = max_t(u32, hwi, 1);
	iocg->hweight_gen = ioc_gen;
out:
	if (hw_activep)
		*hw_activep = iocg->hweight_active;
	if (hw_inusep)
		*hw_inusep = iocg->hweight_inuse;
}

/*
 * Scale @abs_cost to the inverse of @hw_inuse.  The lower the hierarchical
 * weight, the more expensive each IO.  Must round up.
 */
static u64 abs_cost_to_cost(u64 abs_cost, u32 hw_inuse)
{
	return DIV64_U64_ROUND_UP(abs_cost * WEIGHT_ONE, hw_inuse);
}

static bool iocg_kick_delay(struct ioc_gq *iocg, struct ioc_now *now)
{
	struct ioc *ioc = iocg->ioc;
	struct blkcg_gq *blkg = iocg_to_blkg(iocg);
	u64 tdelta, delay, new_delay;
	s64 vover, vover_pct;
	u32 hwa;

	lockdep_assert_held(&iocg->waitq.lock);

	/* calculate the current delay in effect - 1/2 every second */
	tdelta = now->now - iocg->delay_at;
	if (iocg->delay)
		delay = iocg->delay >> div64_u64(tdelta, USEC_PER_SEC);
	else
		delay = 0;

	/* calculate the new delay from the debt amount */
	current_hweight(iocg, &hwa, NULL);
	vover = atomic64_read(&iocg->vtime) +
		abs_cost_to_cost(iocg->abs_vdebt, hwa) - now->vnow;
	vover_pct = div64_s64(100 * vover,
			      ioc->period_us * ioc->vtime_base_rate);

	if (vover_pct <= MIN_DELAY_THR_PCT)
		new_delay = 0;
	else if (vover_pct >= MAX_DELAY_THR_PCT)
		new_delay = MAX_DELAY;
	else
		new_delay = MIN_DELAY +
			div_u64((MAX_DELAY - MIN_DELAY) *
				(vover_pct - MIN_DELAY_THR_PCT),
				MAX_DELAY_THR_PCT - MIN_DELAY_THR_PCT);

	/* pick the higher one and apply */
	if (new_delay > delay) {
		iocg->delay = new_delay;
		iocg->delay_at = now->now;
		delay = new_delay;
	}

	if (delay >= MIN_DELAY) {
		if (!iocg->indelay_since)
			iocg->indelay_since = now->now;
		blkcg_set_delay(blkg, delay * NSEC_PER_USEC);
		return true;
	} else {
		if (iocg->indelay_since) {
			iocg->stat.indelay_us += now->now - iocg->indelay_since;
			iocg->indelay_since = 0;
		}
		iocg->delay = 0;
		blkcg_clear_delay(blkg);
		return false;
	}
}

/*
 * Update @iocg's `active` and `inuse` to @active and @inuse, update level
 * weight sums and propagate upwards accordingly. If @save, the current margin
 * is saved to be used as reference for later inuse in-period adjustments.
 */
static void __propagate_weights(struct ioc_gq *iocg, u32 active, u32 inuse,
				bool save, struct ioc_now *now)
{
	struct ioc *ioc = iocg->ioc;
	int lvl;

	lockdep_assert_held(&ioc->lock);

	/*
	 * For an active leaf node, its inuse shouldn't be zero or exceed
	 * @active. An active internal node's inuse is solely determined by the
	 * inuse to active ratio of its children regardless of @inuse.
	 */
	if (list_empty(&iocg->active_list) && iocg->child_active_sum) {
		inuse = DIV64_U64_ROUND_UP(active * iocg->child_inuse_sum,
					   iocg->child_active_sum);
	} else {
		inuse = clamp_t(u32, inuse, 1, active);
	}

	iocg->last_inuse = iocg->inuse;
	if (save)
		iocg->saved_margin = now->vnow - atomic64_read(&iocg->vtime);

	if (active == iocg->active && inuse == iocg->inuse)
		return;

	for (lvl = iocg->level - 1; lvl >= 0; lvl--) {
		struct ioc_gq *parent = iocg->ancestors[lvl];
		struct ioc_gq *child = iocg->ancestors[lvl + 1];
		u32 parent_active = 0, parent_inuse = 0;

		/* update the level sums */
		parent->child_active_sum += (s32)(active - child->active);
		parent->child_inuse_sum += (s32)(inuse - child->inuse);
		/* apply the updates */
		child->active = active;
		child->inuse = inuse;

		/*
		 * The delta between inuse and active sums indicates that
		 * much of weight is being given away.  Parent's inuse
		 * and active should reflect the ratio.
		 */
		if (parent->child_active_sum) {
			parent_active = parent->weight;
			parent_inuse = DIV64_U64_ROUND_UP(
				parent_active * parent->child_inuse_sum,
				parent->child_active_sum);
		}

		/* do we need to keep walking up? */
		if (parent_active == parent->active &&
		    parent_inuse == parent->inuse)
			break;

		active = parent_active;
		inuse = parent_inuse;
	}

	ioc->weights_updated = true;
}

void commit_weights(struct ioc *ioc)
{
	lockdep_assert_held(&ioc->lock);

	if (ioc->weights_updated) {
		/* paired with rmb in current_hweight(), see there */
		smp_wmb();
		atomic_inc(&ioc->hweight_gen);
		ioc->weights_updated = false;
	}
}

static void propagate_weights(struct ioc_gq *iocg, u32 active, u32 inuse,
			      bool save, struct ioc_now *now)
{
	__propagate_weights(iocg, active, inuse, save, now);
	commit_weights(iocg->ioc);
}

static void iocg_pay_debt(struct ioc_gq *iocg, u64 abs_vpay,
			  struct ioc_now *now)
{
	lockdep_assert_held(&iocg->ioc->lock);
	lockdep_assert_held(&iocg->waitq.lock);

	/* make sure that nobody messed with @iocg */
	WARN_ON_ONCE(list_empty(&iocg->active_list));
	WARN_ON_ONCE(iocg->inuse > 1);

	iocg->abs_vdebt -= min(abs_vpay, iocg->abs_vdebt);

	/* if debt is paid in full, restore inuse */
	if (!iocg->abs_vdebt) {
		iocg->stat.indebt_us += now->now - iocg->indebt_since;
		iocg->indebt_since = 0;

		propagate_weights(iocg, iocg->active, iocg->last_inuse,
				  false, now);
	}
}

/*
 * The inverse of abs_cost_to_cost().  Must round up.
 */
static u64 cost_to_abs_cost(u64 cost, u32 hw_inuse)
{
	return DIV64_U64_ROUND_UP(cost * hw_inuse, WEIGHT_ONE);
}

/*
 * Calculate the accumulated budget, pay debt if @pay_debt and wake up waiters
 * accordingly. When @pay_debt is %true, the caller must be holding ioc->lock in
 * addition to iocg->waitq.lock.
 */
static void iocg_kick_waitq(struct ioc_gq *iocg, bool pay_debt,
			    struct ioc_now *now)
{
	struct ioc *ioc = iocg->ioc;
	struct iocg_wake_ctx ctx = { .iocg = iocg };
	u64 vshortage, expires, oexpires;
	s64 vbudget;
	u32 hwa;

	lockdep_assert_held(&iocg->waitq.lock);

	current_hweight(iocg, &hwa, NULL);
	vbudget = now->vnow - atomic64_read(&iocg->vtime);

	/* pay off debt */
	if (pay_debt && iocg->abs_vdebt && vbudget > 0) {
		u64 abs_vbudget = cost_to_abs_cost(vbudget, hwa);
		u64 abs_vpay = min_t(u64, abs_vbudget, iocg->abs_vdebt);
		u64 vpay = abs_cost_to_cost(abs_vpay, hwa);

		lockdep_assert_held(&ioc->lock);

		atomic64_add(vpay, &iocg->vtime);
		atomic64_add(vpay, &iocg->done_vtime);
		iocg_pay_debt(iocg, abs_vpay, now);
		vbudget -= vpay;
	}

	if (iocg->abs_vdebt || iocg->delay)
		iocg_kick_delay(iocg, now);

	/*
	 * Debt can still be outstanding if we haven't paid all yet or the
	 * caller raced and called without @pay_debt. Shouldn't wake up waiters
	 * under debt. Make sure @vbudget reflects the outstanding amount and is
	 * not positive.
	 */
	if (iocg->abs_vdebt) {
		s64 vdebt = abs_cost_to_cost(iocg->abs_vdebt, hwa);
		vbudget = min_t(s64, 0, vbudget - vdebt);
	}

	/*
	 * Wake up the ones which are due and see how much vtime we'll need for
	 * the next one. As paying off debt restores hw_inuse, it must be read
	 * after the above debt payment.
	 */
	ctx.vbudget = vbudget;
	current_hweight(iocg, NULL, &ctx.hw_inuse);

	__wake_up_locked_key(&iocg->waitq, TASK_NORMAL, &ctx);

	if (!waitqueue_active(&iocg->waitq)) {
		if (iocg->wait_since) {
			iocg->stat.wait_us += now->now - iocg->wait_since;
			iocg->wait_since = 0;
		}
		return;
	}

	if (!iocg->wait_since)
		iocg->wait_since = now->now;

	if (WARN_ON_ONCE(ctx.vbudget >= 0))
		return;

	/* determine next wakeup, add a timer margin to guarantee chunking */
	vshortage = -ctx.vbudget;
	expires = now->now_ns +
		DIV64_U64_ROUND_UP(vshortage, ioc->vtime_base_rate) *
		NSEC_PER_USEC;
	expires += ioc->timer_slack_ns;

	/* if already active and close enough, don't bother */
	oexpires = ktime_to_ns(hrtimer_get_softexpires(&iocg->waitq_timer));
	if (hrtimer_is_queued(&iocg->waitq_timer) &&
	    abs(oexpires - expires) <= ioc->timer_slack_ns)
		return;

	hrtimer_start_range_ns(&iocg->waitq_timer, ns_to_ktime(expires),
			       ioc->timer_slack_ns, HRTIMER_MODE_ABS);
}

static void iocg_commit_bio(struct ioc_gq *iocg, struct bio *bio,
			    u64 abs_cost, u64 cost)
{
	struct iocg_pcpu_stat *gcs;

	bio->bi_iocost_cost = cost;
	atomic64_add(cost, &iocg->vtime);

	gcs = get_cpu_ptr(iocg->pcpu_stat);
	local64_add(abs_cost, &gcs->abs_vusage);
	put_cpu_ptr(gcs);
}

static int iocg_wake_fn(struct wait_queue_entry *wq_entry, unsigned mode,
			int flags, void *key)
{
	struct iocg_wait *wait = container_of(wq_entry, struct iocg_wait, wait);
	struct iocg_wake_ctx *ctx = key;
	u64 cost = abs_cost_to_cost(wait->abs_cost, ctx->hw_inuse);

	ctx->vbudget -= cost;

	if (ctx->vbudget < 0)
		return -1;

	iocg_commit_bio(ctx->iocg, wait->bio, wait->abs_cost, cost);
	wait->committed = true;

	/*
	 * autoremove_wake_function() removes the wait entry only when it
	 * actually changed the task state. We want the wait always removed.
	 * Remove explicitly and use default_wake_function(). Note that the
	 * order of operations is important as finish_wait() tests whether
	 * @wq_entry is removed without grabbing the lock.
	 */
	default_wake_function(wq_entry, mode, flags, key);
	list_del_init_careful(&wq_entry->entry);
	return 0;
}

static void iocg_incur_debt(struct ioc_gq *iocg, u64 abs_cost,
			    struct ioc_now *now)
{
	struct iocg_pcpu_stat *gcs;

	lockdep_assert_held(&iocg->ioc->lock);
	lockdep_assert_held(&iocg->waitq.lock);
	WARN_ON_ONCE(list_empty(&iocg->active_list));

	/*
	 * Once in debt, debt handling owns inuse. @iocg stays at the minimum
	 * inuse donating all of it share to others until its debt is paid off.
	 */
	if (!iocg->abs_vdebt && abs_cost) {
		iocg->indebt_since = now->now;
		propagate_weights(iocg, iocg->active, 0, false, now);
	}

	iocg->abs_vdebt += abs_cost;

	gcs = get_cpu_ptr(iocg->pcpu_stat);
	local64_add(abs_cost, &gcs->abs_vusage);
	put_cpu_ptr(gcs);
}

static void iocg_unlock(struct ioc_gq *iocg, bool unlock_ioc, unsigned long *flags)
{
	if (unlock_ioc) {
		spin_unlock(&iocg->waitq.lock);
		spin_unlock_irqrestore(&iocg->ioc->lock, *flags);
	} else {
		spin_unlock_irqrestore(&iocg->waitq.lock, *flags);
	}
}

static void iocg_lock(struct ioc_gq *iocg, bool lock_ioc, unsigned long *flags)
{
	if (lock_ioc) {
		spin_lock_irqsave(&iocg->ioc->lock, *flags);
		spin_lock(&iocg->waitq.lock);
	} else {
		spin_lock_irqsave(&iocg->waitq.lock, *flags);
	}
}

static u64 adjust_inuse_and_calc_cost(struct ioc_gq *iocg, u64 vtime,
				      u64 abs_cost, struct ioc_now *now)
{
	struct ioc *ioc = iocg->ioc;
	struct ioc_margins *margins = &ioc->margins;
	u32 __maybe_unused old_inuse = iocg->inuse, __maybe_unused old_hwi;
	u32 hwi, adj_step;
	s64 margin;
	u64 cost, new_inuse;
	unsigned long flags;

	current_hweight(iocg, NULL, &hwi);
	old_hwi = hwi;
	cost = abs_cost_to_cost(abs_cost, hwi);
	margin = now->vnow - vtime - cost;

	/* debt handling owns inuse for debtors */
	if (iocg->abs_vdebt)
		return cost;

	/*
	 * We only increase inuse during period and do so if the margin has
	 * deteriorated since the previous adjustment.
	 */
	if (margin >= iocg->saved_margin || margin >= margins->low ||
	    iocg->inuse == iocg->active)
		return cost;

	spin_lock_irqsave(&ioc->lock, flags);

	/* we own inuse only when @iocg is in the normal active state */
	if (iocg->abs_vdebt || list_empty(&iocg->active_list)) {
		spin_unlock_irqrestore(&ioc->lock, flags);
		return cost;
	}

	/*
	 * Bump up inuse till @abs_cost fits in the existing budget.
	 * adj_step must be determined after acquiring ioc->lock - we might
	 * have raced and lost to another thread for activation and could
	 * be reading 0 iocg->active before ioc->lock which will lead to
	 * infinite loop.
	 */
	new_inuse = iocg->inuse;
	adj_step = DIV_ROUND_UP(iocg->active * INUSE_ADJ_STEP_PCT, 100);
	do {
		new_inuse = new_inuse + adj_step;
		propagate_weights(iocg, iocg->active, new_inuse, true, now);
		current_hweight(iocg, NULL, &hwi);
		cost = abs_cost_to_cost(abs_cost, hwi);
	} while (time_after64(vtime + cost, now->vnow) &&
		 iocg->inuse != iocg->active);

	spin_unlock_irqrestore(&ioc->lock, flags);

	TRACE_IOCG_PATH(inuse_adjust, iocg, now,
			old_inuse, iocg->inuse, old_hwi, hwi);

	return cost;
}

static void ioc_start_period(struct ioc *ioc, struct ioc_now *now)
{
	WARN_ON_ONCE(ioc->running != IOC_RUNNING);

	write_seqcount_begin(&ioc->period_seqcount);
	ioc->period_at = now->now;
	ioc->period_at_vtime = now->vnow;
	write_seqcount_end(&ioc->period_seqcount);

	ioc->timer.expires = jiffies + usecs_to_jiffies(ioc->period_us);
	add_timer(&ioc->timer);
}

/* take a snapshot of the current [v]time and vrate */
static void ioc_now(struct ioc *ioc, struct ioc_now *now)
{
	unsigned seq;
	u64 vrate;

	now->now_ns = ktime_get();
	now->now = ktime_to_us(now->now_ns);
	vrate = atomic64_read(&ioc->vtime_rate);

	/*
	 * The current vtime is
	 *
	 *   vtime at period start + (wallclock time since the start) * vrate
	 *
	 * As a consistent snapshot of `period_at_vtime` and `period_at` is
	 * needed, they're seqcount protected.
	 */
	do {
		seq = read_seqcount_begin(&ioc->period_seqcount);
		now->vnow = ioc->period_at_vtime +
			(now->now - ioc->period_at) * vrate;
	} while (read_seqcount_retry(&ioc->period_seqcount, seq));
}

static bool iocg_activate(struct ioc_gq *iocg, struct ioc_now *now)
{
	struct ioc *ioc = iocg->ioc;
	u64 last_period, cur_period;
	u64 vtime, vtarget;
	int i;

	/*
	 * If seem to be already active, just update the stamp to tell the
	 * timer that we're still active.  We don't mind occassional races.
	 */
	if (!list_empty(&iocg->active_list)) {
		ioc_now(ioc, now);
		cur_period = atomic64_read(&ioc->cur_period);
		if (atomic64_read(&iocg->active_period) != cur_period)
			atomic64_set(&iocg->active_period, cur_period);
		return true;
	}

	/* racy check on internal node IOs, treat as root level IOs */
	if (iocg->child_active_sum)
		return false;

	spin_lock_irq(&ioc->lock);

	ioc_now(ioc, now);

	/* update period */
	cur_period = atomic64_read(&ioc->cur_period);
	last_period = atomic64_read(&iocg->active_period);
	atomic64_set(&iocg->active_period, cur_period);

	/* already activated or breaking leaf-only constraint? */
	if (!list_empty(&iocg->active_list))
		goto succeed_unlock;
	for (i = iocg->level - 1; i > 0; i--)
		if (!list_empty(&iocg->ancestors[i]->active_list))
			goto fail_unlock;

	if (iocg->child_active_sum)
		goto fail_unlock;

	/*
	 * Always start with the target budget. On deactivation, we throw away
	 * anything above it.
	 */
	vtarget = now->vnow - ioc->margins.target;
	vtime = atomic64_read(&iocg->vtime);

	atomic64_add(vtarget - vtime, &iocg->vtime);
	atomic64_add(vtarget - vtime, &iocg->done_vtime);
	vtime = vtarget;

	/*
	 * Activate, propagate weight and start period timer if not
	 * running.  Reset hweight_gen to avoid accidental match from
	 * wrapping.
	 */
	iocg->hweight_gen = atomic_read(&ioc->hweight_gen) - 1;
	list_add(&iocg->active_list, &ioc->active_iocgs);

	propagate_weights(iocg, iocg->weight,
			  iocg->last_inuse ?: iocg->weight, true, now);

	TRACE_IOCG_PATH(iocg_activate, iocg, now,
			last_period, cur_period, vtime);

	iocg->activated_at = now->now;

	if (ioc->running == IOC_IDLE) {
		ioc->running = IOC_RUNNING;
		ioc->dfgv_period_at = now->now;
		ioc->dfgv_period_rem = 0;
		ioc_start_period(ioc, now);
	}

succeed_unlock:
	spin_unlock_irq(&ioc->lock);
	return true;

fail_unlock:
	spin_unlock_irq(&ioc->lock);
	return false;
}

static void calc_vtime_cost_builtin(struct bio *bio, struct ioc_gq *iocg,
				    bool is_merge, u64 *costp)
{
	struct ioc *ioc = iocg->ioc;
	u64 coef_seqio, coef_randio, coef_page;
	u64 pages = max_t(u64, bio_sectors(bio) >> IOC_SECT_TO_PAGE_SHIFT, 1);
	u64 seek_pages = 0;
	u64 cost = 0;

	/* Can't calculate cost for empty bio */
	if (!bio->bi_iter.bi_size)
		goto out;

	switch (bio_op(bio)) {
	case REQ_OP_READ:
		coef_seqio	= ioc->params.lcoefs[LCOEF_RSEQIO];
		coef_randio	= ioc->params.lcoefs[LCOEF_RRANDIO];
		coef_page	= ioc->params.lcoefs[LCOEF_RPAGE];
		break;
	case REQ_OP_WRITE:
		coef_seqio	= ioc->params.lcoefs[LCOEF_WSEQIO];
		coef_randio	= ioc->params.lcoefs[LCOEF_WRANDIO];
		coef_page	= ioc->params.lcoefs[LCOEF_WPAGE];
		break;
	default:
		goto out;
	}

	if (iocg->cursor) {
		seek_pages = abs(bio->bi_iter.bi_sector - iocg->cursor);
		seek_pages >>= IOC_SECT_TO_PAGE_SHIFT;
	}

	if (!is_merge) {
		if (seek_pages > LCOEF_RANDIO_PAGES) {
			cost += coef_randio;
		} else {
			cost += coef_seqio;
		}
	}
	cost += pages * coef_page;
out:
	*costp = cost;
}

static u64 calc_vtime_cost(struct bio *bio, struct ioc_gq *iocg, bool is_merge)
{
	u64 cost;

	calc_vtime_cost_builtin(bio, iocg, is_merge, &cost);
	return cost;
}

static struct blkcg_policy blkcg_policy_iocost;

static struct ioc_gq *pd_to_iocg(struct blkg_policy_data *pd)
{
	return pd ? container_of(pd, struct ioc_gq, pd) : NULL;
}

static struct ioc_gq *blkg_to_iocg(struct blkcg_gq *blkg)
{
	return pd_to_iocg(blkg_to_pd(blkg, &blkcg_policy_iocost));
}

/* accessors and helpers */
static struct ioc *rqos_to_ioc(struct rq_qos *rqos)
{
	return container_of(rqos, struct ioc, rqos);
}



KTDEF(ioc_rqos_throttle);
void _k_ioc_rqos_throttle(struct rq_qos *rqos, struct bio *bio)
{
#ifdef __PROFILING
#endif 
#ifdef __PROFILING
#endif 
	struct blkcg_gq *blkg = bio->bi_blkg;
	struct ioc *ioc = rqos_to_ioc(rqos);
	struct ioc_gq *iocg = blkg_to_iocg(blkg);
	struct ioc_now now;
	struct iocg_wait wait;
	u64 abs_cost, cost, vtime;
	bool use_debt, ioc_locked;
	unsigned long flags;

	/* bypass IOs if disabled, still initializing, or for root cgroup */
	if (!ioc->enabled || !iocg || !iocg->level)
		return;

	/* calculate the absolute vtime cost */
	abs_cost = calc_vtime_cost(bio, iocg, false);
	if (!abs_cost)
		return;

	if (!iocg_activate(iocg, &now))
		return;

	iocg->cursor = bio_end_sector(bio);
	vtime = atomic64_read(&iocg->vtime);
	cost = adjust_inuse_and_calc_cost(iocg, vtime, abs_cost, &now);

	/*
	 * If no one's waiting and within budget, issue right away.  The
	 * tests are racy but the races aren't systemic - we only miss once
	 * in a while which is fine.
	 */
	if (!waitqueue_active(&iocg->waitq) && !iocg->abs_vdebt &&
	    time_before_eq64(vtime + cost, now.vnow)) {
		iocg_commit_bio(iocg, bio, abs_cost, cost);
		return;
	}

	/*
	 * We're over budget. This can be handled in two ways. IOs which may
	 * cause priority inversions are punted to @ioc->aux_iocg and charged as
	 * debt. Otherwise, the issuer is blocked on @iocg->waitq. Debt handling
	 * requires @ioc->lock, waitq handling @iocg->waitq.lock. Determine
	 * whether debt handling is needed and acquire locks accordingly.
	 */
	use_debt = bio_issue_as_root_blkg(bio) || fatal_signal_pending(current);
	ioc_locked = use_debt || READ_ONCE(iocg->abs_vdebt);
retry_lock:
	iocg_lock(iocg, ioc_locked, &flags);

	/*
	 * @iocg must stay activated for debt and waitq handling. Deactivation
	 * is synchronized against both ioc->lock and waitq.lock and we won't
	 * get deactivated as long as we're waiting or has debt, so we're good
	 * if we're activated here. In the unlikely cases that we aren't, just
	 * issue the IO.
	 */
	if (unlikely(list_empty(&iocg->active_list))) {
		iocg_unlock(iocg, ioc_locked, &flags);
		iocg_commit_bio(iocg, bio, abs_cost, cost);
		return;
	}

	/*
	 * We're over budget. If @bio has to be issued regardless, remember
	 * the abs_cost instead of advancing vtime. iocg_kick_waitq() will pay
	 * off the debt before waking more IOs.
	 *
	 * This way, the debt is continuously paid off each period with the
	 * actual budget available to the cgroup. If we just wound vtime, we
	 * would incorrectly use the current hw_inuse for the entire amount
	 * which, for example, can lead to the cgroup staying blocked for a
	 * long time even with substantially raised hw_inuse.
	 *
	 * An iocg with vdebt should stay online so that the timer can keep
	 * deducting its vdebt and [de]activate use_delay mechanism
	 * accordingly. We don't want to race against the timer trying to
	 * clear them and leave @iocg inactive w/ dangling use_delay heavily
	 * penalizing the cgroup and its descendants.
	 */
	if (use_debt) {
		iocg_incur_debt(iocg, abs_cost, &now);
		if (iocg_kick_delay(iocg, &now))
			blkcg_schedule_throttle(rqos->disk,
					(bio->bi_opf & REQ_SWAP) == REQ_SWAP);
		iocg_unlock(iocg, ioc_locked, &flags);
		return;
	}

	/* guarantee that iocgs w/ waiters have maximum inuse */
	if (!iocg->abs_vdebt && iocg->inuse != iocg->active) {
		if (!ioc_locked) {
			iocg_unlock(iocg, false, &flags);
			ioc_locked = true;
			goto retry_lock;
		}
		propagate_weights(iocg, iocg->active, iocg->active, true,
				  &now);
	}

	/*
	 * Append self to the waitq and schedule the wakeup timer if we're
	 * the first waiter.  The timer duration is calculated based on the
	 * current vrate.  vtime and hweight changes can make it too short
	 * or too long.  Each wait entry records the absolute cost it's
	 * waiting for to allow re-evaluation using a custom wait entry.
	 *
	 * If too short, the timer simply reschedules itself.  If too long,
	 * the period timer will notice and trigger wakeups.
	 *
	 * All waiters are on iocg->waitq and the wait states are
	 * synchronized using waitq.lock.
	 */
	init_waitqueue_func_entry(&wait.wait, iocg_wake_fn);
	wait.wait.private = current;
	wait.bio = bio;
	wait.abs_cost = abs_cost;
	wait.committed = false;	/* will be set true by waker */

	__add_wait_queue_entry_tail(&iocg->waitq, &wait.wait);
	iocg_kick_waitq(iocg, ioc_locked, &now);

	iocg_unlock(iocg, ioc_locked, &flags);

	while (true) {
		set_current_state(TASK_UNINTERRUPTIBLE);
		if (wait.committed)
			break;
		io_schedule();
	}

	/* waker already committed us, proceed */
	finish_wait(&iocg->waitq, &wait.wait);
}

static void ioc_rqos_merge(struct rq_qos *rqos, struct request *rq,
			   struct bio *bio)
{
	struct ioc_gq *iocg = blkg_to_iocg(bio->bi_blkg);
	struct ioc *ioc = rqos_to_ioc(rqos);
	sector_t bio_end = bio_end_sector(bio);
	struct ioc_now now;
	u64 vtime, abs_cost, cost;
	unsigned long flags;

	/* bypass if disabled, still initializing, or for root cgroup */
	if (!ioc->enabled || !iocg || !iocg->level)
		return;

	abs_cost = calc_vtime_cost(bio, iocg, true);
	if (!abs_cost)
		return;

	ioc_now(ioc, &now);

	vtime = atomic64_read(&iocg->vtime);
	cost = adjust_inuse_and_calc_cost(iocg, vtime, abs_cost, &now);

	/* update cursor if backmerging into the request at the cursor */
	if (blk_rq_pos(rq) < bio_end &&
	    blk_rq_pos(rq) + blk_rq_sectors(rq) == iocg->cursor)
		iocg->cursor = bio_end;

	/*
	 * Charge if there's enough vtime budget and the existing request has
	 * cost assigned.
	 */
	if (rq->bio && rq->bio->bi_iocost_cost &&
	    time_before_eq64(atomic64_read(&iocg->vtime) + cost, now.vnow)) {
		iocg_commit_bio(iocg, bio, abs_cost, cost);
		return;
	}

	/*
	 * Otherwise, account it as debt if @iocg is online, which it should
	 * be for the vast majority of cases. See debt handling in
	 * ioc_rqos_throttle() for details.
	 */
	spin_lock_irqsave(&ioc->lock, flags);
	spin_lock(&iocg->waitq.lock);

	if (likely(!list_empty(&iocg->active_list))) {
		iocg_incur_debt(iocg, abs_cost, &now);
		if (iocg_kick_delay(iocg, &now))
			blkcg_schedule_throttle(rqos->disk,
					(bio->bi_opf & REQ_SWAP) == REQ_SWAP);
	} else {
		iocg_commit_bio(iocg, bio, abs_cost, cost);
	}

	spin_unlock(&iocg->waitq.lock);
	spin_unlock_irqrestore(&ioc->lock, flags);
}
