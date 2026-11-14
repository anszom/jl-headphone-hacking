#include "profile.h"
#include "asm/cpu.h"
#include "debug.h"
/*
 * CPU-load & I/D cache diagnostics.
 *
 * Time base: the core tick timer. `jiffies` counts 10 ms ticks, TICK_CNT counts up to
 * TICK_PRD within a tick, so  t = jiffies*PRD + CNT  is a monotonic timestamp in TTMR clocks
 * (PRD clocks = 10 ms). Same source the firmware's jiffies_half_msec() uses.
 */

struct perf_stats {
	// all data is collected between profile_start & profile_stop
	u64 cpu_ticks;	
	u64 ic_hit, ic_miss;	// instruction cache, as above
	u64 dc_hit, dc_miss;	// data cache, as above
	u32 period;			// TICK_PRD
};

struct perf_stats perf_stats;

extern volatile u32 jiffies;

static u64 now_ticks(void)
{
	u32 j, c;
	do {
		j = jiffies;
		c = TICK_CNT;
	} while(j != jiffies);	/* tick interrupt in between -> retry */
	return (u64)j * TICK_PRD + c;
}

struct cache_stat {
	u32 ic_hit, ic_miss;
	u32 dc_hit, dc_miss;
	u64 ticks;
};

static void cache_snapshot(struct cache_stat *stat)
{
	// The hit counters are not accurate, they don't count every CPU access, so they can't
	// be easily used for miss percentages.
	stat->ic_hit = q32DSP_icu(0)->CNT_RACK;
	stat->ic_miss = q32DSP_icu(0)->CNT_UNACK;
	stat->dc_hit = JL_DCU->CNT_RACK;
	stat->dc_miss = JL_DCU->CNT_UNACK;
	stat->ticks = now_ticks();
}
static struct cache_stat start_stat;

void profile_start(void)
{
	q32DSP_icu(0)->CON |= 2;
	JL_DCU->CON |= 2;
	perf_stats.period = TICK_PRD;
	cache_snapshot(&start_stat);
}

void profile_stop(void)
{
	struct cache_stat cur;
	cache_snapshot(&cur);

	// Elapsed ticks; clamps the rare negative delta (counter wrapped while the tick IRQ was pending)
	u32 dt = cur.ticks > start_stat.ticks ? (u32)(cur.ticks - start_stat.ticks) : 0;

	// NOTE: hit values don't seem to count every access, any percentage rates computed from hit/miss will be unreliable
	perf_stats.ic_hit  += cur.ic_hit - start_stat.ic_hit;
	perf_stats.ic_miss += cur.ic_miss- start_stat.ic_miss;
	perf_stats.dc_hit  += cur.dc_hit - start_stat.dc_hit;
	perf_stats.dc_miss += cur.dc_miss- start_stat.dc_miss;
	perf_stats.cpu_ticks += dt;
}
