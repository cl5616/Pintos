#ifndef FLOAT_H
#define FLOAT_H

#include <stdint.h>
#include <stddef.h>
typedef int32_t float_t;
#define FIXED (2 << 13) //for p.q fixedpoint format

inline float_t float_mul(float_t x, float_t y)
{
	return ((int64_t) x) * y / FIXED;
}

inline float_t float_div(float_t x, float_t y)
{
	return ((int64_t) x) * FIXED / y;
}

inline float_t calc_load_avg(float_t old, size_t ready_threads)
{
	//load_avg = (59/60)*load_avg + (1/60)*ready_threads;
	float_t fst = float_mul(float_div(59 * FIXED, 60 * FIXED), old);
	float_t snd = float_mul(float_div(FIXED, 60 * FIXED), ready_threads * FIXED);
	return fst + snd;
}

inline float_t calc_recent_cpu(float_t load_avg, float_t old, int nice)
{
	//recent_cpu = (2*load_avg)/(2*load_avg + 1) * recent_cpu + nice;
	float_t avg = float_div((2 * load_avg), (2 * load_avg + FIXED));
	return float_mul(avg, old) + nice * FIXED;
}

inline float_t inc_recent_cpu(float_t old)
{
	return old + FIXED;
}

inline int float_t_to_int(float_t f)
{
	if (f >= 0)
	{
		return (f + FIXED / 2) / FIXED;
	}
	else
	{
		return (f - FIXED / 2) / FIXED;
	}
}

inline int calc_priority(float_t recent_cpu, int nice, int PRI_MAX, int PRI_MIN)
{
	int ret = (PRI_MAX * FIXED - recent_cpu / 4 - nice * FIXED * 2) / FIXED;
	ret = ret >= PRI_MAX ? PRI_MAX : ret;
	ret = ret <= PRI_MIN ? PRI_MIN : ret;
	return ret;
}

#endif

