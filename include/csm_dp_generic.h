/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 * SPDX-License-Identifier: BSD-3-Clause-Clear
 */

#ifndef CSM_DP_GENERIC_H
#define CSM_DP_GENERIC_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stdbool.h>

#ifndef likely
#define likely(cond)	__builtin_expect(!!(cond), 1)
#endif

#ifndef unlikely
#define unlikely(cond)	__builtin_expect(!!(cond), 0)
#endif

typedef struct {
	volatile int cnt;
} csm_dp_atomic_t;

/* inlines */
static __always_inline unsigned int atomic_cmpxchg(
	volatile unsigned *ptr,
	unsigned int old_value,
	unsigned int new_value)
{
	return __sync_val_compare_and_swap(ptr, old_value, new_value);
}

static __always_inline int atomic_read(csm_dp_atomic_t *v)
{
	return v->cnt;
}

static __always_inline void atomic_inc(csm_dp_atomic_t *v)
{
	__sync_fetch_and_add(&v->cnt, 1);
}

static __always_inline void atomic_add(csm_dp_atomic_t *v, int inc)
{
	__sync_fetch_and_add(&v->cnt, inc);
}

static __always_inline void atomic_dec(csm_dp_atomic_t *v)
{
	__sync_fetch_and_sub(&v->cnt, 1);
}

static __always_inline void atomic_sub(csm_dp_atomic_t *v, int inc)
{
	__sync_fetch_and_sub(&v->cnt, inc);
}

static __always_inline int atomic_inc_return(csm_dp_atomic_t *v)
{
	return __sync_add_and_fetch(&v->cnt, 1);
}

static __always_inline int atomic_dec_return(csm_dp_atomic_t *v)
{
	return __sync_sub_and_fetch(&v->cnt, 1);
}

static __always_inline bool atomic_dec_and_test(csm_dp_atomic_t *v)
{
	return atomic_dec_return(v) == 0;
}

static __always_inline int atomic_dec_if_positive(csm_dp_atomic_t *v)
{
	int val, old;

	val = atomic_read(v);
	while (val > 0) {
		old = __sync_val_compare_and_swap(&v->cnt, val, val -1);
		if (old == val)
			break;
		val = old;
	}
	return val;
}

#ifdef __cplusplus
};
#endif

#endif /* CSM_DP_GENERIC_H */
