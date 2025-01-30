/*
* Copyright (c) 2025 Qualcomm Innovation Center, Inc. All rights reserved.
* SPDX-License-Identifier: BSD-3-Clause-Clear
*/

#ifndef CSM_DP_ARCH_ARM64_H
#define CSM_DP_ARCH_ARM64_H

#ifdef __cplusplus
extern "C" {
#endif

#include "csm_dp_generic.h"

/* memory barrier */
#define dsb(opt) asm volatile("dsb " #opt : : : "memory")
#define dmb(opt) asm volatile("dmb " #opt : : : "memory")

#define mb() dsb(sy)
#define wmb() dsb(st)
#define rmb() dsb(ld)
#define smp_mb() dmb(ish)
#define smp_wmb() dmb(ishst)
#define smp_rmb() dmb(ishld)

#ifdef __cplusplus
};
#endif

#endif /* CSM_DP_ARCH_ARM64_H */
