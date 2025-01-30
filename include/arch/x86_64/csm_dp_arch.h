/*
* Copyright (c) 2025 Qualcomm Innovation Center, Inc. All rights reserved.
* SPDX-License-Identifier: BSD-3-Clause-Clear
*/

#ifndef CSM_DP_ARCH_X86_H
#define CSM_DP_ARCH_X86_H

#ifdef __cplusplus
extern "C" {
#endif

#include "csm_dp_generic.h"

/* memory barrier */
#define mb()    asm volatile("mfence":::"memory")
#define wmb()   asm volatile("sfence" ::: "memory")
#define rmb()   asm volatile("lfence":::"memory")

#ifdef __cplusplus
};
#endif

#endif /* CSM_DP_ARCH_X86_H */
