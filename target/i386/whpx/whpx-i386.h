/* SPDX-License-Identifier: GPL-2.0-or-later */

uint32_t whpx_get_supported_cpuid(uint32_t func, uint32_t idx, int reg);
uint64_t whpx_get_supported_msr_feature(uint32_t index);
bool whpx_is_legacy_os(void);

uint32_t whpx_get_supported_cpuid_legacy(uint32_t func, uint32_t idx,
                                 int reg);
bool whpx_has_xsave(void);
bool whpx_has_xsaves(void);
bool whpx_has_rdtscp(void);
bool whpx_has_invpcid(void);
