/*
 * Copyright (C) 2018 int32_tel Corporation. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef PROFILING_H
#define PROFILING_H

#ifdef HV_DEBUG

typedef enum IPI_COMMANDS {
	IPI_MSR_OP = 0,
	IPI_PMU_CONFIG,
	IPI_PMU_START,
	IPI_PMU_STOP,
	IPI_VMSW_CONFIG,
	IPI_UNKNOWN,
} ipi_commands;

/*
 * Wrapper containing  SEP sampling/profiling related data structures
 */
struct profiling_info_wrapper {
	ipi_commands			ipi_cmd;
};

int32_t profiling_get_version(__unused struct vm *vm,
		__unused uint64_t addr);
int32_t profiling_get_pcpuid(__unused struct vm *vm,
		__unused uint64_t addr);
int32_t profiling_msr_ops_all_cpus(__unused struct vm *vm,
		__unused uint64_t addr);
int32_t profiling_vm_list_info(__unused struct vm *vm,
		__unused uint64_t addr);
int32_t profiling_get_control(__unused struct vm *vm,
		__unused uint64_t addr);
int32_t profiling_set_control(__unused struct vm *vm,
		__unused uint64_t addr);
int32_t profiling_config_pmi(__unused struct vm *vm,
		__unused uint64_t addr);
int32_t profiling_config_vmsw(__unused struct vm *vm,
		__unused uint64_t addr);


void profiling_vmenter_handler(__unused struct vcpu *vcpu);
void profiling_vmexit_handler(__unused struct vcpu *vcpu,
		__unused uint64_t exit_reason);
void profiling_setup(void);
void profiling_ipi_handler(__unused void *data);
#endif

#endif /* PROFILING_H */
