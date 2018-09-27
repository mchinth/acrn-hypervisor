/*
 * Copyright (C) 2018 Intel Corporation. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef PROFILING_H
#define PROFILING_H

typedef enum IPI_COMMANDS {
	IPI_BEGIN,
	IPI_MSR_OP,
	IPI_PMU_CONFIG,
	IPI_PMU_START,
	IPI_PMU_STOP,
	IPI_VMSW_CONFIG,
	IPI_UNKNOWN
} ipi_commands;

typedef enum SEP_PMU_STATE {
	PMU_INITIALIZED,
	PMU_SETUP,
	PMU_RUNNING,
	PMU_UNINITIALIZED,
	PMU_UNKNOWN
} sep_pmu_state;

typedef enum SOCWATCH_STATE {
	SW_SETUP,
	SW_RUNNING,
	SW_STOPPED
} socwatch_state;

struct sep_state {
	sep_pmu_state pmu_state;

	uint32_t current_pmi_group_id;
	uint32_t num_pmi_groups;
} __aligned(8);

struct vm_switch_trace {
	int32_t  os_id;
	uint64_t vmenter_tsc;
	uint64_t vmexit_tsc;
	uint64_t vmexit_reason;
} __aligned(32);

/*
 * Wrapper containing  SEP sampling/profiling related data structures
 */
struct sep_profiling_wrapper {
	struct sep_state		sep_state;
	ipi_commands			ipi_cmd;
	struct vm_switch_trace	vm_switch_trace;
	socwatch_state			socwatch_state;
};

#define VM_SWITCH_TRACE_SIZE (sizeof(struct vm_switch_trace))

struct intr_excp_ctx;

int profiling_get_version(uint64_t addr);
int profiling_get_pcpuid(uint64_t addr);
int profiling_msr_ops_all_cpus(uint64_t addr);
int profiling_vm_info_list(uint64_t addr);
int profiling_get_control(uint64_t addr);
int profiling_set_control(uint64_t addr);
int profiling_config_pmi(uint64_t addr);
int profiling_config_vmsw(uint64_t addr);

#ifdef HV_DEBUG
int profiling_vmenter_handler(struct vcpu *vcpu);
int profiling_vmexit_handler(struct vcpu *vcpu, uint64_t exit_reason);
void profiling_capture_intr_context(struct intr_excp_ctx *ctx);
void profiling_setup(void);
int profiling_ipi_handler(void);
#else
static inline int profiling_vmenter_handler(struct vcpu *vcpu) {};
static inline int profiling_vmexit_handler(struct vcpu *vcpu,
				uint64_t exit_reason) {};
static inline void profiling_capture_intr_context(struct intr_excp_ctx *ctx) {};
static inline void profiling_setup(void) {};
static inline int profiling_ipi_handler(void) {};
#endif

#endif /* PROFILING_H */
