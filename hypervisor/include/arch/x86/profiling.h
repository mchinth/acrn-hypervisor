/*
 * Copyright (C) 2018 Intel Corporation. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef PROFILING_H
#define PROFILING_H

#define MAX_MSR_LIST_NUM		15U
#define MAX_GROUP_NUM			1U

#define COLLECT_PROFILE_DATA	0
#define COLLECT_POWER_DATA		1

enum MSR_CMD_STATUS {
	MSR_OP_READY = 0,
	MSR_OP_REQUESTED,
	MSR_OP_HANDLED
};

enum MSR_CMD_TYPE {
	MSR_OP_NONE = 0U,
	MSR_OP_READ,
	MSR_OP_WRITE,
	MSR_OP_READ_CLEAR
};

enum PMU_MSR_TYPE {
	PMU_MSR_CCCR = 0U,
	PMU_MSR_ESCR,
	PMU_MSR_DATA
};

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

struct profiling_msr_op {
	/* MSR address to read/write; last entry will have value of -1 */
	int32_t		msr_id;
	/* value to write or location to write into */
	uint64_t	value;
	uint8_t		op_type;
	uint8_t		reg_type;
	/* parameter; usage depends on operation */
	uint16_t	param;
} __aligned(8);

struct profiling_msr_ops_list {
	int32_t		collector_id;
	uint32_t	num_entries;
	int32_t		msr_op_state;
	struct profiling_msr_op entries[MAX_MSR_LIST_NUM];
} __aligned(8);

struct vmexit_msr {
	uint32_t msr_idx;
	uint32_t reserved;
	uint64_t msr_data;
} __aligned(16);

struct sep_state {
	sep_pmu_state pmu_state;

	uint32_t current_pmi_group_id;
	uint32_t num_pmi_groups;

	struct profiling_msr_op
		pmi_initial_msr_list[MAX_GROUP_NUM][MAX_MSR_LIST_NUM];
	struct profiling_msr_op
		pmi_start_msr_list[MAX_GROUP_NUM][MAX_MSR_LIST_NUM];
	struct profiling_msr_op
		pmi_stop_msr_list[MAX_GROUP_NUM][MAX_MSR_LIST_NUM];
	struct profiling_msr_op
		pmi_entry_msr_list[MAX_GROUP_NUM][MAX_MSR_LIST_NUM];
	struct profiling_msr_op
		pmi_exit_msr_list[MAX_GROUP_NUM][MAX_MSR_LIST_NUM];

	uint32_t current_vmsw_group_id;
	uint32_t num_msw_groups;
	struct profiling_msr_op
		vmsw_initial_msr_list[MAX_GROUP_NUM][MAX_MSR_LIST_NUM];
	struct profiling_msr_op
		vmsw_entry_msr_list[MAX_GROUP_NUM][MAX_MSR_LIST_NUM];
	struct profiling_msr_op
		vmsw_exit_msr_list[MAX_GROUP_NUM][MAX_MSR_LIST_NUM];

	/* sep handling statistics */
	uint32_t samples_logged;
	uint32_t samples_dropped;
	uint32_t valid_pmi_count;
	uint32_t total_pmi_count;
	uint32_t total_vmexit_count;
	uint32_t frozen_well;
	uint32_t frozen_delayed;
	uint32_t nofrozen_pmi;

	struct vmexit_msr *vmexit_msr_list;
	int vmexit_msr_cnt;
	uint64_t guest_debugctl_value;
	uint64_t saved_debugctl_value;
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
