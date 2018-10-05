/*
 * Copyright (C) 2018 Intel Corporation. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef PROFILING_H
#define PROFILING_H

#define MAX_NR_VCPUS			8
#define MAX_NR_VMS				6

#define MAX_MSR_LIST_NUM		15U
#define MAX_GROUP_NUM			1U

#define COLLECT_PROFILE_DATA	0
#define COLLECT_POWER_DATA		1

#define SEP_BUF_ENTRY_SIZE		32U

#define SOCWATCH_MSR_OP			100U

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

typedef enum PROFILING_SEP_FEATURE {
	CORE_PMU_SAMPLING = 0U,
	CORE_PMU_COUNTING,
	PEBS_PMU_SAMPLING,
	LBR_PMU_SAMPLING,
	UNCORE_PMU_SAMPLING,
	VM_SWITCH_TRACING,
	MAX_SEP_FEATURE_ID
} profiling_sep_feature;

typedef enum SOCWATCH_STATE {
	SW_SETUP,
	SW_RUNNING,
	SW_STOPPED
} socwatch_state;

typedef enum PROFILING_SOCWATCH_FEATURE {
	SOCWATCH_COMMAND = 0U,
	SOCWATCH_VM_SWITCH_TRACING,
	MAX_SOCWATCH_FEATURE_ID
} profiling_socwatch_feature;

struct sw_msr_op_info {
	uint64_t core_msr[MAX_MSR_LIST_NUM];
	uint32_t cpu_id;
	uint32_t valid_entries;
	uint16_t sample_id;
};


struct profiling_msr_op {
	/* value to write or location to write into */
	uint64_t	value;
	/* MSR address to read/write; last entry will have value of -1 */
	uint32_t	msr_id;
	/* parameter; usage depends on operation */
	uint16_t	param;
	uint8_t		op_type;
	uint8_t		reg_type;
};

struct profiling_msr_ops_list {
	int32_t		collector_id;
	uint32_t	num_entries;
	int32_t		msr_op_state;
	struct profiling_msr_op entries[MAX_MSR_LIST_NUM];
} __aligned(8);

struct profiling_pmi_config {
	uint32_t num_groups;
	uint32_t trigger_count;
	struct profiling_msr_op initial_list[MAX_GROUP_NUM][MAX_MSR_LIST_NUM];
	struct profiling_msr_op start_list[MAX_GROUP_NUM][MAX_MSR_LIST_NUM];
	struct profiling_msr_op stop_list[MAX_GROUP_NUM][MAX_MSR_LIST_NUM];
	struct profiling_msr_op entry_list[MAX_GROUP_NUM][MAX_MSR_LIST_NUM];
	struct profiling_msr_op exit_list[MAX_GROUP_NUM][MAX_MSR_LIST_NUM];
} __aligned(8);

struct profiling_vmsw_config {
	int32_t collector_id;
	struct profiling_msr_op initial_list[MAX_MSR_LIST_NUM];
	struct profiling_msr_op entry_list[MAX_MSR_LIST_NUM];
	struct profiling_msr_op exit_list[MAX_MSR_LIST_NUM];
} __aligned(8);

struct profiling_vcpu_pcpu_map {
	int32_t vcpu_id;
	int32_t pcpu_id;
	int32_t apic_id;
} __aligned(8);

struct profiling_vm_info {
	int32_t		vm_id;
	unsigned char	guid[16];
	char		vm_name[16];
	int32_t		num_vcpus;
	struct profiling_vcpu_pcpu_map	cpu_map[MAX_NR_VCPUS];
} __aligned(8);

struct profiling_vm_info_list {
	int32_t num_vms;
	struct profiling_vm_info vm_list[MAX_NR_VMS];
} __aligned(8);

struct profiling_version_info {
	int32_t major;
	int32_t minor;
	int64_t supported_features;
	int64_t reserved;
} __aligned(8);

struct profiling_control {
	int32_t		collector_id;
	int32_t		reserved;
	uint64_t	switches;
} __aligned(8);

struct profiling_pcpuid {
	uint32_t leaf;
	uint32_t subleaf;
	uint32_t eax;
	uint32_t ebx;
	uint32_t ecx;
	uint32_t edx;
} __aligned(8);

struct vmexit_msr {
	uint32_t msr_idx;
	uint32_t reserved;
	uint64_t msr_data;
} __aligned(16);

struct guest_vm_info {
	int		vm_id;
	uint64_t	vmenter_tsc;
	uint64_t	vmexit_tsc;
	uint64_t	vmexit_reason;
	int		external_vector;
	uint64_t	guest_rip;
	uint64_t	guest_rflags;
	uint64_t	guest_cs;
} __aligned(8);

struct vmm_ctx_info {
	uint64_t rip;
	uint64_t rflags;
	uint64_t cs;
} __aligned(8);

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

	struct vmexit_msr vmexit_msr_list[MAX_MSR_LIST_NUM];
	int vmexit_msr_cnt;
	uint64_t guest_debugctl_value;
	uint64_t saved_debugctl_value;
} __aligned(8);

struct data_header {
	int32_t collector_id;
	uint16_t cpu_id;
	uint16_t data_type;
	uint64_t tsc;
	uint64_t payload_size;
	uint64_t reserved;
} __aligned(SEP_BUF_ENTRY_SIZE);

#define DATA_HEADER_SIZE (sizeof(struct data_header))

struct core_pmu_sample {
	/* context where PMI is triggered */
	uint32_t	os_id;
	/* the task id */
	uint32_t	task_id;
	/* instruction pointer */
	uint64_t	rip;
	/* the task name */
	char		task[16];
	/* physical cpu ID */
	uint32_t	cpu_id;
	/* the process id */
	uint32_t	process_id;
	/* perf global status msr value (for overflow status) */
	uint64_t	overflow_status;
	/* rflags */
	uint32_t	rflags;
	/* code segment */
	uint32_t	cs;
} __aligned(SEP_BUF_ENTRY_SIZE);

#define CORE_PMU_SAMPLE_SIZE (sizeof(struct core_pmu_sample))

#define NUM_LBR_ENTRY		32

struct lbr_pmu_sample {
	/* LBR TOS */
	uint64_t	lbr_tos;
	/* LBR FROM IP */
	uint64_t	lbr_from_ip[NUM_LBR_ENTRY];
	/* LBR TO IP */
	uint64_t	lbr_to_ip[NUM_LBR_ENTRY];
	/* LBR info */
	uint64_t	lbr_info[NUM_LBR_ENTRY];
} __aligned(SEP_BUF_ENTRY_SIZE);

#define LBR_PMU_SAMPLE_SIZE (sizeof(struct lbr_pmu_sample))

struct pmu_sample {
	/* core pmu sample */
	struct core_pmu_sample	csample;
	/* lbr pmu sample */
	struct lbr_pmu_sample	lsample;
} __aligned(SEP_BUF_ENTRY_SIZE);


#define PMU_SAMPLE_SIZE (sizeof(struct pmu_sample))

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
	struct profiling_msr_ops_list	*msr_node;
	struct sep_state		sep_state;
	struct guest_vm_info		vm_info;
	struct vmm_ctx_info		vmm_ctx;
	ipi_commands			ipi_cmd;
	struct pmu_sample		pmu_sample;
	struct vm_switch_trace	vm_switch_trace;
	socwatch_state			socwatch_state;
	struct sw_msr_op_info		sw_msr_op_info;
};

#define VM_SWITCH_TRACE_SIZE (sizeof(struct vm_switch_trace))

struct intr_excp_ctx;

void profiling_start_pmu(void);
void profiling_stop_pmu(void);
int profiling_get_version(const struct vm *vm, uint64_t addr);
int profiling_get_pcpuid(const struct vm *vm, uint64_t addr);
int profiling_msr_ops_all_cpus(const struct vm *vm, uint64_t addr);
int profiling_vm_info_list(const struct vm *vm, uint64_t addr);
int profiling_get_control(const struct vm *vm, uint64_t addr);
int profiling_set_control(const struct vm *vm, uint64_t addr);
int profiling_config_pmi(const struct vm *vm, uint64_t addr);
int profiling_config_vmsw(const struct vm *vm, uint64_t addr);

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
