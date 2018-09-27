/*
 * Copyright (C) 2018 Intel Corporation. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <hypervisor.h>
#include <hv_lib.h>
#include <acrn_common.h>
#include <hv_arch.h>
#include <hv_debug.h>
#include <profiling.h>

#define ACRN_DBG_PROFILING		5U

#define LVT_PERFCTR_BIT_UNMASK		0xFFFEFFFFU
#define LVT_PERFCTR_BIT_MASK		0x10000U
#define VALID_DEBUGCTL_BIT_MASK		0x1801U

void profiling_initialize_vmsw(void)
{
	dev_dbg(ACRN_DBG_PROFILING, "%s: entering cpu%d",
		__func__, get_cpu_id());

	dev_dbg(ACRN_DBG_PROFILING, "%s: exiting cpu%d",
		__func__, get_cpu_id());
}

/*
 * Configure the PMU's for sep/socwatch profiling.
 * Initial write of PMU registers.
 * Walk through the entries and write the value of the register accordingly.
 * Note: current_group is always set to 0, only 1 group is supported.
 */
void profiling_initialize_pmi(void)
{
	unsigned int i;
	uint32_t group_id;
	struct profiling_msr_op *msrop = NULL;
	struct sep_state *sepstate = &(get_cpu_var(sep_info.sep_state));

	dev_dbg(ACRN_DBG_PROFILING, "%s: entering cpu%d",
		__func__, get_cpu_id());

	group_id = sepstate->current_pmi_group_id = 0U;
	for (i = 0U; i < MAX_MSR_LIST_NUM; i++) {
		msrop = &(sepstate->pmi_initial_msr_list[group_id][i]);
		if (msrop->msr_id == (int32_t)-1) {
			break;
		}
		if ((uint32_t)msrop->msr_id == MSR_IA32_DEBUGCTL) {
			sepstate->guest_debugctl_value = msrop->value;
		}
		if (msrop->op_type == MSR_OP_WRITE) {
			msr_write(msrop->msr_id, msrop->value);
			dev_dbg(ACRN_DBG_PROFILING,
			"%s: MSRWRITE cpu%d, msr_id=0x%x, msr_val=0x%llx",
			__func__, get_cpu_id(), msrop->msr_id, msrop->value);
		}
	}

	sepstate->pmu_state = PMU_SETUP;

	dev_dbg(ACRN_DBG_PROFILING, "%s: exiting cpu%d",
		__func__,  get_cpu_id());
}

/*
 * Enable all the Performance Monitoring Control registers.
 * Unmask LAPIC entry for PMC register to enable performance monitoring
 * Walk through the entries and write to PMU control registers.
 */
void profiling_enable_pmu(void)
{
	uint32_t lvt_perf_ctr;
	unsigned int i;
	uint32_t group_id;
	struct profiling_msr_op *msrop = NULL;
	struct sep_state *sepstate = &(get_cpu_var(sep_info.sep_state));

	/* Unmask LAPIC LVT entry for PMC register */
	lvt_perf_ctr = read_lapic_reg32(LAPIC_LVT_PMC_REGISTER);
	dev_dbg(ACRN_DBG_PROFILING, "%s: 0x%x, 0x%llx",
		__func__, LAPIC_LVT_PMC_REGISTER, lvt_perf_ctr);
	lvt_perf_ctr &= LVT_PERFCTR_BIT_UNMASK;
	write_lapic_reg32(LAPIC_LVT_PMC_REGISTER, lvt_perf_ctr);
	dev_dbg(ACRN_DBG_PROFILING, "%s: 0x%x, 0x%llx",
		__func__, LAPIC_LVT_PMC_REGISTER, lvt_perf_ctr);

	if (sepstate->guest_debugctl_value != 0U) {
		if (sepstate->vmexit_msr_list == NULL) {
			sepstate->vmexit_msr_list = (struct vmexit_msr *)
					malloc(sizeof(struct vmexit_msr));
		}

		/* Set the VM Exit MSR Load in VMCS */
		if (sepstate->vmexit_msr_list != NULL) {
			sepstate->vmexit_msr_cnt = 1;
			sepstate->vmexit_msr_list[0].msr_idx
				= MSR_IA32_DEBUGCTL;
			sepstate->vmexit_msr_list[0].msr_data
				= sepstate->guest_debugctl_value &
					VALID_DEBUGCTL_BIT_MASK;

			exec_vmwrite64(VMX_EXIT_MSR_LOAD_ADDR_FULL,
				hva2hpa(sepstate->vmexit_msr_list));
			exec_vmwrite(VMX_EXIT_MSR_LOAD_COUNT,
				sepstate->vmexit_msr_cnt);
		}
		/* VMCS GUEST field */
		sepstate->saved_debugctl_value
			= exec_vmread64(VMX_GUEST_IA32_DEBUGCTL_FULL);
		exec_vmwrite64(VMX_GUEST_IA32_DEBUGCTL_FULL,
		  (sepstate->guest_debugctl_value & VALID_DEBUGCTL_BIT_MASK));
	}

	group_id = sepstate->current_pmi_group_id;
	for (i = 0U; i < MAX_MSR_LIST_NUM; i++) {
		msrop = &(sepstate->pmi_start_msr_list[group_id][i]);
		if (msrop->msr_id == (int32_t)-1) {
			break;
		}
		if (msrop->op_type == MSR_OP_WRITE) {
			msr_write(msrop->msr_id, msrop->value);
			dev_dbg(ACRN_DBG_PROFILING,
			"%s: MSRWRITE cpu%d, msr_id=0x%x, msr_val=0x%llx",
			__func__, get_cpu_id(), msrop->msr_id, msrop->value);
		}
	}

	sepstate->pmu_state = PMU_RUNNING;
}

/*
 * Disable all Performance Monitoring Control registers
 */
void profiling_disable_pmu(void)
{
	uint32_t lvt_perf_ctr;
	unsigned int i;
	uint32_t group_id;
	struct profiling_msr_op *msrop = NULL;
	struct sep_state *sepstate = &(get_cpu_var(sep_info.sep_state));

	if (sepstate->vmexit_msr_list) {
		/* Set the VM Exit MSR Load in VMCS */
		exec_vmwrite(VMX_EXIT_MSR_LOAD_COUNT, 0x0U);
		exec_vmwrite64(VMX_GUEST_IA32_DEBUGCTL_FULL,
			sepstate->saved_debugctl_value);

		free(sepstate->vmexit_msr_list);
		sepstate->vmexit_msr_list = NULL;
		sepstate->vmexit_msr_cnt = 0;
	}

	group_id = sepstate->current_pmi_group_id;
	for (i = 0U; i < MAX_MSR_LIST_NUM; i++) {
		msrop = &(sepstate->pmi_stop_msr_list[group_id][i]);
		if (msrop->msr_id == (int32_t)-1) {
			break;
		}
		if (msrop->op_type == MSR_OP_WRITE) {
			msr_write(msrop->msr_id, msrop->value);
			dev_dbg(ACRN_DBG_PROFILING,
			"%s: MSRWRITE cpu%d, msr_id=0x%x, msr_val=0x%llx",
			__func__, get_cpu_id(), msrop->msr_id, msrop->value);
		}
	}

	/* Mask LAPIC LVT entry for PMC register */
	lvt_perf_ctr = read_lapic_reg32(LAPIC_LVT_PMC_REGISTER);
	lvt_perf_ctr |= LVT_PERFCTR_BIT_MASK;
	write_lapic_reg32(LAPIC_LVT_PMC_REGISTER, lvt_perf_ctr);

	sepstate->pmu_state = PMU_SETUP;
}

/*
 * Performs MSR operations - read, write and clear
 */
void profiling_handle_msrops(void)
{
	/* to be implemented */
}

/*
 * Performs MSR operations on all the CPU's
 */
int profiling_msr_ops_all_cpus(uint64_t addr)
{
	/* to be implemented */
	return 0;
}

/*
 * Generate VM info list
 */
int profiling_vm_info_list(uint64_t addr)
{
	/* to be implemented */
	return 0;
}

/*
 * Sep/socwatch profiling version
 */
int profiling_get_version(uint64_t addr)
{
	/* to be implemented */
	return 0;
}

/*
 * Gets type of profiling - sep/socwatch
 */
int profiling_get_control(uint64_t addr)
{
	/* to be implemented */
	return 0;
}

/*
 * Update the profiling type based on control switch
 */
int profiling_set_control(uint64_t addr)
{
	/* to be implemented */
	return 0;
}

/*
 * Configure PMI on all cpus
 */
int profiling_config_pmi(uint64_t addr)
{
	/* to be implemented */
	return 0;
}

/*
 * Configure for VM-switch data on all cpus
 */
int profiling_config_vmsw(uint64_t addr)
{
	/* to be implemented */
	return 0;
}

/*
 * Get the physical cpu id
 */
int profiling_get_pcpuid(uint64_t addr)
{
	/* to be implemented */
	return 0;
}

#ifdef HV_DEBUG
/*
 * IPI interrupt handler function
 */
int profiling_ipi_handler(void)
{
	switch (get_cpu_var(sep_info.ipi_cmd)) {
	case IPI_PMU_START:
		profiling_enable_pmu();
		break;
	case IPI_PMU_STOP:
		profiling_disable_pmu();
		break;
	case IPI_MSR_OP:
		profiling_handle_msrops();
		break;
	case IPI_PMU_CONFIG:
		profiling_initialize_pmi();
		break;
	case IPI_VMSW_CONFIG:
		profiling_initialize_vmsw();
		break;
	default:
		pr_err("%s: unknown IPI command %d on cpu %d",
			__func__, get_cpu_var(sep_info.ipi_cmd), get_cpu_id());
	}

	get_cpu_var(sep_info.ipi_cmd) = IPI_UNKNOWN;

	return 0;
}

/*
 * Save the VCPU info on vmenter
 */
int profiling_vmenter_handler(__unused struct vcpu *vcpu)
{
	/* to be implemented */
	return 0;
}

/*
 * Save the VCPU info on vmexit
 */
int profiling_vmexit_handler(struct vcpu *vcpu, uint64_t exit_reason)
{
	/* to be implemented */
	return 0;
}

/*
 * Save the context info on interrupt
 */
void profiling_capture_intr_context(struct intr_excp_ctx *ctx)
{
	/* to be implemented */
}

/*
 * Setup IPI and PMI irq vectors
 */
void profiling_setup(void)
{
	/* to be implemented */
}

#endif

