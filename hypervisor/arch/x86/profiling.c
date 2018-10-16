/*
 * Copyright (C) 2018 Intel Corporation. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifdef HV_DEBUG

#include <hypervisor.h>
#include <acrn_common.h>
#include <hv_arch.h>
#include <hv_debug.h>
#include <profiling.h>

#define ACRN_DBG_PROFILING		5U

#define MAJOR_VERSION			1
#define MINOR_VERSION			0

#define LVT_PERFCTR_BIT_MASK		0x10000U

static uint64_t	sep_collection_switch;

static uint32_t profiling_pmi_irq = IRQ_INVALID;

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
	struct sep_state *sepstate = &(get_cpu_var(profiling_info.sep_state));

	dev_dbg(ACRN_DBG_PROFILING, "%s: entering cpu%d",
		__func__, get_cpu_id());

	group_id = sepstate->current_pmi_group_id = 0U;
	for (i = 0U; i < MAX_MSR_LIST_NUM; i++) {
		msrop = &(sepstate->pmi_initial_msr_list[group_id][i]);
		if (msrop->msr_id == (uint32_t)-1) {
			break;
		}
		if (msrop->msr_id == MSR_IA32_DEBUGCTL) {
			sepstate->guest_debugctl_value = msrop->value;
		}
		if (msrop->op_type == (uint8_t)MSR_OP_WRITE) {
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
 */
void profiling_enable_pmu(void)
{
	/* to be implemented */
}

/*
 * Disable all Performance Monitoring Control registers
 */
void profiling_disable_pmu(void)
{
	/* to be implemented */
}

/*
 * Performs MSR operations - read, write and clear
 */
void profiling_handle_msrops(void)
{
	/* to be implemented */
}

/*
 * Interrupt handler for performance monitoring interrupts
 */
void profiling_pmi_handler(__unused unsigned int irq, __unused void *data)
{
	/* to be implemented */
}

/*
 * Performs MSR operations on all the CPU's
 */

int32_t profiling_msr_ops_all_cpus(__unused struct vm *vm, __unused uint64_t addr)
{
	/* to be implemented
	 * call to smp_call_function(0xFUL, profiling_ipi_handler, NULL);
	 */
	return 0;
}

/*
 * Generate VM info list
 */
int32_t profiling_vm_list_info(struct vm *vm, uint64_t addr)
{
	struct vm *tmp_vm;
	struct vcpu *vcpu;
	int i, j, vm_idx;
	struct profiling_vm_info_list vm_info_list;

	memset((void *)&vm_info_list, 0U, sizeof(vm_info_list));

	dev_dbg(ACRN_DBG_PROFILING, "%s: entering", __func__);

	if (copy_from_gpa(vm, &vm_info_list, addr, sizeof(vm_info_list)) != 0) {
		pr_err("%s: Unable to copy addr from vm\n", __func__);
		return -EINVAL;
	}

	vm_idx = 0;
	vm_info_list.vm_list[vm_idx].vm_id = 0xFFFFFFFFU;
	memcpy_s(vm_info_list.vm_list[vm_idx].vm_name, 4, "VMM\0", 4);
	for (i = 0; i < (int)phys_cpu_num; i++) {
		vm_info_list.vm_list[vm_idx].cpu_map[i].vcpu_id = i;
		vm_info_list.vm_list[vm_idx].cpu_map[i].pcpu_id = i;
		vm_info_list.vm_list[vm_idx].cpu_map[i].apic_id
			= per_cpu(lapic_id, i);
	}
	vm_info_list.vm_list[vm_idx].num_vcpus = i;
	vm_info_list.num_vms = 1;

	for (j = 0; j < (int)CONFIG_MAX_VM_NUM; j++) {
		i = 0;

		tmp_vm = get_vm_from_vmid(j);

		if (tmp_vm == NULL) {
			break;
		}
		vm_info_list.num_vms++;
		vm_idx++;

		vm_info_list.vm_list[vm_idx].vm_id = tmp_vm->vm_id;
		memcpy_s(vm_info_list.vm_list[vm_idx].guid, 16, tmp_vm->GUID, 16);
		snprintf(vm_info_list.vm_list[vm_idx].vm_name, 16, "vm_%d",
				tmp_vm->vm_id, 16);
		vm_info_list.vm_list[vm_idx].num_vcpus = 0;
		foreach_vcpu(i, tmp_vm, vcpu) {
			vm_info_list.vm_list[vm_idx].cpu_map[i].vcpu_id
					= vcpu->vcpu_id;
			vm_info_list.vm_list[vm_idx].cpu_map[i].pcpu_id
					= vcpu->pcpu_id;
			vm_info_list.vm_list[vm_idx].cpu_map[i].apic_id = 0;
			vm_info_list.vm_list[vm_idx].num_vcpus++;
		}
	}

	if (copy_to_gpa(vm, &vm_info_list, addr, sizeof(vm_info_list)) != 0) {
		pr_err("%s: Unable to copy addr to vm\n", __func__);
		return -EINVAL;
	}

	dev_dbg(ACRN_DBG_PROFILING, "%s: exiting", __func__);
	return 0;
}

/*
 * Sep/socwatch profiling version
 */
int32_t profiling_get_version(struct vm *vm, uint64_t addr)
{
	struct profiling_version_info ver_info;

	memset((void *)&ver_info, 0U, sizeof(ver_info));

	dev_dbg(ACRN_DBG_PROFILING, "%s: entering", __func__);

	if (copy_from_gpa(vm, &ver_info, addr, sizeof(ver_info)) != 0) {
		pr_err("%s: Unable to copy addr from vm\n", __func__);
		return -EINVAL;
	}

	ver_info.major = MAJOR_VERSION;
	ver_info.minor = MINOR_VERSION;
	ver_info.supported_features = (int64_t)
					(1 << CORE_PMU_SAMPLING) |
					(1 << CORE_PMU_COUNTING) |
					(1 << LBR_PMU_SAMPLING) |
					(1 << VM_SWITCH_TRACING);

	if (copy_to_gpa(vm, &ver_info, addr, sizeof(ver_info)) != 0) {
		pr_err("%s: Unable to copy addr to vm\n", __func__);
		return -EINVAL;
	}

	dev_dbg(ACRN_DBG_PROFILING, "%s: exiting", __func__);

	return 0;
}

/*
 * Gets type of profiling - sep/socwatch
 */
int32_t profiling_get_control(struct vm *vm, uint64_t addr)
{
	struct profiling_control prof_control;

	memset((void *)&prof_control, 0U, sizeof(prof_control));

	dev_dbg(ACRN_DBG_PROFILING, "%s: entering", __func__);

	if (copy_from_gpa(vm, &prof_control, addr, sizeof(prof_control)) != 0) {
		pr_err("%s: Unable to copy addr from vm\n", __func__);
		return -EINVAL;
	}

	switch (prof_control.collector_id) {
	case COLLECT_PROFILE_DATA:
		prof_control.switches = sep_collection_switch;
		break;
	case COLLECT_POWER_DATA:
		break;
	default:
		pr_err("%s: unknown collector %d",
			__func__, prof_control.collector_id);
	}

	if (copy_to_gpa(vm, &prof_control, addr, sizeof(prof_control)) != 0) {
		pr_err("%s: Unable to copy addr to vm\n", __func__);
		return -EINVAL;
	}

	dev_dbg(ACRN_DBG_PROFILING, "%s: exiting", __func__);

	return 0;
}

/*
 * Update the profiling type based on control switch
 */
int32_t profiling_set_control(__unused struct vm *vm, __unused uint64_t addr)
{
	/* to be implemented */
	return 0;
}

/*
 * Configure PMI on all cpus
 */
int32_t profiling_config_pmi(struct vm *vm, uint64_t addr)
{
	unsigned int i;
	struct profiling_pmi_config pmi_config;

	memset((void *)&pmi_config, 0U, sizeof(pmi_config));

	dev_dbg(ACRN_DBG_PROFILING, "%s: entering", __func__);

	if (copy_from_gpa(vm, &pmi_config, addr, sizeof(pmi_config)) != 0) {
		pr_err("%s: Unable to copy addr from vm\n", __func__);
		return -EINVAL;
	}

	for (i = 0U; i < phys_cpu_num; i++) {
		if (!((per_cpu(profiling_info.sep_state, i).pmu_state ==
				PMU_INITIALIZED) ||
			(per_cpu(profiling_info.sep_state, i).pmu_state ==
				PMU_SETUP))) {
			pr_err("%s: invalid pmu_state %u on cpu%d",
			__func__, per_cpu(profiling_info.sep_state, i).pmu_state, i);
			return -EINVAL;
		}
	}

	if (pmi_config.num_groups == 0U ||
		pmi_config.num_groups > MAX_GROUP_NUM) {
		pr_err("%s: invalid num_groups %u",
			__func__, pmi_config.num_groups);
		return -EINVAL;
	}

	for (i = 0U; i < phys_cpu_num; i++) {
		per_cpu(profiling_info.ipi_cmd, i) = IPI_PMU_CONFIG;
		per_cpu(profiling_info.sep_state, i).num_pmi_groups
			= pmi_config.num_groups;

		memcpy_s(per_cpu(profiling_info.sep_state, i).pmi_initial_msr_list,
		sizeof(struct profiling_msr_op)*MAX_MSR_LIST_NUM*MAX_GROUP_NUM,
		pmi_config.initial_list,
		sizeof(struct profiling_msr_op)*MAX_MSR_LIST_NUM*MAX_GROUP_NUM);

		memcpy_s(per_cpu(profiling_info.sep_state, i).pmi_start_msr_list,
		sizeof(struct profiling_msr_op)*MAX_MSR_LIST_NUM*MAX_GROUP_NUM,
		pmi_config.start_list,
		sizeof(struct profiling_msr_op)*MAX_MSR_LIST_NUM*MAX_GROUP_NUM);

		memcpy_s(per_cpu(profiling_info.sep_state, i).pmi_stop_msr_list,
		sizeof(struct profiling_msr_op)*MAX_MSR_LIST_NUM*MAX_GROUP_NUM,
		pmi_config.stop_list,
		sizeof(struct profiling_msr_op)*MAX_MSR_LIST_NUM*MAX_GROUP_NUM);

		memcpy_s(per_cpu(profiling_info.sep_state, i).pmi_entry_msr_list,
		sizeof(struct profiling_msr_op)*MAX_MSR_LIST_NUM*MAX_GROUP_NUM,
		pmi_config.entry_list,
		sizeof(struct profiling_msr_op)*MAX_MSR_LIST_NUM*MAX_GROUP_NUM);

		memcpy_s(per_cpu(profiling_info.sep_state, i).pmi_exit_msr_list,
		sizeof(struct profiling_msr_op)*MAX_MSR_LIST_NUM*MAX_GROUP_NUM,
		pmi_config.exit_list,
		sizeof(struct profiling_msr_op)*MAX_MSR_LIST_NUM*MAX_GROUP_NUM);
	}

	smp_call_function(0xFUL, profiling_ipi_handler, NULL);

	if (copy_to_gpa(vm, &pmi_config, addr, sizeof(pmi_config)) != 0) {
		pr_err("%s: Unable to copy addr to vm\n", __func__);
		return -EINVAL;
	}

	dev_dbg(ACRN_DBG_PROFILING, "%s: exiting", __func__);
	return 0;
}

/*
 * Configure for VM-switch data on all cpus
 */
int32_t profiling_config_vmsw(struct vm *vm, uint64_t addr)
{
	uint16_t i;
	struct profiling_vmsw_config vmsw_config;

	memset((void *)&vmsw_config, 0U, sizeof(vmsw_config));

	dev_dbg(ACRN_DBG_PROFILING, "%s: entering", __func__);

	if (copy_from_gpa(vm, &vmsw_config, addr, sizeof(vmsw_config)) != 0) {
		pr_err("%s: Unable to copy addr from vm\n", __func__);
		return -EINVAL;
	}

	switch (vmsw_config.collector_id) {
	case COLLECT_PROFILE_DATA:
		for (i = 0U; i < phys_cpu_num; i++) {
			per_cpu(profiling_info.ipi_cmd, i) = IPI_VMSW_CONFIG;

			memcpy_s(
			per_cpu(profiling_info.sep_state, i).vmsw_initial_msr_list,
			sizeof(struct profiling_msr_op)*MAX_MSR_LIST_NUM,
			vmsw_config.initial_list,
			sizeof(struct profiling_msr_op)*MAX_MSR_LIST_NUM);

			memcpy_s(
			per_cpu(profiling_info.sep_state, i).vmsw_entry_msr_list,
			sizeof(struct profiling_msr_op)*MAX_MSR_LIST_NUM,
			vmsw_config.entry_list,
			sizeof(struct profiling_msr_op)*MAX_MSR_LIST_NUM);

			memcpy_s(
			per_cpu(profiling_info.sep_state, i).vmsw_exit_msr_list,
			sizeof(struct profiling_msr_op)*MAX_MSR_LIST_NUM,
			vmsw_config.exit_list,
			sizeof(struct profiling_msr_op)*MAX_MSR_LIST_NUM);
		}

		smp_call_function(0xFUL, profiling_ipi_handler, NULL);

		break;
	case COLLECT_POWER_DATA:
		break;
	default:
		pr_err("%s: unknown collector %d",
			__func__, vmsw_config.collector_id);
		return -EINVAL;
	}

	if (copy_to_gpa(vm, &vmsw_config, addr, sizeof(vmsw_config)) != 0) {
		pr_err("%s: Unable to copy addr to vm\n", __func__);
		return -EINVAL;
	}

	dev_dbg(ACRN_DBG_PROFILING, "%s: exiting", __func__);

	return 0;
}

/*
 * Get the physical cpu id
 */
int32_t profiling_get_pcpuid(struct vm *vm, uint64_t addr)
{
	struct profiling_pcpuid pcpuid;

	memset((void *)&pcpuid, 0U, sizeof(pcpuid));

	dev_dbg(ACRN_DBG_PROFILING, "%s: entering", __func__);

	if (copy_from_gpa(vm, &pcpuid, addr, sizeof(pcpuid)) != 0) {
		pr_err("%s: Unable to copy addr from vm\n", __func__);
		return -EINVAL;
	}

	cpuid_subleaf(pcpuid.leaf, pcpuid.subleaf, &pcpuid.eax,
			&pcpuid.ebx, &pcpuid.ecx, &pcpuid.edx);

	if (copy_to_gpa(vm, &pcpuid, addr, sizeof(pcpuid)) != 0) {
		pr_err("%s: Unable to copy param to vm\n", __func__);
		return -EINVAL;
	}

	dev_dbg(ACRN_DBG_PROFILING, "%s: exiting", __func__);

	return 0;
}

/*
 * IPI interrupt handler function
 */
void profiling_ipi_handler(__unused void *data)
{
	switch (get_cpu_var(profiling_info.ipi_cmd)) {
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
		__func__, get_cpu_var(profiling_info.ipi_cmd), get_cpu_id());
	}
	get_cpu_var(profiling_info.ipi_cmd) = IPI_UNKNOWN;
}

/*
 * Save the VCPU info on vmenter
 */
void profiling_vmenter_handler(__unused struct vcpu *vcpu)
{
	/* to be implemented */
}

/*
 * Save the VCPU info on vmexit
 */
void profiling_vmexit_handler(__unused struct vcpu *vcpu, __unused uint64_t exit_reason)
{
	if (exit_reason == VMX_EXIT_REASON_EXTERNAL_INTERRUPT) {
		/* to be implemented */
	} else {
		/* to be implemented */
	}
}

/*
 * Setup PMI irq vector
 */
void profiling_setup(void)
{
	int cpu;
	int retval;
	dev_dbg(ACRN_DBG_PROFILING, "%s: entering", __func__);
	cpu = (int)get_cpu_id();
	/* support PMI notification, VM0 will register all CPU */
	if (cpu == 0) {
		pr_info("%s: calling request_irq", __func__);
		retval = request_irq(PMI_IRQ,
			profiling_pmi_handler, NULL, IRQF_NONE);
		if (retval < 0) {
			pr_err("Failed to add PMI isr");
			return;
		}
		profiling_pmi_irq = (uint32_t)retval;
	}

	per_cpu(profiling_info.sep_state, cpu).pmu_state = PMU_INITIALIZED;

	write_lapic_reg32(LAPIC_LVT_PMC_REGISTER,
		VECTOR_PMI | LVT_PERFCTR_BIT_MASK);

	dev_dbg(ACRN_DBG_PROFILING, "%s: exiting", __func__);
}

#endif
