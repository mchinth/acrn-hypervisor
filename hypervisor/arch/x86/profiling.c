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

#define LVT_PERFCTR_BIT_MASK		0x10000U

static uint32_t profiling_pmi_irq = IRQ_INVALID;

void profiling_initialize_vmsw(void)
{
	/* to be implemented */
}

/*
 * Configure the PMU's for sep/socwatch profiling.
 */
void profiling_initialize_pmi(void)
{
	/* to be implemented */
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
int32_t profiling_vm_list_info(__unused struct vm *vm, __unused uint64_t addr)
{
	/* to be implemented */
	return 0;
}

/*
 * Sep/socwatch profiling version
 */
int32_t profiling_get_version(__unused struct vm *vm, __unused uint64_t addr)
{
	/* to be implemented */
	return 0;
}

/*
 * Gets type of profiling - sep/socwatch
 */
int32_t profiling_get_control(__unused struct vm *vm, __unused uint64_t addr)
{
	/* to be implemented */
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
int32_t profiling_config_pmi(__unused struct vm *vm, __unused uint64_t addr)
{
	/* to be implemented
	 * call to smp_call_function(0xFUL, profiling_ipi_handler, NULL);
	 */
	return 0;
}

/*
 * Configure for VM-switch data on all cpus
 */
int32_t profiling_config_vmsw(__unused struct vm *vm, __unused uint64_t addr)
{
	/* to be implemented
	 * call to smp_call_function(0xFUL, profiling_ipi_handler, NULL);
	 */
	return 0;
}

/*
 * Get the physical cpu id
 */
int32_t profiling_get_pcpuid(__unused struct vm *vm, __unused uint64_t addr)
{
	/* to be implemented */
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

	write_lapic_reg32(LAPIC_LVT_PMC_REGISTER,
		VECTOR_PMI | LVT_PERFCTR_BIT_MASK);

	dev_dbg(ACRN_DBG_PROFILING, "%s: exiting", __func__);
}

#endif
