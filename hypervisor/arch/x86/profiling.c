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

