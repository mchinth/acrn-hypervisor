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

#define MAJOR_VERSION			1
#define MINOR_VERSION			0

#define LBR_NUM_REGISTERS		32U

#define PERF_OVF_BIT_MASK		0xC0000070000000FULL
#define LVT_PERFCTR_BIT_UNMASK		0xFFFEFFFFU
#define LVT_PERFCTR_BIT_MASK		0x10000U
#define VALID_DEBUGCTL_BIT_MASK		0x1801U

static uint64_t		sep_collection_switch;
static uint64_t		socwatch_collection_switch;
static bool			in_pmu_profiling;

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

static inline uint32_t sbuf_next_ptr(uint32_t pos,
		uint32_t span, uint32_t scope)
{
	pos += span;
	pos = (pos >= scope) ? (pos - scope) : pos;
	return pos;
}

/*
 * Writes specified size of data into sbuf
 */
static int profiling_sbuf_put_variable(struct shared_buf *sbuf,
					uint8_t *data, uint32_t size)
{
	uint32_t remaining_space, offset, next_tail;
	void *to;

	/*
	 * 1. check for null pointers and non-zero size
	 * 2. check if enough room available in the buffer
	 *     2a. if not, drop the sample, increment count of dropped samples,
	 *         return
	 *     2b. unless overwrite flag is enabled
	 * 3. Continue if buffer has space for the sample
	 * 4. Copy sample to buffer
	 *     4a. Split variable sample to be copied if the sample is going to
	 *         wrap around the buffer
	 *     4b. Otherwise do a simple copy
	 * 5. return number of bytes of data put in buffer
	 */

	if ((sbuf == NULL) || (data == NULL)) {
		dev_dbg(ACRN_DBG_PROFILING, "buffer or data not initialized!");
		return -EINVAL;
	}

	if (size == 0U) {
		dev_dbg(ACRN_DBG_PROFILING,
			"0 bytes reqeusted to be put in buffer!");
		return 0;
	}

	if (sbuf->tail >= sbuf->head) {
		remaining_space = sbuf->size - (sbuf->tail - sbuf->head);
	} else {
		remaining_space = sbuf->head - sbuf->tail;
	}

	if (size >= remaining_space) {
		/* Only (remaining_space - 1) can be written to sbuf.
		 * Since if the next_tail equals head, then it is assumed
		 * that buffer is empty, not full
		 */
		dev_dbg(ACRN_DBG_PROFILING,
		"Not enough space to write data! Returning without writing");
		return 0;
	}

	next_tail = sbuf_next_ptr(sbuf->tail, size, sbuf->size);
	dev_dbg(ACRN_DBG_PROFILING, "sbuf->tail: %llu, next_tail: %llu",
		sbuf->tail, next_tail);

	to = (void *)sbuf + SBUF_HEAD_SIZE + sbuf->tail;

	if (next_tail < sbuf->tail) { /* wrap-around */
		dev_dbg(ACRN_DBG_PROFILING, "wrap-around condition!");
		offset = sbuf->size - sbuf->tail;
		memcpy_s(to, offset, data, offset);

		/* 2nd part */
		to = (void *)sbuf + SBUF_HEAD_SIZE;

		if (size - offset) {
			memcpy_s(to, size - offset,
				data + offset, size - offset);
		}
	} else {
		dev_dbg(ACRN_DBG_PROFILING, "non-wrap-around!");
		memcpy_s(to, size, data, size);
	}

	sbuf->tail = next_tail;

	return size;
}

/*
 * Read profiling data and transfered to SOS
 * Drop transfer of profiling data if sbuf is full/insufficient and log it
 */
static int profiling_generate_data(int32_t collector, uint32_t type)
{
	uint32_t i, remaining_space = 0U;
	struct data_header pkt_header;
	uint64_t payload_size = 0U;
	uint8_t *payload = NULL;
	struct shared_buf *sbuf = NULL;
	struct sep_state *sepstate = &(get_cpu_var(sep_info.sep_state));
	struct sw_msr_op_info *sw_msrop
		= &(get_cpu_var(sep_info.sw_msr_op_info));

	if (collector == COLLECT_PROFILE_DATA) {
		sbuf = (struct shared_buf *)
			get_cpu_var(sbuf)[ACRN_SEP];

		if (sbuf == NULL) {
			sepstate->samples_dropped++;
			return 0;
		}

		if (sepstate->pmu_state == PMU_RUNNING) {
			if (sbuf->tail >= sbuf->head) {
				remaining_space = sbuf->size
						- (sbuf->tail - sbuf->head);
			} else {
				remaining_space = sbuf->head - sbuf->tail;
			}

			/* populate the data header */
			pkt_header.tsc = rdtsc();
			pkt_header.collector_id = collector;
			pkt_header.cpu_id = get_cpu_id();
			pkt_header.data_type = (uint16_t) (1U << type);

			switch (type) {
			case CORE_PMU_SAMPLING:
				payload_size = CORE_PMU_SAMPLE_SIZE;
				payload = (uint8_t *)
					&get_cpu_var(sep_info.pmu_sample);
				break;
			case LBR_PMU_SAMPLING:
				payload_size = CORE_PMU_SAMPLE_SIZE
					+ LBR_PMU_SAMPLE_SIZE;
				payload = (uint8_t *)
					&get_cpu_var(sep_info.pmu_sample);
				break;
			case VM_SWITCH_TRACING:
				payload_size = VM_SWITCH_TRACE_SIZE;
				payload = (uint8_t *)
					&get_cpu_var(sep_info.vm_switch_trace);
				break;
			default:
				pr_err("%s: unknown data type %u on cpu %d",
					__func__, type, get_cpu_id());
				return 0;
			}

			pkt_header.payload_size = payload_size;

			if ((uint64_t)remaining_space < DATA_HEADER_SIZE + payload_size) {
				sepstate->samples_dropped++;
				return 0;
			}

			uint32_t tmp_size
				= (DATA_HEADER_SIZE-1)/SEP_BUF_ENTRY_SIZE+1;

			for (i = 0U; i < tmp_size; i++) {
				sbuf_put(sbuf, (uint8_t *)
					&pkt_header+i*SEP_BUF_ENTRY_SIZE);
			}

			tmp_size = (uint32_t)(payload_size - 1) / SEP_BUF_ENTRY_SIZE + 1;
			for (i = 0U; i < tmp_size; i++) {
				sbuf_put(sbuf, (uint8_t *)payload+i*SEP_BUF_ENTRY_SIZE);
			}

			sepstate->samples_logged++;
		}
	} else if (collector == COLLECT_POWER_DATA) {

		sbuf = (struct shared_buf *)
				get_cpu_var(sbuf)[ACRN_SOCWATCH];

		if (sbuf == NULL) {
			dev_dbg(ACRN_DBG_PROFILING,
			"%s: socwatch buffers not initialized?", __func__);
			return 0;
		}

		if (sbuf->tail >= sbuf->head) {
			remaining_space
				= sbuf->size - (sbuf->tail - sbuf->head);
		} else {
			remaining_space = sbuf->head - sbuf->tail;
		}

		/* populate the data header */
		pkt_header.tsc = rdtsc();
		pkt_header.collector_id = collector;
		pkt_header.cpu_id = get_cpu_id();
		pkt_header.data_type = (uint16_t)type;

		switch (type) {
		case SOCWATCH_MSR_OP:
			dev_dbg(ACRN_DBG_PROFILING,
				"%s: generating cstate/pstate sample socwatch cpu %d",
				__func__, sw_msrop->cpu_id);
			pkt_header.cpu_id = sw_msrop->cpu_id;
			pkt_header.data_type = sw_msrop->sample_id;
			payload_size
				= (sw_msrop->valid_entries * sizeof(uint64_t));
			payload = (uint8_t *)&(sw_msrop->core_msr[0]);
			break;

		case SOCWATCH_VM_SWITCH_TRACING:
			dev_dbg(ACRN_DBG_PROFILING,
				"%s: generating vm-switch sample", __func__);
			payload_size = VM_SWITCH_TRACE_SIZE;
			payload = (uint8_t *)
					&get_cpu_var(sep_info.vm_switch_trace);
			break;
		default:
			pr_err("%s: unknown data type %u on cpu %d",
				__func__, type, get_cpu_id());
			return 0;
		}

		pkt_header.payload_size = payload_size;

		if ((DATA_HEADER_SIZE + payload_size) >= (uint64_t)remaining_space) {
			pr_err("%s: not enough space in socwatch buffer on cpu %d",
				__func__, get_cpu_id());
			return 0;
		}
		/* copy header */
		profiling_sbuf_put_variable(sbuf,
			(uint8_t *)&pkt_header, DATA_HEADER_SIZE);
		/* copy payload */
		profiling_sbuf_put_variable(sbuf,
			(uint8_t *)payload, payload_size);
	}
	return 0;
}

/*
 * Performs MSR operations - read, write and clear
 */
void profiling_handle_msrops(void)
{
	unsigned int i, j;
	struct profiling_msr_ops_list *my_msr_node;
	struct sw_msr_op_info *sw_msrop
		= &(get_cpu_var(sep_info.sw_msr_op_info));

	dev_dbg(ACRN_DBG_PROFILING, "%s: entering cpu%d",
		__func__, get_cpu_id());

	my_msr_node = get_cpu_var(sep_info.msr_node);

	if (my_msr_node == NULL ||
		my_msr_node->msr_op_state != MSR_OP_REQUESTED) {
		dev_dbg(ACRN_DBG_PROFILING, "%s: invalid my_msr_node on cpu%d",
			__func__, get_cpu_id());
		return;
	}

	if (my_msr_node->num_entries == 0U
		|| my_msr_node->num_entries >= MAX_MSR_LIST_NUM) {
		dev_dbg(ACRN_DBG_PROFILING,
		"%s: invalid num_entries on cpu%d",
		__func__, get_cpu_id());
		return;
	}

	for (i = 0U; i < my_msr_node->num_entries; i++) {
		switch (my_msr_node->entries[i].op_type) {
		case MSR_OP_READ:
			my_msr_node->entries[i].value
				= msr_read(my_msr_node->entries[i].msr_id);

			dev_dbg(ACRN_DBG_PROFILING,
			"%s: MSRREAD cpu%d, msr_id=0x%x, msr_val=0x%llx",
			__func__, get_cpu_id(),	my_msr_node->entries[i].msr_id,
			my_msr_node->entries[i].value);
			break;
		case MSR_OP_READ_CLEAR:
			my_msr_node->entries[i].value
				= msr_read(my_msr_node->entries[i].msr_id);

			dev_dbg(ACRN_DBG_PROFILING,
			"%s: MSRREADCLEAR cpu%d, msr_id=0x%x, msr_val=0x%llx",
			__func__, get_cpu_id(), my_msr_node->entries[i].msr_id,
			my_msr_node->entries[i].value);
			msr_write(my_msr_node->entries[i].msr_id, 0);
			break;
		case MSR_OP_WRITE:
			msr_write(my_msr_node->entries[i].msr_id,
				my_msr_node->entries[i].value);

			dev_dbg(ACRN_DBG_PROFILING,
			"%s: MSRWRITE cpu%d, msr_id=0x%x, msr_val=0x%llx",
			__func__, get_cpu_id(), my_msr_node->entries[i].msr_id,
			my_msr_node->entries[i].value);
			break;
		default:
			pr_err("%s: unknown MSR op_type %u on cpu %d",
			__func__, my_msr_node->entries[i].op_type,
			get_cpu_id());
		}
	}

	my_msr_node->msr_op_state = MSR_OP_HANDLED;

	/* Also generates sample */
	if (my_msr_node->collector_id == COLLECT_POWER_DATA) {

		sw_msrop->cpu_id = get_cpu_id();
		sw_msrop->valid_entries = my_msr_node->num_entries;

		/*
		 * if 'param' is 0, then skip generating a sample since it is
		 * an immediate MSR read operation.
		 */
		if (my_msr_node->entries[0].param) {
			for (j = 0U; j < my_msr_node->num_entries; ++j) {
				sw_msrop->core_msr[j]
					= my_msr_node->entries[j].value;
				/*
				 * socwatch uses the 'param' field to store the
				 * sample id needed by socwatch to identify the
				 * type of sample during post-processing
				 */
				sw_msrop->sample_id
					= my_msr_node->entries[j].param;
			}

			/* generate sample */
			profiling_generate_data(COLLECT_POWER_DATA,
						SOCWATCH_MSR_OP);
		}
		my_msr_node->msr_op_state = MSR_OP_REQUESTED;
	}

	dev_dbg(ACRN_DBG_PROFILING, "%s: exiting cpu%d",
		__func__, get_cpu_id());
}

/*
 * Requests IRQ
 */
int profiling_pmi_request_irq(int cpu, irq_action_t func,
		void *data, const char *name)
{
	int irq = PMI_IRQ; /* system allocate */
	int retval;

	dev_dbg(ACRN_DBG_PROFILING, "%s: entering", __func__);

	if (cpu > 0) {
		dev_dbg(ACRN_DBG_PROFILING, "%s: exiting", __func__);
		return 0;
	}

	if (profiling_pmi_irq != IRQ_INVALID) {
		pr_info("PMI node already allocated on CPU%d", cpu);
		free_irq(profiling_pmi_irq);
	}

	pr_info("%s: calling request_irq", __func__);

	/* all cpu register same PMI vector */

	retval = request_irq(irq, func, data, IRQF_NONE);
	if (retval < 0) {
		pr_err("Failed to add PMI isr");
		return -1;
	}
	profiling_pmi_irq = (uint32_t) retval;

	dev_dbg(ACRN_DBG_PROFILING, "%s: exiting", __func__);
	return 0;
}

/*
 * Interrupt handler for performance monitoring interrupts
 */
static int profiling_pmi_handler(__unused int irq, __unused void *data)
{
	uint64_t perf_ovf_status;
	uint32_t lvt_perf_ctr;
	unsigned int i;
	uint32_t group_id;
	struct profiling_msr_op *msrop = NULL;
	struct pmu_sample *psample = &get_cpu_var(sep_info.pmu_sample);
	struct sep_state *sepstate = &(get_cpu_var(sep_info.sep_state));

	/* Stop all the counters first */
	msr_write(MSR_IA32_PERF_GLOBAL_CTRL, 0x0U);

	group_id = sepstate->current_pmi_group_id;
	for (i = 0U; i < MAX_MSR_LIST_NUM; i++) {
		msrop = &(sepstate->pmi_entry_msr_list[group_id][i]);
		if (msrop->msr_id == (int32_t) -1) {
			break;
		}
		if (msrop->op_type == MSR_OP_WRITE) {
			msr_write(msrop->msr_id, msrop->value);
		}
	}

	sepstate->total_pmi_count++;
	perf_ovf_status = msr_read(MSR_IA32_PERF_GLOBAL_STATUS);
	lvt_perf_ctr = read_lapic_reg32(LAPIC_LVT_PMC_REGISTER);

	if (!perf_ovf_status) {
		goto reconfig;
	}

	if (!(perf_ovf_status & 0x80000000000000FULL)) {
		sepstate->nofrozen_pmi++;
	}

	memset(psample, 0, sizeof(struct pmu_sample));

	/* Attribute PMI to guest context */
	if ((get_cpu_var(sep_info.vm_info).vmexit_reason
			== VMX_EXIT_REASON_EXTERNAL_INTERRUPT) &&
			(get_cpu_var(sep_info.vm_info).external_vector
			== VECTOR_PMI)) {
		psample->csample.os_id = (uint32_t) get_cpu_var(sep_info.vm_info).vm_id;
		memset(psample->csample.task, 0, 16);
		psample->csample.cpu_id = get_cpu_id();
		psample->csample.process_id = 0U;
		psample->csample.task_id = 0U;
		psample->csample.overflow_status = perf_ovf_status;
		psample->csample.rip = get_cpu_var(sep_info.vm_info).guest_rip;
		psample->csample.rflags
			= (uint32_t) get_cpu_var(sep_info.vm_info).guest_rflags;
		psample->csample.cs = (uint32_t) get_cpu_var(sep_info.vm_info).guest_cs;
		get_cpu_var(sep_info.vm_info).vmexit_reason = 0U;
		get_cpu_var(sep_info.vm_info).external_vector = -1;
	/* Attribute PMI to hypervisor context */
	} else {
		psample->csample.os_id = 0xFFFFFFFFU;
		memcpy_s(psample->csample.task, 16, "VMM\0", 4);
		psample->csample.cpu_id = get_cpu_id();
		psample->csample.process_id = 0U;
		psample->csample.task_id = 0U;
		psample->csample.overflow_status = perf_ovf_status;
		psample->csample.rip = get_cpu_var(sep_info.vmm_ctx).rip;
		psample->csample.rflags
			= (uint32_t) get_cpu_var(sep_info.vmm_ctx).rflags;
		psample->csample.cs = (uint32_t) get_cpu_var(sep_info.vmm_ctx).cs;
	}

	if (sep_collection_switch & (1 << LBR_PMU_SAMPLING)) {
		psample->lsample.lbr_tos = msr_read(MSR_CORE_LASTBRANCH_TOS);
		for (i = 0U; i < LBR_NUM_REGISTERS; i++) {
			psample->lsample.lbr_from_ip[i]
				= msr_read(MSR_CORE_LASTBRANCH_0_FROM_IP + i);
			psample->lsample.lbr_to_ip[i]
				= msr_read(MSR_CORE_LASTBRANCH_0_TO_IP + i);
		}
		/* Generate core pmu sample and lbr data */
		profiling_generate_data(COLLECT_PROFILE_DATA, LBR_PMU_SAMPLING);
	} else {
		/* Generate core pmu sample only */
		profiling_generate_data(COLLECT_PROFILE_DATA, CORE_PMU_SAMPLING);
	}

	/* Clear PERF_GLOBAL_OVF_STATUS bits */
	msr_write(MSR_IA32_PERF_GLOBAL_OVF_CTRL,
			perf_ovf_status & PERF_OVF_BIT_MASK);

	sepstate->valid_pmi_count++;

	group_id = sepstate->current_pmi_group_id;
	for (i = 0U; i < MAX_MSR_LIST_NUM; i++) {
		msrop = &(sepstate->pmi_exit_msr_list[group_id][i]);
		if (msrop->msr_id == (int32_t)-1) {
			break;
		}
		if (msrop->op_type == MSR_OP_WRITE) {
			if (msrop->reg_type != PMU_MSR_DATA) {
				if ((uint32_t)msrop->msr_id
					!= MSR_IA32_PERF_GLOBAL_CTRL) {
					msr_write(msrop->msr_id, msrop->value);
				}
			} else if ((perf_ovf_status >> msrop->param) & 0x1U) {
				msr_write(msrop->msr_id, msrop->value);
			}
		}
	}

reconfig:

	if (sepstate->pmu_state == PMU_RUNNING) {
		/* Unmask the interrupt */
		lvt_perf_ctr &= LVT_PERFCTR_BIT_UNMASK;
		write_lapic_reg32(LAPIC_LVT_PMC_REGISTER, lvt_perf_ctr);
		group_id = sepstate->current_pmi_group_id;
		for (i = 0U; i < MAX_MSR_LIST_NUM; i++) {
			msrop = &(sepstate->pmi_start_msr_list[group_id][i]);
			if (msrop->msr_id == (int32_t)-1) {
				break;
			}
			if (msrop->op_type == MSR_OP_WRITE) {
				msr_write(msrop->msr_id, msrop->value);
			}
		}
	} else {
		/* Mask the interrupt */
		lvt_perf_ctr |= LVT_PERFCTR_BIT_MASK;
		write_lapic_reg32(LAPIC_LVT_PMC_REGISTER, lvt_perf_ctr);
	}

	return 0;
}

/*
 * Initialize sep state and enable PMU counters
 */
void profiling_start_pmu(void)
{
	int i;

	dev_dbg(ACRN_DBG_PROFILING, "%s: entering", __func__);

	if (in_pmu_profiling) {
		return;
	}

	for (i = 0; i < phys_cpu_num; i++) {
		if (per_cpu(sep_info.sep_state, i).pmu_state != PMU_SETUP) {
			pr_err("%s: invalid pmu_state %u on cpu%d",
			__func__, get_cpu_var(sep_info.sep_state).pmu_state, i);
			return;
		}
	}

	for (i = 0; i < phys_cpu_num; i++) {
		per_cpu(sep_info.ipi_cmd, i) = IPI_PMU_START;
		per_cpu(sep_info.sep_state, i).samples_logged = 0U;
		per_cpu(sep_info.sep_state, i).samples_dropped = 0U;
		per_cpu(sep_info.sep_state, i).valid_pmi_count = 0U;
		per_cpu(sep_info.sep_state, i).total_pmi_count = 0U;
		per_cpu(sep_info.sep_state, i).total_vmexit_count = 0U;
		per_cpu(sep_info.sep_state, i).frozen_well = 0U;
		per_cpu(sep_info.sep_state, i).frozen_delayed = 0U;
		per_cpu(sep_info.sep_state, i).nofrozen_pmi = 0U;
		per_cpu(sep_info.sep_state, i).pmu_state = PMU_RUNNING;
	}

	send_shorthand_ipi(VECTOR_NOTIFY_VCPU,
		INTR_LAPIC_ICR_ALL_EX_SELF, INTR_LAPIC_ICR_FIXED);

	in_pmu_profiling = true;

	dev_dbg(ACRN_DBG_PROFILING, "%s: done", __func__);
}

/*
 * Reset sep state and Disable all the PMU counters
 */
void profiling_stop_pmu(void)
{
	int i;

	dev_dbg(ACRN_DBG_PROFILING, "%s: entering", __func__);

	if (!in_pmu_profiling) {
		return;
	}

	for (i = 0; i < phys_cpu_num; i++) {
		per_cpu(sep_info.ipi_cmd, i) = IPI_PMU_STOP;
		if (per_cpu(sep_info.sep_state, i).pmu_state == PMU_RUNNING) {
			per_cpu(sep_info.sep_state, i).pmu_state = PMU_SETUP;
		}
		dev_dbg(ACRN_DBG_PROFILING,
		"%s: pmi_cnt[%d] = total:%u valid=%u, vmexit_cnt=%u",
		__func__, i, per_cpu(sep_info.sep_state, i).total_pmi_count,
		per_cpu(sep_info.sep_state, i).valid_pmi_count,
		per_cpu(sep_info.sep_state, i).total_vmexit_count);

		dev_dbg(ACRN_DBG_PROFILING,
		"%s: cpu%d frozen well:%u frozen delayed=%u, nofrozen_pmi=%u",
		__func__, i, per_cpu(sep_info.sep_state, i).frozen_well,
		per_cpu(sep_info.sep_state, i).frozen_delayed,
		per_cpu(sep_info.sep_state, i).nofrozen_pmi);

		dev_dbg(ACRN_DBG_PROFILING,
		"%s: cpu%d samples captured:%u samples dropped=%u",
		__func__, i, per_cpu(sep_info.sep_state, i).samples_logged,
		per_cpu(sep_info.sep_state, i).samples_dropped);

		per_cpu(sep_info.sep_state, i).samples_logged = 0U;
		per_cpu(sep_info.sep_state, i).samples_dropped = 0U;
		per_cpu(sep_info.sep_state, i).valid_pmi_count = 0U;
		per_cpu(sep_info.sep_state, i).total_pmi_count = 0U;
		per_cpu(sep_info.sep_state, i).total_vmexit_count = 0U;
		per_cpu(sep_info.sep_state, i).frozen_well = 0U;
		per_cpu(sep_info.sep_state, i).frozen_delayed = 0U;
		per_cpu(sep_info.sep_state, i).nofrozen_pmi = 0U;
	}

	send_shorthand_ipi(VECTOR_NOTIFY_VCPU,
		INTR_LAPIC_ICR_ALL_EX_SELF, INTR_LAPIC_ICR_FIXED);

	in_pmu_profiling = false;

	dev_dbg(ACRN_DBG_PROFILING, "%s: done.", __func__);
}

/*
 * Request IRQ for performance monitoring interrupts
 */
void profiling_setup_pmi(void)
{
	int cpu;
	char name[32] = {0};

	dev_dbg(ACRN_DBG_PROFILING, "%s: entering", __func__);

	cpu = (int) get_cpu_id();

	per_cpu(sep_info.sep_state, cpu).valid_pmi_count = 0U;
	per_cpu(sep_info.sep_state, cpu).total_pmi_count = 0U;
	per_cpu(sep_info.sep_state, cpu).total_vmexit_count = 0U;
	per_cpu(sep_info.sep_state, cpu).pmu_state = PMU_INITIALIZED;

	/* support PMI notification, VM0 will register all CPU */
	snprintf(name, 32, "PMI_ISR%d", cpu);
	if (profiling_pmi_request_irq(cpu,
			profiling_pmi_handler, NULL, name) < 0) {
		pr_err("PMI setup failed");
		return;
	}

	pr_info("%s : irq[%d] setup vector %x",
	__func__, profiling_pmi_irq, irq_to_vector(profiling_pmi_irq));

	write_lapic_reg32(LAPIC_LVT_PMC_REGISTER,
		VECTOR_PMI | LVT_PERFCTR_BIT_MASK);

	dev_dbg(ACRN_DBG_PROFILING, "%s: exiting", __func__);
}

/*
 * Performs MSR operations on all the CPU's
 */
int profiling_msr_ops_all_cpus(uint64_t addr)
{
	unsigned int i;
	struct profiling_msr_ops_list *msr_list
			= (struct profiling_msr_ops_list *)addr;

	dev_dbg(ACRN_DBG_PROFILING, "%s: entering", __func__);

	if (msr_list == NULL) {
		return -EINVAL;
	}

	for (i = 0U; i < (uint32_t)phys_cpu_num; i++) {
		per_cpu(sep_info.ipi_cmd, i) = IPI_MSR_OP;
		per_cpu(sep_info.msr_node, i) = &(msr_list[i]);
	}

	send_shorthand_ipi(VECTOR_NOTIFY_VCPU,
		INTR_LAPIC_ICR_ALL_EX_SELF, INTR_LAPIC_ICR_FIXED);

	dev_dbg(ACRN_DBG_PROFILING, "%s: exiting", __func__);
	return 0;
}

/*
 * Generate VM info list
 */
int profiling_vm_info_list(uint64_t addr)
{
	struct list_head *pos;
	struct vm *vm;
	struct vcpu *vcpu;
	int i, vm_idx;
	struct profiling_vm_info_list *vm_info_list
			= (struct profiling_vm_info_list *)addr;

	dev_dbg(ACRN_DBG_PROFILING, "%s: entering", __func__);

	if (vm_info_list == NULL) {
		return -EINVAL;
	}

	vm_idx = 0;
	vm_info_list->vm_list[vm_idx].vm_id = 0xFFFFFFFFU;
	memcpy_s(vm_info_list->vm_list[vm_idx].vm_name, 4, "VMM\0", 4);
	for (i = 0; i < phys_cpu_num; i++) {
		vm_info_list->vm_list[vm_idx].cpu_map[i].vcpu_id = i;
		vm_info_list->vm_list[vm_idx].cpu_map[i].pcpu_id = i;
		vm_info_list->vm_list[vm_idx].cpu_map[i].apic_id
			= per_cpu(lapic_id, i);
	}
	vm_info_list->vm_list[vm_idx].num_vcpus = i;
	vm_info_list->num_vms = 1;

	spinlock_obtain(&vm_list_lock);
	list_for_each(pos, &vm_list) {
		i = 0;

		vm = list_entry(pos, struct vm, list);

		vm_info_list->num_vms++;
		vm_idx++;

		vm_info_list->vm_list[vm_idx].vm_id = vm->vm_id;
		memcpy_s(vm_info_list->vm_list[vm_idx].guid, 16, vm->GUID, 16);
		snprintf(vm_info_list->vm_list[vm_idx].vm_name, 16, "%vm_%d",
				vm->vm_id, 16);
		vm_info_list->vm_list[vm_idx].num_vcpus = 0;
		foreach_vcpu(i, vm, vcpu) {
			vm_info_list->vm_list[vm_idx].cpu_map[i].vcpu_id
					= vcpu->vcpu_id;
			vm_info_list->vm_list[vm_idx].cpu_map[i].pcpu_id
					= vcpu->pcpu_id;
			vm_info_list->vm_list[vm_idx].cpu_map[i].apic_id = 0;
			vm_info_list->vm_list[vm_idx].num_vcpus++;
		}
	}
	spinlock_release(&vm_list_lock);

	dev_dbg(ACRN_DBG_PROFILING, "%s: exiting", __func__);
	return 0;
}

/*
 * Sep/socwatch profiling version
 */
int profiling_get_version(uint64_t addr)
{
	struct profiling_version_info *ver_info
			= (struct profiling_version_info *)addr;

	dev_dbg(ACRN_DBG_PROFILING, "%s: entering", __func__);

	if (ver_info == NULL) {
		return -EINVAL;
	}

	ver_info->major = MAJOR_VERSION;
	ver_info->minor = MINOR_VERSION;
	ver_info->supported_features = (int64_t)
					(1 << CORE_PMU_SAMPLING) |
					(1 << CORE_PMU_COUNTING) |
					(1 << LBR_PMU_SAMPLING) |
					(1 << VM_SWITCH_TRACING);

	dev_dbg(ACRN_DBG_PROFILING, "%s: exiting", __func__);

	return 0;
}

/*
 * Gets type of profiling - sep/socwatch
 */
int profiling_get_control(uint64_t addr)
{
	struct profiling_control *prof_control
			= (struct profiling_control *)addr;

	dev_dbg(ACRN_DBG_PROFILING, "%s: entering", __func__);

	if (prof_control == NULL) {
		return -EINVAL;
	}

	switch (prof_control->collector_id) {
	case COLLECT_PROFILE_DATA:
		prof_control->switches = sep_collection_switch;
		break;
	case COLLECT_POWER_DATA:
		break;
	default:
		pr_err("%s: unknown collector %d",
			__func__, prof_control->collector_id);
	}

	dev_dbg(ACRN_DBG_PROFILING, "%s: exiting", __func__);

	return 0;
}

/*
 * Update the profiling type based on control switch
 */
int profiling_set_control(uint64_t addr)
{
	uint64_t old_switch;
	uint64_t new_switch;
	uint64_t i;
	struct profiling_control *prof_control
			= (struct profiling_control *)addr;

	dev_dbg(ACRN_DBG_PROFILING, "%s: entering", __func__);

	if (prof_control == NULL) {
		pr_err("%s: prof_control is NULL", __func__);
		return -EINVAL;
	}

	switch (prof_control->collector_id) {
	case COLLECT_PROFILE_DATA:
		old_switch = sep_collection_switch;
		new_switch = prof_control->switches;
		sep_collection_switch = prof_control->switches;

		for (i = 0U; i < MAX_SEP_FEATURE_ID; i++) {
			if ((new_switch ^ old_switch) & (0x1U << i)) {
				switch (i) {
				case CORE_PMU_SAMPLING:
				case CORE_PMU_COUNTING:
					if (new_switch & (0x1U << i)) {
						profiling_start_pmu();
					} else {
						profiling_stop_pmu();
					}
					break;
				case LBR_PMU_SAMPLING:
					break;
				case VM_SWITCH_TRACING:
					break;
				default:
					dev_dbg(ACRN_DBG_PROFILING,
					"%s: feature not supported %u",
					 __func__, i);
				}
			}
		}
		break;
	case COLLECT_POWER_DATA:
		dev_dbg(ACRN_DBG_PROFILING,
			"%s: configuring socwatch", __func__);

		socwatch_collection_switch = prof_control->switches;

		dev_dbg(ACRN_DBG_PROFILING,
			"socwatch_collection_switch: %llu!",
			socwatch_collection_switch);

		if (socwatch_collection_switch) {
			dev_dbg(ACRN_DBG_PROFILING,
			"%s: socwatch start collection invoked!", __func__);
			for (i = 0U; i < MAX_SOCWATCH_FEATURE_ID; i++) {
				if (socwatch_collection_switch & (0x1 << i)) {
					switch (i) {
					case SOCWATCH_COMMAND:
						break;
					case SOCWATCH_VM_SWITCH_TRACING:
						dev_dbg(ACRN_DBG_PROFILING,
						"%s: socwatch vm-switch feature requested!",
						__func__);
						break;
					default:
						dev_dbg(ACRN_DBG_PROFILING,
						"%s: socwatch feature not supported %u",
						__func__, i);
					}
				}
			}
			for (i = 0U; i < (uint32_t)phys_cpu_num; i++) {
				per_cpu(sep_info.socwatch_state, i)
					= SW_RUNNING;
			}
		} else { /* stop socwatch collection */
			dev_dbg(ACRN_DBG_PROFILING,
			"%s: socwatch stop collection invoked or collection switch not set!",
			__func__);
			for (i = 0U; i < (uint32_t)phys_cpu_num; i++) {
				per_cpu(sep_info.socwatch_state, i)
					= SW_STOPPED;
			}
		}
		break;
	default:
		pr_err("%s: unknown collector %d",
			__func__, prof_control->collector_id);
	}

	dev_dbg(ACRN_DBG_PROFILING, "%s: exiting", __func__);

	return 0;
}

/*
 * Configure PMI on all cpus
 */
int profiling_config_pmi(uint64_t addr)
{
	unsigned int i;
	struct profiling_pmi_config *pmi_config
			= (struct profiling_pmi_config *)addr;

	dev_dbg(ACRN_DBG_PROFILING, "%s: entering", __func__);

	if (pmi_config == NULL) {
		pr_err("%s: pmi_config is NULL!", __func__);
		return -EINVAL;
	}

	for (i = 0U; i < (uint32_t)phys_cpu_num; i++) {
		if (!((per_cpu(sep_info.sep_state, i).pmu_state ==
				PMU_INITIALIZED) ||
			(per_cpu(sep_info.sep_state, i).pmu_state ==
				PMU_SETUP))) {
			pr_err("%s: invalid pmu_state %u on cpu%d",
			__func__, get_cpu_var(sep_info.sep_state).pmu_state, i);
			return -EINVAL;
		}
	}

	if (pmi_config->num_groups == 0U ||
		pmi_config->num_groups > MAX_GROUP_NUM) {
		pr_err("%s: invalid num_groups %u",
			__func__, pmi_config->num_groups);
		return -EINVAL;
	}

	for (i = 0U; i < (uint32_t)phys_cpu_num; i++) {
		per_cpu(sep_info.ipi_cmd, i) = IPI_PMU_CONFIG;
		per_cpu(sep_info.sep_state, i).num_pmi_groups
			= pmi_config->num_groups;

		memcpy_s(per_cpu(sep_info.sep_state, i).pmi_initial_msr_list,
		sizeof(struct profiling_msr_op)*MAX_MSR_LIST_NUM*MAX_GROUP_NUM,
		pmi_config->initial_list,
		sizeof(struct profiling_msr_op)*MAX_MSR_LIST_NUM*MAX_GROUP_NUM);

		memcpy_s(per_cpu(sep_info.sep_state, i).pmi_start_msr_list,
		sizeof(struct profiling_msr_op)*MAX_MSR_LIST_NUM*MAX_GROUP_NUM,
		pmi_config->start_list,
		sizeof(struct profiling_msr_op)*MAX_MSR_LIST_NUM*MAX_GROUP_NUM);

		memcpy_s(per_cpu(sep_info.sep_state, i).pmi_stop_msr_list,
		sizeof(struct profiling_msr_op)*MAX_MSR_LIST_NUM*MAX_GROUP_NUM,
		pmi_config->stop_list,
		sizeof(struct profiling_msr_op)*MAX_MSR_LIST_NUM*MAX_GROUP_NUM);

		memcpy_s(per_cpu(sep_info.sep_state, i).pmi_entry_msr_list,
		sizeof(struct profiling_msr_op)*MAX_MSR_LIST_NUM*MAX_GROUP_NUM,
		pmi_config->entry_list,
		sizeof(struct profiling_msr_op)*MAX_MSR_LIST_NUM*MAX_GROUP_NUM);

		memcpy_s(per_cpu(sep_info.sep_state, i).pmi_exit_msr_list,
		sizeof(struct profiling_msr_op)*MAX_MSR_LIST_NUM*MAX_GROUP_NUM,
		pmi_config->exit_list,
		sizeof(struct profiling_msr_op)*MAX_MSR_LIST_NUM*MAX_GROUP_NUM);
	}

	send_shorthand_ipi(VECTOR_NOTIFY_VCPU, INTR_LAPIC_ICR_ALL_EX_SELF,
			INTR_LAPIC_ICR_FIXED);

	dev_dbg(ACRN_DBG_PROFILING, "%s: exiting", __func__);
	return 0;
}

/*
 * Configure for VM-switch data on all cpus
 */
int profiling_config_vmsw(uint64_t addr)
{
	unsigned int i;
	struct profiling_vmsw_config *vmsw_config
			= (struct profiling_vmsw_config *)addr;

	dev_dbg(ACRN_DBG_PROFILING, "%s: entering", __func__);

	if (vmsw_config == NULL) {
		pr_err("%s: vmsw_config is NULL!", __func__);
		return -EINVAL;
	}

	switch (vmsw_config->collector_id) {
	case COLLECT_PROFILE_DATA:
		for (i = 0; i < (uint32_t)phys_cpu_num; i++) {
			per_cpu(sep_info.ipi_cmd, i) = IPI_VMSW_CONFIG;

			memcpy_s(
			per_cpu(sep_info.sep_state, i).vmsw_initial_msr_list,
			sizeof(struct profiling_msr_op)*MAX_MSR_LIST_NUM,
			vmsw_config->initial_list,
			sizeof(struct profiling_msr_op)*MAX_MSR_LIST_NUM);

			memcpy_s(
			per_cpu(sep_info.sep_state, i).vmsw_entry_msr_list,
			sizeof(struct profiling_msr_op)*MAX_MSR_LIST_NUM,
			vmsw_config->entry_list,
			sizeof(struct profiling_msr_op)*MAX_MSR_LIST_NUM);

			memcpy_s(
			per_cpu(sep_info.sep_state, i).vmsw_exit_msr_list,
			sizeof(struct profiling_msr_op)*MAX_MSR_LIST_NUM,
			vmsw_config->exit_list,
			sizeof(struct profiling_msr_op)*MAX_MSR_LIST_NUM);
		}

		send_shorthand_ipi(VECTOR_NOTIFY_VCPU, INTR_LAPIC_ICR_ALL_EX_SELF,
				INTR_LAPIC_ICR_FIXED);

		break;
	case COLLECT_POWER_DATA:
		break;
	default:
		pr_err("%s: unknown collector %d",
			__func__, vmsw_config->collector_id);
		return -EINVAL;
	}

	dev_dbg(ACRN_DBG_PROFILING, "%s: exiting", __func__);
	return 0;
}

/*
 * Get the physical cpu id
 */
int profiling_get_pcpuid(uint64_t addr)
{
	struct profiling_pcpuid *pcpuid
			= (struct profiling_pcpuid *)addr;
	dev_dbg(ACRN_DBG_PROFILING, "%s: entering", __func__);

	if (pcpuid == NULL) {
		return -EINVAL;
	}

	cpuid_subleaf(pcpuid->leaf, pcpuid->subleaf, &pcpuid->eax,
			&pcpuid->ebx, &pcpuid->ecx, &pcpuid->edx);

	dev_dbg(ACRN_DBG_PROFILING, "%s: exiting", __func__);

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
	if ((get_cpu_var(sep_info.sep_state).pmu_state == PMU_RUNNING &&
		sep_collection_switch & (1 << VM_SWITCH_TRACING)) ||
		(get_cpu_var(sep_info.socwatch_state) == SW_RUNNING &&
		socwatch_collection_switch &
		(1 << SOCWATCH_VM_SWITCH_TRACING))) {

		get_cpu_var(sep_info.vm_info).vmenter_tsc = rdtsc();
	}

	return 0;
}

/*
 * Save the VCPU info on vmexit
 */
int profiling_vmexit_handler(struct vcpu *vcpu, uint64_t exit_reason)
{
	per_cpu(sep_info.sep_state, vcpu->pcpu_id).total_vmexit_count++;

	if (get_cpu_var(sep_info.sep_state).pmu_state == PMU_RUNNING ||
		get_cpu_var(sep_info.socwatch_state) == SW_RUNNING) {

		get_cpu_var(sep_info.vm_info).vmexit_tsc = rdtsc();
		get_cpu_var(sep_info.vm_info).vmexit_reason = exit_reason;
		if (exit_reason == VMX_EXIT_REASON_EXTERNAL_INTERRUPT) {
			get_cpu_var(sep_info.vm_info).external_vector
				= (int)exec_vmread(VMX_EXIT_INT_INFO) & 0xFFU;
		} else {
			get_cpu_var(sep_info.vm_info).external_vector = -1;
		}
		get_cpu_var(sep_info.vm_info).guest_rip
			= vcpu->arch_vcpu.contexts[
				vcpu->arch_vcpu.cur_context].run_ctx.rip;

		get_cpu_var(sep_info.vm_info).guest_rflags
			= vcpu->arch_vcpu.contexts[
				vcpu->arch_vcpu.cur_context].run_ctx.rflags;

		get_cpu_var(sep_info.vm_info).guest_cs
			= vcpu->arch_vcpu.contexts[
			vcpu->arch_vcpu.cur_context].ext_ctx.cs.selector;

		get_cpu_var(sep_info.vm_info).vm_id = (int) vcpu->vm->vm_id;

		/* Generate vmswitch sample */
		if ((sep_collection_switch & (1 << VM_SWITCH_TRACING)) ||
			(socwatch_collection_switch &
			(1 << SOCWATCH_VM_SWITCH_TRACING))) {
			get_cpu_var(sep_info.vm_switch_trace).os_id
				= (int32_t)vcpu->vm->vm_id;
			get_cpu_var(sep_info.vm_switch_trace).vmenter_tsc
				= get_cpu_var(sep_info.vm_info).vmenter_tsc;
			get_cpu_var(sep_info.vm_switch_trace).vmexit_tsc
				= get_cpu_var(sep_info.vm_info).vmexit_tsc;
			get_cpu_var(sep_info.vm_switch_trace).vmexit_reason
				= exit_reason;

			if (sep_collection_switch &
				(1 << VM_SWITCH_TRACING)) {
				profiling_generate_data(COLLECT_PROFILE_DATA,
					VM_SWITCH_TRACING);
			}
			if (socwatch_collection_switch &
				(1 << SOCWATCH_VM_SWITCH_TRACING)) {
				profiling_generate_data(COLLECT_POWER_DATA,
					SOCWATCH_VM_SWITCH_TRACING);
			}
		}
	}
	return 0;
}

/*
 * Save the context info on interrupt
 */
void profiling_capture_intr_context(struct intr_excp_ctx *ctx)
{
	get_cpu_var(sep_info.vmm_ctx).rip = ctx->rip;
	get_cpu_var(sep_info.vmm_ctx).rflags = ctx->rflags;
	get_cpu_var(sep_info.vmm_ctx).cs = ctx->cs;
}

/*
 * Setup PMI irq vectors
 */
void profiling_setup(void)
{
	dev_dbg(ACRN_DBG_PROFILING, "%s: entering", __func__);

	profiling_setup_pmi();

	get_cpu_var(sep_info.sep_state).vmexit_msr_list = NULL;
	get_cpu_var(sep_info.sep_state).vmexit_msr_cnt = 1;

	get_cpu_var(sep_info.sep_state).pmu_state = PMU_INITIALIZED;

	dev_dbg(ACRN_DBG_PROFILING, "%s: exiting", __func__);
}

#endif

