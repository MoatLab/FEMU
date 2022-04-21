// SPDX-License-Identifier: Apache-2.0
/*
 * Machine Check Exceptions
 *
 * Copyright 2020 IBM Corp.
 */

#define pr_fmt(fmt)	"MCE: " fmt

#include <ras.h>
#include <opal.h>
#include <cpu.h>

#define SRR1_MC_LOADSTORE(srr1)	((srr1) & PPC_BIT(42))

struct mce_ierror_table {
	unsigned long srr1_mask;
	unsigned long srr1_value;
	uint64_t type;
	const char *error_str;
};

static const struct mce_ierror_table mce_p9_ierror_table[] = {
{ 0x00000000081c0000, 0x0000000000040000,
  MCE_INSNFETCH | MCE_MEMORY_ERROR | MCE_INVOLVED_EA,
  "instruction fetch memory uncorrectable error", },
{ 0x00000000081c0000, 0x0000000000080000,
  MCE_INSNFETCH | MCE_SLB_ERROR | MCE_INVOLVED_EA,
  "instruction fetch SLB parity error", },
{ 0x00000000081c0000, 0x00000000000c0000,
  MCE_INSNFETCH | MCE_SLB_ERROR | MCE_INVOLVED_EA,
  "instruction fetch SLB multi-hit error", },
{ 0x00000000081c0000, 0x0000000000100000,
  MCE_INSNFETCH | MCE_INVOLVED_EA | MCE_ERAT_ERROR,
  "instruction fetch ERAT multi-hit error", },
{ 0x00000000081c0000, 0x0000000000140000,
  MCE_INSNFETCH | MCE_INVOLVED_EA | MCE_TLB_ERROR,
  "instruction fetch TLB multi-hit error", },
{ 0x00000000081c0000, 0x0000000000180000,
  MCE_INSNFETCH | MCE_MEMORY_ERROR | MCE_TABLE_WALK | MCE_INVOLVED_EA,
  "instruction fetch page table access memory uncorrectable error", },
{ 0x00000000081c0000, 0x00000000001c0000,
  MCE_INSNFETCH | MCE_INVOLVED_EA,
  "instruction fetch to foreign address", },
{ 0x00000000081c0000, 0x0000000008000000,
  MCE_INSNFETCH | MCE_INVOLVED_EA,
  "instruction fetch foreign link time-out", },
{ 0x00000000081c0000, 0x0000000008040000,
  MCE_INSNFETCH | MCE_TABLE_WALK | MCE_INVOLVED_EA,
  "instruction fetch page table access foreign link time-out", },
{ 0x00000000081c0000, 0x00000000080c0000,
  MCE_INSNFETCH | MCE_INVOLVED_EA,
  "instruction fetch real address error", },
{ 0x00000000081c0000, 0x0000000008100000,
  MCE_INSNFETCH | MCE_TABLE_WALK | MCE_INVOLVED_EA,
  "instruction fetch page table access real address error", },
{ 0x00000000081c0000, 0x0000000008140000,
  MCE_LOADSTORE | MCE_IMPRECISE,
  "store real address asynchronous error", },
{ 0x00000000081c0000, 0x0000000008180000,
  MCE_LOADSTORE | MCE_IMPRECISE,
  "store foreign link time-out asynchronous error", },
{ 0x00000000081c0000, 0x00000000081c0000,
  MCE_INSNFETCH | MCE_TABLE_WALK | MCE_INVOLVED_EA,
  "instruction fetch page table access to foreign address", },
{ 0 } };

static const struct mce_ierror_table mce_p10_ierror_table[] = {
{ 0x00000000081c0000, 0x0000000000040000,
  MCE_INSNFETCH | MCE_MEMORY_ERROR | MCE_INVOLVED_EA,
  "instruction fetch memory uncorrectable error", },
{ 0x00000000081c0000, 0x0000000000080000,
  MCE_INSNFETCH | MCE_SLB_ERROR | MCE_INVOLVED_EA,
  "instruction fetch SLB parity error", },
{ 0x00000000081c0000, 0x00000000000c0000,
  MCE_INSNFETCH | MCE_SLB_ERROR | MCE_INVOLVED_EA,
  "instruction fetch SLB multi-hit error", },
{ 0x00000000081c0000, 0x0000000000100000,
  MCE_INSNFETCH | MCE_INVOLVED_EA | MCE_ERAT_ERROR,
  "instruction fetch ERAT multi-hit error", },
{ 0x00000000081c0000, 0x0000000000140000,
  MCE_INSNFETCH | MCE_INVOLVED_EA | MCE_TLB_ERROR,
  "instruction fetch TLB multi-hit error", },
{ 0x00000000081c0000, 0x0000000000180000,
  MCE_INSNFETCH | MCE_MEMORY_ERROR | MCE_TABLE_WALK | MCE_INVOLVED_EA,
  "instruction fetch page table access memory uncorrectable error", },
{ 0x00000000081c0000, 0x00000000001c0000,
  MCE_INSNFETCH | MCE_INVOLVED_EA,
  "instruction fetch to control real address", },
{ 0x00000000081c0000, 0x00000000080c0000,
  MCE_INSNFETCH | MCE_INVOLVED_EA,
  "instruction fetch real address error", },
{ 0x00000000081c0000, 0x0000000008100000,
  MCE_INSNFETCH | MCE_TABLE_WALK | MCE_INVOLVED_EA,
  "instruction fetch page table access real address error", },
{ 0x00000000081c0000, 0x0000000008140000,
  MCE_LOADSTORE | MCE_IMPRECISE,
  "store real address asynchronous error", },
{ 0x00000000081c0000, 0x00000000081c0000,
  MCE_INSNFETCH | MCE_TABLE_WALK | MCE_INVOLVED_EA,
  "instruction fetch page table access to control real address", },
{ 0 } };

struct mce_derror_table {
	unsigned long dsisr_value;
	uint64_t type;
	const char *error_str;
};

static const struct mce_derror_table mce_p9_derror_table[] = {
{ 0x00008000,
  MCE_LOADSTORE | MCE_MEMORY_ERROR,
  "load/store memory uncorrectable error", },
{ 0x00004000,
  MCE_LOADSTORE | MCE_MEMORY_ERROR | MCE_TABLE_WALK | MCE_INVOLVED_EA,
  "load/store page table access memory uncorrectable error", },
{ 0x00002000,
  MCE_LOADSTORE | MCE_INVOLVED_EA,
  "load/store foreign link time-out", },
{ 0x00001000,
  MCE_LOADSTORE | MCE_TABLE_WALK | MCE_INVOLVED_EA,
  "load/store page table access foreign link time-out", },
{ 0x00000800,
  MCE_LOADSTORE | MCE_INVOLVED_EA | MCE_ERAT_ERROR,
  "load/store ERAT multi-hit error", },
{ 0x00000400,
  MCE_LOADSTORE | MCE_INVOLVED_EA | MCE_TLB_ERROR,
  "load/store TLB multi-hit error", },
{ 0x00000200,
  MCE_LOADSTORE | MCE_TLBIE_ERROR,
  "TLBIE or TLBIEL instruction programming error", },
{ 0x00000100,
  MCE_LOADSTORE | MCE_INVOLVED_EA | MCE_SLB_ERROR,
  "load/store SLB parity error", },
{ 0x00000080,
  MCE_LOADSTORE | MCE_INVOLVED_EA | MCE_SLB_ERROR,
  "load/store SLB multi-hit error", },
{ 0x00000040,
  MCE_LOADSTORE | MCE_INVOLVED_EA,
  "load real address error", },
{ 0x00000020,
  MCE_LOADSTORE | MCE_TABLE_WALK,
  "load/store page table access real address error", },
{ 0x00000010,
  MCE_LOADSTORE | MCE_TABLE_WALK,
  "load/store page table access to foreign address", },
{ 0x00000008,
  MCE_LOADSTORE,
  "load/store to foreign address", },
{ 0 } };

static const struct mce_derror_table mce_p10_derror_table[] = {
{ 0x00008000,
  MCE_LOADSTORE | MCE_MEMORY_ERROR,
  "load/store memory uncorrectable error", },
{ 0x00004000,
  MCE_LOADSTORE | MCE_MEMORY_ERROR | MCE_TABLE_WALK | MCE_INVOLVED_EA,
  "load/store page table access memory uncorrectable error", },
{ 0x00000800,
  MCE_LOADSTORE | MCE_INVOLVED_EA | MCE_ERAT_ERROR,
  "load/store ERAT multi-hit error", },
{ 0x00000400,
  MCE_LOADSTORE | MCE_INVOLVED_EA | MCE_TLB_ERROR,
  "load/store TLB multi-hit error", },
{ 0x00000200,
  MCE_TLBIE_ERROR,
  "TLBIE or TLBIEL instruction programming error", },
{ 0x00000100,
  MCE_LOADSTORE | MCE_INVOLVED_EA | MCE_SLB_ERROR,
  "load/store SLB parity error", },
{ 0x00000080,
  MCE_LOADSTORE | MCE_INVOLVED_EA | MCE_SLB_ERROR,
  "load/store SLB multi-hit error", },
{ 0x00000040,
  MCE_LOADSTORE | MCE_INVOLVED_EA,
  "load real address error", },
{ 0x00000020,
  MCE_LOADSTORE | MCE_TABLE_WALK,
  "load/store page table access real address error", },
{ 0x00000010,
  MCE_LOADSTORE | MCE_TABLE_WALK,
  "load/store page table access to control real address", },
{ 0x00000008,
  MCE_LOADSTORE,
  "load/store to control real address", },
{ 0 } };

static void decode_ierror(const struct mce_ierror_table table[],
				uint64_t srr1,
				uint64_t *type,
				const char **error_str)
{
	int i;

	for (i = 0; table[i].srr1_mask; i++) {
		if ((srr1 & table[i].srr1_mask) != table[i].srr1_value)
			continue;

		*type = table[i].type;
		*error_str = table[i].error_str;
	}
}

static void decode_derror(const struct mce_derror_table table[],
		uint32_t dsisr,
		uint64_t *type,
		const char **error_str)
{
	int i;

	for (i = 0; table[i].dsisr_value; i++) {
		if (!(dsisr & table[i].dsisr_value))
			continue;

		*type = table[i].type;
		*error_str = table[i].error_str;
	}
}

static void decode_mce_p9(uint64_t srr0, uint64_t srr1,
		uint32_t dsisr, uint64_t dar,
		uint64_t *type, const char **error_str,
		uint64_t *address)
{
	/*
	 * On POWER9 DD2.1 and below, it's possible to get a machine check
	 * caused by a paste instruction where only DSISR bit 25 is set. This
	 * will result in the MCE handler seeing an unknown event and the
	 * kernel crashing. An MCE that occurs like this is spurious, so we
	 * don't need to do anything in terms of servicing it. If there is
	 * something that needs to be serviced, the CPU will raise the MCE
	 * again with the correct DSISR so that it can be serviced properly.
	 * So detect this case and mark it as handled.
	 */
	if (SRR1_MC_LOADSTORE(srr1) && dsisr == 0x02000000) {
		*type = MCE_NO_ERROR;
		*error_str = "no error (superfluous machine check)";
		return;
	}

	/*
	 * Async machine check due to bad real address from store or foreign
	 * link time out comes with the load/store bit (PPC bit 42) set in
	 * SRR1, but the cause comes in SRR1 not DSISR. Clear bit 42 so we're
	 * directed to the ierror table so it will find the cause (which
	 * describes it correctly as a store error).
	 */
	if (SRR1_MC_LOADSTORE(srr1) &&
			((srr1 & 0x081c0000) == 0x08140000 ||
			 (srr1 & 0x081c0000) == 0x08180000)) {
		srr1 &= ~PPC_BIT(42);
	}

	if (SRR1_MC_LOADSTORE(srr1)) {
		decode_derror(mce_p9_derror_table, dsisr, type, error_str);
		if (*type & MCE_INVOLVED_EA)
			*address = dar;
	} else {
		decode_ierror(mce_p9_ierror_table, srr1, type, error_str);
		if (*type & MCE_INVOLVED_EA)
			*address = srr0;
	}
}

static void decode_mce_p10(uint64_t srr0, uint64_t srr1,
		uint32_t dsisr, uint64_t dar,
		uint64_t *type, const char **error_str,
		uint64_t *address)
{
	/*
	 * Async machine check due to bad real address from store or foreign
	 * link time out comes with the load/store bit (PPC bit 42) set in
	 * SRR1, but the cause comes in SRR1 not DSISR. Clear bit 42 so we're
	 * directed to the ierror table so it will find the cause (which
	 * describes it correctly as a store error).
	 */
	if (SRR1_MC_LOADSTORE(srr1) &&
			(srr1 & 0x081c0000) == 0x08140000) {
		srr1 &= ~PPC_BIT(42);
	}

	if (SRR1_MC_LOADSTORE(srr1)) {
		decode_derror(mce_p10_derror_table, dsisr, type, error_str);
		if (*type & MCE_INVOLVED_EA)
			*address = dar;
	} else {
		decode_ierror(mce_p10_ierror_table, srr1, type, error_str);
		if (*type & MCE_INVOLVED_EA)
			*address = srr0;
	}
}

void decode_mce(uint64_t srr0, uint64_t srr1,
		uint32_t dsisr, uint64_t dar,
		uint64_t *type, const char **error_str,
		uint64_t *address)
{
	*type = MCE_UNKNOWN;
	*error_str = "unknown error";
	*address = 0;

	if (proc_gen == proc_gen_p9) {
		decode_mce_p9(srr0, srr1, dsisr, dar, type, error_str, address);
	} else if (proc_gen == proc_gen_p10) {
		decode_mce_p10(srr0, srr1, dsisr, dar, type, error_str, address);
	} else {
		*error_str = "unknown error (processor not supported)";
	}
}
