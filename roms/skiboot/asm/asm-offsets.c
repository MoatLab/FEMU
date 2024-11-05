// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
/* Copyright 2013-2019 IBM Corp.
 */

#include <stddef.h>
#include <types.h>
#include <skiboot.h>
#include "../hdata/spira.h"
#include <processor.h>
#include <cpu.h>
#include <stack.h>

#define DEFINE(sym, val) \
        asm volatile("\n#define " #sym " %0 /* " #val " */\n" : : "i" (val))

#define OFFSET(sym, str, mem) \
	DEFINE(sym, offsetof(struct str, mem))

/*
 * 64-bit ELF ABI specifies 288 byte redzone size.
 */
#define REDZONE_SIZE 288

int main(void);

int main(void)
{
	OFFSET(CPUTHREAD_PIR, cpu_thread, pir);
	OFFSET(CPUTHREAD_SAVE_R1, cpu_thread, save_r1);
	OFFSET(CPUTHREAD_STATE, cpu_thread, state);
	OFFSET(CPUTHREAD_IN_OPAL_CALL, cpu_thread, in_opal_call);
	OFFSET(CPUTHREAD_QUIESCE_OPAL_CALL, cpu_thread, quiesce_opal_call);
	OFFSET(CPUTHREAD_CUR_TOKEN, cpu_thread, current_token);
	DEFINE(CPUTHREAD_GAP, sizeof(struct cpu_thread) + STACK_SAFETY_GAP);
#ifdef STACK_CHECK_ENABLED
	OFFSET(CPUTHREAD_STACK_BOT_MARK, cpu_thread, stack_bot_mark);
	OFFSET(CPUTHREAD_STACK_BOT_PC, cpu_thread, stack_bot_pc);
	OFFSET(CPUTHREAD_STACK_BOT_TOK, cpu_thread, stack_bot_tok);
#endif
	OFFSET(STACK_TYPE,	stack_frame, type);
	OFFSET(STACK_MAGIC,	stack_frame, magic);
	OFFSET(STACK_LOCALS,	stack_frame, locals);
	OFFSET(STACK_GPR0,	stack_frame, gpr[0]);
	OFFSET(STACK_GPR1,	stack_frame, gpr[1]);
	OFFSET(STACK_GPR2,	stack_frame, gpr[2]);
	OFFSET(STACK_GPR3,	stack_frame, gpr[3]);
	OFFSET(STACK_GPR4,	stack_frame, gpr[4]);
	OFFSET(STACK_GPR5,	stack_frame, gpr[5]);
	OFFSET(STACK_GPR6,	stack_frame, gpr[6]);
	OFFSET(STACK_GPR7,	stack_frame, gpr[7]);
	OFFSET(STACK_GPR8,	stack_frame, gpr[8]);
	OFFSET(STACK_GPR9,	stack_frame, gpr[9]);
	OFFSET(STACK_GPR10,	stack_frame, gpr[10]);
	OFFSET(STACK_GPR11,	stack_frame, gpr[11]);
	OFFSET(STACK_GPR12,	stack_frame, gpr[12]);
	OFFSET(STACK_GPR13,	stack_frame, gpr[13]);
	OFFSET(STACK_GPR14,	stack_frame, gpr[14]);
	OFFSET(STACK_GPR15,	stack_frame, gpr[15]);
	OFFSET(STACK_GPR16,	stack_frame, gpr[16]);
	OFFSET(STACK_GPR17,	stack_frame, gpr[17]);
	OFFSET(STACK_GPR18,	stack_frame, gpr[18]);
	OFFSET(STACK_GPR19,	stack_frame, gpr[19]);
	OFFSET(STACK_GPR20,	stack_frame, gpr[20]);
	OFFSET(STACK_GPR21,	stack_frame, gpr[21]);
	OFFSET(STACK_GPR22,	stack_frame, gpr[22]);
	OFFSET(STACK_GPR23,	stack_frame, gpr[23]);
	OFFSET(STACK_GPR24,	stack_frame, gpr[24]);
	OFFSET(STACK_GPR25,	stack_frame, gpr[25]);
	OFFSET(STACK_GPR26,	stack_frame, gpr[26]);
	OFFSET(STACK_GPR27,	stack_frame, gpr[27]);
	OFFSET(STACK_GPR28,	stack_frame, gpr[28]);
	OFFSET(STACK_GPR29,	stack_frame, gpr[29]);
	OFFSET(STACK_GPR30,	stack_frame, gpr[30]);
	OFFSET(STACK_GPR31,	stack_frame, gpr[31]);

	OFFSET(STACK_CR,	stack_frame, cr);
	OFFSET(STACK_XER,	stack_frame, xer);
	OFFSET(STACK_DSISR,	stack_frame, dsisr);
	OFFSET(STACK_CTR,	stack_frame, ctr);
	OFFSET(STACK_LR,	stack_frame, lr);
	OFFSET(STACK_PC,	stack_frame, pc);
	OFFSET(STACK_MSR,	stack_frame, msr);
	OFFSET(STACK_CFAR,	stack_frame, cfar);
	OFFSET(STACK_SRR0,	stack_frame, srr0);
	OFFSET(STACK_SRR1,	stack_frame, srr1);
	OFFSET(STACK_HSRR0,	stack_frame, hsrr0);
	OFFSET(STACK_HSRR1,	stack_frame, hsrr1);
	OFFSET(STACK_DAR,	stack_frame, dar);
	DEFINE(STACK_FRAMESIZE,	sizeof(struct stack_frame));
	DEFINE(INT_FRAMESIZE,	(sizeof(struct stack_frame) + REDZONE_SIZE));

	return 0;
}
