/*
 * Top-level entry points to the Boot ROM. This includes:
 * - Reset, exception and interrupt vectors.
 * - C run-time initialization.
 * - Secondary CPU boot code.
 *
 * Copyright 2022 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#define KiB (1024)

#define SRAM_SIZE (256 * KiB)

.section .text.vectors, "ax"

.global _start
.type _start, %function
_start:
b    reset
. = 0x04
b    undefined_instruction
. = 0x08
b    software_interrupt
. = 0x0c
b    prefetch_abort
. = 0x10
b    data_abort
. = 0x18
b    interrupt
. = 0x1c
b    fast_interrupt

undefined_instruction:
mov    x0, #1
b      handle_exception

software_interrupt:
mov    x0, #2
b      handle_exception

prefetch_abort:
mov    x0, #3
b    handle_exception

data_abort:
mov    x0, #4
b    handle_exception

interrupt:
mov    x0, #6
b    handle_exception

fast_interrupt:
mov    x0, #7
b    handle_exception

vectors_end:

.text
.align 2
handle_exception:

.global panic
.type panic, %function
panic:
1:    wfi
b    1b
.size panic, . - panic

.type reset, %function
reset:
mov    x0, #0
// Read the CPU ID from MPIDR_EL1.
mrs    x1, MPIDR_EL1
and    x1, x1, #0x03
cbz    x1, cpu0_init

// Not CPU0 -- clear the SCRPAD register and wait for it to change.
ldr    x2, scrpad_addr
str    x0, [x2]
dsb    st
sev
1:     wfe
ldr    x3, [x2]
cmp    x3, #0
beq    1b

// SCRPAD is no longer NULL, so jump there.
ret   x3
.size reset, . - reset

.type scrpad_addr, %object
scrpad_addr:
.dword    0xF0800E00
.size scrpad_addr, . - scrpad_addr

.type cpu0_init, %function
cpu0_init:
ldr    x1, sram_base_addr
add    sp, x1, #SRAM_SIZE

// Load the boot image into SRAM. Returns the entry address.
bl    load_boot_image

// Jump to the boot image. Panic if it returns back to us.
ret  x0
b    panic

.size cpu0_init, . - cpu0_init

.type sram_base_addr, %object
sram_base_addr:
.dword    0xFFFB0000
.size sram_base_addr, . - sram_base_addr

.type sdram_base_addr, %object
sdram_base_addr:
.dword    0x00000000
.size sdram_base_addr, . - sdram_base_addr

.type etext_addr, %object
etext_addr:
.dword    _etext
.size etext_addr, . - etext_addr

.type edata_addr, %object
edata_addr:
.dword    _edata
.size edata_addr, . - edata_addr

.type end_addr, %object
end_addr:
.dword    _end
.size end_addr, . - end_addr
