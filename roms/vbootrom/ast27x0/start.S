/*
 * Top-level entry points to the Boot ROM. This includes:
 * - Reset, exception and interrupt vectors.
 * - C run-time initialization.
 * - Secondary CPU boot code.
 *
 * Copyright 2025 Google LLC
 * Copyright (C) ASPEED Technology Inc.
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

#define SRAM_SIZE (128 * KiB)

.section .bss

.global next_boot_addr
.type next_boot_addr, %object
next_boot_addr:
    .skip 8
.size next_boot_addr, . - next_boot_addr

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
// Determine the current core ID using MPIDR_EL1.
// If it's core 0, jump to CPU0 initialization routine.
// Otherwise, wait for CPU0 to publish the boot entry point.
mrs    x1, MPIDR_EL1
and    x1, x1, #0x03
cbz    x1, cpu0_init

// Non-CPU0 cores wait here until CPU0 sets the next_boot_addr.
// Once it's non-zero, jump to that address.
1:
ldr     x2, =next_boot_addr
ldr     x3, [x2]
cbnz    x3, 2f
wfe
b       1b

// Perform synchronization before branching to boot image.
2:
dsb     sy
isb
br      x3

// Should never reach here unless boot entry is invalid.
b       panic
.size reset, . - reset

.type cpu0_init, %function
cpu0_init:
// Set up stack pointer to top of SRAM (with 16-byte safety margin).
// This ensures the stack is within the SRAM region and avoids overflow.
ldr    x1, sram_base_addr
mov    x2, #SRAM_SIZE
sub    x2, x2, #0x10        // leave 16-byte safety margin
add    sp, x1, x2           // SP = base + size - 0x10

// Copy initialized .data section from ROM (LMA) to RAM (VMA)
ldr     x3, =__data_loadaddr     // source address in ROM
ldr     x4, =__data              // destination address in RAM
ldr     x5, =__edata             // end of .data in RAM
copy_data_loop:
cmp     x4, x5
b.ge    data_copy_done
ldr     w6, [x3], #4          // load word from ROM and post-increment
str     w6, [x4]              // store word to RAM
add     x4, x4, #4            // move to next word
b       copy_data_loop
data_copy_done:
// Zero-initialize the .bss section in RAM
ldr     x4, =__bss_start
ldr     x5, =__bss_end
clear_bss_loop:
cmp     x4, x5
b.ge    bss_clear_done
mov     w6, #0
str     w6, [x4]          // store zero to memory
add     x4, x4, #4        // move to next word
b       clear_bss_loop
bss_clear_done:
// Load the boot image.
// Returns the entry point in x0
bl      load_boot_image

// Write entry point to shared memory for other CPUs
// and send an event to wake them up from WFE.
// x0 now holds the boot image entry point
ldr     x2, =next_boot_addr
str     x0, [x2]
dsb     st
sev

// Synchronize memory and pipeline before jumping to the boot image.
dsb     sy
isb
br      x0

// Should never reach here unless something goes wrong.
b       panic
.size cpu0_init, . - cpu0_init

.section .rodata
.type sram_base_addr, %object
sram_base_addr:
.dword    0x10000000
.size sram_base_addr, . - sram_base_addr

