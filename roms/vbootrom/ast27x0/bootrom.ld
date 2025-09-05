/*
 * Linker script for the Boot ROM.
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

MEMORY
{
	rom (rx) : ORIGIN = 0x00000000, LENGTH = 128K
	ram (arwx) : ORIGIN = 0x10000000, LENGTH = 128K
}

SECTIONS
{
	/* Vectors are loaded into ROM */
	.text.vectors : {
		__vectors_vma = .;
		*(.text.vectors)
		. = 0x100;
		__vectors_end = .;
	} >rom
	/* The rest of the code follows the vectors.
	 * The main code and read-only data, located in ROM
	 */
	.text : {
		__text = .;
		*(.text .text.*)
		. = ALIGN(32);
		*(.rodata .rodata.*)
		. = ALIGN(32);
		__etext = .;
	} >rom
	/*
	 * Initialized data section
	 * Data follows the code in ROM, and is copied in RAM.
	 */
	.data : {
		__data = .;
		*(.data .data.*)
		. = ALIGN(32);
		__edata = .;
	} >ram AT>rom
	__data_loadaddr = LOADADDR(.data);

	/* Zero-initialized data (BSS) lives in RAM, after the data section. */
	.bss : {
		__bss_start = .;
		*(.bss .bss.*)
		. = ALIGN(32);
		*(COMMON)
		. = ALIGN(32);
		__bss_end = .;
		__end = .;
	} >ram
}
