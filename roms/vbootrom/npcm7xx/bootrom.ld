/*
 * Linker script for the Boot ROM.
 *
 * Copyright 2020 Google LLC
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
	rom (rx) : ORIGIN = 0xFFFF0000, LENGTH = 64K
	ram (a!rx) : ORIGIN = 0xFFFD0000, LENGTH = 128K
}

SECTIONS
{
	/* Vectors are loaded into ROM, and copied into SRAM. */
	.text.vectors : {
		*(.text.vectors)
		. = 0x100;
	} >ram AT>rom
	/* The rest of the code follows the vectors, but is not copied. */
	.text : {
		*(.text .text.*)
		*(.rodata .rodata.*)
		. = ALIGN(32);
		_etext = .;
	} >rom
	/*
	 * Data follows the code in ROM, and is copied after the vectors in RAM.
	 * 32-byte aligned so we can use simple and fast copy loops.
	 */
	.data : {
		_data = .;
		*(.data.rom_status)
		*(.data .data.*)
		. = ALIGN(32);
		_edata = .;
	} >ram AT>rom
	/* BSS lives in RAM, after the data section. */
	.bss : {
		*(.bss .bss.*)
		. = ALIGN(32);
		_end = .;
	} >ram
}
