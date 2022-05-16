//
// Fake ati bios tables.
//
// aty128fb and radeonfb try to gather informations from these tables,
// so add some stuff here to make the drivers happy.  Specifically
// radeonfb needs the pll information, otherwise it'll crash with a
// division by zero ...
//
	.org 0x48
	.word _ati_main

	// main info
	.org 0x50
_ati_main:
	.org 0x50 + 0x30
	.word _ati_pll
	.org 0x50 + 0x50
	.word _ati_connector

	// pll info
	.org 0x100
_ati_pll:
	.word	0		// ??? (not used by radeonfb)
	.word	0
	.word	0
	.word	0
	.word	23000		// sclk
	.word	23000		// mclk
	.word	0
	.word	2700		// ref_clk
	.word	4		// ref_div
	.long	12000		// ppll_min
	.long	35000		// ppll_max

	// connector info
	.org 0x140
_ati_connector:
	.byte 0x10		// one chip
	.byte 0x01		// one connector
	.word 0x3000		// type DVI-I
	.word 0			// end of list

	.org 0x200
