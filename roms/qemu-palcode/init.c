/* Initialization of the system and the HWRPB.

   Copyright (C) 2011 Richard Henderson

   This file is part of QEMU PALcode.

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2 of the License or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the text
   of the GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; see the file COPYING.  If not see
   <http://www.gnu.org/licenses/>.  */

#include "hwrpb.h"
#include "osf.h"
#include "ioport.h"
#include "uart.h"
#include "protos.h"
#include SYSTEM_H

#define PAGE_SHIFT	13
#define PAGE_SIZE	(1ul << PAGE_SHIFT)
#define PAGE_OFFSET	0xfffffc0000000000UL

#define VPTPTR		0xfffffffe00000000UL

#define PA(VA)		((unsigned long)(VA) & 0xfffffffffful)
#define VA(PA)		((void *)(PA) + PAGE_OFFSET)

#define HZ	1024

/* Upon entry, register a2 contains configuration information from the VM:

   bits 0-5 -- ncpus
   bit  6   -- "nographics" option (used to initialize CTB)  */

#define CONFIG_NCPUS(x)      ((x) & 63)
#define CONFIG_NOGRAPHICS(x) ((x) & (1ull << 6))

struct hwrpb_combine {
  struct hwrpb_struct hwrpb;
  struct percpu_struct processor[4];
  struct memdesc_struct md;
  struct memclust_struct mc[2];
  struct ctb_struct ctb;
  struct crb_struct crb;
  struct procdesc_struct proc_dispatch;
  struct procdesc_struct proc_fixup;
};

extern char stack[PAGE_SIZE] __attribute__((section(".sbss")));
extern char _end[] __attribute__((visibility("hidden"), nocommon));

struct pcb_struct pcb __attribute__((section(".sbss")));

static unsigned long page_dir[1024]
  __attribute__((aligned(PAGE_SIZE), section(".bss.page_dir")));

/* The HWRPB must be aligned because it is exported at INIT_HWRPB.  */
struct hwrpb_combine hwrpb __attribute__((aligned(PAGE_SIZE)));

void *last_alloc;
bool have_vga;
unsigned int pci_vga_bus;
unsigned int pci_vga_dev;

static void *
alloc (unsigned long size, unsigned long align)
{
  void *p = (void *)(((unsigned long)last_alloc + align - 1) & ~(align - 1));
  last_alloc = p + size;
  return memset (p, 0, size);
}

static inline unsigned long
pt_index(unsigned long addr, int level)
{
  return (addr >> (PAGE_SHIFT + (10 * level))) & 0x3ff;
}

static inline unsigned long
build_pte (void *page)
{
  unsigned long bits;

  bits = PA((unsigned long)page) << (32 - PAGE_SHIFT);
  bits += _PAGE_VALID | _PAGE_KRE | _PAGE_KWE;

  return bits;
}

static inline void *
pte_page (unsigned long pte)
{
  return VA(pte >> 32 << PAGE_SHIFT);
}

static void
set_pte (unsigned long addr, void *page)
{
  unsigned long *pt = page_dir;
  unsigned long index;

  index = pt_index(addr, 2);
  if (pt[index] != 0)
    pt = pte_page (pt[index]);
  else
    {
      unsigned long *npt = alloc(PAGE_SIZE, PAGE_SIZE);
      pt[index] = build_pte (npt);
      pt = npt;
    }

  index = pt_index(addr, 1);
  if (pt[index] != 0)
    pt = pte_page (pt[index]);
  else
    {
      unsigned long *npt = alloc(PAGE_SIZE, PAGE_SIZE);
      pt[index] = build_pte (npt);
      pt = npt;
    }

  index = pt_index(addr, 0);
  pt[index] = build_pte (page);
}

static void
init_page_table(void)
{
  /* Install the self-reference for the virtual page table base register.  */
  page_dir[pt_index(VPTPTR, 2)] = build_pte(page_dir);

  set_pte ((unsigned long)INIT_HWRPB, &hwrpb);
  
  /* ??? SRM maps some amount of memory at 0x20000000 for use by programs
     started from the console prompt.  Including the bootloader.  While
     we're emulating MILO, don't bother as we jump straight to the kernel
     loaded into KSEG.  */
}

static void
init_hwrpb (unsigned long memsize, unsigned long config)
{
  unsigned long pal_pages;
  unsigned long amask;
  unsigned long i;
  unsigned long proc_type = EV4_CPU;
  unsigned long cpus = CONFIG_NCPUS(config);
  
  hwrpb.hwrpb.phys_addr = PA(&hwrpb);

  /* Yes, the 'HWRPB' magic is in big-endian byte ordering.  */
  hwrpb.hwrpb.id = ( (long)'H' << 56
		   | (long)'W' << 48
		   | (long)'R' << 40
		   | (long)'P' << 32
		   | (long)'B' << 24);

  hwrpb.hwrpb.size = sizeof(struct hwrpb_struct);

  ((int *)hwrpb.hwrpb.ssn)[0] = ( 'Q' << 0
				| 'E' << 8
				| 'M' << 16
				| 'U' << 24);

  amask = ~__builtin_alpha_amask(-1);
  switch (__builtin_alpha_implver())
    {
    case 0: /* EV4 */
      proc_type = EV4_CPU;
      hwrpb.hwrpb.max_asn = 63;
      break;

    case 1: /* EV5 */
      proc_type
	= ((amask & 0x101) == 0x101 ? PCA56_CPU		/* MAX+BWX */
	   : amask & 1 ? EV56_CPU			/* BWX */
	   : EV5_CPU);
      hwrpb.hwrpb.max_asn = 127;
      break;

    case 2: /* EV6 */
      proc_type = (amask & 4 ? EV67_CPU : EV6_CPU);     /* CIX */
      hwrpb.hwrpb.max_asn = 255;
      break;
    }

  /* This field is the WHAMI of the primary CPU.  Just initialize
     this to 0; CPU #0 is always the primary on real Alpha systems
     (except for the TurboLaser).  */
  hwrpb.hwrpb.cpuid = 0;

  hwrpb.hwrpb.pagesize = PAGE_SIZE;
  hwrpb.hwrpb.pa_bits = 40;
  hwrpb.hwrpb.sys_type = SYS_TYPE;
  hwrpb.hwrpb.sys_variation = SYS_VARIATION;
  hwrpb.hwrpb.sys_revision = SYS_REVISION;
  for (i = 0; i < cpus; ++i)
    {
      /* Set the following PCS flags:
	 (bit 2) Processor Available
	 (bit 3) Processor Present
	 (bit 6) PALcode Valid
	 (bit 7) PALcode Memory Valid
	 (bit 8) PALcode Loaded

	 ??? We really should be intializing the PALcode memory and
	 scratch space fields if we're setting PMV, or not set PMV,
	 but Linux checks for it, so...  */
      hwrpb.processor[i].flags = 0x1cc;
      hwrpb.processor[i].type = proc_type;
    }

  hwrpb.hwrpb.intr_freq = HZ * 4096;
  hwrpb.hwrpb.cycle_freq = 250000000;	/* QEMU architects 250MHz.  */

  hwrpb.hwrpb.vptb = VPTPTR;

  hwrpb.hwrpb.nr_processors = cpus;
  hwrpb.hwrpb.processor_size = sizeof(struct percpu_struct);
  hwrpb.hwrpb.processor_offset = offsetof(struct hwrpb_combine, processor);

  hwrpb.hwrpb.mddt_offset = offsetof(struct hwrpb_combine, md);
  hwrpb.md.numclusters = 2;

  pal_pages = (PA(last_alloc) + PAGE_SIZE - 1) >> PAGE_SHIFT;

  hwrpb.mc[0].numpages = pal_pages;
  hwrpb.mc[0].usage = 1;
  hwrpb.mc[1].start_pfn = pal_pages;
  hwrpb.mc[1].numpages = (memsize >> PAGE_SHIFT) - pal_pages;

  hwrpb.hwrpb.ctbt_offset = offsetof(struct hwrpb_combine, ctb);
  hwrpb.hwrpb.ctb_size = sizeof(hwrpb.ctb);
  hwrpb.ctb.len = sizeof(hwrpb.ctb) - offsetof(struct ctb_struct, ipl);
  if (have_vga && !CONFIG_NOGRAPHICS(config))
    {
      hwrpb.ctb.type = CTB_MULTIPURPOSE;
      hwrpb.ctb.term_type = CTB_GRAPHICS;
      hwrpb.ctb.turboslot = (CTB_TURBOSLOT_TYPE_PCI << 16) |
			    (pci_vga_bus << 8) | pci_vga_dev;
    }
  else
    {
      hwrpb.ctb.type = CTB_PRINTERPORT;
      hwrpb.ctb.term_type = CTB_PRINTERPORT;
    }

  hwrpb.hwrpb.crb_offset = offsetof(struct hwrpb_combine, crb);
  hwrpb.crb.dispatch_va = &hwrpb.proc_dispatch;
  hwrpb.crb.dispatch_pa = PA(&hwrpb.proc_dispatch);
  hwrpb.crb.fixup_va = &hwrpb.proc_fixup;
  hwrpb.crb.fixup_pa = PA(&hwrpb.proc_fixup);
  hwrpb.crb.map_entries = 1;
  hwrpb.crb.map_pages = 1;
  hwrpb.crb.map[0].va = &hwrpb;
  hwrpb.crb.map[0].pa = PA(&hwrpb);
  hwrpb.crb.map[0].count = 1;

  /* See crb.c for how we match the VMS calling conventions to Unix.  */
  hwrpb.proc_dispatch.address = (unsigned long)crb_dispatch;
  hwrpb.proc_fixup.address = (unsigned long)crb_fixup;

  hwrpb_update_checksum(&hwrpb.hwrpb);
}

static void
init_pcb (void)
{
  pcb.ksp = (unsigned long)stack + sizeof(stack);
  pcb.ptbr = PA(page_dir) >> PAGE_SHIFT;
  pcb.flags = 1; /* FEN */
}

static void
init_i8259 (void)
{
  /* ??? MILO initializes the PIC as edge triggered; I do not know how SRM
     initializes them.  However, Linux seems to expect that these are level
     triggered.  That may be a kernel bug, but level triggers are more
     reliable anyway so lets go with that.  */

  /* Initialize the slave PIC.  */
  outb(0x11, PORT_PIC2_CMD);	/* ICW1: edge trigger, cascade, ICW4 req */
  outb(0x08, PORT_PIC2_DATA);	/* ICW2: irq offset = 8 */
  outb(0x02, PORT_PIC2_DATA);	/* ICW3: slave ID 2 */
  outb(0x01, PORT_PIC2_DATA);	/* ICW4: not special nested, normal eoi */

  /* Initialize the master PIC.  */
  outb(0x11, PORT_PIC1_CMD);	/* ICW1 */
  outb(0x00, PORT_PIC1_DATA);	/* ICW2: irq offset = 0 */
  outb(0x04, PORT_PIC1_DATA);	/* ICW3: slave control INTC2 */
  outb(0x01, PORT_PIC1_DATA);	/* ICW4 */

  /* Initialize level triggers.  The CY82C693UB that's on some real alpha
     hardware doesn't have this; this is a PIIX extension.  However,
     QEMU doesn't implement regular level triggers.  */
  outb(0xff, PORT_PIC2_ELCR);
  outb(0xff, PORT_PIC1_ELCR);

  /* Disable all interrupts.  */
  outb(0xff, PORT_PIC2_DATA);
  outb(0xff, PORT_PIC1_DATA);

  /* Non-specific EOI, clearing anything the might be pending.  */
  outb(0x20, PORT_PIC2_CMD);
  outb(0x20, PORT_PIC1_CMD);
}

static void __attribute__((noreturn))
swppal(void *entry, void *pcb, unsigned long vptptr, unsigned long pv)
{
  register int variant __asm__("$16") = 2;	/* OSF/1 PALcode */
  register void *pc __asm__("$17") = entry;
  register unsigned long pa_pcb __asm__("$18") = PA(pcb);
  register unsigned long newvptptr __asm__("$19") = vptptr;
  register unsigned long newpv __asm__("$20") = pv;

  asm("call_pal 0x0a" : :
      "r"(variant), "r"(pc), "r"(pa_pcb), "r"(newvptptr), "r"(newpv));
  __builtin_unreachable ();
}

void
do_start(unsigned long memsize, void (*kernel_entry)(void),
         unsigned long config)
{
  last_alloc = _end;

  init_page_table();
  init_pcb();
  init_i8259();
  uart_init();
  ps2port_setup();
  pci_setup();
  vgahw_init();
  init_hwrpb(memsize, config);

  void *new_pc = kernel_entry ? kernel_entry : do_console;

  swppal(new_pc, &pcb, VPTPTR, (unsigned long)new_pc);
}

void
do_start_wait(unsigned long cpuid)
{
  while (1)
    {
      /* Wait 1ms for the kernel to wake us.  */
      ndelay(1000000);

      if (hwrpb.hwrpb.rxrdy & (1ull << cpuid))
	{
	  /* ??? The only message I know of is "START\r\n".
	     I can't be bothered to verify more than 4 characters.  */

	  /* Use use a private extension to SWPPAL to get the
	     CPU_restart_data into $27.  Linux fills it in, but does
	     not require it. Other operating systems, however, do use
	     CPU_restart_data as part of secondary CPU start-up.  */

	  unsigned int len = hwrpb.processor[cpuid].ipc_buffer[0];
	  unsigned int msg = hwrpb.processor[cpuid].ipc_buffer[1];
	  void *CPU_restart = hwrpb.hwrpb.CPU_restart;
	  unsigned long CPU_restart_data = hwrpb.hwrpb.CPU_restart_data;
	  __sync_synchronize();
	  hwrpb.hwrpb.rxrdy = 0;

          if (len == 7 && msg == ('S' | 'T' << 8 | 'A' << 16 | 'R' << 24))
	    {
	      /* Set bootstrap in progress */
	      hwrpb.processor[cpuid].flags |= 1;
	      swppal(CPU_restart, hwrpb.processor[cpuid].hwpcb,
		     hwrpb.hwrpb.vptb, CPU_restart_data);
	    }
	}
    }
}
