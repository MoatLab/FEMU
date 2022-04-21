#ifndef X86INTERFACE_H
#define X86INTERFACE_H

extern u16 A1_rdw(u32 addr);
extern int execute_bios(pci_dev_t gr_dev, void *reloc_addr);
extern void shutdown_bios(void);

#endif
