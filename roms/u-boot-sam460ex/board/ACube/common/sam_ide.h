#ifndef SAM_IDE_H
#define SAM_IDE_H

#include <part.h>
#include "sys_dep.h"

typedef void * base_io_address;

struct controller_context
{
	UBYTE				cc_present;		//This is in fact a BOOL
	UBYTE 				cc_maxunit;
	UBYTE				cc_maxbus;
	UBYTE				cc_units_per_bus;
	char *				cc_maxbus_var;
	BOOL *				cc_bus_ok;		//Length is cc_maxbus
	base_io_address 	*cc_base_io;	//Length is cc_maxbus
	block_dev_desc_t 	*cc_units;		//Length is cc_maxunit
	char *				cc_description;
	unsigned long (* cc_block_read)(int dev, unsigned long start, lbaint_t blkcnt, unsigned long *buffer);
	unsigned long (* cc_atapi_read)(int device, lbaint_t blknr, ulong blkcnt, ulong *buffer);
};

#define MAX_SCSI_UNITNUM  CFG_SCSI_MAX_DEVICE

#define MAX_P_SII_UNITS	4
#define MAX_P_SII_BUS	2

#define MAX_S_SII_UNITS	2
#define MAX_S_SII_BUS	2 //One unit per bus, two buses.

#define MAX_S_4_SII_UNITS	4
#define MAX_S_4_SII_BUS		4 //One unit per bus, four buses.

#define MAX_S2_SII_UNITS	2
#define MAX_S2_SII_BUS		2 //One unit per bus, two buses.

#ifdef CONFIG_SAM460EX
#define MAX_SATA2_460_UNITS	CONFIG_SYS_SATA_MAX_DEVICE
#define MAX_SATA2_460_BUS	1
#endif

#define PCI_DEVICE_ID_SII_3132 0x3132 //It's not present in pci_ids.h so I have to supply it myself.
#define PCI_DEVICE_ID_SII_3114 0x3114 //Same as above.
#define PCI_DEVICE_ID_SII_3512 0x3512 //Same as above.

#define SILLY_SIL_4_PORTS_OFFSET 0x200

extern void ide_controllers_init(void);
extern void print_all_controllers(void);

extern block_dev_desc_t * p_sii_get_dev(const unsigned unit);
extern block_dev_desc_t *s_sii_get_dev(const unsigned unit);
extern block_dev_desc_t *s_4_sii_get_dev(const unsigned unit);

#ifdef CONFIG_SAM460EX
extern block_dev_desc_t *sata2_460_get_dev(const unsigned unit);
#endif

#endif //SAM_IDE_H
