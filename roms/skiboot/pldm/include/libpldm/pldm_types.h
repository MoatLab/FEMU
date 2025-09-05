#ifndef PLDM_TYPES_H
#define PLDM_TYPES_H

#include <stdint.h>

typedef union {
	uint8_t byte;
	struct {
		uint8_t bit0 : 1;
		uint8_t bit1 : 1;
		uint8_t bit2 : 1;
		uint8_t bit3 : 1;
		uint8_t bit4 : 1;
		uint8_t bit5 : 1;
		uint8_t bit6 : 1;
		uint8_t bit7 : 1;
	} __attribute__((packed)) bits;
} bitfield8_t;

/** @struct pldm_version
 *
 *
 */
typedef struct pldm_version {
	uint8_t alpha;
	uint8_t update;
	uint8_t minor;
	uint8_t major;
} __attribute__((packed)) ver32_t;

typedef uint8_t bool8_t;

typedef union {
	uint16_t value;
	struct {
		uint8_t bit0 : 1;
		uint8_t bit1 : 1;
		uint8_t bit2 : 1;
		uint8_t bit3 : 1;
		uint8_t bit4 : 1;
		uint8_t bit5 : 1;
		uint8_t bit6 : 1;
		uint8_t bit7 : 1;
		uint8_t bit8 : 1;
		uint8_t bit9 : 1;
		uint8_t bit10 : 1;
		uint8_t bit11 : 1;
		uint8_t bit12 : 1;
		uint8_t bit13 : 1;
		uint8_t bit14 : 1;
		uint8_t bit15 : 1;
	} __attribute__((packed)) bits;
} bitfield16_t;

typedef union {
	uint32_t value;
	struct {
		uint8_t bit0 : 1;
		uint8_t bit1 : 1;
		uint8_t bit2 : 1;
		uint8_t bit3 : 1;
		uint8_t bit4 : 1;
		uint8_t bit5 : 1;
		uint8_t bit6 : 1;
		uint8_t bit7 : 1;
		uint8_t bit8 : 1;
		uint8_t bit9 : 1;
		uint8_t bit10 : 1;
		uint8_t bit11 : 1;
		uint8_t bit12 : 1;
		uint8_t bit13 : 1;
		uint8_t bit14 : 1;
		uint8_t bit15 : 1;
		uint8_t bit16 : 1;
		uint8_t bit17 : 1;
		uint8_t bit18 : 1;
		uint8_t bit19 : 1;
		uint8_t bit20 : 1;
		uint8_t bit21 : 1;
		uint8_t bit22 : 1;
		uint8_t bit23 : 1;
		uint8_t bit24 : 1;
		uint8_t bit25 : 1;
		uint8_t bit26 : 1;
		uint8_t bit27 : 1;
		uint8_t bit28 : 1;
		uint8_t bit29 : 1;
		uint8_t bit30 : 1;
		uint8_t bit31 : 1;
	} __attribute__((packed)) bits;
} bitfield32_t;

typedef union {
	uint64_t value;
	struct {
		uint8_t bit0 : 1;
		uint8_t bit1 : 1;
		uint8_t bit2 : 1;
		uint8_t bit3 : 1;
		uint8_t bit4 : 1;
		uint8_t bit5 : 1;
		uint8_t bit6 : 1;
		uint8_t bit7 : 1;
		uint8_t bit8 : 1;
		uint8_t bit9 : 1;
		uint8_t bit10 : 1;
		uint8_t bit11 : 1;
		uint8_t bit12 : 1;
		uint8_t bit13 : 1;
		uint8_t bit14 : 1;
		uint8_t bit15 : 1;
		uint8_t bit16 : 1;
		uint8_t bit17 : 1;
		uint8_t bit18 : 1;
		uint8_t bit19 : 1;
		uint8_t bit20 : 1;
		uint8_t bit21 : 1;
		uint8_t bit22 : 1;
		uint8_t bit23 : 1;
		uint8_t bit24 : 1;
		uint8_t bit25 : 1;
		uint8_t bit26 : 1;
		uint8_t bit27 : 1;
		uint8_t bit28 : 1;
		uint8_t bit29 : 1;
		uint8_t bit30 : 1;
		uint8_t bit31 : 1;
		uint8_t bit32 : 1;
		uint8_t bit33 : 1;
		uint8_t bit34 : 1;
		uint8_t bit35 : 1;
		uint8_t bit36 : 1;
		uint8_t bit37 : 1;
		uint8_t bit38 : 1;
		uint8_t bit39 : 1;
		uint8_t bit40 : 1;
		uint8_t bit41 : 1;
		uint8_t bit42 : 1;
		uint8_t bit43 : 1;
		uint8_t bit44 : 1;
		uint8_t bit45 : 1;
		uint8_t bit46 : 1;
		uint8_t bit47 : 1;
		uint8_t bit48 : 1;
		uint8_t bit49 : 1;
		uint8_t bit50 : 1;
		uint8_t bit51 : 1;
		uint8_t bit52 : 1;
		uint8_t bit53 : 1;
		uint8_t bit54 : 1;
		uint8_t bit55 : 1;
		uint8_t bit56 : 1;
		uint8_t bit57 : 1;
		uint8_t bit58 : 1;
		uint8_t bit59 : 1;
		uint8_t bit60 : 1;
		uint8_t bit61 : 1;
		uint8_t bit62 : 1;
		uint8_t bit63 : 1;
	} __attribute__((packed)) bits;
} bitfield64_t;

typedef float real32_t;

#endif /* PLDM_TYPES_H */
