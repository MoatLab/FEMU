#ifndef OEM_IBM_FRU_H
#define OEM_IBM_FRU_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>
#include <stdint.h>

enum pldm_oem_ibm_fru_field_type {
	PLDM_OEM_FRU_FIELD_TYPE_IANA = 0X01,
	PLDM_OEM_FRU_FIELD_TYPE_RT = 0X02,
	PLDM_OEM_FRU_FIELD_TYPE_LOCATION_CODE = 0XFE,
};

#ifdef __cplusplus
}
#endif

#endif /* OEM_IBM_FRU_H */
