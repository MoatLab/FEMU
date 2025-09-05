#ifndef STATES_H
#define STATES_H

#ifdef __cplusplus
extern "C" {
#endif

#include "pldm_types.h"

/** @brief PLDM enums for the boot progress state set
 */
enum pldm_boot_progress_states {
	PLDM_BOOT_NOT_ACTIVE = 1,
	PLDM_BOOT_COMPLETED = 2,
};

/** @brief PLDM enums for system power states
 */
enum pldm_system_power_states {
	PLDM_OFF_SOFT_GRACEFUL = 9,
};

#ifdef __cplusplus
}
#endif

#endif /* STATES_H */
