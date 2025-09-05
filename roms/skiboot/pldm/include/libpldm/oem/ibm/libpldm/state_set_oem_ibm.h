#ifndef STATE_SET_OEM_IBM_H
#define STATE_SET_OEM_IBM_H

#ifdef __cplusplus
extern "C" {
#endif

/** @brief IBM OEM State Set IDs */
enum ibm_oem_pldm_state_set_ids {
	PLDM_OEM_IBM_FIRMWARE_UPDATE_STATE = 32768,
	PLDM_OEM_IBM_BOOT_STATE = 32769,
	PLDM_OEM_IBM_VERIFICATION_STATE = 32770,
	PLDM_OEM_IBM_SYSTEM_POWER_STATE = 32771,
	PLDM_OEM_IBM_SBE_MAINTENANCE_STATE = 32772,
	PLDM_OEM_IBM_SBE_HRESET_STATE = 32776,
};

enum ibm_oem_pldm_state_set_firmware_update_state_values {
	START = 0x1,
	END = 0x2,
	FAIL = 0x3,
	ABORT = 0x4,
	ACCEPT = 0x5,
	REJECT = 0x6,
};

enum ibm_oem_pldm_state_set_boot_state_values {
	P = 0x1,
	T = 0x2,
};

enum ibm_oem_pldm_state_set_verification_state_values {
	VALID = 0x0,
	ENTITLEMENT_FAIL = 0x1,
	BANNED_PLATFORM_FAIL = 0x2,
	MIN_MIF_FAIL = 0x4,
};

enum ibm_oem_pldm_state_set_system_power_state_values {
	POWER_CYCLE_HARD = 0x1
};

enum ibm_oem_pldm_state_set_sbe_dump_state_values {
	SBE_DUMP_COMPLETED = 0x1,
	SBE_RETRY_REQUIRED = 0x2,
};

enum ibm_oem_pldm_state_set_sbe_hreset_state_values {
	SBE_HRESET_NOT_READY = 0x1,
	SBE_HRESET_READY = 0x2,
	SBE_HRESET_FAILED = 0x3,
};

#ifdef __cplusplus
}
#endif

#endif /* STATE_SET_OEM_IBM_H */
