/** @file
  Intel FSP API definition from Intel Firmware Support Package External
  Architecture Specification v2.0 and above.

  Copyright (c) 2014 - 2022, Intel Corporation. All rights reserved.<BR>
  SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#ifndef _FSP_API_H_
#define _FSP_API_H_

#include <Pi/PiStatusCode.h>
#include <Base.h>

///
/// FSP Reset Status code
/// These are defined in FSP EAS v2.4 section 13.2.2 - OEM Status Code
/// @{

#define ENCODE_RESET_REQUEST(ResetType)  \
        ((EFI_STATUS)((MAX_BIT >> 1) | (ResetType)))
#define FSP_STATUS_RESET_REQUIRED_COLD  ENCODE_RESET_REQUEST(1)
#define FSP_STATUS_RESET_REQUIRED_WARM  ENCODE_RESET_REQUEST(2)
#define FSP_STATUS_RESET_REQUIRED_3     ENCODE_RESET_REQUEST(3)
#define FSP_STATUS_RESET_REQUIRED_4     ENCODE_RESET_REQUEST(4)
#define FSP_STATUS_RESET_REQUIRED_5     ENCODE_RESET_REQUEST(5)
#define FSP_STATUS_RESET_REQUIRED_6     ENCODE_RESET_REQUEST(6)
#define FSP_STATUS_RESET_REQUIRED_7     ENCODE_RESET_REQUEST(7)
#define FSP_STATUS_RESET_REQUIRED_8     ENCODE_RESET_REQUEST(8)
#define FSP_STATUS_VARIABLE_REQUEST     ENCODE_RESET_REQUEST(10)
/// @}

///
/// FSP Event related definition.
///
#define FSP_EVENT_CODE  0xF5000000
#define FSP_POST_CODE   (FSP_EVENT_CODE | 0x00F80000)

/*
  FSP may optionally include the capability of generating events messages to aid in the debugging of firmware issues.
  These events fall under three catagories: Error, Progress, and Debug. The event reporting mechanism follows the
  status code services described in section 6 and 7 of the PI Specification v1.7 Volume 3.

  @param[in] Type                   Indicates the type of event being reported.
                                    See MdePkg/Include/Pi/PiStatusCode.h for the definition of EFI_STATUS_CODE_TYPE.
  @param[in] Value                  Describes the current status of a hardware or software entity.
                                    This includes information about the class and subclass that is used to classify the entity as well as an operation.
                                    For progress events, the operation is the current activity. For error events, it is the exception.
                                    For debug events, it is not defined at this time.
                                    See MdePkg/Include/Pi/PiStatusCode.h for the definition of EFI_STATUS_CODE_VALUE.
  @param[in] Instance               The enumeration of a hardware or software entity within the system.
                                    A system may contain multiple entities that match a class/subclass pairing. The instance differentiates between them.
                                    An instance of 0 indicates that instance information is unavailable, not meaningful, or not relevant.
                                    Valid instance numbers start with 1.
  @param[in] *CallerId              This parameter can be used to identify the sub-module within the FSP generating the event.
                                    This parameter may be NULL.
  @param[in] *Data                  This optional parameter may be used to pass additional data. The contents can have event-specific data.
                                    For example, the FSP provides a EFI_STATUS_CODE_STRING_DATA instance to this parameter when sending debug messages.
                                    This parameter is NULL when no additional data is provided.

  @retval EFI_SUCCESS               The event was handled successfully.
  @retval EFI_INVALID_PARAMETER     Input parameters are invalid.
  @retval EFI_DEVICE_ERROR          The event handler failed.
*/
typedef
EFI_STATUS
(EFIAPI *FSP_EVENT_HANDLER)(
  IN          EFI_STATUS_CODE_TYPE   Type,
  IN          EFI_STATUS_CODE_VALUE  Value,
  IN          UINT32                 Instance,
  IN OPTIONAL EFI_GUID               *CallerId,
  IN OPTIONAL EFI_STATUS_CODE_DATA   *Data
  );

/*
  Handler for FSP-T debug log messages, provided by the bootloader.

  @param[in] DebugMessage           A pointer to the debug message to be written to the log.
  @param[in] MessageLength          Number of bytes to written to the debug log.

  @retval UINT32                    The return value indicates the number of bytes actually written to
                                    the debug log. If the return value is less than MessageLength,
                                    an error occurred.
*/
typedef
UINT32
(EFIAPI *FSP_DEBUG_HANDLER)(
  IN CHAR8 *DebugMessage,
  IN UINT32                 MessageLength
  );

#pragma pack(1)
///
/// FSP_UPD_HEADER Configuration.
///
typedef struct {
  ///
  /// UPD Region Signature. This signature will be
  /// "XXXXXX_T" for FSP-T
  /// "XXXXXX_M" for FSP-M
  /// "XXXXXX_S" for FSP-S
  /// "XXXXXX_I" for FSP-I
  /// Where XXXXXX is an unique signature
  ///
  UINT64    Signature;
  ///
  /// Revision of the Data structure.
  ///   For FSP spec 2.0/2.1, this value is 1 and only FSPM_UPD having ARCH_UPD.
  ///   For FSP spec 2.2 and above, this value is 2 and ARCH_UPD present in all UPD structures.
  ///
  UINT8     Revision;
  UINT8     Reserved[23];
} FSP_UPD_HEADER;

///
/// FSPT_ARCH_UPD Configuration.
///
typedef struct {
  ///
  /// Revision of the structure is 1 for this version of the specification.
  ///
  UINT8                Revision;
  UINT8                Reserved[3];
  ///
  /// Length of the structure in bytes. The current value for this field is 32.
  ///
  UINT32               Length;
  ///
  /// FspDebugHandler Optional debug handler for the bootloader to receive debug messages
  /// occurring during FSP execution.
  ///
  FSP_DEBUG_HANDLER    FspDebugHandler;
  UINT8                Reserved1[20];
} FSPT_ARCH_UPD;

///
/// FSPT_ARCH2_UPD Configuration for FSP 2.4 and above.
///
typedef struct {
  ///
  /// Revision of the structure is 2 for this version of the specification.
  ///
  UINT8                   Revision;
  UINT8                   Reserved[3];
  ///
  /// Length of the structure in bytes. The current value for this field is 32.
  ///
  UINT32                  Length;
  ///
  /// FspDebugHandler Optional debug handler for the bootloader to receive debug messages
  /// occurring during FSP execution.
  ///
  EFI_PHYSICAL_ADDRESS    FspDebugHandler;
  UINT8                   Reserved1[16];
} FSPT_ARCH2_UPD;

///
/// FSPM_ARCH_UPD Configuration.
///
typedef struct {
  ///
  /// Revision of the structure. For FSP v2.0 value is 1.
  ///
  UINT8                Revision;
  UINT8                Reserved[3];
  ///
  /// Pointer to the non-volatile storage (NVS) data buffer.
  /// If it is NULL it indicates the NVS data is not available.
  ///
  VOID                 *NvsBufferPtr;
  ///
  /// Pointer to the temporary stack base address to be
  /// consumed inside FspMemoryInit() API.
  ///
  VOID                 *StackBase;
  ///
  /// Temporary stack size to be consumed inside
  /// FspMemoryInit() API.
  ///
  UINT32               StackSize;
  ///
  /// Size of memory to be reserved by FSP below "top
  /// of low usable memory" for bootloader usage.
  ///
  UINT32               BootLoaderTolumSize;
  ///
  /// Current boot mode.
  ///
  UINT32               BootMode;
  ///
  /// Optional event handler for the bootloader to be informed of events occurring during FSP execution.
  /// This value is only valid if Revision is >= 2.
  ///
  FSP_EVENT_HANDLER    *FspEventHandler;
  UINT8                Reserved1[4];
} FSPM_ARCH_UPD;

///
/// FSPM_ARCH2_UPD Configuration for FSP 2.4 and above.
///
typedef struct {
  ///
  /// Revision of the structure is 3 for this version of the specification.
  ///
  UINT8                   Revision;
  UINT8                   Reserved[3];
  ///
  /// Length of the structure in bytes. The current value for this field is 64.
  ///
  UINT32                  Length;
  ///
  /// Pointer to the non-volatile storage (NVS) data buffer.
  /// If it is NULL it indicates the NVS data is not available.
  /// This value is deprecated starting with v2.4 of the FSP specification,
  /// and will be removed in an upcoming version of the FSP specification.
  ///
  EFI_PHYSICAL_ADDRESS    NvsBufferPtr;
  ///
  /// Pointer to the temporary stack base address to be
  /// consumed inside FspMemoryInit() API.
  ///
  EFI_PHYSICAL_ADDRESS    StackBase;
  ///
  /// Temporary stack size to be consumed inside
  /// FspMemoryInit() API.
  ///
  UINT64                  StackSize;
  ///
  /// Size of memory to be reserved by FSP below "top
  /// of low usable memory" for bootloader usage.
  ///
  UINT32                  BootLoaderTolumSize;
  ///
  /// Current boot mode.
  ///
  UINT32                  BootMode;
  ///
  /// Optional event handler for the bootloader to be informed of events occurring during FSP execution.
  /// This value is only valid if Revision is >= 2.
  ///
  EFI_PHYSICAL_ADDRESS    FspEventHandler;
  UINT8                   Reserved1[16];
} FSPM_ARCH2_UPD;

///
/// FSPS_ARCH_UPD Configuration.
///
typedef struct {
  ///
  /// Revision of the structure is 1 for this version of the specification.
  ///
  UINT8                Revision;
  UINT8                Reserved[3];
  ///
  /// Length of the structure in bytes. The current value for this field is 32.
  ///
  UINT32               Length;
  ///
  /// FspEventHandler Optional event handler for the bootloader to be informed of events
  /// occurring during FSP execution.
  ///
  FSP_EVENT_HANDLER    FspEventHandler;
  ///
  /// A FSP binary may optionally implement multi-phase silicon initialization,
  /// This is only supported if the FspMultiPhaseSiInitEntryOffset field in FSP_INFO_HEADER
  /// is non-zero.
  /// To enable multi-phase silicon initialization, the bootloader must set
  /// EnableMultiPhaseSiliconInit to a non-zero value.
  ///
  UINT8                EnableMultiPhaseSiliconInit;
  UINT8                Reserved1[19];
} FSPS_ARCH_UPD;

///
/// FSPS_ARCH2_UPD Configuration for FSP 2.4 and above.
///
typedef struct {
  ///
  /// Revision of the structure is 2 for this version of the specification.
  ///
  UINT8                   Revision;
  UINT8                   Reserved[3];
  ///
  /// Length of the structure in bytes. The current value for this field is 32.
  ///
  UINT32                  Length;
  ///
  /// FspEventHandler Optional event handler for the bootloader to be informed of events
  /// occurring during FSP execution.
  ///
  EFI_PHYSICAL_ADDRESS    FspEventHandler;
  UINT8                   Reserved1[16];
} FSPS_ARCH2_UPD;

///
/// FSPI_ARCH_UPD Configuration.
///
typedef struct {
  ///
  /// Revision of the structure is 1 for this version of the specification.
  ///
  UINT8                   Revision;
  UINT8                   Reserved[3];
  ///
  /// Length of the structure in bytes. The current value for this field is 64.
  ///
  UINT32                  Length;
  ///
  /// The physical memory-mapped base address of the bootloader SMM firmware volume (FV).
  ///
  EFI_PHYSICAL_ADDRESS    BootloaderSmmFvBaseAddress;
  ///
  /// The length in bytes of the bootloader SMM firmware volume (FV).
  ///
  UINT64                  BootloaderSmmFvLength;
  ///
  /// The physical memory-mapped base address of the bootloader SMM FV context data.
  /// This data is provided to bootloader SMM drivers through a HOB by the FSP MM Foundation.
  ///
  EFI_PHYSICAL_ADDRESS    BootloaderSmmFvContextData;
  ///
  /// The length in bytes of the bootloader SMM FV context data.
  /// This data is provided to bootloader SMM drivers through a HOB by the FSP MM Foundation.
  ///
  UINT16                  BootloaderSmmFvContextDataLength;
  UINT8                   Reserved1[30];
} FSPI_ARCH_UPD;

///
/// FSPT_UPD_COMMON Configuration.
///
typedef struct {
  ///
  /// FSP_UPD_HEADER Configuration.
  ///
  FSP_UPD_HEADER    FspUpdHeader;
} FSPT_UPD_COMMON;

///
/// FSPT_UPD_COMMON Configuration for FSP spec. 2.2 and above.
///
typedef struct {
  ///
  /// FSP_UPD_HEADER Configuration.
  ///
  FSP_UPD_HEADER    FspUpdHeader;

  ///
  /// FSPT_ARCH_UPD Configuration.
  ///
  FSPT_ARCH_UPD     FsptArchUpd;
} FSPT_UPD_COMMON_FSP22;

///
/// FSPT_UPD_COMMON Configuration for FSP spec. 2.4 and above.
///
typedef struct {
  ///
  /// FSP_UPD_HEADER Configuration.
  ///
  FSP_UPD_HEADER    FspUpdHeader;

  ///
  /// FSPT_ARCH2_UPD Configuration.
  ///
  FSPT_ARCH2_UPD    FsptArchUpd;
} FSPT_UPD_COMMON_FSP24;

///
/// FSPM_UPD_COMMON Configuration.
///
typedef struct {
  ///
  /// FSP_UPD_HEADER Configuration.
  ///
  FSP_UPD_HEADER    FspUpdHeader;
  ///
  /// FSPM_ARCH_UPD Configuration.
  ///
  FSPM_ARCH_UPD     FspmArchUpd;
} FSPM_UPD_COMMON;

///
/// FSPM_UPD_COMMON Configuration for FSP spec. 2.4 and above.
///
typedef struct {
  ///
  /// FSP_UPD_HEADER Configuration.
  ///
  FSP_UPD_HEADER    FspUpdHeader;
  ///
  /// FSPM_ARCH2_UPD Configuration.
  ///
  FSPM_ARCH2_UPD    FspmArchUpd;
} FSPM_UPD_COMMON_FSP24;

///
/// FSPS_UPD_COMMON Configuration.
///
typedef struct {
  ///
  /// FSP_UPD_HEADER Configuration.
  ///
  FSP_UPD_HEADER    FspUpdHeader;
} FSPS_UPD_COMMON;

///
/// FSPS_UPD_COMMON Configuration for FSP spec. 2.2 and above.
///
typedef struct {
  ///
  /// FSP_UPD_HEADER Configuration.
  ///
  FSP_UPD_HEADER    FspUpdHeader;

  ///
  /// FSPS_ARCH_UPD Configuration.
  ///
  FSPS_ARCH_UPD     FspsArchUpd;
} FSPS_UPD_COMMON_FSP22;

///
/// FSPS_UPD_COMMON Configuration for FSP spec. 2.4 and above.
///
typedef struct {
  ///
  /// FSP_UPD_HEADER Configuration.
  ///
  FSP_UPD_HEADER    FspUpdHeader;

  ///
  /// FSPS_ARCH2_UPD Configuration.
  ///
  FSPS_ARCH2_UPD    FspsArchUpd;
} FSPS_UPD_COMMON_FSP24;

///
/// FSPI_UPD_COMMON Configuration.
///
typedef struct {
  ///
  /// FSP_UPD_HEADER Configuration.
  ///
  FSP_UPD_HEADER    FspUpdHeader;

  ///
  /// FSPI_ARCH_UPD Configuration.
  ///
  FSPI_ARCH_UPD     FspiArchUpd;
} FSPI_UPD_COMMON;

///
/// Enumeration of FSP_INIT_PHASE for NOTIFY_PHASE.
///
typedef enum {
  ///
  /// This stage is notified when the bootloader completes the
  /// PCI enumeration and the resource allocation for the
  /// PCI devices is complete.
  ///
  EnumInitPhaseAfterPciEnumeration = 0x20,
  ///
  /// This stage is notified just before the bootloader hand-off
  /// to the OS loader.
  ///
  EnumInitPhaseReadyToBoot = 0x40,
  ///
  /// This stage is notified just before the firmware/Preboot
  /// environment transfers management of all system resources
  /// to the OS or next level execution environment.
  ///
  EnumInitPhaseEndOfFirmware = 0xF0
} FSP_INIT_PHASE;

///
/// Definition of NOTIFY_PHASE_PARAMS.
///
typedef struct {
  ///
  /// Notification phase used for NotifyPhase API
  ///
  FSP_INIT_PHASE    Phase;
} NOTIFY_PHASE_PARAMS;

///
/// Action definition for FspMultiPhaseSiInit API
///
typedef enum {
  EnumMultiPhaseGetNumberOfPhases       = 0x0,
  EnumMultiPhaseExecutePhase            = 0x1,
  EnumMultiPhaseGetVariableRequestInfo  = 0x2,
  EnumMultiPhaseCompleteVariableRequest = 0x3
} FSP_MULTI_PHASE_ACTION;

typedef enum {
  EnumFspVariableRequestGetVariable         = 0x0,
  EnumFspVariableRequestGetNextVariableName = 0x1,
  EnumFspVariableRequestSetVariable         = 0x2,
  EnumFspVariableRequestQueryVariableInfo   = 0x3
} FSP_VARIABLE_REQUEST_TYPE;

#pragma pack(16)
typedef struct {
  IN     FSP_VARIABLE_REQUEST_TYPE    VariableRequest;
  IN OUT CHAR16                       *VariableName;
  IN OUT UINT64                       *VariableNameSize;
  IN OUT EFI_GUID                     *VariableGuid;
  IN OUT UINT32                       *Attributes;
  IN OUT UINT64                       *DataSize;
  IN OUT VOID                         *Data;
  OUT    UINT64                       *MaximumVariableStorageSize;
  OUT    UINT64                       *RemainingVariableStorageSize;
  OUT    UINT64                       *MaximumVariableSize;
} FSP_MULTI_PHASE_VARIABLE_REQUEST_INFO_PARAMS;

typedef struct {
  EFI_STATUS    VariableRequestStatus;
} FSP_MULTI_PHASE_COMPLETE_VARIABLE_REQUEST_PARAMS;
#pragma pack()

///
/// Data structure returned by FSP when bootloader calling
/// FspMultiPhaseSiInit API with action 0 (EnumMultiPhaseGetNumberOfPhases)
///
typedef struct {
  UINT32    NumberOfPhases;
  UINT32    PhasesExecuted;
} FSP_MULTI_PHASE_GET_NUMBER_OF_PHASES_PARAMS;

///
/// FspMultiPhaseSiInit function parameter.
///
/// For action 0 (EnumMultiPhaseGetNumberOfPhases):
///   - PhaseIndex must be 0.
///   - MultiPhaseParamPtr should point to an instance of FSP_MULTI_PHASE_GET_NUMBER_OF_PHASES_PARAMS.
///
/// For action 1 (EnumMultiPhaseExecutePhase):
///   - PhaseIndex will be the phase that will be executed by FSP.
///   - MultiPhaseParamPtr shall be NULL.
///
typedef struct {
  IN     FSP_MULTI_PHASE_ACTION    MultiPhaseAction;
  IN     UINT32                    PhaseIndex;
  IN OUT VOID                      *MultiPhaseParamPtr;
} FSP_MULTI_PHASE_PARAMS;

#pragma pack()

/**
  This FSP API is called soon after coming out of reset and before memory and stack is
  available. This FSP API will load the microcode update, enable code caching for the
  region specified by the boot loader and also setup a temporary stack to be used until
  main memory is initialized.

  A hardcoded stack can be set up with the following values, and the "esp" register
  initialized to point to this hardcoded stack.
  1. The return address where the FSP will return control after setting up a temporary
     stack.
  2. A pointer to the input parameter structure

  However, since the stack is in ROM and not writeable, this FSP API cannot be called
  using the "call" instruction, but needs to be jumped to.

  @param[in] FsptUpdDataPtr     Pointer to the FSPT_UPD data structure.

  @retval EFI_SUCCESS           Temporary RAM was initialized successfully.
  @retval EFI_INVALID_PARAMETER Input parameters are invalid.
  @retval EFI_UNSUPPORTED       The FSP calling conditions were not met.
  @retval EFI_DEVICE_ERROR      Temp RAM initialization failed.

  If this function is successful, the FSP initializes the ECX and EDX registers to point to
  a temporary but writeable memory range available to the boot loader and returns with
  FSP_SUCCESS in register EAX. Register ECX points to the start of this temporary
  memory range and EDX points to the end of the range. Boot loader is free to use the
  whole range described. Typically the boot loader can reload the ESP register to point
  to the end of this returned range so that it can be used as a standard stack.
**/
typedef
EFI_STATUS
(EFIAPI *FSP_TEMP_RAM_INIT)(
  IN  VOID    *FsptUpdDataPtr
  );

/**
  This FSP API is used to notify the FSP about the different phases in the boot process.
  This allows the FSP to take appropriate actions as needed during different initialization
  phases. The phases will be platform dependent and will be documented with the FSP
  release. The current FSP supports two notify phases:
    Post PCI enumeration
    Ready To Boot

  @param[in] NotifyPhaseParamPtr Address pointer to the NOTIFY_PHASE_PRAMS

  @retval EFI_SUCCESS           The notification was handled successfully.
  @retval EFI_UNSUPPORTED       The notification was not called in the proper order.
  @retval EFI_INVALID_PARAMETER The notification code is invalid.
**/
typedef
EFI_STATUS
(EFIAPI *FSP_NOTIFY_PHASE)(
  IN NOTIFY_PHASE_PARAMS *NotifyPhaseParamPtr
  );

/**
  This FSP API is called after TempRamInit and initializes the memory.
  This FSP API accepts a pointer to a data structure that will be platform dependent
  and defined for each FSP binary. This will be documented in Integration guide with
  each FSP release.
  After FspMemInit completes its execution, it passes the pointer to the HobList and
  returns to the boot loader from where it was called. BootLoader is responsible to
  migrate its stack and data to Memory.
  FspMemoryInit, TempRamExit and FspSiliconInit APIs provide an alternate method to
  complete the silicon initialization and provides bootloader an opportunity to get
  control after system memory is available and before the temporary RAM is torn down.

  @param[in]  FspmUpdDataPtr          Pointer to the FSPM_UPD data structure.
  @param[out] HobListPtr              Pointer to receive the address of the HOB list.

  @retval EFI_SUCCESS                 FSP execution environment was initialized successfully.
  @retval EFI_INVALID_PARAMETER       Input parameters are invalid.
  @retval EFI_UNSUPPORTED             The FSP calling conditions were not met.
  @retval EFI_DEVICE_ERROR            FSP initialization failed.
  @retval EFI_OUT_OF_RESOURCES        Stack range requested by FSP is not met.
  @retval FSP_STATUS_RESET_REQUIREDx  A reset is required. These status codes will not be returned during S3.
**/
typedef
EFI_STATUS
(EFIAPI *FSP_MEMORY_INIT)(
  IN  VOID    *FspmUpdDataPtr,
  OUT VOID    **HobListPtr
  );

/**
  This FSP API is called after FspMemoryInit API. This FSP API tears down the temporary
  memory setup by TempRamInit API. This FSP API accepts a pointer to a data structure
  that will be platform dependent and defined for each FSP binary. This will be
  documented in Integration Guide.
  FspMemoryInit, TempRamExit and FspSiliconInit APIs provide an alternate method to
  complete the silicon initialization and provides bootloader an opportunity to get
  control after system memory is available and before the temporary RAM is torn down.

  @param[in] TempRamExitParamPtr Pointer to the Temp Ram Exit parameters structure.
                                 This structure is normally defined in the Integration Guide.
                                 And if it is not defined in the Integration Guide, pass NULL.

  @retval EFI_SUCCESS            FSP execution environment was initialized successfully.
  @retval EFI_INVALID_PARAMETER  Input parameters are invalid.
  @retval EFI_UNSUPPORTED        The FSP calling conditions were not met.
  @retval EFI_DEVICE_ERROR       FSP initialization failed.
**/
typedef
EFI_STATUS
(EFIAPI *FSP_TEMP_RAM_EXIT)(
  IN  VOID    *TempRamExitParamPtr
  );

/**
  This FSP API is called after TempRamExit API.
  FspMemoryInit, TempRamExit and FspSiliconInit APIs provide an alternate method to complete the
  silicon initialization.

  @param[in] FspsUpdDataPtr     Pointer to the FSPS_UPD data structure.
                                If NULL, FSP will use the default parameters.

  @retval EFI_SUCCESS                 FSP execution environment was initialized successfully.
  @retval EFI_INVALID_PARAMETER       Input parameters are invalid.
  @retval EFI_UNSUPPORTED             The FSP calling conditions were not met.
  @retval EFI_DEVICE_ERROR            FSP initialization failed.
  @retval FSP_STATUS_RESET_REQUIREDx  A reset is required. These status codes will not be returned during S3.
**/
typedef
EFI_STATUS
(EFIAPI *FSP_SILICON_INIT)(
  IN  VOID    *FspsUpdDataPtr
  );

/**
  This FSP API is expected to be called after FspSiliconInit but before FspNotifyPhase.
  This FSP API provides multi-phase silicon initialization; which brings greater modularity
  beyond the existing FspSiliconInit() API. Increased modularity is achieved by adding an
  extra API to FSP-S. This allows the bootloader to add board specific initialization steps
  throughout the SiliconInit flow as needed.

  @param[in,out] FSP_MULTI_PHASE_PARAMS   For action - EnumMultiPhaseGetNumberOfPhases:
                                            FSP_MULTI_PHASE_PARAMS->MultiPhaseParamPtr will contain
                                            how many phases supported by FSP.
                                          For action - EnumMultiPhaseExecutePhase:
                                            FSP_MULTI_PHASE_PARAMS->MultiPhaseParamPtr shall be NULL.
  @retval EFI_SUCCESS                     FSP execution environment was initialized successfully.
  @retval EFI_INVALID_PARAMETER           Input parameters are invalid.
  @retval EFI_UNSUPPORTED                 The FSP calling conditions were not met.
  @retval EFI_DEVICE_ERROR                FSP initialization failed.
  @retval FSP_STATUS_RESET_REQUIREDx      A reset is required. These status codes will not be returned during S3.
**/
typedef
EFI_STATUS
(EFIAPI *FSP_MULTI_PHASE_SI_INIT)(
  IN FSP_MULTI_PHASE_PARAMS     *MultiPhaseSiInitParamPtr
  );

/**
  This FSP API initializes SMM and provide any OS runtime silicon services,
  including Reliability, Availability, and Serviceability (RAS) features implemented by the CPU.

  @param[in] FspiUpdDataPtr     Pointer to the FSPI_UPD data structure.
                                If NULL, FSP will use the default parameters.

  @retval EFI_SUCCESS                 FSP execution environment was initialized successfully.
  @retval EFI_INVALID_PARAMETER       Input parameters are invalid.
  @retval EFI_UNSUPPORTED             The FSP calling conditions were not met.
  @retval EFI_DEVICE_ERROR            FSP initialization failed.
  @retval FSP_STATUS_RESET_REQUIREDx  A reset is required. These status codes will not be returned during S3.
**/
typedef
EFI_STATUS
(EFIAPI *FSP_SMM_INIT)(
  IN VOID          *FspiUpdDataPtr
  );

/**
  This FSP API provides multi-phase memory and silicon initialization, which brings greater modularity to the existing
  FspMemoryInit() and FspSiliconInit() API. Increased modularity is achieved by adding an extra API to FSP-M and FSP-S.
  This allows the bootloader to add board specific initialization steps throughout the MemoryInit and SiliconInit flows as needed.
  The FspMemoryInit() API is always called before FspMultiPhaseMemInit(); it is the first phase of memory initialization. Similarly,
  the FspSiliconInit() API is always called before FspMultiPhaseSiInit(); it is the first phase of silicon initialization.
  After the first phase, subsequent phases are invoked by calling the FspMultiPhaseMem/SiInit() API.
  The FspMultiPhaseMemInit() API may only be called after the FspMemoryInit() API and before the FspSiliconInit() API;
  or in the case that FSP-T is being used, before the TempRamExit() API. The FspMultiPhaseSiInit() API may only be called after
  the FspSiliconInit() API and before NotifyPhase() API; or in the case that FSP-I is being used, before the FspSmmInit() API.
  The multi-phase APIs may not be called at any other time.

  @param[in,out] FSP_MULTI_PHASE_PARAMS   For action - EnumMultiPhaseGetNumberOfPhases:
                                            FSP_MULTI_PHASE_PARAMS->MultiPhaseParamPtr will contain
                                            how many phases supported by FSP.
                                          For action - EnumMultiPhaseExecutePhase:
                                            FSP_MULTI_PHASE_PARAMS->MultiPhaseParamPtr shall be NULL.
  @retval EFI_SUCCESS                     FSP execution environment was initialized successfully.
  @retval EFI_INVALID_PARAMETER           Input parameters are invalid.
  @retval EFI_UNSUPPORTED                 The FSP calling conditions were not met.
  @retval EFI_DEVICE_ERROR                FSP initialization failed.
  @retval FSP_STATUS_RESET_REQUIRED_*     A reset is required. These status codes will not be returned during S3.
  @retval FSP_STATUS_VARIABLE_REQUEST     A variable request has been made by FSP that needs boot loader handling.
**/
typedef
EFI_STATUS
(EFIAPI *FSP_MULTI_PHASE_INIT)(
  IN FSP_MULTI_PHASE_PARAMS     *MultiPhaseInitParamPtr
  );

#endif
