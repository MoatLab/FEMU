/** @file
  Protocol to describe overrides required to support non-standard SDHCI
  implementations

  Copyright (c) 2017 - 2018, Linaro, Ltd. All rights reserved.<BR>

  SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#ifndef __SD_MMC_OVERRIDE_H__
#define __SD_MMC_OVERRIDE_H__

#include <Protocol/SdMmcPassThru.h>

#define EDKII_SD_MMC_OVERRIDE_PROTOCOL_GUID \
  { 0xeaf9e3c1, 0xc9cd, 0x46db, { 0xa5, 0xe5, 0x5a, 0x12, 0x4c, 0x83, 0x23, 0x23 } }

#define EDKII_SD_MMC_OVERRIDE_PROTOCOL_VERSION  0x3

typedef struct _EDKII_SD_MMC_OVERRIDE EDKII_SD_MMC_OVERRIDE;

#define EDKII_SD_MMC_BUS_WIDTH_IGNORE        MAX_UINT8
#define EDKII_SD_MMC_CLOCK_FREQ_IGNORE       MAX_UINT32
#define EDKII_SD_MMC_DRIVER_STRENGTH_IGNORE  MAX_UINT8

typedef enum {
  SdDriverStrengthTypeB = 0,
  SdDriverStrengthTypeA,
  SdDriverStrengthTypeC,
  SdDriverStrengthTypeD,
  SdDriverStrengthIgnore = EDKII_SD_MMC_DRIVER_STRENGTH_IGNORE
} SD_DRIVER_STRENGTH_TYPE;

typedef enum {
  EmmcDriverStrengthType0 = 0,
  EmmcDriverStrengthType1,
  EmmcDriverStrengthType2,
  EmmcDriverStrengthType3,
  EmmcDriverStrengthType4,
  EmmcDriverStrengthIgnore = EDKII_SD_MMC_DRIVER_STRENGTH_IGNORE
} EMMC_DRIVER_STRENGTH_TYPE;

typedef union {
  SD_DRIVER_STRENGTH_TYPE      Sd;
  EMMC_DRIVER_STRENGTH_TYPE    Emmc;
} EDKII_SD_MMC_DRIVER_STRENGTH;

typedef struct {
  //
  // The target width of the bus. If user tells driver to ignore it
  // or specifies unsupported width driver will choose highest supported
  // bus width for a given mode.
  //
  UINT8                           BusWidth;
  //
  // The target clock frequency of the bus in MHz. If user tells driver to ignore
  // it or specifies unsupported frequency driver will choose highest supported
  // clock frequency for a given mode.
  //
  UINT32                          ClockFreq;
  //
  // The target driver strength of the bus. If user tells driver to
  // ignore it or specifies unsupported driver strength, driver will
  // default to Type0 for eMMC cards and TypeB for SD cards. Driver strength
  // setting is only considered if chosen bus timing supports them.
  //
  EDKII_SD_MMC_DRIVER_STRENGTH    DriverStrength;
} EDKII_SD_MMC_OPERATING_PARAMETERS;

typedef enum {
  SdMmcSdDs,
  SdMmcSdHs,
  SdMmcUhsSdr12,
  SdMmcUhsSdr25,
  SdMmcUhsSdr50,
  SdMmcUhsDdr50,
  SdMmcUhsSdr104,
  SdMmcMmcLegacy,
  SdMmcMmcHsSdr,
  SdMmcMmcHsDdr,
  SdMmcMmcHs200,
  SdMmcMmcHs400,
} SD_MMC_BUS_MODE;

typedef enum {
  EdkiiSdMmcResetPre,
  EdkiiSdMmcResetPost,
  EdkiiSdMmcInitHostPre,
  EdkiiSdMmcInitHostPost,
  EdkiiSdMmcUhsSignaling,
  EdkiiSdMmcSwitchClockFreqPost,
  EdkiiSdMmcGetOperatingParam
} EDKII_SD_MMC_PHASE_TYPE;

/**
  Override function for SDHCI capability bits

  @param[in]      ControllerHandle      The EFI_HANDLE of the controller.
  @param[in]      Slot                  The 0 based slot index.
  @param[in,out]  SdMmcHcSlotCapability The SDHCI capability structure.
  @param[in,out]  BaseClkFreq           The base clock frequency value that
                                        optionally can be updated.

  @retval EFI_SUCCESS           The override function completed successfully.
  @retval EFI_NOT_FOUND         The specified controller or slot does not exist.
  @retval EFI_INVALID_PARAMETER SdMmcHcSlotCapability is NULL

**/
typedef
EFI_STATUS
(EFIAPI *EDKII_SD_MMC_CAPABILITY)(
  IN      EFI_HANDLE                      ControllerHandle,
  IN      UINT8                           Slot,
  IN OUT  VOID                            *SdMmcHcSlotCapability,
  IN OUT  UINT32                          *BaseClkFreq
  );

/**
  Override function for SDHCI controller operations

  @param[in]      ControllerHandle      The EFI_HANDLE of the controller.
  @param[in]      Slot                  The 0 based slot index.
  @param[in]      PhaseType             The type of operation and whether the
                                        hook is invoked right before (pre) or
                                        right after (post)
  @param[in,out]  PhaseData             The pointer to a phase-specific data.

  @retval EFI_SUCCESS           The override function completed successfully.
  @retval EFI_NOT_FOUND         The specified controller or slot does not exist.
  @retval EFI_INVALID_PARAMETER PhaseType is invalid

**/
typedef
EFI_STATUS
(EFIAPI *EDKII_SD_MMC_NOTIFY_PHASE)(
  IN      EFI_HANDLE                      ControllerHandle,
  IN      UINT8                           Slot,
  IN      EDKII_SD_MMC_PHASE_TYPE         PhaseType,
  IN OUT  VOID                           *PhaseData
  );

struct _EDKII_SD_MMC_OVERRIDE {
  //
  // Protocol version of this implementation
  //
  UINTN                        Version;
  //
  // Callback to override SD/MMC host controller capability bits
  //
  EDKII_SD_MMC_CAPABILITY      Capability;
  //
  // Callback to invoke SD/MMC override hooks
  //
  EDKII_SD_MMC_NOTIFY_PHASE    NotifyPhase;
};

extern EFI_GUID  gEdkiiSdMmcOverrideProtocolGuid;

#endif
