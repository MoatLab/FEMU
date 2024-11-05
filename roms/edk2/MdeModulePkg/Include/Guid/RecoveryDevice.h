/** @file
  Defines Name GUIDs to represent a Recovery Capsule loaded from a recovery device.

  These are contracts between the recovery module and device recovery module
  that convey the name of a given recovery module type.

Copyright (c) 2006 - 2018, Intel Corporation. All rights reserved.<BR>

SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#ifndef _RECOVERY_DEVICE_H_
#define _RECOVERY_DEVICE_H_

///
/// The Global ID used to identify a recovery capsule that was loaded from a CD/DVD device.
///
#define RECOVERY_ON_DATA_CD_GUID \
  { \
    0x5cac0099, 0x0dc9, 0x48e5, {0x80, 0x68, 0xbb, 0x95, 0xf5, 0x40, 0x0a, 0x9f } \
  }

///
/// The Global ID used to identify a recovery capsule that was loaded from floppy device.
///
#define RECOVERY_ON_FAT_FLOPPY_DISK_GUID \
  { \
    0x2e3d2e75, 0x9b2e, 0x412d, {0xb4, 0xb1, 0x70, 0x41, 0x6b, 0x87, 0x0, 0xff } \
  }

///
/// The Global ID used to identify a recovery capsule that was loaded from IDE hard drive.
///
#define RECOVERY_ON_FAT_IDE_DISK_GUID \
  { \
    0xb38573b6, 0x6200, 0x4ac5, {0xb5, 0x1d, 0x82, 0xe6, 0x59, 0x38, 0xd7, 0x83 } \
  }

///
/// The Global ID used to identify a recovery capsule that was loaded from USB BOT device.
///
#define RECOVERY_ON_FAT_USB_DISK_GUID \
  { \
    0x0ffbce19, 0x324c, 0x4690, {0xa0, 0x09, 0x98, 0xc6, 0xae, 0x2e, 0xb1, 0x86 } \
  }

///
/// The Global ID used to identify a recovery capsule that was loaded from NVM Express device.
///
#define RECOVERY_ON_FAT_NVME_DISK_GUID \
  { \
    0xc770a27f, 0x956a, 0x497a, {0x85, 0x48, 0xe0, 0x61, 0x97, 0x58, 0x8b, 0xf6 } \
  }

extern EFI_GUID  gRecoveryOnDataCdGuid;
extern EFI_GUID  gRecoveryOnFatFloppyDiskGuid;
extern EFI_GUID  gRecoveryOnFatIdeDiskGuid;
extern EFI_GUID  gRecoveryOnFatUsbDiskGuid;
extern EFI_GUID  gRecoveryOnFatNvmeDiskGuid;

#endif
