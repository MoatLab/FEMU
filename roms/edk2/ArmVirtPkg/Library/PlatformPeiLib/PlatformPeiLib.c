/** @file
*
*  Copyright (c) 2011-2014, ARM Limited. All rights reserved.
*  Copyright (c) 2014-2020, Linaro Limited. All rights reserved.
*
*  SPDX-License-Identifier: BSD-2-Clause-Patent
*
**/

#include <PiPei.h>

#include <Library/MemoryAllocationLib.h>
#include <Library/DebugLib.h>
#include <Library/HobLib.h>
#include <Library/PcdLib.h>
#include <Library/PeiServicesLib.h>
#include <libfdt.h>

#include <Guid/EarlyPL011BaseAddress.h>
#include <Guid/FdtHob.h>

STATIC CONST EFI_PEI_PPI_DESCRIPTOR  mTpm2DiscoveredPpi = {
  EFI_PEI_PPI_DESCRIPTOR_PPI | EFI_PEI_PPI_DESCRIPTOR_TERMINATE_LIST,
  &gOvmfTpmDiscoveredPpiGuid,
  NULL
};

STATIC CONST EFI_PEI_PPI_DESCRIPTOR  mTpm2InitializationDonePpi = {
  EFI_PEI_PPI_DESCRIPTOR_PPI | EFI_PEI_PPI_DESCRIPTOR_TERMINATE_LIST,
  &gPeiTpmInitializationDonePpiGuid,
  NULL
};

EFI_STATUS
EFIAPI
PlatformPeim (
  VOID
  )
{
  VOID          *Base;
  VOID          *NewBase;
  UINTN         FdtSize;
  UINTN         FdtPages;
  UINT64        *FdtHobData;
  UINT64        *UartHobData;
  INT32         Node, Prev;
  INT32         Parent, Depth;
  CONST CHAR8   *Compatible;
  CONST CHAR8   *CompItem;
  CONST CHAR8   *NodeStatus;
  INT32         Len;
  INT32         RangesLen;
  INT32         StatusLen;
  CONST UINT64  *RegProp;
  CONST UINT32  *RangesProp;
  UINT64        UartBase;
  UINT64        TpmBase;
  EFI_STATUS    Status;

  Base = (VOID *)(UINTN)PcdGet64 (PcdDeviceTreeInitialBaseAddress);
  ASSERT (Base != NULL);
  ASSERT (fdt_check_header (Base) == 0);

  FdtSize  = fdt_totalsize (Base) + PcdGet32 (PcdDeviceTreeAllocationPadding);
  FdtPages = EFI_SIZE_TO_PAGES (FdtSize);
  NewBase  = AllocatePages (FdtPages);
  ASSERT (NewBase != NULL);
  fdt_open_into (Base, NewBase, EFI_PAGES_TO_SIZE (FdtPages));

  FdtHobData = BuildGuidHob (&gFdtHobGuid, sizeof *FdtHobData);
  ASSERT (FdtHobData != NULL);
  *FdtHobData = (UINTN)NewBase;

  UartHobData = BuildGuidHob (&gEarlyPL011BaseAddressGuid, sizeof *UartHobData);
  ASSERT (UartHobData != NULL);
  *UartHobData = 0;

  TpmBase = 0;

  //
  // Set Parent to suppress incorrect compiler/analyzer warnings.
  //
  Parent = 0;

  for (Prev = Depth = 0; ; Prev = Node) {
    Node = fdt_next_node (Base, Prev, &Depth);
    if (Node < 0) {
      break;
    }

    if (Depth == 1) {
      Parent = Node;
    }

    Compatible = fdt_getprop (Base, Node, "compatible", &Len);

    //
    // Iterate over the NULL-separated items in the compatible string
    //
    for (CompItem = Compatible; CompItem != NULL && CompItem < Compatible + Len;
         CompItem += 1 + AsciiStrLen (CompItem))
    {
      if (AsciiStrCmp (CompItem, "arm,pl011") == 0) {
        NodeStatus = fdt_getprop (Base, Node, "status", &StatusLen);
        if ((NodeStatus != NULL) && (AsciiStrCmp (NodeStatus, "okay") != 0)) {
          continue;
        }

        RegProp = fdt_getprop (Base, Node, "reg", &Len);
        ASSERT (Len == 16);

        UartBase = fdt64_to_cpu (ReadUnaligned64 (RegProp));

        DEBUG ((DEBUG_INFO, "%a: PL011 UART @ 0x%lx\n", __FUNCTION__, UartBase));

        *UartHobData = UartBase;
        break;
      } else if (FeaturePcdGet (PcdTpm2SupportEnabled) &&
                 (AsciiStrCmp (CompItem, "tcg,tpm-tis-mmio") == 0))
      {
        RegProp = fdt_getprop (Base, Node, "reg", &Len);
        ASSERT (Len == 8 || Len == 16);
        if (Len == 8) {
          TpmBase = fdt32_to_cpu (RegProp[0]);
        } else if (Len == 16) {
          TpmBase = fdt64_to_cpu (ReadUnaligned64 ((UINT64 *)RegProp));
        }

        if (Depth > 1) {
          //
          // QEMU/mach-virt may put the TPM on the platform bus, in which case
          // we have to take its 'ranges' property into account to translate the
          // MMIO address. This consists of a <child base, parent base, size>
          // tuple, where the child base and the size use the same number of
          // cells as the 'reg' property above, and the parent base uses 2 cells
          //
          RangesProp = fdt_getprop (Base, Parent, "ranges", &RangesLen);
          ASSERT (RangesProp != NULL);

          //
          // a plain 'ranges' attribute without a value implies a 1:1 mapping
          //
          if (RangesLen != 0) {
            //
            // assume a single translated range with 2 cells for the parent base
            //
            if (RangesLen != Len + 2 * sizeof (UINT32)) {
              DEBUG ((
                DEBUG_WARN,
                "%a: 'ranges' property has unexpected size %d\n",
                __FUNCTION__,
                RangesLen
                ));
              break;
            }

            if (Len == 8) {
              TpmBase -= fdt32_to_cpu (RangesProp[0]);
            } else {
              TpmBase -= fdt64_to_cpu (ReadUnaligned64 ((UINT64 *)RangesProp));
            }

            //
            // advance RangesProp to the parent bus address
            //
            RangesProp = (UINT32 *)((UINT8 *)RangesProp + Len / 2);
            TpmBase   += fdt64_to_cpu (ReadUnaligned64 ((UINT64 *)RangesProp));
          }
        }

        break;
      }
    }
  }

  if (FeaturePcdGet (PcdTpm2SupportEnabled)) {
    if (TpmBase != 0) {
      DEBUG ((DEBUG_INFO, "%a: TPM @ 0x%lx\n", __FUNCTION__, TpmBase));

      Status = (EFI_STATUS)PcdSet64S (PcdTpmBaseAddress, TpmBase);
      ASSERT_EFI_ERROR (Status);

      Status = PeiServicesInstallPpi (&mTpm2DiscoveredPpi);
    } else {
      Status = PeiServicesInstallPpi (&mTpm2InitializationDonePpi);
    }

    ASSERT_EFI_ERROR (Status);
  }

  BuildFvHob (PcdGet64 (PcdFvBaseAddress), PcdGet32 (PcdFvSize));

  return EFI_SUCCESS;
}
