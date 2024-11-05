/** @file
  Define APIs to retrieve USB Host Controller Info such as controller type and
  I/O Port Base Address.

Copyright (c) 2006 - 2018, Intel Corporation. All rights reserved.<BR>

SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#ifndef _PEI_USB_CONTROLLER_PPI_H_
#define _PEI_USB_CONTROLLER_PPI_H_

///
/// Global ID for the PEI_USB_CONTROLLER_PPI.
///
#define PEI_USB_CONTROLLER_PPI_GUID \
  { \
    0x3bc1f6de, 0x693e, 0x4547,{ 0xa3, 0x0, 0x21, 0x82, 0x3c, 0xa4, 0x20, 0xb2} \
  }

///
/// Forward declaration for the PEI_USB_CONTROLLER_PPI.
///
typedef struct _PEI_USB_CONTROLLER_PPI PEI_USB_CONTROLLER_PPI;

///
/// This bit is used in the ControllerType return parameter of GetUsbController()
/// to identify the USB Host Controller type as UHCI
///
#define PEI_UHCI_CONTROLLER  0x01

///
/// This bit is used in the ControllerType return parameter of GetUsbController()
/// to identify the USB Host Controller type as OHCI
///
#define PEI_OHCI_CONTROLLER  0x02

///
/// This bit is used in the ControllerType return parameter of GetUsbController()
/// to identify the USB Host Controller type as EHCI
///
#define PEI_EHCI_CONTROLLER  0x03

///
/// This bit is used in the ControllerType return parameter of GetUsbController()
/// to identify the USB Host Controller type as XHCI
///
#define PEI_XHCI_CONTROLLER  0x04

/**
  Retrieve USB Host Controller Info such as controller type and I/O Base Address.

  @param[in]  PeiServices      The pointer to the PEI Services Table.
  @param[in]  This             The pointer to this instance of the PEI_USB_CONTROLLER_PPI.
  @param[in]  ControllerId     The ID of the USB controller.
  @param[out] ControllerType   On output, returns the type of the USB controller.
  @param[out] BaseAddress      On output, returns the base address of UHCI's I/O ports
                               if UHCI is enabled or the base address of EHCI's MMIO
                               if EHCI is enabled.

  @retval EFI_SUCCESS             USB controller attributes were returned successfully.
  @retval EFI_INVALID_PARAMETER   ControllerId is greater than the maximum number
                                  of USB controller supported by this platform.

**/
typedef
EFI_STATUS
(EFIAPI *PEI_GET_USB_CONTROLLER)(
  IN  EFI_PEI_SERVICES        **PeiServices,
  IN  PEI_USB_CONTROLLER_PPI  *This,
  IN  UINT8                   UsbControllerId,
  OUT UINTN                   *ControllerType,
  OUT UINTN                   *BaseAddress
  );

///
/// This PPI contains a single service to retrieve the USB Host Controller type
/// and the base address of the I/O ports used to access the USB Host Controller.
///
struct _PEI_USB_CONTROLLER_PPI {
  PEI_GET_USB_CONTROLLER    GetUsbController;
};

extern EFI_GUID  gPeiUsbControllerPpiGuid;

#endif
