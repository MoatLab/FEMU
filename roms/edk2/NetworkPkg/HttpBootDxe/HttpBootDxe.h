/** @file
  UEFI HTTP boot driver's private data structure and interfaces declaration.

Copyright (c) 2015 - 2018, Intel Corporation. All rights reserved.<BR>
(C) Copyright 2016 - 2020 Hewlett Packard Enterprise Development LP<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#ifndef __EFI_HTTP_BOOT_DXE_H__
#define __EFI_HTTP_BOOT_DXE_H__

#include <Uefi.h>

#include <IndustryStandard/Http11.h>
#include <IndustryStandard/Dhcp.h>

//
// Libraries
//
#include <Library/UefiBootServicesTableLib.h>
#include <Library/UefiHiiServicesLib.h>
#include <Library/UefiRuntimeServicesTableLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/BaseLib.h>
#include <Library/UefiLib.h>
#include <Library/DevicePathLib.h>
#include <Library/DebugLib.h>
#include <Library/NetLib.h>
#include <Library/HttpLib.h>
#include <Library/HttpIoLib.h>
#include <Library/HiiLib.h>
#include <Library/PrintLib.h>
#include <Library/DpcLib.h>

//
// UEFI Driver Model Protocols
//
#include <Protocol/DriverBinding.h>
#include <Protocol/ComponentName2.h>
#include <Protocol/ComponentName.h>

//
// Consumed Protocols
//
#include <Protocol/ServiceBinding.h>
#include <Protocol/HiiConfigAccess.h>
#include <Protocol/NetworkInterfaceIdentifier.h>
#include <Protocol/Dhcp4.h>
#include <Protocol/Dhcp6.h>
#include <Protocol/Dns6.h>
#include <Protocol/Http.h>
#include <Protocol/Ip4Config2.h>
#include <Protocol/Ip6Config.h>
#include <Protocol/RamDisk.h>
#include <Protocol/AdapterInformation.h>

//
// Produced Protocols
//
#include <Protocol/LoadFile.h>
#include <Protocol/HttpBootCallback.h>

//
// Consumed Guids
//
#include <Guid/HttpBootConfigHii.h>

//
// Driver Version
//
#define HTTP_BOOT_DXE_VERSION  0xa

//
// Standard Media Types defined in
// http://www.iana.org/assignments/media-types
//
#define HTTP_CONTENT_TYPE_APP_EFI  "application/efi"
#define HTTP_CONTENT_TYPE_APP_IMG  "application/vnd.efi-img"
#define HTTP_CONTENT_TYPE_APP_ISO  "application/vnd.efi-iso"

//
// Protocol instances
//
extern EFI_DRIVER_BINDING_PROTOCOL   gHttpBootDxeDriverBinding;
extern EFI_COMPONENT_NAME2_PROTOCOL  gHttpBootDxeComponentName2;
extern EFI_COMPONENT_NAME_PROTOCOL   gHttpBootDxeComponentName;

//
// Private data structure
//
typedef struct _HTTP_BOOT_PRIVATE_DATA  HTTP_BOOT_PRIVATE_DATA;
typedef struct _HTTP_BOOT_VIRTUAL_NIC   HTTP_BOOT_VIRTUAL_NIC;

typedef enum  {
  ImageTypeEfi,
  ImageTypeVirtualCd,
  ImageTypeVirtualDisk,
  ImageTypeMax
} HTTP_BOOT_IMAGE_TYPE;

//
// Include files with internal function prototypes
//
#include "HttpBootComponentName.h"
#include "HttpBootDhcp4.h"
#include "HttpBootDhcp6.h"
#include "HttpBootImpl.h"
#include "HttpBootSupport.h"
#include "HttpBootClient.h"
#include "HttpBootConfig.h"

typedef union {
  HTTP_BOOT_DHCP4_PACKET_CACHE    Dhcp4;
  HTTP_BOOT_DHCP6_PACKET_CACHE    Dhcp6;
} HTTP_BOOT_DHCP_PACKET_CACHE;

struct _HTTP_BOOT_VIRTUAL_NIC {
  UINT32                      Signature;
  EFI_HANDLE                  Controller;
  EFI_HANDLE                  ImageHandle;
  EFI_LOAD_FILE_PROTOCOL      LoadFile;
  EFI_DEVICE_PATH_PROTOCOL    *DevicePath;
  HTTP_BOOT_PRIVATE_DATA      *Private;
};

#define HTTP_BOOT_PRIVATE_DATA_FROM_CALLBACK_INFO(Callback) \
  CR ( \
  Callback, \
  HTTP_BOOT_PRIVATE_DATA, \
  CallbackInfo, \
  HTTP_BOOT_PRIVATE_DATA_SIGNATURE \
  )

#define HTTP_BOOT_PRIVATE_DATA_FROM_CALLBACK_PROTOCOL(CallbackProtocol) \
    CR ( \
    CallbackProtocol, \
    HTTP_BOOT_PRIVATE_DATA, \
    LoadFileCallback, \
    HTTP_BOOT_PRIVATE_DATA_SIGNATURE \
    )

struct _HTTP_BOOT_PRIVATE_DATA {
  UINT32                                       Signature;
  EFI_HANDLE                                   Controller;

  HTTP_BOOT_VIRTUAL_NIC                        *Ip4Nic;
  HTTP_BOOT_VIRTUAL_NIC                        *Ip6Nic;

  //
  // Consumed children
  //
  EFI_HANDLE                                   Ip6Child;
  EFI_HANDLE                                   Dhcp4Child;
  EFI_HANDLE                                   Dhcp6Child;
  HTTP_IO                                      HttpIo;
  BOOLEAN                                      HttpCreated;

  //
  // Consumed protocol
  //
  EFI_NETWORK_INTERFACE_IDENTIFIER_PROTOCOL    *Nii;
  EFI_IP6_PROTOCOL                             *Ip6;
  EFI_IP4_CONFIG2_PROTOCOL                     *Ip4Config2;
  EFI_IP6_CONFIG_PROTOCOL                      *Ip6Config;
  EFI_DHCP4_PROTOCOL                           *Dhcp4;
  EFI_DHCP6_PROTOCOL                           *Dhcp6;
  EFI_DEVICE_PATH_PROTOCOL                     *ParentDevicePath;

  //
  // Produced protocol
  //
  EFI_LOAD_FILE_PROTOCOL                       LoadFile;
  EFI_DEVICE_PATH_PROTOCOL                     *DevicePath;
  UINT32                                       Id;
  EFI_HTTP_BOOT_CALLBACK_PROTOCOL              *HttpBootCallback;
  EFI_HTTP_BOOT_CALLBACK_PROTOCOL              LoadFileCallback;

  //
  // Data for the default HTTP Boot callback protocol
  //
  UINT64                                       FileSize;
  UINT64                                       ReceivedSize;
  UINT32                                       Percentage;

  //
  // HII callback info block
  //
  HTTP_BOOT_FORM_CALLBACK_INFO                 CallbackInfo;

  //
  // Mode data
  //
  BOOLEAN                                      UsingIpv6;
  BOOLEAN                                      Started;
  EFI_IP_ADDRESS                               StationIp;
  EFI_IP_ADDRESS                               SubnetMask;
  EFI_IP_ADDRESS                               GatewayIp;
  EFI_IP_ADDRESS                               ServerIp;
  UINT16                                       Port;
  UINT32                                       DnsServerCount;
  EFI_IP_ADDRESS                               *DnsServerIp;

  //
  // The URI string attempt to download through HTTP, may point to
  // the memory in cached DHCP offer, or to the memory in FilePathUri.
  //
  CHAR8                                        *BootFileUri;
  VOID                                         *BootFileUriParser;
  UINTN                                        BootFileSize;
  BOOLEAN                                      NoGateway;
  HTTP_BOOT_IMAGE_TYPE                         ImageType;

  //
  // URI string extracted from the input FilePath parameter.
  //
  CHAR8                                        *FilePathUri;
  VOID                                         *FilePathUriParser;

  //
  // Cached HTTP data
  //
  LIST_ENTRY                                   CacheList;

  //
  // Cached DHCP offer
  //
  // OfferIndex records the index of DhcpOffer[] buffer, and OfferCount records the num of each type of offer.
  //
  // It supposed that
  //
  //   OfferNum:    8
  //   OfferBuffer: [ProxyNameUri, DhcpNameUri, DhcpIpUri, ProxyNameUri, ProxyIpUri, DhcpOnly, DhcpIpUri, DhcpNameUriDns]
  //   (OfferBuffer is 0-based.)
  //
  // And assume that (DhcpIpUri is the first priority actually.)
  //
  //   SelectIndex:     5
  //   SelectProxyType: HttpOfferTypeProxyIpUri
  //   (SelectIndex is 1-based, and 0 means no one is selected.)
  //
  // So it should be
  //
  //                 DhcpIpUri  DhcpNameUriDns  DhcpDns  DhcpOnly  ProxyNameUri  ProxyIpUri  DhcpNameUri
  //   OfferCount:  [       2,              1,       0,        1,            2,          1,            1]
  //
  //   OfferIndex: {[       2,              7,       0,        5,            0,         *4,            1]
  //                [       6,              0,       0,        0,            3,          0,            0]
  //                [       0,              0,       0,        0,            0,          0,            0]
  //                ...                                                                                 ]}
  //   (OfferIndex is 0-based.)
  //
  //
  UINT32                         SelectIndex;
  UINT32                         SelectProxyType;
  HTTP_BOOT_DHCP_PACKET_CACHE    OfferBuffer[HTTP_BOOT_OFFER_MAX_NUM];
  UINT32                         OfferNum;
  UINT32                         OfferCount[HttpOfferTypeMax];
  UINT32                         OfferIndex[HttpOfferTypeMax][HTTP_BOOT_OFFER_MAX_NUM];
};

#define HTTP_BOOT_PRIVATE_DATA_SIGNATURE  SIGNATURE_32 ('H', 'B', 'P', 'D')
#define HTTP_BOOT_VIRTUAL_NIC_SIGNATURE   SIGNATURE_32 ('H', 'B', 'V', 'N')
#define HTTP_BOOT_PRIVATE_DATA_FROM_LOADFILE(a)  CR (a, HTTP_BOOT_PRIVATE_DATA, LoadFile, HTTP_BOOT_PRIVATE_DATA_SIGNATURE)
#define HTTP_BOOT_PRIVATE_DATA_FROM_ID(a)        CR (a, HTTP_BOOT_PRIVATE_DATA, Id, HTTP_BOOT_PRIVATE_DATA_SIGNATURE)
#define HTTP_BOOT_VIRTUAL_NIC_FROM_LOADFILE(a)   CR (a, HTTP_BOOT_VIRTUAL_NIC, LoadFile, HTTP_BOOT_VIRTUAL_NIC_SIGNATURE)
extern EFI_LOAD_FILE_PROTOCOL  gHttpBootDxeLoadFile;

/**
  Tests to see if this driver supports a given controller. If a child device is provided,
  it further tests to see if this driver supports creating a handle for the specified child device.

  This function checks to see if the driver specified by This supports the device specified by
  ControllerHandle. Drivers will typically use the device path attached to
  ControllerHandle and/or the services from the bus I/O abstraction attached to
  ControllerHandle to determine if the driver supports ControllerHandle. This function
  may be called many times during platform initialization. In order to reduce boot times, the tests
  performed by this function must be very small, and take as little time as possible to execute. This
  function must not change the state of any hardware devices, and this function must be aware that the
  device specified by ControllerHandle may already be managed by the same driver or a
  different driver. This function must match its calls to AllocatePages() with FreePages(),
  AllocatePool() with FreePool(), and OpenProtocol() with CloseProtocol().
  Because ControllerHandle may have been previously started by the same driver, if a protocol is
  already in the opened state, then it must not be closed with CloseProtocol(). This is required
  to guarantee the state of ControllerHandle is not modified by this function.

  @param[in]  This                 A pointer to the EFI_DRIVER_BINDING_PROTOCOL instance.
  @param[in]  ControllerHandle     The handle of the controller to test. This handle
                                   must support a protocol interface that supplies
                                   an I/O abstraction to the driver.
  @param[in]  RemainingDevicePath  A pointer to the remaining portion of a device path.  This
                                   parameter is ignored by device drivers, and is optional for bus
                                   drivers. For bus drivers, if this parameter is not NULL, then
                                   the bus driver must determine if the bus controller specified
                                   by ControllerHandle and the child controller specified
                                   by RemainingDevicePath are both supported by this
                                   bus driver.

  @retval EFI_SUCCESS              The device specified by ControllerHandle and
                                   RemainingDevicePath is supported by the driver specified by This.
  @retval EFI_ALREADY_STARTED      The device specified by ControllerHandle and
                                   RemainingDevicePath is already being managed by the driver
                                   specified by This.
  @retval EFI_ACCESS_DENIED        The device specified by ControllerHandle and
                                   RemainingDevicePath is already being managed by a different
                                   driver or an application that requires exclusive access.
                                   Currently not implemented.
  @retval EFI_UNSUPPORTED          The device specified by ControllerHandle and
                                   RemainingDevicePath is not supported by the driver specified by This.
**/
EFI_STATUS
EFIAPI
HttpBootIp4DxeDriverBindingSupported (
  IN EFI_DRIVER_BINDING_PROTOCOL  *This,
  IN EFI_HANDLE                   ControllerHandle,
  IN EFI_DEVICE_PATH_PROTOCOL     *RemainingDevicePath OPTIONAL
  );

/**
  Starts a device controller or a bus controller.

  The Start() function is designed to be invoked from the EFI boot service ConnectController().
  As a result, much of the error checking on the parameters to Start() has been moved into this
  common boot service. It is legal to call Start() from other locations,
  but the following calling restrictions must be followed, or the system behavior will not be deterministic.
  1. ControllerHandle must be a valid EFI_HANDLE.
  2. If RemainingDevicePath is not NULL, then it must be a pointer to a naturally aligned
     EFI_DEVICE_PATH_PROTOCOL.
  3. Prior to calling Start(), the Supported() function for the driver specified by This must
     have been called with the same calling parameters, and Supported() must have returned EFI_SUCCESS.

  @param[in]  This                 A pointer to the EFI_DRIVER_BINDING_PROTOCOL instance.
  @param[in]  ControllerHandle     The handle of the controller to start. This handle
                                   must support a protocol interface that supplies
                                   an I/O abstraction to the driver.
  @param[in]  RemainingDevicePath  A pointer to the remaining portion of a device path.  This
                                   parameter is ignored by device drivers, and is optional for bus
                                   drivers. For a bus driver, if this parameter is NULL, then handles
                                   for all the children of Controller are created by this driver.
                                   If this parameter is not NULL and the first Device Path Node is
                                   not the End of Device Path Node, then only the handle for the
                                   child device specified by the first Device Path Node of
                                   RemainingDevicePath is created by this driver.
                                   If the first Device Path Node of RemainingDevicePath is
                                   the End of Device Path Node, no child handle is created by this
                                   driver.

  @retval EFI_SUCCESS              The device was started.
  @retval EFI_DEVICE_ERROR         The device could not be started due to a device error.Currently not implemented.
  @retval EFI_OUT_OF_RESOURCES     The request could not be completed due to a lack of resources.
  @retval Others                   The driver failed to start the device.

**/
EFI_STATUS
EFIAPI
HttpBootIp4DxeDriverBindingStart (
  IN EFI_DRIVER_BINDING_PROTOCOL  *This,
  IN EFI_HANDLE                   ControllerHandle,
  IN EFI_DEVICE_PATH_PROTOCOL     *RemainingDevicePath OPTIONAL
  );

/**
  Stops a device controller or a bus controller.

  The Stop() function is designed to be invoked from the EFI boot service DisconnectController().
  As a result, much of the error checking on the parameters to Stop() has been moved
  into this common boot service. It is legal to call Stop() from other locations,
  but the following calling restrictions must be followed, or the system behavior will not be deterministic.
  1. ControllerHandle must be a valid EFI_HANDLE that was used on a previous call to this
     same driver's Start() function.
  2. The first NumberOfChildren handles of ChildHandleBuffer must all be a valid
     EFI_HANDLE. In addition, all of these handles must have been created in this driver's
     Start() function, and the Start() function must have called OpenProtocol() on
     ControllerHandle with an Attribute of EFI_OPEN_PROTOCOL_BY_CHILD_CONTROLLER.

  @param[in]  This              A pointer to the EFI_DRIVER_BINDING_PROTOCOL instance.
  @param[in]  ControllerHandle  A handle to the device being stopped. The handle must
                                support a bus specific I/O protocol for the driver
                                to use to stop the device.
  @param[in]  NumberOfChildren  The number of child device handles in ChildHandleBuffer.
  @param[in]  ChildHandleBuffer An array of child handles to be freed. May be NULL
                                if NumberOfChildren is 0.

  @retval EFI_SUCCESS           The device was stopped.
  @retval EFI_DEVICE_ERROR      The device could not be stopped due to a device error.

**/
EFI_STATUS
EFIAPI
HttpBootIp4DxeDriverBindingStop (
  IN EFI_DRIVER_BINDING_PROTOCOL  *This,
  IN EFI_HANDLE                   ControllerHandle,
  IN UINTN                        NumberOfChildren,
  IN EFI_HANDLE                   *ChildHandleBuffer OPTIONAL
  );

/**
  Tests to see if this driver supports a given controller. If a child device is provided,
  it further tests to see if this driver supports creating a handle for the specified child device.

  This function checks to see if the driver specified by This supports the device specified by
  ControllerHandle. Drivers will typically use the device path attached to
  ControllerHandle and/or the services from the bus I/O abstraction attached to
  ControllerHandle to determine if the driver supports ControllerHandle. This function
  may be called many times during platform initialization. In order to reduce boot times, the tests
  performed by this function must be very small, and take as little time as possible to execute. This
  function must not change the state of any hardware devices, and this function must be aware that the
  device specified by ControllerHandle may already be managed by the same driver or a
  different driver. This function must match its calls to AllocatePages() with FreePages(),
  AllocatePool() with FreePool(), and OpenProtocol() with CloseProtocol().
  Because ControllerHandle may have been previously started by the same driver, if a protocol is
  already in the opened state, then it must not be closed with CloseProtocol(). This is required
  to guarantee the state of ControllerHandle is not modified by this function.

  @param[in]  This                 A pointer to the EFI_DRIVER_BINDING_PROTOCOL instance.
  @param[in]  ControllerHandle     The handle of the controller to test. This handle
                                   must support a protocol interface that supplies
                                   an I/O abstraction to the driver.
  @param[in]  RemainingDevicePath  A pointer to the remaining portion of a device path.  This
                                   parameter is ignored by device drivers, and is optional for bus
                                   drivers. For bus drivers, if this parameter is not NULL, then
                                   the bus driver must determine if the bus controller specified
                                   by ControllerHandle and the child controller specified
                                   by RemainingDevicePath are both supported by this
                                   bus driver.

  @retval EFI_SUCCESS              The device specified by ControllerHandle and
                                   RemainingDevicePath is supported by the driver specified by This.
  @retval EFI_ALREADY_STARTED      The device specified by ControllerHandle and
                                   RemainingDevicePath is already being managed by the driver
                                   specified by This.
  @retval EFI_ACCESS_DENIED        The device specified by ControllerHandle and
                                   RemainingDevicePath is already being managed by a different
                                   driver or an application that requires exclusive access.
                                   Currently not implemented.
  @retval EFI_UNSUPPORTED          The device specified by ControllerHandle and
                                   RemainingDevicePath is not supported by the driver specified by This.
**/
EFI_STATUS
EFIAPI
HttpBootIp6DxeDriverBindingSupported (
  IN EFI_DRIVER_BINDING_PROTOCOL  *This,
  IN EFI_HANDLE                   ControllerHandle,
  IN EFI_DEVICE_PATH_PROTOCOL     *RemainingDevicePath OPTIONAL
  );

/**
  Starts a device controller or a bus controller.

  The Start() function is designed to be invoked from the EFI boot service ConnectController().
  As a result, much of the error checking on the parameters to Start() has been moved into this
  common boot service. It is legal to call Start() from other locations,
  but the following calling restrictions must be followed, or the system behavior will not be deterministic.
  1. ControllerHandle must be a valid EFI_HANDLE.
  2. If RemainingDevicePath is not NULL, then it must be a pointer to a naturally aligned
     EFI_DEVICE_PATH_PROTOCOL.
  3. Prior to calling Start(), the Supported() function for the driver specified by This must
     have been called with the same calling parameters, and Supported() must have returned EFI_SUCCESS.

  @param[in]  This                 A pointer to the EFI_DRIVER_BINDING_PROTOCOL instance.
  @param[in]  ControllerHandle     The handle of the controller to start. This handle
                                   must support a protocol interface that supplies
                                   an I/O abstraction to the driver.
  @param[in]  RemainingDevicePath  A pointer to the remaining portion of a device path.  This
                                   parameter is ignored by device drivers, and is optional for bus
                                   drivers. For a bus driver, if this parameter is NULL, then handles
                                   for all the children of Controller are created by this driver.
                                   If this parameter is not NULL and the first Device Path Node is
                                   not the End of Device Path Node, then only the handle for the
                                   child device specified by the first Device Path Node of
                                   RemainingDevicePath is created by this driver.
                                   If the first Device Path Node of RemainingDevicePath is
                                   the End of Device Path Node, no child handle is created by this
                                   driver.

  @retval EFI_SUCCESS              The device was started.
  @retval EFI_DEVICE_ERROR         The device could not be started due to a device error.Currently not implemented.
  @retval EFI_OUT_OF_RESOURCES     The request could not be completed due to a lack of resources.
  @retval Others                   The driver failed to start the device.

**/
EFI_STATUS
EFIAPI
HttpBootIp6DxeDriverBindingStart (
  IN EFI_DRIVER_BINDING_PROTOCOL  *This,
  IN EFI_HANDLE                   ControllerHandle,
  IN EFI_DEVICE_PATH_PROTOCOL     *RemainingDevicePath OPTIONAL
  );

/**
  Stops a device controller or a bus controller.

  The Stop() function is designed to be invoked from the EFI boot service DisconnectController().
  As a result, much of the error checking on the parameters to Stop() has been moved
  into this common boot service. It is legal to call Stop() from other locations,
  but the following calling restrictions must be followed, or the system behavior will not be deterministic.
  1. ControllerHandle must be a valid EFI_HANDLE that was used on a previous call to this
     same driver's Start() function.
  2. The first NumberOfChildren handles of ChildHandleBuffer must all be a valid
     EFI_HANDLE. In addition, all of these handles must have been created in this driver's
     Start() function, and the Start() function must have called OpenProtocol() on
     ControllerHandle with an Attribute of EFI_OPEN_PROTOCOL_BY_CHILD_CONTROLLER.

  @param[in]  This              A pointer to the EFI_DRIVER_BINDING_PROTOCOL instance.
  @param[in]  ControllerHandle  A handle to the device being stopped. The handle must
                                support a bus specific I/O protocol for the driver
                                to use to stop the device.
  @param[in]  NumberOfChildren  The number of child device handles in ChildHandleBuffer.
  @param[in]  ChildHandleBuffer An array of child handles to be freed. May be NULL
                                if NumberOfChildren is 0.

  @retval EFI_SUCCESS           The device was stopped.
  @retval EFI_DEVICE_ERROR      The device could not be stopped due to a device error.

**/
EFI_STATUS
EFIAPI
HttpBootIp6DxeDriverBindingStop (
  IN EFI_DRIVER_BINDING_PROTOCOL  *This,
  IN EFI_HANDLE                   ControllerHandle,
  IN UINTN                        NumberOfChildren,
  IN EFI_HANDLE                   *ChildHandleBuffer OPTIONAL
  );

#endif
