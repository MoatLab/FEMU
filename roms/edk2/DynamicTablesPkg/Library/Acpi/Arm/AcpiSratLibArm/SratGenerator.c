/** @file
  SRAT Table Generator

  Copyright (c) 2019 - 2020, Arm Limited. All rights reserved.
  SPDX-License-Identifier: BSD-2-Clause-Patent

  @par Reference(s):
  - ACPI 6.3 Specification, January 2019

  @par Glossary:
  - Cm or CM   - Configuration Manager
  - Obj or OBJ - Object
**/

#include <Library/AcpiLib.h>
#include <Library/BaseLib.h>
#include <Library/DebugLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Protocol/AcpiTable.h>

// Module specific include files.
#include <AcpiTableGenerator.h>
#include <ConfigurationManagerObject.h>
#include <ConfigurationManagerHelper.h>
#include <Library/TableHelperLib.h>
#include <Protocol/ConfigurationManagerProtocol.h>

/**
  ARM standard SRAT Generator

  Requirements:
    The following Configuration Manager Object(s) are used by this Generator:
    - EArmObjGicCInfo (REQUIRED)
    - EArmObjGicItsInfo (OPTIONAL)
    - EArmObjMemoryAffinityInfo (OPTIONAL)
    - EArmObjGenericInitiatorAffinityInfo (OPTIONAL)
    - EArmObjDeviceHandleAcpi (OPTIONAL)
    - EArmObjDeviceHandlePci (OPTIONAL)
*/

/** This macro expands to a function that retrieves the GIC
    CPU interface Information from the Configuration Manager.
*/
GET_OBJECT_LIST (
  EObjNameSpaceArm,
  EArmObjGicCInfo,
  CM_ARM_GICC_INFO
  );

/** This macro expands to a function that retrieves the GIC
    Interrupt Translation Service Information from the
    Configuration Manager.
*/
GET_OBJECT_LIST (
  EObjNameSpaceArm,
  EArmObjGicItsInfo,
  CM_ARM_GIC_ITS_INFO
  );

/**
  This macro expands to a function that retrieves the Memory Affinity
  information from the Configuration Manager.
*/
GET_OBJECT_LIST (
  EObjNameSpaceArm,
  EArmObjMemoryAffinityInfo,
  CM_ARM_MEMORY_AFFINITY_INFO
  );

/**
  This macro expands to a function that retrieves the Generic Initiator Affinity
  information from the Configuration Manager.
*/
GET_OBJECT_LIST (
  EObjNameSpaceArm,
  EArmObjGenericInitiatorAffinityInfo,
  CM_ARM_GENERIC_INITIATOR_AFFINITY_INFO
  );

/**
  This macro expands to a function that retrieves the ACPI Device Handle
  information from the Configuration Manager.
*/
GET_OBJECT_LIST (
  EObjNameSpaceArm,
  EArmObjDeviceHandleAcpi,
  CM_ARM_DEVICE_HANDLE_ACPI
  );

/**
  This macro expands to a function that retrieves the PCI Device Handle
  information from the Configuration Manager.
*/
GET_OBJECT_LIST (
  EObjNameSpaceArm,
  EArmObjDeviceHandlePci,
  CM_ARM_DEVICE_HANDLE_PCI
  );

/** Return the PCI Device information in BDF format

    PCI Bus Number - Max 256 busses (Bits 15:8 of BDF)
    PCI Device Number - Max 32 devices (Bits 7:3 of BDF)
    PCI Function Number - Max 8 functions (Bits 2:0 of BDF)

    @param [in]  DeviceHandlePci   Pointer to the PCI Device Handle.

    @retval BDF value corresponding to the PCI Device Handle.
**/
STATIC
UINT16
GetBdf (
  IN CONST CM_ARM_DEVICE_HANDLE_PCI  *DeviceHandlePci
  )
{
  UINT16  Bdf;

  Bdf  = (UINT16)DeviceHandlePci->BusNumber << 8;
  Bdf |= (DeviceHandlePci->DeviceNumber & 0x1F) << 3;
  Bdf |= DeviceHandlePci->FunctionNumber & 0x7;
  return Bdf;
}

/** Add the GICC Affinity Structures in the SRAT Table.

  @param [in]  CfgMgrProtocol   Pointer to the Configuration Manager
                                Protocol Interface.
  @param [in]  Srat             Pointer to the SRAT Table.
  @param [in]  GicCAffOffset    Offset of the GICC Affinity
                                information in the SRAT Table.
  @param [in]  GicCInfo         Pointer to the GIC CPU Information list.
  @param [in]  GicCCount        Count of GIC CPU Interfaces.

  @retval EFI_SUCCESS           Table generated successfully.
**/
STATIC
EFI_STATUS
AddGICCAffinity (
  IN CONST EDKII_CONFIGURATION_MANAGER_PROTOCOL         *CONST  CfgMgrProtocol,
  IN EFI_ACPI_6_3_SYSTEM_RESOURCE_AFFINITY_TABLE_HEADER *CONST  Srat,
  IN CONST UINT32                                               GicCAffOffset,
  IN CONST CM_ARM_GICC_INFO                                     *GicCInfo,
  IN       UINT32                                               GicCCount
  )
{
  EFI_ACPI_6_3_GICC_AFFINITY_STRUCTURE  *GicCAff;

  ASSERT (Srat != NULL);
  ASSERT (GicCInfo != NULL);

  GicCAff = (EFI_ACPI_6_3_GICC_AFFINITY_STRUCTURE *)((UINT8 *)Srat +
                                                     GicCAffOffset);

  while (GicCCount-- != 0) {
    DEBUG ((DEBUG_INFO, "SRAT: GicCAff = 0x%p\n", GicCAff));

    GicCAff->Type             = EFI_ACPI_6_3_GICC_AFFINITY;
    GicCAff->Length           = sizeof (EFI_ACPI_6_3_GICC_AFFINITY_STRUCTURE);
    GicCAff->ProximityDomain  = GicCInfo->ProximityDomain;
    GicCAff->AcpiProcessorUid = GicCInfo->AcpiProcessorUid;
    GicCAff->Flags            = GicCInfo->AffinityFlags;
    GicCAff->ClockDomain      = GicCInfo->ClockDomain;

    // Next
    GicCAff++;
    GicCInfo++;
  }// while

  return EFI_SUCCESS;
}

/** Add the GIC ITS Affinity Structures in the SRAT Table.

  @param [in]  CfgMgrProtocol   Pointer to the Configuration Manager
                                Protocol Interface.
  @param [in]  Srat             Pointer to the SRAT Table.
  @param [in]  GicItsAffOffset  Offset of the GIC ITS Affinity
                                information in the SRAT Table.
  @param [in]  GicItsInfo       Pointer to the GIC ITS Information list.
  @param [in]  GicItsCount      Count of GIC ITS.

  @retval EFI_SUCCESS           Table generated successfully.
**/
STATIC
EFI_STATUS
AddGICItsAffinity (
  IN CONST EDKII_CONFIGURATION_MANAGER_PROTOCOL         *CONST  CfgMgrProtocol,
  IN EFI_ACPI_6_3_SYSTEM_RESOURCE_AFFINITY_TABLE_HEADER *CONST  Srat,
  IN CONST UINT32                                               GicItsAffOffset,
  IN CONST CM_ARM_GIC_ITS_INFO                                  *GicItsInfo,
  IN       UINT32                                               GicItsCount
  )
{
  EFI_ACPI_6_3_GIC_ITS_AFFINITY_STRUCTURE  *GicItsAff;

  ASSERT (Srat != NULL);
  ASSERT (GicItsInfo != NULL);

  GicItsAff = (EFI_ACPI_6_3_GIC_ITS_AFFINITY_STRUCTURE *)((UINT8 *)Srat +
                                                          GicItsAffOffset);

  while (GicItsCount-- != 0) {
    DEBUG ((DEBUG_INFO, "SRAT: GicItsAff = 0x%p\n", GicItsAff));

    GicItsAff->Type            = EFI_ACPI_6_3_GIC_ITS_AFFINITY;
    GicItsAff->Length          = sizeof (EFI_ACPI_6_3_GIC_ITS_AFFINITY_STRUCTURE);
    GicItsAff->ProximityDomain = GicItsInfo->ProximityDomain;
    GicItsAff->Reserved[0]     = EFI_ACPI_RESERVED_BYTE;
    GicItsAff->Reserved[1]     = EFI_ACPI_RESERVED_BYTE;
    GicItsAff->ItsId           = GicItsInfo->GicItsId;

    // Next
    GicItsAff++;
    GicItsInfo++;
  }// while

  return EFI_SUCCESS;
}

/** Add the Memory Affinity Structures in the SRAT Table.

  @param [in]  CfgMgrProtocol   Pointer to the Configuration Manager
                                Protocol Interface.
  @param [in]  Srat             Pointer to the SRAT Table.
  @param [in]  MemAffOffset     Offset of the Memory Affinity
                                information in the SRAT Table.
  @param [in]  MemAffInfo       Pointer to the Memory Affinity Information list.
  @param [in]  MemAffCount      Count of Memory Affinity objects.

  @retval EFI_SUCCESS           Table generated successfully.
**/
STATIC
EFI_STATUS
AddMemoryAffinity (
  IN CONST EDKII_CONFIGURATION_MANAGER_PROTOCOL         *CONST  CfgMgrProtocol,
  IN EFI_ACPI_6_3_SYSTEM_RESOURCE_AFFINITY_TABLE_HEADER *CONST  Srat,
  IN CONST UINT32                                               MemAffOffset,
  IN CONST CM_ARM_MEMORY_AFFINITY_INFO                          *MemAffInfo,
  IN       UINT32                                               MemAffCount
  )
{
  EFI_ACPI_6_3_MEMORY_AFFINITY_STRUCTURE  *MemAff;

  ASSERT (Srat != NULL);
  ASSERT (MemAffInfo != NULL);

  MemAff = (EFI_ACPI_6_3_MEMORY_AFFINITY_STRUCTURE *)((UINT8 *)Srat +
                                                      MemAffOffset);

  while (MemAffCount-- != 0) {
    DEBUG ((DEBUG_INFO, "SRAT: MemAff = 0x%p\n", MemAff));

    MemAff->Type            = EFI_ACPI_6_3_MEMORY_AFFINITY;
    MemAff->Length          = sizeof (EFI_ACPI_6_3_MEMORY_AFFINITY_STRUCTURE);
    MemAff->ProximityDomain = MemAffInfo->ProximityDomain;
    MemAff->Reserved1       = EFI_ACPI_RESERVED_WORD;
    MemAff->AddressBaseLow  = (UINT32)(MemAffInfo->BaseAddress & MAX_UINT32);
    MemAff->AddressBaseHigh = (UINT32)(MemAffInfo->BaseAddress >> 32);
    MemAff->LengthLow       = (UINT32)(MemAffInfo->Length & MAX_UINT32);
    MemAff->LengthHigh      = (UINT32)(MemAffInfo->Length >> 32);
    MemAff->Reserved2       = EFI_ACPI_RESERVED_DWORD;
    MemAff->Flags           = MemAffInfo->Flags;
    MemAff->Reserved3       = EFI_ACPI_RESERVED_QWORD;

    // Next
    MemAff++;
    MemAffInfo++;
  }// while

  return EFI_SUCCESS;
}

/** Add the Generic Initiator Affinity Structures in the SRAT Table.

  @param [in]  CfgMgrProtocol   Pointer to the Configuration Manager
                                Protocol Interface.
  @param [in]  Srat             Pointer to the SRAT Table.
  @param [in]  GenInitAffOff    Offset of the Generic Initiator Affinity
                                information in the SRAT Table.
  @param [in]  GenInitAffInfo   Pointer to the Generic Initiator Affinity
                                Information list.
  @param [in]  GenInitAffCount  Count of Generic Initiator Affinity
                                objects.

  @retval EFI_SUCCESS           Table generated successfully.
  @retval EFI_INVALID_PARAMETER A parameter is invalid.
  @retval EFI_NOT_FOUND         The required object information is not found.
  @retval EFI_BAD_BUFFER_SIZE   The size returned by the Configuration
                                Manager is less than the Object size for the
                                requested object.
**/
STATIC
EFI_STATUS
AddGenericInitiatorAffinity (
  IN CONST EDKII_CONFIGURATION_MANAGER_PROTOCOL         *CONST  CfgMgrProtocol,
  IN EFI_ACPI_6_3_SYSTEM_RESOURCE_AFFINITY_TABLE_HEADER *CONST  Srat,
  IN CONST UINT32                                               GenInitAffOff,
  IN CONST CM_ARM_GENERIC_INITIATOR_AFFINITY_INFO               *GenInitAffInfo,
  IN       UINT32                                               GenInitAffCount
  )
{
  EFI_STATUS                                         Status;
  EFI_ACPI_6_3_GENERIC_INITIATOR_AFFINITY_STRUCTURE  *GenInitAff;
  CM_ARM_DEVICE_HANDLE_ACPI                          *DeviceHandleAcpi;
  CM_ARM_DEVICE_HANDLE_PCI                           *DeviceHandlePci;
  UINT32                                             DeviceHandleCount;

  ASSERT (Srat != NULL);
  ASSERT (GenInitAffInfo != NULL);

  GenInitAff = (EFI_ACPI_6_3_GENERIC_INITIATOR_AFFINITY_STRUCTURE *)(
                                                                     (UINT8 *)Srat + GenInitAffOff);

  while (GenInitAffCount-- != 0) {
    DEBUG ((DEBUG_INFO, "SRAT: GenInitAff = 0x%p\n", GenInitAff));

    GenInitAff->Type   = EFI_ACPI_6_3_GENERIC_INITIATOR_AFFINITY;
    GenInitAff->Length =
      sizeof (EFI_ACPI_6_3_GENERIC_INITIATOR_AFFINITY_STRUCTURE);
    GenInitAff->Reserved1        = EFI_ACPI_RESERVED_WORD;
    GenInitAff->DeviceHandleType = GenInitAffInfo->DeviceHandleType;
    GenInitAff->ProximityDomain  = GenInitAffInfo->ProximityDomain;

    if (GenInitAffInfo->DeviceHandleToken == CM_NULL_TOKEN) {
      DEBUG ((
        DEBUG_ERROR,
        "ERROR: SRAT: Invalid Device Handle Token.\n"
        ));
      ASSERT (0);
      return EFI_INVALID_PARAMETER;
    }

    if (GenInitAffInfo->DeviceHandleType == EFI_ACPI_6_3_ACPI_DEVICE_HANDLE) {
      Status = GetEArmObjDeviceHandleAcpi (
                 CfgMgrProtocol,
                 GenInitAffInfo->DeviceHandleToken,
                 &DeviceHandleAcpi,
                 &DeviceHandleCount
                 );
      if (EFI_ERROR (Status)) {
        DEBUG ((
          DEBUG_ERROR,
          "ERROR: SRAT: Failed to get ACPI Device Handle Inf."
          " DeviceHandleToken = %p."
          " Status = %r\n",
          GenInitAffInfo->DeviceHandleToken,
          Status
          ));
        return Status;
      }

      // We are expecting only one device handle.
      ASSERT (DeviceHandleCount == 1);

      // Populate the ACPI device handle information.
      GenInitAff->DeviceHandle.Acpi.AcpiHid     = DeviceHandleAcpi->Hid;
      GenInitAff->DeviceHandle.Acpi.AcpiUid     = DeviceHandleAcpi->Uid;
      GenInitAff->DeviceHandle.Acpi.Reserved[0] = EFI_ACPI_RESERVED_BYTE;
      GenInitAff->DeviceHandle.Acpi.Reserved[1] = EFI_ACPI_RESERVED_BYTE;
      GenInitAff->DeviceHandle.Acpi.Reserved[2] = EFI_ACPI_RESERVED_BYTE;
      GenInitAff->DeviceHandle.Acpi.Reserved[3] = EFI_ACPI_RESERVED_BYTE;
    } else if (GenInitAffInfo->DeviceHandleType ==
               EFI_ACPI_6_3_PCI_DEVICE_HANDLE)
    {
      Status = GetEArmObjDeviceHandlePci (
                 CfgMgrProtocol,
                 GenInitAffInfo->DeviceHandleToken,
                 &DeviceHandlePci,
                 &DeviceHandleCount
                 );
      if (EFI_ERROR (Status)) {
        DEBUG ((
          DEBUG_ERROR,
          "ERROR: SRAT: Failed to get ACPI Device Handle Inf."
          " DeviceHandleToken = %p."
          " Status = %r\n",
          GenInitAffInfo->DeviceHandleToken,
          Status
          ));
        return Status;
      }

      // We are expecting only one device handle
      ASSERT (DeviceHandleCount == 1);

      // Populate the ACPI device handle information.
      GenInitAff->DeviceHandle.Pci.PciSegment   = DeviceHandlePci->SegmentNumber;
      GenInitAff->DeviceHandle.Pci.PciBdfNumber = GetBdf (DeviceHandlePci);

      GenInitAff->DeviceHandle.Pci.Reserved[0]  = EFI_ACPI_RESERVED_BYTE;
      GenInitAff->DeviceHandle.Pci.Reserved[1]  = EFI_ACPI_RESERVED_BYTE;
      GenInitAff->DeviceHandle.Pci.Reserved[2]  = EFI_ACPI_RESERVED_BYTE;
      GenInitAff->DeviceHandle.Pci.Reserved[3]  = EFI_ACPI_RESERVED_BYTE;
      GenInitAff->DeviceHandle.Pci.Reserved[4]  = EFI_ACPI_RESERVED_BYTE;
      GenInitAff->DeviceHandle.Pci.Reserved[5]  = EFI_ACPI_RESERVED_BYTE;
      GenInitAff->DeviceHandle.Pci.Reserved[6]  = EFI_ACPI_RESERVED_BYTE;
      GenInitAff->DeviceHandle.Pci.Reserved[7]  = EFI_ACPI_RESERVED_BYTE;
      GenInitAff->DeviceHandle.Pci.Reserved[8]  = EFI_ACPI_RESERVED_BYTE;
      GenInitAff->DeviceHandle.Pci.Reserved[9]  = EFI_ACPI_RESERVED_BYTE;
      GenInitAff->DeviceHandle.Pci.Reserved[10] = EFI_ACPI_RESERVED_BYTE;
      GenInitAff->DeviceHandle.Pci.Reserved[11] = EFI_ACPI_RESERVED_BYTE;
    } else {
      DEBUG ((
        DEBUG_ERROR,
        "ERROR: SRAT: Invalid Device Handle Type.\n"
        ));
      ASSERT (0);
      return EFI_INVALID_PARAMETER;
    }

    GenInitAff->Flags        = GenInitAffInfo->Flags;
    GenInitAff->Reserved2[0] = EFI_ACPI_RESERVED_BYTE;
    GenInitAff->Reserved2[1] = EFI_ACPI_RESERVED_BYTE;

    // Next
    GenInitAff++;
    GenInitAffInfo++;
  }// while

  return EFI_SUCCESS;
}

/** Construct the SRAT ACPI table.

  Called by the Dynamic Table Manager, this function invokes the
  Configuration Manager protocol interface to get the required hardware
  information for generating the ACPI table.

  If this function allocates any resources then they must be freed
  in the FreeXXXXTableResources function.

  @param [in]  This           Pointer to the table generator.
  @param [in]  AcpiTableInfo  Pointer to the ACPI Table Info.
  @param [in]  CfgMgrProtocol Pointer to the Configuration Manager
                              Protocol Interface.
  @param [out] Table          Pointer to the constructed ACPI Table.

  @retval EFI_SUCCESS           Table generated successfully.
  @retval EFI_INVALID_PARAMETER A parameter is invalid.
  @retval EFI_NOT_FOUND         The required object was not found.
  @retval EFI_BAD_BUFFER_SIZE   The size returned by the Configuration
                                Manager is less than the Object size for the
                                requested object.
  @retval EFI_OUT_OF_RESOURCES  Memory allocation failed.
**/
STATIC
EFI_STATUS
EFIAPI
BuildSratTable (
  IN  CONST ACPI_TABLE_GENERATOR                  *CONST  This,
  IN  CONST CM_STD_OBJ_ACPI_TABLE_INFO            *CONST  AcpiTableInfo,
  IN  CONST EDKII_CONFIGURATION_MANAGER_PROTOCOL  *CONST  CfgMgrProtocol,
  OUT       EFI_ACPI_DESCRIPTION_HEADER          **CONST  Table
  )
{
  EFI_STATUS  Status;
  UINT32      TableSize;
  UINT32      GicCCount;
  UINT32      GicItsCount;
  UINT32      MemAffCount;
  UINT32      GenInitiatorAffCount;

  UINT32  GicCAffOffset;
  UINT32  GicItsAffOffset;
  UINT32  MemAffOffset;
  UINT32  GenInitiatorAffOffset;

  CM_ARM_GICC_INFO                        *GicCInfo;
  CM_ARM_GIC_ITS_INFO                     *GicItsInfo;
  CM_ARM_MEMORY_AFFINITY_INFO             *MemAffInfo;
  CM_ARM_GENERIC_INITIATOR_AFFINITY_INFO  *GenInitiatorAffInfo;

  EFI_ACPI_6_3_SYSTEM_RESOURCE_AFFINITY_TABLE_HEADER  *Srat;

  ASSERT (
    (This != NULL) &&
    (AcpiTableInfo != NULL) &&
    (CfgMgrProtocol != NULL) &&
    (Table != NULL) &&
    (AcpiTableInfo->TableGeneratorId == This->GeneratorID) &&
    (AcpiTableInfo->AcpiTableSignature == This->AcpiTableSignature)
    );

  if ((AcpiTableInfo->AcpiTableRevision < This->MinAcpiTableRevision) ||
      (AcpiTableInfo->AcpiTableRevision > This->AcpiTableRevision))
  {
    DEBUG ((
      DEBUG_ERROR,
      "ERROR: SRAT: Requested table revision = %d is not supported. "
      "Supported table revisions: Minimum = %d. Maximum = %d\n",
      AcpiTableInfo->AcpiTableRevision,
      This->MinAcpiTableRevision,
      This->AcpiTableRevision
      ));
    return EFI_INVALID_PARAMETER;
  }

  *Table = NULL;

  Status = GetEArmObjGicCInfo (
             CfgMgrProtocol,
             CM_NULL_TOKEN,
             &GicCInfo,
             &GicCCount
             );
  if (EFI_ERROR (Status)) {
    DEBUG ((
      DEBUG_ERROR,
      "ERROR: SRAT: Failed to get GICC Info. Status = %r\n",
      Status
      ));
    goto error_handler;
  }

  if (GicCCount == 0) {
    DEBUG ((
      DEBUG_ERROR,
      "ERROR: SRAT: GIC CPU Interface information not provided.\n"
      ));
    ASSERT (0);
    Status = EFI_INVALID_PARAMETER;
    goto error_handler;
  }

  Status = GetEArmObjGicItsInfo (
             CfgMgrProtocol,
             CM_NULL_TOKEN,
             &GicItsInfo,
             &GicItsCount
             );
  if (EFI_ERROR (Status) && (Status != EFI_NOT_FOUND)) {
    DEBUG ((
      DEBUG_ERROR,
      "ERROR: SRAT: Failed to get GIC ITS Info. Status = %r\n",
      Status
      ));
    goto error_handler;
  }

  Status = GetEArmObjMemoryAffinityInfo (
             CfgMgrProtocol,
             CM_NULL_TOKEN,
             &MemAffInfo,
             &MemAffCount
             );
  if (EFI_ERROR (Status) && (Status != EFI_NOT_FOUND)) {
    DEBUG ((
      DEBUG_ERROR,
      "ERROR: SRAT: Failed to get Memory Affinity Info. Status = %r\n",
      Status
      ));
    goto error_handler;
  }

  Status = GetEArmObjGenericInitiatorAffinityInfo (
             CfgMgrProtocol,
             CM_NULL_TOKEN,
             &GenInitiatorAffInfo,
             &GenInitiatorAffCount
             );
  if (EFI_ERROR (Status) && (Status != EFI_NOT_FOUND)) {
    DEBUG ((
      DEBUG_ERROR,
      "ERROR: SRAT: Failed to get Generic Initiator Affinity Info."
      " Status = %r\n",
      Status
      ));
    goto error_handler;
  }

  // Calculate the size of the SRAT table
  TableSize = sizeof (EFI_ACPI_6_3_SYSTEM_RESOURCE_AFFINITY_TABLE_HEADER);

  GicCAffOffset = TableSize;
  TableSize    += (sizeof (EFI_ACPI_6_3_GICC_AFFINITY_STRUCTURE) * GicCCount);

  if (GicItsCount != 0) {
    GicItsAffOffset = TableSize;
    TableSize      += (sizeof (EFI_ACPI_6_3_GIC_ITS_AFFINITY_STRUCTURE) *
                       GicItsCount);
  }

  if (MemAffCount != 0) {
    MemAffOffset = TableSize;
    TableSize   += (sizeof (EFI_ACPI_6_3_MEMORY_AFFINITY_STRUCTURE) *
                    MemAffCount);
  }

  if (GenInitiatorAffCount != 0) {
    GenInitiatorAffOffset = TableSize;
    TableSize            += (sizeof (EFI_ACPI_6_3_GENERIC_INITIATOR_AFFINITY_STRUCTURE) *
                             GenInitiatorAffCount);
  }

  // Allocate the Buffer for SRAT table
  *Table = (EFI_ACPI_DESCRIPTION_HEADER *)AllocateZeroPool (TableSize);
  if (*Table == NULL) {
    Status = EFI_OUT_OF_RESOURCES;
    DEBUG ((
      DEBUG_ERROR,
      "ERROR: SRAT: Failed to allocate memory for SRAT Table, Size = %d," \
      " Status = %r\n",
      TableSize,
      Status
      ));
    goto error_handler;
  }

  Srat = (EFI_ACPI_6_3_SYSTEM_RESOURCE_AFFINITY_TABLE_HEADER *)*Table;

  DEBUG ((
    DEBUG_INFO,
    "SRAT: Srat = 0x%p TableSize = 0x%x\n",
    Srat,
    TableSize
    ));

  Status = AddAcpiHeader (
             CfgMgrProtocol,
             This,
             &Srat->Header,
             AcpiTableInfo,
             TableSize
             );
  if (EFI_ERROR (Status)) {
    DEBUG ((
      DEBUG_ERROR,
      "ERROR: SRAT: Failed to add ACPI header. Status = %r\n",
      Status
      ));
    goto error_handler;
  }

  // Setup the Reserved fields
  // Reserved1 must be set to 1 for backward compatibility
  Srat->Reserved1 = 1;
  Srat->Reserved2 = EFI_ACPI_RESERVED_QWORD;

  Status = AddGICCAffinity (
             CfgMgrProtocol,
             Srat,
             GicCAffOffset,
             GicCInfo,
             GicCCount
             );
  if (EFI_ERROR (Status)) {
    DEBUG ((
      DEBUG_ERROR,
      "ERROR: SRAT: Failed to add GICC Affinity structures. Status = %r\n",
      Status
      ));
    goto error_handler;
  }

  if (GicItsCount != 0) {
    Status = AddGICItsAffinity (
               CfgMgrProtocol,
               Srat,
               GicItsAffOffset,
               GicItsInfo,
               GicItsCount
               );
    if (EFI_ERROR (Status)) {
      DEBUG ((
        DEBUG_ERROR,
        "ERROR: SRAT: Failed to add GIC ITS Affinity structures. Status = %r\n",
        Status
        ));
      goto error_handler;
    }
  }

  if (MemAffCount != 0) {
    Status = AddMemoryAffinity (
               CfgMgrProtocol,
               Srat,
               MemAffOffset,
               MemAffInfo,
               MemAffCount
               );
    if (EFI_ERROR (Status)) {
      DEBUG ((
        DEBUG_ERROR,
        "ERROR: SRAT: Failed to add Memory Affinity structures. Status = %r\n",
        Status
        ));
      goto error_handler;
    }
  }

  if (GenInitiatorAffCount != 0) {
    Status = AddGenericInitiatorAffinity (
               CfgMgrProtocol,
               Srat,
               GenInitiatorAffOffset,
               GenInitiatorAffInfo,
               GenInitiatorAffCount
               );
    if (EFI_ERROR (Status)) {
      DEBUG ((
        DEBUG_ERROR,
        "ERROR: SRAT: Failed to add Generic Initiator Affinity structures."
        " Status = %r\n",
        Status
        ));
      goto error_handler;
    }
  }

  return Status;

error_handler:

  if (*Table != NULL) {
    FreePool (*Table);
    *Table = NULL;
  }

  return Status;
}

/** Free any resources allocated for constructing the SRAT.

  @param [in]      This           Pointer to the table generator.
  @param [in]      AcpiTableInfo  Pointer to the ACPI Table Info.
  @param [in]      CfgMgrProtocol Pointer to the Configuration Manager
                                  Protocol Interface.
  @param [in, out] Table          Pointer to the ACPI Table.

  @retval EFI_SUCCESS           The resources were freed successfully.
  @retval EFI_INVALID_PARAMETER The table pointer is NULL or invalid.
**/
STATIC
EFI_STATUS
FreeSratTableResources (
  IN      CONST ACPI_TABLE_GENERATOR                  *CONST  This,
  IN      CONST CM_STD_OBJ_ACPI_TABLE_INFO            *CONST  AcpiTableInfo,
  IN      CONST EDKII_CONFIGURATION_MANAGER_PROTOCOL  *CONST  CfgMgrProtocol,
  IN OUT        EFI_ACPI_DESCRIPTION_HEADER          **CONST  Table
  )
{
  ASSERT (
    (This != NULL) &&
    (AcpiTableInfo != NULL) &&
    (CfgMgrProtocol != NULL) &&
    (AcpiTableInfo->TableGeneratorId == This->GeneratorID) &&
    (AcpiTableInfo->AcpiTableSignature == This->AcpiTableSignature)
    );

  if ((Table == NULL) || (*Table == NULL)) {
    DEBUG ((DEBUG_ERROR, "ERROR: SRAT: Invalid Table Pointer\n"));
    ASSERT (0);
    return EFI_INVALID_PARAMETER;
  }

  FreePool (*Table);
  *Table = NULL;
  return EFI_SUCCESS;
}

/** The SRAT Table Generator revision.
*/
#define SRAT_GENERATOR_REVISION  CREATE_REVISION (1, 0)

/** The interface for the SRAT Table Generator.
*/
STATIC
CONST
ACPI_TABLE_GENERATOR  SratGenerator = {
  // Generator ID
  CREATE_STD_ACPI_TABLE_GEN_ID (EStdAcpiTableIdSrat),
  // Generator Description
  L"ACPI.STD.SRAT.GENERATOR",
  // ACPI Table Signature
  EFI_ACPI_6_3_SYSTEM_RESOURCE_AFFINITY_TABLE_SIGNATURE,
  // ACPI Table Revision supported by this Generator
  EFI_ACPI_6_3_SYSTEM_RESOURCE_AFFINITY_TABLE_REVISION,
  // Minimum supported ACPI Table Revision
  EFI_ACPI_6_3_SYSTEM_RESOURCE_AFFINITY_TABLE_REVISION,
  // Creator ID
  TABLE_GENERATOR_CREATOR_ID_ARM,
  // Creator Revision
  SRAT_GENERATOR_REVISION,
  // Build Table function
  BuildSratTable,
  // Free Resource function
  FreeSratTableResources,
  // Extended build function not needed
  NULL,
  // Extended build function not implemented by the generator.
  // Hence extended free resource function is not required.
  NULL
};

/** Register the Generator with the ACPI Table Factory.

  @param [in]  ImageHandle  The handle to the image.
  @param [in]  SystemTable  Pointer to the System Table.

  @retval EFI_SUCCESS           The Generator is registered.
  @retval EFI_INVALID_PARAMETER A parameter is invalid.
  @retval EFI_ALREADY_STARTED   The Generator for the Table ID
                                is already registered.
**/
EFI_STATUS
EFIAPI
AcpiSratLibConstructor (
  IN  EFI_HANDLE        ImageHandle,
  IN  EFI_SYSTEM_TABLE  *SystemTable
  )
{
  EFI_STATUS  Status;

  Status = RegisterAcpiTableGenerator (&SratGenerator);
  DEBUG ((DEBUG_INFO, "SRAT: Register Generator. Status = %r\n", Status));
  ASSERT_EFI_ERROR (Status);
  return Status;
}

/** Deregister the Generator from the ACPI Table Factory.

  @param [in]  ImageHandle  The handle to the image.
  @param [in]  SystemTable  Pointer to the System Table.

  @retval EFI_SUCCESS           The Generator is deregistered.
  @retval EFI_INVALID_PARAMETER A parameter is invalid.
  @retval EFI_NOT_FOUND         The Generator is not registered.
**/
EFI_STATUS
EFIAPI
AcpiSratLibDestructor (
  IN  EFI_HANDLE        ImageHandle,
  IN  EFI_SYSTEM_TABLE  *SystemTable
  )
{
  EFI_STATUS  Status;

  Status = DeregisterAcpiTableGenerator (&SratGenerator);
  DEBUG ((DEBUG_INFO, "SRAT: Deregister Generator. Status = %r\n", Status));
  ASSERT_EFI_ERROR (Status);
  return Status;
}
