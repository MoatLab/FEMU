/** @file
  Locate, get and update PE/COFF permissions during Standalone MM
  Foundation Entry point on ARM platforms.

Copyright (c) 2017 - 2021, Arm Ltd. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include <PiMm.h>

#include <PiPei.h>
#include <Guid/MmramMemoryReserve.h>
#include <Guid/MpInformation.h>

#include <Library/Arm/StandaloneMmCoreEntryPoint.h>
#include <Library/ArmMmuLib.h>
#include <Library/ArmSvcLib.h>
#include <Library/DebugLib.h>
#include <Library/HobLib.h>
#include <Library/BaseLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/SerialPortLib.h>

#include <IndustryStandard/ArmStdSmc.h>

/**
  Privileged firmware assigns RO & Executable attributes to all memory occupied
  by the Boot Firmware Volume. This function sets the correct permissions of
  sections in the Standalone MM Core module to be able to access RO and RW data
  and make further progress in the boot process.

  @param  [in] ImageContext           Pointer to PE/COFF image context
  @param  [in] ImageBase              Base of image in memory
  @param  [in] SectionHeaderOffset    Offset of PE/COFF image section header
  @param  [in] NumberOfSections       Number of Sections
  @param  [in] TextUpdater            Function to change code permissions
  @param  [in] ReadOnlyUpdater        Function to change RO permissions
  @param  [in] ReadWriteUpdater       Function to change RW permissions

**/
EFI_STATUS
EFIAPI
UpdateMmFoundationPeCoffPermissions (
  IN  CONST PE_COFF_LOADER_IMAGE_CONTEXT  *ImageContext,
  IN  EFI_PHYSICAL_ADDRESS                ImageBase,
  IN  UINT32                              SectionHeaderOffset,
  IN  CONST  UINT16                       NumberOfSections,
  IN  REGION_PERMISSION_UPDATE_FUNC       TextUpdater,
  IN  REGION_PERMISSION_UPDATE_FUNC       ReadOnlyUpdater,
  IN  REGION_PERMISSION_UPDATE_FUNC       ReadWriteUpdater
  )
{
  EFI_IMAGE_SECTION_HEADER  SectionHeader;
  RETURN_STATUS             Status;
  EFI_PHYSICAL_ADDRESS      Base;
  UINTN                     Size;
  UINTN                     ReadSize;
  UINTN                     Index;

  ASSERT (ImageContext != NULL);

  //
  // Iterate over the sections
  //
  for (Index = 0; Index < NumberOfSections; Index++) {
    //
    // Read section header from file
    //
    Size     = sizeof (EFI_IMAGE_SECTION_HEADER);
    ReadSize = Size;
    Status   = ImageContext->ImageRead (
                               ImageContext->Handle,
                               SectionHeaderOffset,
                               &Size,
                               &SectionHeader
                               );

    if (RETURN_ERROR (Status) || (Size != ReadSize)) {
      DEBUG ((
        DEBUG_ERROR,
        "%a: ImageContext->ImageRead () failed (Status = %r)\n",
        __FUNCTION__,
        Status
        ));
      return Status;
    }

    DEBUG ((
      DEBUG_INFO,
      "%a: Section %d of image at 0x%lx has 0x%x permissions\n",
      __FUNCTION__,
      Index,
      ImageContext->ImageAddress,
      SectionHeader.Characteristics
      ));
    DEBUG ((
      DEBUG_INFO,
      "%a: Section %d of image at 0x%lx has %a name\n",
      __FUNCTION__,
      Index,
      ImageContext->ImageAddress,
      SectionHeader.Name
      ));
    DEBUG ((
      DEBUG_INFO,
      "%a: Section %d of image at 0x%lx has 0x%x address\n",
      __FUNCTION__,
      Index,
      ImageContext->ImageAddress,
      ImageContext->ImageAddress + SectionHeader.VirtualAddress
      ));
    DEBUG ((
      DEBUG_INFO,
      "%a: Section %d of image at 0x%lx has 0x%x data\n",
      __FUNCTION__,
      Index,
      ImageContext->ImageAddress,
      SectionHeader.PointerToRawData
      ));

    //
    // If the section is marked as XN then remove the X attribute. Furthermore,
    // if it is a writeable section then mark it appropriately as well.
    //
    if ((SectionHeader.Characteristics & EFI_IMAGE_SCN_MEM_EXECUTE) == 0) {
      Base = ImageBase + SectionHeader.VirtualAddress;

      TextUpdater (Base, SectionHeader.Misc.VirtualSize);

      if ((SectionHeader.Characteristics & EFI_IMAGE_SCN_MEM_WRITE) != 0) {
        ReadWriteUpdater (Base, SectionHeader.Misc.VirtualSize);
        DEBUG ((
          DEBUG_INFO,
          "%a: Mapping section %d of image at 0x%lx with RW-XN permissions\n",
          __FUNCTION__,
          Index,
          ImageContext->ImageAddress
          ));
      } else {
        DEBUG ((
          DEBUG_INFO,
          "%a: Mapping section %d of image at 0x%lx with RO-XN permissions\n",
          __FUNCTION__,
          Index,
          ImageContext->ImageAddress
          ));
      }
    } else {
      DEBUG ((
        DEBUG_INFO,
        "%a: Ignoring section %d of image at 0x%lx with 0x%x permissions\n",
        __FUNCTION__,
        Index,
        ImageContext->ImageAddress,
        SectionHeader.Characteristics
        ));
    }

    SectionHeaderOffset += sizeof (EFI_IMAGE_SECTION_HEADER);
  }

  return RETURN_SUCCESS;
}

/**
  Privileged firmware assigns RO & Executable attributes to all memory occupied
  by the Boot Firmware Volume. This function locates the Standalone MM Core
  module PE/COFF image in the BFV and returns this information.

  @param  [in]      BfvAddress         Base Address of Boot Firmware Volume
  @param  [in, out] TeData             Pointer to address for allocating memory
                                       for PE/COFF image data
  @param  [in, out] TeDataSize         Pointer to size of PE/COFF image data

**/
EFI_STATUS
EFIAPI
LocateStandaloneMmCorePeCoffData (
  IN        EFI_FIRMWARE_VOLUME_HEADER  *BfvAddress,
  IN  OUT   VOID                        **TeData,
  IN  OUT   UINTN                       *TeDataSize
  )
{
  EFI_FFS_FILE_HEADER  *FileHeader;
  EFI_STATUS           Status;

  FileHeader = NULL;
  Status     = FfsFindNextFile (
                 EFI_FV_FILETYPE_SECURITY_CORE,
                 BfvAddress,
                 &FileHeader
                 );

  if (EFI_ERROR (Status)) {
    DEBUG ((
      DEBUG_ERROR,
      "Unable to locate Standalone MM FFS file - 0x%x\n",
      Status
      ));
    return Status;
  }

  Status = FfsFindSectionData (EFI_SECTION_PE32, FileHeader, TeData, TeDataSize);
  if (EFI_ERROR (Status)) {
    Status = FfsFindSectionData (EFI_SECTION_TE, FileHeader, TeData, TeDataSize);
    if (EFI_ERROR (Status)) {
      DEBUG ((
        DEBUG_ERROR,
        "Unable to locate Standalone MM Section data - %r\n",
        Status
        ));
      return Status;
    }
  }

  DEBUG ((DEBUG_INFO, "Found Standalone MM PE data - 0x%x\n", *TeData));
  return Status;
}

/**
  Returns the PC COFF section information.

  @param  [in, out] ImageContext         Pointer to PE/COFF image context
  @param  [out]     ImageBase            Base of image in memory
  @param  [out]     SectionHeaderOffset  Offset of PE/COFF image section header
  @param  [out]     NumberOfSections     Number of Sections

**/
STATIC
EFI_STATUS
GetPeCoffSectionInformation (
  IN  OUT   PE_COFF_LOADER_IMAGE_CONTEXT  *ImageContext,
  OUT   EFI_PHYSICAL_ADDRESS              *ImageBase,
  OUT   UINT32                            *SectionHeaderOffset,
  OUT   UINT16                            *NumberOfSections
  )
{
  RETURN_STATUS                        Status;
  EFI_IMAGE_OPTIONAL_HEADER_PTR_UNION  Hdr;
  EFI_IMAGE_OPTIONAL_HEADER_UNION      HdrData;
  UINTN                                Size;
  UINTN                                ReadSize;

  ASSERT (ImageContext != NULL);
  ASSERT (SectionHeaderOffset != NULL);
  ASSERT (NumberOfSections != NULL);

  Status = PeCoffLoaderGetImageInfo (ImageContext);
  if (RETURN_ERROR (Status)) {
    DEBUG ((
      DEBUG_ERROR,
      "%a: PeCoffLoaderGetImageInfo () failed (Status == %r)\n",
      __FUNCTION__,
      Status
      ));
    return Status;
  }

  if (ImageContext->SectionAlignment < EFI_PAGE_SIZE) {
    //
    // The sections need to be at least 4 KB aligned, since that is the
    // granularity at which we can tighten permissions.
    //
    if (!ImageContext->IsTeImage) {
      DEBUG ((
        DEBUG_WARN,
        "%a: non-TE Image at 0x%lx has SectionAlignment < 4 KB (%lu)\n",
        __FUNCTION__,
        ImageContext->ImageAddress,
        ImageContext->SectionAlignment
        ));
      return RETURN_UNSUPPORTED;
    }

    ImageContext->SectionAlignment = EFI_PAGE_SIZE;
  }

  //
  // Read the PE/COFF Header. For PE32 (32-bit) this will read in too much
  // data, but that should not hurt anything. Hdr.Pe32->OptionalHeader.Magic
  // determines if this is a PE32 or PE32+ image. The magic is in the same
  // location in both images.
  //
  Hdr.Union = &HdrData;
  Size      = sizeof (EFI_IMAGE_OPTIONAL_HEADER_UNION);
  ReadSize  = Size;
  Status    = ImageContext->ImageRead (
                              ImageContext->Handle,
                              ImageContext->PeCoffHeaderOffset,
                              &Size,
                              Hdr.Pe32
                              );

  if (RETURN_ERROR (Status) || (Size != ReadSize)) {
    DEBUG ((
      DEBUG_ERROR,
      "%a: TmpContext->ImageRead () failed (Status = %r)\n",
      __FUNCTION__,
      Status
      ));
    return Status;
  }

  *ImageBase = ImageContext->ImageAddress;
  if (!ImageContext->IsTeImage) {
    ASSERT (Hdr.Pe32->Signature == EFI_IMAGE_NT_SIGNATURE);

    *SectionHeaderOffset = ImageContext->PeCoffHeaderOffset + sizeof (UINT32) +
                           sizeof (EFI_IMAGE_FILE_HEADER);
    *NumberOfSections = Hdr.Pe32->FileHeader.NumberOfSections;

    switch (Hdr.Pe32->OptionalHeader.Magic) {
      case EFI_IMAGE_NT_OPTIONAL_HDR32_MAGIC:
        *SectionHeaderOffset += Hdr.Pe32->FileHeader.SizeOfOptionalHeader;
        break;
      case EFI_IMAGE_NT_OPTIONAL_HDR64_MAGIC:
        *SectionHeaderOffset += Hdr.Pe32Plus->FileHeader.SizeOfOptionalHeader;
        break;
      default:
        ASSERT (FALSE);
    }
  } else {
    *SectionHeaderOffset = (UINTN)(sizeof (EFI_TE_IMAGE_HEADER));
    *NumberOfSections    = Hdr.Te->NumberOfSections;
    *ImageBase          -= (UINT32)Hdr.Te->StrippedSize - sizeof (EFI_TE_IMAGE_HEADER);
  }

  return RETURN_SUCCESS;
}

/**
  Privileged firmware assigns RO & Executable attributes to all memory occupied
  by the Boot Firmware Volume. This function locates the section information of
  the Standalone MM Core module to be able to change permissions of the
  individual sections later in the boot process.

  @param  [in]      TeData                Pointer to PE/COFF image data
  @param  [in, out] ImageContext          Pointer to PE/COFF image context
  @param  [out]     ImageBase             Pointer to ImageBase variable
  @param  [in, out] SectionHeaderOffset   Offset of PE/COFF image section header
  @param  [in, out] NumberOfSections      Number of Sections

**/
EFI_STATUS
EFIAPI
GetStandaloneMmCorePeCoffSections (
  IN        VOID                          *TeData,
  IN  OUT   PE_COFF_LOADER_IMAGE_CONTEXT  *ImageContext,
  OUT   EFI_PHYSICAL_ADDRESS              *ImageBase,
  IN  OUT   UINT32                        *SectionHeaderOffset,
  IN  OUT   UINT16                        *NumberOfSections
  )
{
  EFI_STATUS  Status;

  // Initialize the Image Context
  ZeroMem (ImageContext, sizeof (PE_COFF_LOADER_IMAGE_CONTEXT));
  ImageContext->Handle    = TeData;
  ImageContext->ImageRead = PeCoffLoaderImageReadFromMemory;

  DEBUG ((DEBUG_INFO, "Found Standalone MM PE data - 0x%x\n", TeData));

  Status = GetPeCoffSectionInformation (
             ImageContext,
             ImageBase,
             SectionHeaderOffset,
             NumberOfSections
             );
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, "Unable to locate Standalone MM Core PE-COFF Section information - %r\n", Status));
    return Status;
  }

  DEBUG ((
    DEBUG_INFO,
    "Standalone MM Core PE-COFF SectionHeaderOffset - 0x%x, NumberOfSections - %d\n",
    *SectionHeaderOffset,
    *NumberOfSections
    ));

  return Status;
}
