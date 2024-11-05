/** @file
  FrameBufferBltLib - Library to perform blt operations on a frame buffer.

  Copyright (c) 2007 - 2018, Intel Corporation. All rights reserved.<BR>
  SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include <Uefi/UefiBaseType.h>
#include <Protocol/GraphicsOutput.h>

#include <Library/BaseLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/DebugLib.h>
#include <Library/FrameBufferBltLib.h>

struct FRAME_BUFFER_CONFIGURE {
  UINT32                       PixelsPerScanLine;
  UINT32                       BytesPerPixel;
  UINT32                       Width;
  UINT32                       Height;
  UINT8                        *FrameBuffer;
  EFI_GRAPHICS_PIXEL_FORMAT    PixelFormat;
  EFI_PIXEL_BITMASK            PixelMasks;
  INT8                         PixelShl[4];    // R-G-B-Rsvd
  INT8                         PixelShr[4];    // R-G-B-Rsvd
  UINT8                        LineBuffer[0];
};

CONST EFI_PIXEL_BITMASK  mRgbPixelMasks = {
  0x000000ff, 0x0000ff00, 0x00ff0000, 0xff000000
};

CONST EFI_PIXEL_BITMASK  mBgrPixelMasks = {
  0x00ff0000, 0x0000ff00, 0x000000ff, 0xff000000
};

/**
  Initialize the bit mask in frame buffer configure.

  @param BitMask       The bit mask of pixel.
  @param BytesPerPixel Size in bytes of pixel.
  @param PixelShl      Left shift array.
  @param PixelShr      Right shift array.
**/
VOID
FrameBufferBltLibConfigurePixelFormat (
  IN CONST EFI_PIXEL_BITMASK  *BitMask,
  OUT UINT32                  *BytesPerPixel,
  OUT INT8                    *PixelShl,
  OUT INT8                    *PixelShr
  )
{
  UINT8   Index;
  UINT32  *Masks;
  UINT32  MergedMasks;

  ASSERT (BytesPerPixel != NULL);

  MergedMasks = 0;
  Masks       = (UINT32 *)BitMask;
  for (Index = 0; Index < 3; Index++) {
    ASSERT ((MergedMasks & Masks[Index]) == 0);

    PixelShl[Index] = (INT8)HighBitSet32 (Masks[Index]) - 23 + (Index * 8);
    if (PixelShl[Index] < 0) {
      PixelShr[Index] = -PixelShl[Index];
      PixelShl[Index] = 0;
    } else {
      PixelShr[Index] = 0;
    }

    DEBUG ((
      DEBUG_INFO,
      "%d: shl:%d shr:%d mask:%x\n",
      Index,
      PixelShl[Index],
      PixelShr[Index],
      Masks[Index]
      ));

    MergedMasks = (UINT32)(MergedMasks | Masks[Index]);
  }

  MergedMasks = (UINT32)(MergedMasks | Masks[3]);

  ASSERT (MergedMasks != 0);
  *BytesPerPixel = (UINT32)((HighBitSet32 (MergedMasks) + 7) / 8);
  DEBUG ((DEBUG_INFO, "Bytes per pixel: %d\n", *BytesPerPixel));
}

/**
  Create the configuration for a video frame buffer.

  The configuration is returned in the caller provided buffer.

  @param[in] FrameBuffer       Pointer to the start of the frame buffer.
  @param[in] FrameBufferInfo   Describes the frame buffer characteristics.
  @param[in,out] Configure     The created configuration information.
  @param[in,out] ConfigureSize Size of the configuration information.

  @retval RETURN_SUCCESS            The configuration was successful created.
  @retval RETURN_BUFFER_TOO_SMALL   The Configure is to too small. The required
                                    size is returned in ConfigureSize.
  @retval RETURN_UNSUPPORTED        The requested mode is not supported by
                                    this implementaion.

**/
RETURN_STATUS
EFIAPI
FrameBufferBltConfigure (
  IN     VOID                                  *FrameBuffer,
  IN     EFI_GRAPHICS_OUTPUT_MODE_INFORMATION  *FrameBufferInfo,
  IN OUT FRAME_BUFFER_CONFIGURE                *Configure,
  IN OUT UINTN                                 *ConfigureSize
  )
{
  CONST EFI_PIXEL_BITMASK  *BitMask;
  UINT32                   BytesPerPixel;
  INT8                     PixelShl[4];
  INT8                     PixelShr[4];

  if (ConfigureSize == NULL) {
    return RETURN_INVALID_PARAMETER;
  }

  switch (FrameBufferInfo->PixelFormat) {
    case PixelRedGreenBlueReserved8BitPerColor:
      BitMask = &mRgbPixelMasks;
      break;

    case PixelBlueGreenRedReserved8BitPerColor:
      BitMask = &mBgrPixelMasks;
      break;

    case PixelBitMask:
      BitMask = &FrameBufferInfo->PixelInformation;
      break;

    case PixelBltOnly:
      ASSERT (FrameBufferInfo->PixelFormat != PixelBltOnly);
      return RETURN_UNSUPPORTED;

    default:
      ASSERT (FALSE);
      return RETURN_INVALID_PARAMETER;
  }

  if (FrameBufferInfo->PixelsPerScanLine < FrameBufferInfo->HorizontalResolution) {
    return RETURN_UNSUPPORTED;
  }

  FrameBufferBltLibConfigurePixelFormat (BitMask, &BytesPerPixel, PixelShl, PixelShr);

  if (*ConfigureSize < sizeof (FRAME_BUFFER_CONFIGURE)
      + FrameBufferInfo->HorizontalResolution * BytesPerPixel)
  {
    *ConfigureSize = sizeof (FRAME_BUFFER_CONFIGURE)
                     + FrameBufferInfo->HorizontalResolution * BytesPerPixel;
    return RETURN_BUFFER_TOO_SMALL;
  }

  if (Configure == NULL) {
    return RETURN_INVALID_PARAMETER;
  }

  CopyMem (&Configure->PixelMasks, BitMask, sizeof (*BitMask));
  CopyMem (Configure->PixelShl, PixelShl, sizeof (PixelShl));
  CopyMem (Configure->PixelShr, PixelShr, sizeof (PixelShr));
  Configure->BytesPerPixel     = BytesPerPixel;
  Configure->PixelFormat       = FrameBufferInfo->PixelFormat;
  Configure->FrameBuffer       = (UINT8 *)FrameBuffer;
  Configure->Width             = FrameBufferInfo->HorizontalResolution;
  Configure->Height            = FrameBufferInfo->VerticalResolution;
  Configure->PixelsPerScanLine = FrameBufferInfo->PixelsPerScanLine;

  return RETURN_SUCCESS;
}

/**
  Performs a UEFI Graphics Output Protocol Blt Video Fill.

  @param[in]  Configure     Pointer to a configuration which was successfully
                            created by FrameBufferBltConfigure ().
  @param[in]  Color         Color to fill the region with.
  @param[in]  DestinationX  X location to start fill operation.
  @param[in]  DestinationY  Y location to start fill operation.
  @param[in]  Width         Width (in pixels) to fill.
  @param[in]  Height        Height to fill.

  @retval  RETURN_INVALID_PARAMETER Invalid parameter was passed in.
  @retval  RETURN_SUCCESS           The video was filled successfully.

**/
EFI_STATUS
FrameBufferBltLibVideoFill (
  IN  FRAME_BUFFER_CONFIGURE         *Configure,
  IN  EFI_GRAPHICS_OUTPUT_BLT_PIXEL  *Color,
  IN  UINTN                          DestinationX,
  IN  UINTN                          DestinationY,
  IN  UINTN                          Width,
  IN  UINTN                          Height
  )
{
  UINTN    IndexX;
  UINTN    IndexY;
  UINT8    *Destination;
  UINT8    Uint8;
  UINT32   Uint32;
  UINT64   WideFill;
  BOOLEAN  UseWideFill;
  BOOLEAN  LineBufferReady;
  UINTN    Offset;
  UINTN    WidthInBytes;
  UINTN    SizeInBytes;

  //
  // BltBuffer to Video: Source is BltBuffer, destination is Video
  //
  if (DestinationY + Height > Configure->Height) {
    DEBUG ((DEBUG_VERBOSE, "VideoFill: Past screen (Y)\n"));
    return RETURN_INVALID_PARAMETER;
  }

  if (DestinationX + Width > Configure->Width) {
    DEBUG ((DEBUG_VERBOSE, "VideoFill: Past screen (X)\n"));
    return RETURN_INVALID_PARAMETER;
  }

  if ((Width == 0) || (Height == 0)) {
    DEBUG ((DEBUG_VERBOSE, "VideoFill: Width or Height is 0\n"));
    return RETURN_INVALID_PARAMETER;
  }

  WidthInBytes = Width * Configure->BytesPerPixel;

  Uint32   = *(UINT32 *)Color;
  WideFill =
    (UINT32)(
             (((Uint32 << Configure->PixelShl[0]) >> Configure->PixelShr[0]) &
              Configure->PixelMasks.RedMask) |
             (((Uint32 << Configure->PixelShl[1]) >> Configure->PixelShr[1]) &
              Configure->PixelMasks.GreenMask) |
             (((Uint32 << Configure->PixelShl[2]) >> Configure->PixelShr[2]) &
              Configure->PixelMasks.BlueMask)
             );
  DEBUG ((
    DEBUG_VERBOSE,
    "VideoFill: color=0x%x, wide-fill=0x%x\n",
    Uint32,
    WideFill
    ));

  //
  // If the size of the pixel data evenly divides the sizeof
  // WideFill, then a wide fill operation can be used
  //
  UseWideFill = TRUE;
  if ((sizeof (WideFill) % Configure->BytesPerPixel) == 0) {
    for (IndexX = Configure->BytesPerPixel; IndexX < sizeof (WideFill); IndexX++) {
      ((UINT8 *)&WideFill)[IndexX] = ((UINT8 *)&WideFill)[IndexX % Configure->BytesPerPixel];
    }
  } else {
    //
    // If all the bytes in the pixel are the same value, then use
    // a wide fill operation.
    //
    for (
         IndexX = 1, Uint8 = ((UINT8 *)&WideFill)[0];
         IndexX < Configure->BytesPerPixel;
         IndexX++)
    {
      if (Uint8 != ((UINT8 *)&WideFill)[IndexX]) {
        UseWideFill = FALSE;
        break;
      }
    }

    if (UseWideFill) {
      SetMem (&WideFill, sizeof (WideFill), Uint8);
    }
  }

  if (UseWideFill && (DestinationX == 0) && (Width == Configure->PixelsPerScanLine)) {
    DEBUG ((DEBUG_VERBOSE, "VideoFill (wide, one-shot)\n"));
    Offset      = DestinationY * Configure->PixelsPerScanLine;
    Offset      = Configure->BytesPerPixel * Offset;
    Destination = Configure->FrameBuffer + Offset;
    SizeInBytes = WidthInBytes * Height;
    if (SizeInBytes >= 8) {
      SetMem32 (Destination, SizeInBytes & ~3, (UINT32)WideFill);
      Destination += SizeInBytes & ~3;
      SizeInBytes &= 3;
    }

    if (SizeInBytes > 0) {
      SetMem (Destination, SizeInBytes, (UINT8)(UINTN)WideFill);
    }
  } else {
    LineBufferReady = FALSE;
    for (IndexY = DestinationY; IndexY < (Height + DestinationY); IndexY++) {
      Offset      = (IndexY * Configure->PixelsPerScanLine) + DestinationX;
      Offset      = Configure->BytesPerPixel * Offset;
      Destination = Configure->FrameBuffer + Offset;

      if (UseWideFill && (((UINTN)Destination & 7) == 0)) {
        DEBUG ((DEBUG_VERBOSE, "VideoFill (wide)\n"));
        SizeInBytes = WidthInBytes;
        if (SizeInBytes >= 8) {
          SetMem64 (Destination, SizeInBytes & ~7, WideFill);
          Destination += SizeInBytes & ~7;
          SizeInBytes &= 7;
        }

        if (SizeInBytes > 0) {
          CopyMem (Destination, &WideFill, SizeInBytes);
        }
      } else {
        DEBUG ((DEBUG_VERBOSE, "VideoFill (not wide)\n"));
        if (!LineBufferReady) {
          CopyMem (Configure->LineBuffer, &WideFill, Configure->BytesPerPixel);
          for (IndexX = 1; IndexX < Width; ) {
            CopyMem (
              (Configure->LineBuffer + (IndexX * Configure->BytesPerPixel)),
              Configure->LineBuffer,
              MIN (IndexX, Width - IndexX) * Configure->BytesPerPixel
              );
            IndexX += MIN (IndexX, Width - IndexX);
          }

          LineBufferReady = TRUE;
        }

        CopyMem (Destination, Configure->LineBuffer, WidthInBytes);
      }
    }
  }

  return RETURN_SUCCESS;
}

/**
  Performs a UEFI Graphics Output Protocol Blt Video to Buffer operation
  with extended parameters.

  @param[in]  Configure     Pointer to a configuration which was successfully
                            created by FrameBufferBltConfigure ().
  @param[out] BltBuffer     Output buffer for pixel color data.
  @param[in]  SourceX       X location within video.
  @param[in]  SourceY       Y location within video.
  @param[in]  DestinationX  X location within BltBuffer.
  @param[in]  DestinationY  Y location within BltBuffer.
  @param[in]  Width         Width (in pixels).
  @param[in]  Height        Height.
  @param[in]  Delta         Number of bytes in a row of BltBuffer.

  @retval RETURN_INVALID_PARAMETER Invalid parameter were passed in.
  @retval RETURN_SUCCESS           The Blt operation was performed successfully.
**/
RETURN_STATUS
FrameBufferBltLibVideoToBltBuffer (
  IN     FRAME_BUFFER_CONFIGURE      *Configure,
  OUT EFI_GRAPHICS_OUTPUT_BLT_PIXEL  *BltBuffer,
  IN     UINTN                       SourceX,
  IN     UINTN                       SourceY,
  IN     UINTN                       DestinationX,
  IN     UINTN                       DestinationY,
  IN     UINTN                       Width,
  IN     UINTN                       Height,
  IN     UINTN                       Delta
  )
{
  UINTN                          DstY;
  UINTN                          SrcY;
  EFI_GRAPHICS_OUTPUT_BLT_PIXEL  *Blt;
  UINT8                          *Source;
  UINT8                          *Destination;
  UINTN                          IndexX;
  UINT32                         Uint32;
  UINTN                          Offset;
  UINTN                          WidthInBytes;

  //
  // Video to BltBuffer: Source is Video, destination is BltBuffer
  //
  if (SourceY + Height > Configure->Height) {
    return RETURN_INVALID_PARAMETER;
  }

  if (SourceX + Width > Configure->Width) {
    return RETURN_INVALID_PARAMETER;
  }

  if ((Width == 0) || (Height == 0)) {
    return RETURN_INVALID_PARAMETER;
  }

  //
  // If Delta is zero, then the entire BltBuffer is being used, so Delta is
  // the number of bytes in each row of BltBuffer. Since BltBuffer is Width
  // pixels size, the number of bytes in each row can be computed.
  //
  if (Delta == 0) {
    Delta = Width * sizeof (EFI_GRAPHICS_OUTPUT_BLT_PIXEL);
  }

  WidthInBytes = Width * Configure->BytesPerPixel;

  //
  // Video to BltBuffer: Source is Video, destination is BltBuffer
  //
  for (SrcY = SourceY, DstY = DestinationY;
       DstY < (Height + DestinationY);
       SrcY++, DstY++)
  {
    Offset = (SrcY * Configure->PixelsPerScanLine) + SourceX;
    Offset = Configure->BytesPerPixel * Offset;
    Source = Configure->FrameBuffer + Offset;

    if (Configure->PixelFormat == PixelBlueGreenRedReserved8BitPerColor) {
      Destination = (UINT8 *)BltBuffer + (DstY * Delta) + (DestinationX * sizeof (EFI_GRAPHICS_OUTPUT_BLT_PIXEL));
    } else {
      Destination = Configure->LineBuffer;
    }

    CopyMem (Destination, Source, WidthInBytes);

    if (Configure->PixelFormat != PixelBlueGreenRedReserved8BitPerColor) {
      for (IndexX = 0; IndexX < Width; IndexX++) {
        Blt = (EFI_GRAPHICS_OUTPUT_BLT_PIXEL *)
              ((UINT8 *)BltBuffer + (DstY * Delta) +
               (DestinationX + IndexX) * sizeof (EFI_GRAPHICS_OUTPUT_BLT_PIXEL));
        Uint32         = *(UINT32 *)(Configure->LineBuffer + (IndexX * Configure->BytesPerPixel));
        *(UINT32 *)Blt =
          (UINT32)(
                   (((Uint32 & Configure->PixelMasks.RedMask) >>
                     Configure->PixelShl[0]) << Configure->PixelShr[0]) |
                   (((Uint32 & Configure->PixelMasks.GreenMask) >>
                     Configure->PixelShl[1]) << Configure->PixelShr[1]) |
                   (((Uint32 & Configure->PixelMasks.BlueMask) >>
                     Configure->PixelShl[2]) << Configure->PixelShr[2])
                   );
      }
    }
  }

  return RETURN_SUCCESS;
}

/**
  Performs a UEFI Graphics Output Protocol Blt Buffer to Video operation
  with extended parameters.

  @param[in]  Configure     Pointer to a configuration which was successfully
                            created by FrameBufferBltConfigure ().
  @param[in]  BltBuffer     Output buffer for pixel color data.
  @param[in]  SourceX       X location within BltBuffer.
  @param[in]  SourceY       Y location within BltBuffer.
  @param[in]  DestinationX  X location within video.
  @param[in]  DestinationY  Y location within video.
  @param[in]  Width         Width (in pixels).
  @param[in]  Height        Height.
  @param[in]  Delta         Number of bytes in a row of BltBuffer.

  @retval RETURN_INVALID_PARAMETER Invalid parameter were passed in.
  @retval RETURN_SUCCESS           The Blt operation was performed successfully.
**/
RETURN_STATUS
FrameBufferBltLibBufferToVideo (
  IN  FRAME_BUFFER_CONFIGURE         *Configure,
  IN  EFI_GRAPHICS_OUTPUT_BLT_PIXEL  *BltBuffer,
  IN  UINTN                          SourceX,
  IN  UINTN                          SourceY,
  IN  UINTN                          DestinationX,
  IN  UINTN                          DestinationY,
  IN  UINTN                          Width,
  IN  UINTN                          Height,
  IN  UINTN                          Delta
  )
{
  UINTN                          DstY;
  UINTN                          SrcY;
  EFI_GRAPHICS_OUTPUT_BLT_PIXEL  *Blt;
  UINT8                          *Source;
  UINT8                          *Destination;
  UINTN                          IndexX;
  UINT32                         Uint32;
  UINTN                          Offset;
  UINTN                          WidthInBytes;

  //
  // BltBuffer to Video: Source is BltBuffer, destination is Video
  //
  if (DestinationY + Height > Configure->Height) {
    return RETURN_INVALID_PARAMETER;
  }

  if (DestinationX + Width > Configure->Width) {
    return RETURN_INVALID_PARAMETER;
  }

  if ((Width == 0) || (Height == 0)) {
    return RETURN_INVALID_PARAMETER;
  }

  //
  // If Delta is zero, then the entire BltBuffer is being used, so Delta is
  // the number of bytes in each row of BltBuffer. Since BltBuffer is Width
  // pixels size, the number of bytes in each row can be computed.
  //
  if (Delta == 0) {
    Delta = Width * sizeof (EFI_GRAPHICS_OUTPUT_BLT_PIXEL);
  }

  WidthInBytes = Width * Configure->BytesPerPixel;

  for (SrcY = SourceY, DstY = DestinationY;
       SrcY < (Height + SourceY);
       SrcY++, DstY++)
  {
    Offset      = (DstY * Configure->PixelsPerScanLine) + DestinationX;
    Offset      = Configure->BytesPerPixel * Offset;
    Destination = Configure->FrameBuffer + Offset;

    if (Configure->PixelFormat == PixelBlueGreenRedReserved8BitPerColor) {
      Source = (UINT8 *)BltBuffer + (SrcY * Delta) + SourceX * sizeof (EFI_GRAPHICS_OUTPUT_BLT_PIXEL);
    } else {
      for (IndexX = 0; IndexX < Width; IndexX++) {
        Blt =
          (EFI_GRAPHICS_OUTPUT_BLT_PIXEL *)(
                                            (UINT8 *)BltBuffer +
                                            (SrcY * Delta) +
                                            ((SourceX + IndexX) * sizeof (EFI_GRAPHICS_OUTPUT_BLT_PIXEL))
                                            );
        Uint32                                                                   = *(UINT32 *)Blt;
        *(UINT32 *)(Configure->LineBuffer + (IndexX * Configure->BytesPerPixel)) =
          (UINT32)(
                   (((Uint32 << Configure->PixelShl[0]) >> Configure->PixelShr[0]) &
                    Configure->PixelMasks.RedMask) |
                   (((Uint32 << Configure->PixelShl[1]) >> Configure->PixelShr[1]) &
                    Configure->PixelMasks.GreenMask) |
                   (((Uint32 << Configure->PixelShl[2]) >> Configure->PixelShr[2]) &
                    Configure->PixelMasks.BlueMask)
                   );
      }

      Source = Configure->LineBuffer;
    }

    CopyMem (Destination, Source, WidthInBytes);
  }

  return RETURN_SUCCESS;
}

/**
  Performs a UEFI Graphics Output Protocol Blt Video to Video operation

  @param[in]  Configure     Pointer to a configuration which was successfully
                            created by FrameBufferBltConfigure ().
  @param[in]  SourceX       X location within video.
  @param[in]  SourceY       Y location within video.
  @param[in]  DestinationX  X location within video.
  @param[in]  DestinationY  Y location within video.
  @param[in]  Width         Width (in pixels).
  @param[in]  Height        Height.

  @retval RETURN_INVALID_PARAMETER Invalid parameter were passed in.
  @retval RETURN_SUCCESS           The Blt operation was performed successfully.
**/
RETURN_STATUS
FrameBufferBltLibVideoToVideo (
  IN  FRAME_BUFFER_CONFIGURE  *Configure,
  IN  UINTN                   SourceX,
  IN  UINTN                   SourceY,
  IN  UINTN                   DestinationX,
  IN  UINTN                   DestinationY,
  IN  UINTN                   Width,
  IN  UINTN                   Height
  )
{
  UINT8  *Source;
  UINT8  *Destination;
  UINTN  Offset;
  UINTN  WidthInBytes;
  INTN   LineStride;

  //
  // Video to Video: Source is Video, destination is Video
  //
  if (SourceY + Height > Configure->Height) {
    return RETURN_INVALID_PARAMETER;
  }

  if (SourceX + Width > Configure->Width) {
    return RETURN_INVALID_PARAMETER;
  }

  if (DestinationY + Height > Configure->Height) {
    return RETURN_INVALID_PARAMETER;
  }

  if (DestinationX + Width > Configure->Width) {
    return RETURN_INVALID_PARAMETER;
  }

  if ((Width == 0) || (Height == 0)) {
    return RETURN_INVALID_PARAMETER;
  }

  WidthInBytes = Width * Configure->BytesPerPixel;

  Offset = (SourceY * Configure->PixelsPerScanLine) + SourceX;
  Offset = Configure->BytesPerPixel * Offset;
  Source = Configure->FrameBuffer + Offset;

  Offset      = (DestinationY * Configure->PixelsPerScanLine) + DestinationX;
  Offset      = Configure->BytesPerPixel * Offset;
  Destination = Configure->FrameBuffer + Offset;

  LineStride = Configure->BytesPerPixel * Configure->PixelsPerScanLine;
  if (Destination > Source) {
    //
    // Copy from last line to avoid source is corrupted by copying
    //
    Source      += Height * LineStride;
    Destination += Height * LineStride;
    LineStride   = -LineStride;
  }

  while (Height-- > 0) {
    CopyMem (Destination, Source, WidthInBytes);

    Source      += LineStride;
    Destination += LineStride;
  }

  return RETURN_SUCCESS;
}

/**
  Performs a UEFI Graphics Output Protocol Blt operation.

  @param[in]     Configure    Pointer to a configuration which was successfully
                              created by FrameBufferBltConfigure ().
  @param[in,out] BltBuffer    The data to transfer to screen.
  @param[in]     BltOperation The operation to perform.
  @param[in]     SourceX      The X coordinate of the source for BltOperation.
  @param[in]     SourceY      The Y coordinate of the source for BltOperation.
  @param[in]     DestinationX The X coordinate of the destination for
                              BltOperation.
  @param[in]     DestinationY The Y coordinate of the destination for
                              BltOperation.
  @param[in]     Width        The width of a rectangle in the blt rectangle
                              in pixels.
  @param[in]     Height       The height of a rectangle in the blt rectangle
                              in pixels.
  @param[in]     Delta        Not used for EfiBltVideoFill and
                              EfiBltVideoToVideo operation. If a Delta of 0
                              is used, the entire BltBuffer will be operated
                              on. If a subrectangle of the BltBuffer is
                              used, then Delta represents the number of
                              bytes in a row of the BltBuffer.

  @retval RETURN_INVALID_PARAMETER Invalid parameter were passed in.
  @retval RETURN_SUCCESS           The Blt operation was performed successfully.
**/
RETURN_STATUS
EFIAPI
FrameBufferBlt (
  IN     FRAME_BUFFER_CONFIGURE             *Configure,
  IN OUT EFI_GRAPHICS_OUTPUT_BLT_PIXEL      *BltBuffer  OPTIONAL,
  IN     EFI_GRAPHICS_OUTPUT_BLT_OPERATION  BltOperation,
  IN     UINTN                              SourceX,
  IN     UINTN                              SourceY,
  IN     UINTN                              DestinationX,
  IN     UINTN                              DestinationY,
  IN     UINTN                              Width,
  IN     UINTN                              Height,
  IN     UINTN                              Delta
  )
{
  if (Configure == NULL) {
    return RETURN_INVALID_PARAMETER;
  }

  switch (BltOperation) {
    case EfiBltVideoToBltBuffer:
      return FrameBufferBltLibVideoToBltBuffer (
               Configure,
               BltBuffer,
               SourceX,
               SourceY,
               DestinationX,
               DestinationY,
               Width,
               Height,
               Delta
               );

    case EfiBltVideoToVideo:
      return FrameBufferBltLibVideoToVideo (
               Configure,
               SourceX,
               SourceY,
               DestinationX,
               DestinationY,
               Width,
               Height
               );

    case EfiBltVideoFill:
      return FrameBufferBltLibVideoFill (
               Configure,
               BltBuffer,
               DestinationX,
               DestinationY,
               Width,
               Height
               );

    case EfiBltBufferToVideo:
      return FrameBufferBltLibBufferToVideo (
               Configure,
               BltBuffer,
               SourceX,
               SourceY,
               DestinationX,
               DestinationY,
               Width,
               Height,
               Delta
               );

    default:
      return RETURN_INVALID_PARAMETER;
  }
}
