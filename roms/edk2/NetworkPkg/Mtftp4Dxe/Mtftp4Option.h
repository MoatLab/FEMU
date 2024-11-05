/** @file
  Routines to process MTFTP4 options.

Copyright (c) 2006 - 2018, Intel Corporation. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#ifndef __EFI_MTFTP4_OPTION_H__
#define __EFI_MTFTP4_OPTION_H__

#define MTFTP4_SUPPORTED_OPTIONS  5
#define MTFTP4_OPCODE_LEN         2
#define MTFTP4_ERRCODE_LEN        2
#define MTFTP4_BLKNO_LEN          2
#define MTFTP4_DATA_HEAD_LEN      4

#define MTFTP4_BLKSIZE_EXIST     0x01
#define MTFTP4_TIMEOUT_EXIST     0x02
#define MTFTP4_TSIZE_EXIST       0x04
#define MTFTP4_MCAST_EXIST       0x08
#define MTFTP4_WINDOWSIZE_EXIST  0x10

typedef struct {
  UINT16      BlkSize;
  UINT16      WindowSize;
  UINT8       Timeout;
  UINT32      Tsize;
  IP4_ADDR    McastIp;
  UINT16      McastPort;
  BOOLEAN     Master;
  UINT32      Exist;
} MTFTP4_OPTION;

/**
  Allocate and fill in a array of Mtftp options from the Packet.

  It first calls Mtftp4FillOption to get the option number, then allocate
  the array, at last, call Mtftp4FillOption again to save the options.

  @param  Packet                 The packet to parse
  @param  PacketLen              The length of the packet
  @param  OptionCount            The number of options in the packet
  @param  OptionList             The point to get the option array.

  @retval EFI_INVALID_PARAMETER  The parametera are invalid or packet isn't a
                                 well-formatted OACK packet.
  @retval EFI_SUCCESS            The option array is build
  @retval EFI_OUT_OF_RESOURCES   Failed to allocate memory for the array

**/
EFI_STATUS
Mtftp4ExtractOptions (
  IN     EFI_MTFTP4_PACKET  *Packet,
  IN     UINT32             PacketLen,
  OUT UINT32                *OptionCount,
  OUT EFI_MTFTP4_OPTION     **OptionList        OPTIONAL
  );

/**
  Parse the option in Options array to MTFTP4_OPTION which program
  can access directly.

  @param  Options                The option array, which contains addresses of each
                                 option's name/value string.
  @param  Count                  The number of options in the Options
  @param  Request                Whether this is a request or OACK. The format of
                                 multicast is different according to this setting.
  @param  Operation              The current performed operation.
  @param  MtftpOption            The MTFTP4_OPTION for easy access.

  @retval EFI_INVALID_PARAMETER  The option is malformatted
  @retval EFI_UNSUPPORTED        Some option isn't supported
  @retval EFI_SUCCESS            The option are OK and has been parsed.

**/
EFI_STATUS
Mtftp4ParseOption (
  IN     EFI_MTFTP4_OPTION  *Options,
  IN     UINT32             Count,
  IN     BOOLEAN            Request,
  IN     UINT16             Operation,
  OUT MTFTP4_OPTION         *MtftpOption
  );

/**
  Parse the options in the OACK packet to MTFTP4_OPTION which program
  can access directly.

  @param  Packet                 The OACK packet to parse
  @param  PacketLen              The length of the packet
  @param  Operation              The current performed operation.
  @param  MtftpOption            The MTFTP_OPTION for easy access.

  @retval EFI_INVALID_PARAMETER  The packet option is malformatted
  @retval EFI_UNSUPPORTED        Some option isn't supported
  @retval EFI_SUCCESS            The option are OK and has been parsed.

**/
EFI_STATUS
Mtftp4ParseOptionOack (
  IN     EFI_MTFTP4_PACKET  *Packet,
  IN     UINT32             PacketLen,
  IN     UINT16             Operation,
  OUT MTFTP4_OPTION         *MtftpOption
  );

extern CHAR8  *mMtftp4SupportedOptions[MTFTP4_SUPPORTED_OPTIONS];

#endif
