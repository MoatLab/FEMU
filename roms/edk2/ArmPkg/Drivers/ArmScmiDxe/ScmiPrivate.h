/** @file

  Copyright (c) 2017-2021, Arm Limited. All rights reserved.<BR>

  SPDX-License-Identifier: BSD-2-Clause-Patent

  System Control and Management Interface V1.0
    http://infocenter.arm.com/help/topic/com.arm.doc.den0056a/
    DEN0056A_System_Control_and_Management_Interface.pdf
**/

#ifndef SCMI_PRIVATE_H_
#define SCMI_PRIVATE_H_

// SCMI protocol IDs.
typedef enum {
  ScmiProtocolIdBase        = 0x10,
  ScmiProtocolIdPowerDomain = 0x11,
  ScmiProtocolIdSystemPower = 0x12,
  ScmiProtocolIdPerformance = 0x13,
  ScmiProtocolIdClock       = 0x14,
  ScmiProtocolIdSensor      = 0x15
} SCMI_PROTOCOL_ID;

// SCMI message types.
typedef enum {
  ScmiMessageTypeCommand         = 0,
  ScmiMessageTypeDelayedResponse = 2, // Skipping 1 is deliberate.
  ScmiMessageTypeNotification    = 3
} SCMI_MESSAGE_TYPE;

// SCMI response error codes.
typedef enum {
  ScmiSuccess           =  0,
  ScmiNotSupported      = -1,
  ScmiInvalidParameters = -2,
  ScmiDenied            = -3,
  ScmiNotFound          = -4,
  ScmiOutOfRange        = -5,
  ScmiBusy              = -6,
  ScmiCommsError        = -7,
  ScmiGenericError      = -8,
  ScmiHardwareError     = -9,
  ScmiProtocolError     = -10
} SCMI_STATUS;

// SCMI message IDs common to all protocols.
typedef enum {
  ScmiMessageIdProtocolVersion           = 0x0,
  ScmiMessageIdProtocolAttributes        = 0x1,
  ScmiMessageIdProtocolMessageAttributes = 0x2
} SCMI_MESSAGE_ID;

// Not defined in SCMI specification but will help to identify a message.
typedef struct {
  SCMI_PROTOCOL_ID    ProtocolId;
  UINT32              MessageId;
} SCMI_COMMAND;

#pragma pack(1)

// Response to a SCMI command.
typedef struct {
  INT32     Status;
  UINT32    ReturnValues[];
} SCMI_MESSAGE_RESPONSE;

// Message header. MsgId[7:0], MsgType[9:8], ProtocolId[17:10]
#define MESSAGE_TYPE_SHIFT  8
#define PROTOCOL_ID_SHIFT   10
#define SCMI_MESSAGE_HEADER(MsgId, MsgType, ProtocolId)  (           \
                            MsgType << MESSAGE_TYPE_SHIFT   |        \
                            ProtocolId << PROTOCOL_ID_SHIFT |        \
                            MsgId                                    \
                            )
// SCMI message header.
typedef struct {
  UINT32    MessageHeader;
} SCMI_MESSAGE_HEADER;

#pragma pack()

/** Return a pointer to the message payload.

  @param[out] Payload         Holds pointer to the message payload.

  @retval EFI_SUCCESS         Payload holds a valid message payload pointer.
  @retval EFI_TIMEOUT         Time out error if MTL channel is busy.
  @retval EFI_UNSUPPORTED     If MTL channel is unsupported.
**/
EFI_STATUS
ScmiCommandGetPayload (
  OUT UINT32  **Payload
  );

/** Execute a SCMI command and receive a response.

  This function uses a MTL channel to transfer message to SCP
  and waits for a response.

  @param[in]   Command      Pointer to the SCMI command (Protocol ID
                            and Message ID)

  @param[in,out] PayloadLength   SCMI command message length.

  @param[out] OPTIONAL  ReturnValues   Pointer to SCMI response.

  @retval OUT EFI_SUCCESS       Command sent and message received successfully.
  @retval OUT EFI_UNSUPPORTED   Channel not supported.
  @retval OUT EFI_TIMEOUT       Timeout on the channel.
  @retval OUT EFI_DEVICE_ERROR  Channel not ready.
  @retval OUT EFI_DEVICE_ERROR  Message Header corrupted.
  @retval OUT EFI_DEVICE_ERROR  SCMI error.
**/
EFI_STATUS
ScmiCommandExecute (
  IN     SCMI_COMMAND  *Command,
  IN OUT UINT32        *PayloadLength,
  OUT    UINT32        **ReturnValues OPTIONAL
  );

/** Return protocol version from SCP for a given protocol ID.

  @param[in]  Protocol ID    Protocol ID.
  @param[out] Version        Pointer to version of the protocol.

  @retval EFI_SUCCESS       Version holds a valid version received
                             from the SCP.
  @retval EFI_DEVICE_ERROR  SCMI error.
  @retval !(EFI_SUCCESS)    Other errors.
**/
EFI_STATUS
ScmiGetProtocolVersion (
  IN  SCMI_PROTOCOL_ID  ProtocolId,
  OUT UINT32            *Version
  );

/** Return protocol attributes from SCP for a given protocol ID.

  @param[in]  Protocol ID    Protocol ID.
  @param[out] ReturnValues   Pointer to attributes of the protocol.

  @retval EFI_SUCCESS       ReturnValues points to protocol attributes.
  @retval EFI_DEVICE_ERROR  SCMI error.
  @retval !(EFI_SUCCESS)    Other errors.
**/
EFI_STATUS
ScmiGetProtocolAttributes (
  IN  SCMI_PROTOCOL_ID  ProtocolId,
  OUT UINT32            **ReturnValues
  );

/** Return protocol message attributes from SCP for a given protocol ID.

  @param[in]  Protocol ID    Protocol ID.

  @param[out] Attributes     Pointer to attributes of the protocol.

  @retval EFI_SUCCESS       ReturnValues points to protocol message attributes.
  @retval EFI_DEVICE_ERROR  SCMI error.
  @retval !(EFI_SUCCESS)    Other errors.
**/
EFI_STATUS
ScmiGetProtocolMessageAttributes (
  IN  SCMI_PROTOCOL_ID  ProtocolId,
  OUT UINT32            **ReturnValues
  );

#endif /* SCMI_PRIVATE_H_ */
