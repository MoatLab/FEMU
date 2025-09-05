# libspdm Library Design

1. Use static linking (Library) when there is one instance that can be linked to the device.
   For example, cryptography engine.

2. Use dynamic linking (function registration) when there are multiple instances that can be linked to the device.
   For example, transport layer.

## SPDM Library Layer

   ```
        +================+               +================+
        | SPDM Requester |               | SPDM Responder |        // PCI Component Measurement and Authentication (CMA)
        | Device Driver  |               | Device Driver  |        // PCI Integrity and Data Encryption (IDE)
        +================+               +================+
               | spdm_send_receive_data            ^ spdm_get_response_func
   =============================================================
               V                                   |
   +------------------+  +---------------+  +------------------+
   |spdm_requester_lib|->|spdm_common_lib|<-|spdm_responder_lib|   // DSP0274 - SPDM
   +------------------+  +---------------+  +------------------+
         | | |            |    |      V              | | |
         | | |            |    |  +-----------+      | | |
         | | |            |    |  |asymsignlib|      | | |         // HAL: Device Secret handling (PrivateKey)
         | | |            |    V  +-----------+      | | |
         | | |            |  +--------------+        | | |
         | | |            |  |spdm_crypt_lib|        | | |         // SPDM related crypto
         | | |            V  +--------------+        | | |
         | | |      +------------------------+       | | |
         | |  ----->|spdm_secured_message_lib|<------  | |         // DSP0277 - Secured Message in SPDM session
         | |        +------------------------+         | |
         | |                     ^      V              | |
         | |                     |  +--------+         | |
         | |                     |  | psklib |         | |         // HAL: Device Secret handling (PSK)
         | |                     |  +--------+         | |
   =============================================================
         | |                     |                     | |
         | |         +----------------------+          | |
         |  -------->|spdm_transport_xxx_lib|<---------  |         // DSP0275/DSP0276 - SPDM/SecuredMessage over MCTP
         |           | (XXX = mctp, pcidoe) |            |         // PCI Data Object Exchange (DOE) message
         |           +----------------------+            |
         |   spdm_transport_encode/decode_message_func   |
         |                                               |
   =============================================================
         |                                               |
         |     spdm_device_send/receive_message_func     |
         |              +----------------+               |
          ------------->| SPDM Device IO |<--------------          // DSP0237 - MCTP over SMBus
                        | (SMBus, PciDoe)|                         // DSP0238 - MCTP over PCIeVDM
                        +----------------+                         // PCI DOE - PCI DOE message over PCI DOE mailbox.
   ```

1) [spdm_requester_lib](https://github.com/DMTF/libspdm/blob/main/include/library/spdm_requester_lib.h) (follows DSP0274)

   This library is linked for an SPDM Requester.

2) [spdm_responder_lib](https://github.com/DMTF/libspdm/blob/main/include/library/spdm_responder_lib.h) (follows DSP0274)

   This library is linked for an SPDM Responder.

3) [spdm_common_lib](https://github.com/DMTF/libspdm/blob/main/include/library/spdm_common_lib.h) (follows DSP0274)

   This library provides common services for `spdm_requester_lib` and `spdm_responder_lib`.

4) [spdm_secured_message_lib](https://github.com/DMTF/libspdm/blob/main/include/library/spdm_secured_message_lib.h) (follows DSP0277)

   This library handles the session key generation and secured message encryption and decryption.

   This can be implemented in a secure environment if the session keys are considered a secret.

5) [spdm_crypt_lib](https://github.com/DMTF/libspdm/blob/main/include/library/spdm_crypt_lib.h)

   This library provides SPDM-related cryptography functions.

6) Transport layer encode/decode

6.1) [spdm_transport_mctp_lib](https://github.com/DMTF/libspdm/blob/main/include/library/spdm_transport_mctp_lib.h) (follows DSP0275 and DSP0276)

   This library encodes and decodes MCTP message header.

   SPDM Requester / Responder needs to register `max_spdm_msg_size`, `LIBSPDM_MCTP_TRANSPORT_HEADER_SIZE`, `LIBSPDM_MCTP_TRANSPORT_TAIL_SIZE`, `libspdm_transport_mctp_encode_message` and `libspdm_transport_mctp_decode_message` to the `spdm_requester_lib` / `spdm_responder_lib` via `libspdm_register_transport_layer_func`.

   These APIs encode and decode transport layer messages to or from a SPDM device.

6.2) [spdm_transport_pcidoe_lib](https://github.com/DMTF/libspdm/blob/main/include/library/spdm_transport_pcidoe_lib.h) (follows PCI DOE)

   This library encodes and decodes PCI DOE message header.

   SPDM Requester / Responders need to register `max_spdm_msg_size`, `LIBSPDM_PCI_DOE_TRANSPORT_HEADER_SIZE`, `LIBSPDM_PCI_DOE_TRANSPORT_TAIL_SIZE`, `libspdm_transport_pci_doe_encode_message` and `libspdm_transport_pci_doe_decode_message` to the `spdm_requester_lib` / `spdm_responder_lib` via `libspdm_register_transport_layer_func`.

   These APIs encode and decode transport layer messages to or from a SPDM device.

7) Device IO

   SPDM Requester / Responder needs to register `libspdm_device_send_message_func` and `libspdm_device_receive_message_func` to the `spdm_requester_lib` / `spdm_responder_lib` via `libspdm_register_device_io_func`.

   SPDM Requester / Responder needs to register `sender_buffer_size`, `receiver_buffer_size`, `libspdm_device_acquire_sender_buffer_func`, `libspdm_device_release_sender_buffer_func`, `libspdm_device_acquire_receiver_buffer_func`, and `libspdm_device_release_receiver_buffer_func` to the `spdm_requester_lib` / `spdm_responder_lib` via `libspdm_register_device_buffer_func`.

   These APIs send and receive transport layer messages to and from an SPDM device.

   The size of scratch buffer can be got via `libspdm_get_sizeof_required_scratch_buffer` at runtime or pre-calculated via `libspdm_get_scratch_buffer_capacity` statically.

   ```
   The sender flow is:
   {
     libspdm_acquire_sender_buffer (&sender_buffer, &sender_buffer_size);
     spdm_message_buffer = sender_buffer + transport_header_size;

     /* build SPDM request/response in spdm_message_buffer */
     transport_encode_message (spdm_message_buffer, spdm_message_buffer_size,
         &transport_message_buffer, &transport_message_buffer_size);
     send_message (transport_message_buffer, transport_message_buffer_size);

     libspdm_release_sender_buffer (sender_buffer);
   }

   The buffer usage of sender buffer is:

     ===== : SPDM message (max_header_size must be reserved before message)

     |<---                          sender_buffer_size                          --->|
           |<---                transport_message_buffer_size            --->|
     |<-transport_header_size->|<-spdm_message_buffer_size->|<-transport_tail_size->|
     +-----+-------------------+============================+----------------+------+
     |     | transport header  |         SPDM message       | transport tail |      |
     +-----+-------------------+============================+----------------+------+
     ^     ^                   ^
     |     |                   | spdm_message_buffer
     |     | transport_message_buffer
     | sender_buffer

   For secured messages the scratch_buffer is used to store plain text and the final cipher text will be in sender_buffer.

   libspdm_transport_xx_encode_message(spdm_message_buffer, &transport_message_buffer)
   {
     /* spdm_message_buffer is inside of scratch_buffer.
      * transport_message_buffer is inside of sender_buffer. */

     libspdm_xxx_encode_message (spdm_message_buffer, spdm_message_buffer_size,
         &app_message_buffer, &app_message_buffer_size);
     secured_message_buffer = transport_message_buffer + transport_header_size;
     libspdm_encode_secured_message (app_message_buffer, app_message_buffer_size,
         secured_message_buffer, &secured_message_buffer_size);
     libspdm_xxx_encode_message (secured_message_buffer, secured_message_buffer_size,
         &transport_message_buffer, &transport_message_buffer_size);
   }

   The buffer usage of sender_buffer and scratch_buffer is:

     ===== : SPDM message (max_header_size must be reserved before message, for sender_buffer and scratch_buffer)
     ***** : encrypted data
     $$$$$ : additional authenticated data (AAD)
     &&&&& : message authentication code (MAC) / TAG

     |<---                             sender_buffer_size                                --->|
               |<---                   transport_message_buffer_size                 --->|
     |sec_trans_header_size|<---       secured_message_buffer_size          --->|
     |<---             transport_header_size              --->|<spdm>|<-transport_tail_size->|
     +---------+-----------+$$$$$$$$$$$$$$$$$$$$+***************************+&&&+--------+---+
     |         | TransHdr  |      EncryptionHeader     |AppHdr| SPDM |Random|MAC|AlignPad|   |
     |         |           |SessionId|SeqNum|Len|AppLen|      |      |      |   |        |   |
     +---------+-----------+$$$$$$$$$$$$$$$$$$$$+***************************+&&&+--------+---+
     ^         ^           ^
     |         |           | secured_message_buffer
     |         | transport_message_buffer
     | sender_buffer

     |<---                             scratch_buffer_size                               --->|
                                                |<---  plain text size  --->|
                                                       |<-app_msg_s->|
     |<---             transport_header_size              --->|<spdm>|<-transport_tail_size->|
     +------------------------------------------+-------------+======+------+----------------+
     |                                          |EncHdr|AppHdr| SPDM |Random|                |
     |                                          |AppLen|      |      |      |                |
     +------------------------------------------+-------------+======+------+----------------+
     ^                                          ^      ^      ^
     |                                          |      |      | spdm_message_buffer
     |                                          |      | app_message_buffer
     |                                          | plain text
     | scratch_buffer

   ```

   ```
   The receiver flow is:
   {
     libspdm_acquire_receiver_buffer (&receiver_buffer, &receiver_buffer_size);

     transport_message_buffer = receiver_buffer;
     receive_message (&transport_message_buffer, &transport_message_buffer_size);
     transport_decode_message (transport_message_buffer, transport_message_buffer_size,
         &spdm_message_buffer, &spdm_message_buffer_size);
     /* process SPDM request/response in spdm_message_buffer */

     libspdm_release_receiver_buffer (receiver_buffer);
   }

   The buffer usage of sender buffer is:

     ===== : SPDM message

     |<---                       receiver_buffer_size                    --->|
        |<---                transport_message_buffer_size            --->|
                            |<-spdm_message_buffer_size->|
     +--+-------------------+============================+----------------+--+
     |  | transport header  |         SPDM message       | transport tail |  |
     +--+-------------------+============================+----------------+--+
     ^  ^                   ^
     |  |                   | spdm_message_buffer
     |  | transport_message_buffer
     | receiver_buffer

   For secured messages the scratch_buffer will be used to store plain text and the cipher text is in receiver_buffer.

   libspdm_transport_xxx_decode_message(transport_message_buffer, &spdm_message_buffer)
   {
     /* transport_message_buffer is inside of receiver_buffer.
      * spdm_message_buffer is inside of scratch_buffer. */

     libspdm_xxx_decode_message (transport_message_buffer, transport_message_buffer_size,
         &secured_message_buffer, &secured_message_buffer_size);
     app_message_buffer = spdm_message_buffer
     libspdm_decode_secured_message (secured_message_buffer, secured_message_buffer_size,
         &app_message_buffer, &app_message_buffer_size);
     libspdm_xxx_decode_message (app_message_buffer, app_message_buffer_size,
         &spdm_message_buffer, &spdm_message_buffer_size);
   }

   The buffer usage of receiver_buffer and scratch_buffer is:

     ===== : SPDM message
     ***** : encrypted data
     $$$$$ : additional authenticated data (AAD)
     &&&&& : message authentication code (MAC) / TAG

     |<---                            receiver_buffer_size                         --->|
        |<---                     transport_message_buffer_size                 --->|
                      |<---       secured_message_buffer_size          --->|
     +--+-------------+$$$$$$$$$$$$$$$$$$$$+***************************+&&&+--------+--+
     |  |  TransHdr   |      EncryptionHeader     |AppHdr| SPDM |Random|MAC|AlignPad|  |
     |  |             |SessionId|SeqNum|Len|AppLen|      |      |      |   |        |  |
     +--+-------------+$$$$$$$$$$$$$$$$$$$$+***************************+&&&+--------+--+
     ^  ^             ^
     |  |             | secured_message_buffer
     |  | transport_message_buffer
     | receiver_buffer

     |<---                            scratch_buffer_size                          --->|
                                           |<---  plain text size  --->|
                                                  |<-app_msg_s->|
                                                         |<spdm>|
     +-------------------------------------+-------------+======+------+---------------+
     |                                     |EncHdr|AppHdr| SPDM |Random|               |
     |                                     |AppLen|      |      |      |               |
     +-------------------------------------+-------------+======+------+---------------+
     ^                                     ^      ^      ^
     |                                     |      |      | spdm_message_buffer
     |                                     |      | app_message_buffer
     |                                     | plain text
     | scratch_buffer

   ```
   The buffers have the following properties:

   * libspdm never writes data to the receive buffer so the buffer may be read-only.
   * libspdm both reads from and writes to the send buffer. Note that in a future release libspdm
   may never read from the send buffer, allowing it to be write-only.
   * libspdm always releases the send buffer before acquiring the receive buffer and releases the
   receive buffer before acquiring the send buffer. Because of this the send buffer and receive buffer
   may overlap or be the same buffer.
   * libspdm assumes that, when populating the send buffer or parsing the receive buffer, both buffers
   cannot be modified by external agents. It is the library Integrator's responsibility to ensure that
   the buffers cannot be tampered with while libspdm is accessing them.

8) [spdm_lib_config.h](https://github.com/DMTF/libspdm/blob/main/include/library/spdm_lib_config.h) provides an example of the configuration macros used in the libspdm library.

   The Integrator can override the use of this file by defining the `LIBSPDM_CONFIG` macro.

9) SPDM library depends upon the [HAL library](https://github.com/DMTF/libspdm/tree/main/include/hal).

   Sample implementations can be found at [os_stub](https://github.com/DMTF/libspdm/tree/main/os_stub)

   10.1) [cryptlib](https://github.com/DMTF/libspdm/blob/main/include/hal/library/cryptlib.h) provides cryptography functions.

   10.2) [memlib](https://github.com/DMTF/libspdm/blob/main/include/hal/library/memlib.h) provides memory operations.

   10.3) [debuglib](https://github.com/DMTF/libspdm/blob/main/include/hal/library/debuglib.h) provides debug functions.

   10.4) [requester library](https://github.com/DMTF/libspdm/tree/main/include/hal/requester)

   10.4.1) [timelib](https://github.com/DMTF/libspdm/blob/main/include/hal/library/requester/timelib.h) provides sleep function.

   10.4.2) [reqasymsignlib](https://github.com/DMTF/libspdm/blob/main/include/hal/library/requester/reqasymsignlib.h) provides private key signing in a secure environment.

   10.4.3) [psklib](https://github.com/DMTF/libspdm/blob/main/include/hal/library/requester/psklib.h) provides PSK HMAC operation in a secure environment.

   10.5) [responder library](https://github.com/DMTF/libspdm/tree/main/include/hal/responder)

   10.5.1) [watchdoglib](https://github.com/DMTF/libspdm/blob/main/include/hal/library/responder/watchdoglib.h) provides watchdog function.

   10.5.2) [asymsignlib](https://github.com/DMTF/libspdm/blob/main/include/hal/library/responder/asymsignlib.h) provides private key signing in a secure environment.

   10.5.3) [psklib](https://github.com/DMTF/libspdm/blob/main/include/hal/library/responder/psklib.h) provides PSK HMAC operation in a secure environment.

   10.5.4) [measlib](https://github.com/DMTF/libspdm/blob/main/include/library/responder/measlib.h) provides measurement collection.

   10.5.5) [csrlib](https://github.com/DMTF/libspdm/blob/main/include/library/responder/csrlib.h) provides CSR signing.

   10.5.6) [setcertlib](https://github.com/DMTF/libspdm/blob/main/include/library/responder/setcertlib.h) provides certificate chain setting function.
