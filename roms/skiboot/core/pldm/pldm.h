/* SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 * Copyright 2022 IBM Corp.
 */

#ifndef __COREPLDM_H__
#define __COREPLDM_H__

#include <ast.h>
#include <base.h>
#include <utils.h>
#include <pldm.h>

#define PLDM_MSG_SIZE(x) (sizeof(struct pldm_msg_hdr) + sizeof(x))

/* For all of the encode functions just pass in a default ID (0x00) */
#define DEFAULT_INSTANCE_ID 0

extern bool watchdog_armed;
extern int watchdog_period_sec;

struct pldm_tx_data {
	/* Contains an message header and payload of an MCTP packet.
	 * Size of data[]
	 */
	size_t data_size;

	/* Holds data related to the routing of an MCTP packet */
	bool tag_owner;
	uint8_t msg_tag;

	/* This byte is situated just before the message body */
	uint8_t mctp_msg_type;

	/* The message payload (e.g. PLDM message) */
	uint8_t data[1];
};

/* Return an integer with a bit set in the position corresponding to
 * the given enumeration (starting from 0 = the least significant
 * bit) and zeroes in the other positions.
 * Used for libpldm enumeration constants.
 *
 *
 * @example enum_bit(0) = 0x00000001
 * @example enum_bit(1) = 0x00000002
 * @example enum_bit(4) = 0x00000010
 */
inline uint32_t enum_bit(unsigned int enumeration)
{
	return 1 << enumeration;
}

struct pldm_rx_data {
	struct pldm_header_info hdrinf; /* parsed message header */

	struct pldm_msg *msg;
	int msg_len;
	int source_eid;
	bool tag_owner;
	uint8_t msg_tag;
};

int pldm_mctp_message_tx(struct pldm_tx_data *tx);

int pldm_mctp_message_rx(uint8_t eid, bool tag_owner, uint8_t msg_tag,
			 const uint8_t *buf, int len);

/* Responder support */
int pldm_responder_handle_request(struct pldm_rx_data *rx);
int pldm_responder_init(void);

/* Requester support */
int pldm_find_file_handle_by_lid_id(const char *lid_id,
				    uint32_t *file_handle,
				    uint32_t *file_length);
int pldm_file_io_read_file(uint32_t file_handle, uint32_t file_length,
			   uint32_t pos, void *buf, uint64_t len);
int pldm_file_io_write_file(uint32_t file_handle, uint32_t pos,
			    const void *buf, uint64_t len);
int pldm_file_io_init(void);

int pldm_fru_get_bmc_version(void *bv, int len);
void pldm_fru_set_local_table(uint32_t *table_length,
			      uint16_t *total_record_set_identifiers,
			      uint16_t *total_table_records);
int pldm_fru_get_local_table(void **fru_record_table_bytes,
			     uint32_t *fru_record_table_size);
int pldm_fru_init(void);

int pldm_bios_find_lid_by_attr_name(const char *name, char **lid);
int pldm_bios_get_lids_id(char **lid_ids_string);
int pldm_bios_init(void);

uint8_t pldm_base_get_bmc_tid(void);
int pldm_base_get_tid_req(void);

int pldm_platform_reload_pdrs(void);
int pldm_platform_init(void);
void pldm_platform_exit(void);

int pldm_platform_pdr_find_record(uint32_t record_handle,
				  uint8_t **pdr_data,
				  uint32_t *pdr_data_size,
				  uint32_t *next_record_handle);
int pldm_requester_handle_response(struct pldm_rx_data *rx);
int pldm_requester_queue(struct pldm_tx_data *tx,
			 void (*complete)(struct pldm_rx_data *rx, void *data),
			 void *complete_data);
int pldm_requester_queue_and_wait(struct pldm_tx_data *tx,
				  void **msg, size_t *msg_size);
int pldm_requester_init(void);

#endif /* __COREPLDM_H__ */
