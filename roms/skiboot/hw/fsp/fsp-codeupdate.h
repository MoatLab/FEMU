// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
/* Copyright 2013-2015 IBM Corp. */

#ifndef __CODEUPDATE_H
#define __CODEUPDATE_H

/* Flash SG list version */
#define SG_LIST_VERSION		(1UL)

/* LID size <= 16M */
#define LID_MAX_SIZE            0x1000000

/* Delete all LIDs in */
#define DEL_UPD_SIDE_LIDS	0xFFFFFFFF

/* System parameter values used in code update validation */
#define INBAND_UPDATE_ALLOWED   0x01
#define PLATFORM_HMC_MANAGED    0x01
#define FW_LICENSE_ACCEPT       0x01

/* Running image side */
#define FW_IPL_SIDE_TEMP	0x01
#define FW_IPL_SIDE_PERM	0x00

/* Manage operations */
#define OPAL_REJECT_TMP_SIDE	0
#define OPAL_COMMIT_TMP_SIDE	1

/* Validate image size */
#define VALIDATE_BUF_SIZE	4096

/* Code update operation status */
#define OPAL_INVALID_IMAGE	-1003	/* Unacceptable image */
#define OPAL_ACTIVE_SIDE_ERR	-9001
#define OPAL_FLASH_NO_AUTH	-9002

/* Validate image update result tokens */
#define VALIDATE_TMP_UPDATE	0     /* T side will be updated */
#define VALIDATE_FLASH_AUTH	1     /* Partition does not have authority */
#define VALIDATE_INVALID_IMG	2     /* Candidate image is not valid */
#define VALIDATE_CUR_UNKNOWN	3     /* Current fixpack level is unknown */
/*
 * Current T side will be committed to P side before being replace with new
 * image, and the new image is downlevel from current image
 */
#define VALIDATE_TMP_COMMIT_DL	4
/*
 * Current T side will be committed to P side before being replaced with new
 * image
 */
#define VALIDATE_TMP_COMMIT	5
/*
 * T side will be updated with a downlevel image
 */
#define VALIDATE_TMP_UPDATE_DL	6
/*
 * The candidate image's release date is later than the system's firmware
 * service entitlement date - service warranty period has expired
 */
#define VALIDATE_OUT_OF_WRNTY	7

/* default version */
#define FW_VERSION_UNKNOWN "UNKNOWN"

/* Actual size of MI & ML keyword including NULL */
#define MI_KEYWORD_SIZE		10
#define ML_KEYWORD_SIZE		9

/* Firmware image VPD data */
struct fw_image_vpd {
	char	mi_keyword[MI_KEYWORD_SIZE];	/* NNSSS_FFF */
	char	ext_fw_id[ML_KEYWORD_SIZE];	/* FWxxx.yy */
};

/* Master LID header */
struct master_lid_header {
	char		key[3];		/* "MLH" */
	uint8_t		version;	/* 0x02 */
	__be16		header_size;
	__be16		entry_size;
	uint8_t		reserved[56];
};

/* LID index entry */
struct lid_index_entry {
	__be32		id;
	__be32		size;
	__be32		offset;
	__be32		crc;
};

/* SP flags */
#define FW_ONE_OFF_SP	0x80000000
#define FW_EMERGENCY_SP	0x40000000

/*
 * SP GA date
 *
 * sp_flag addr = header->data + header->ext_fw_id_size
 */
struct update_image_ga_date {
	__be32		sp_flag;
	char		sp_ga_date[8];	/* YYYYMMDD */
};

/* Image magic number */
#define IMAGE_MAGIC_NUMBER	0x5549

/* Image header structure */
struct update_image_header {
	__be16		magic;
	__be16		version;
	__be32		package_size;
	__be32		crc;
	__be16		lid_index_offset;
	__be16		number_lids;
	__be16		package_flags;
	__be16		mi_keyword_size;
	char		mi_keyword_data[40];
	__be16	ext_fw_id_size;
	/* Rest of the image data including ext fw id, sp flags */
	char		data[];
};

/* FipS header */
struct fips_header {
	__be16		magic;
	__be16		version;
	__be32		lid_id;
	__be32		lid_date;	/* YYYYMMDD */
	__be16		lid_time;	/* HHMM */
	__be16		lid_class;
	__be32		crc;
	__be32		lid_size;	/* Number of bytes below header */
	__be32		header_size;
	uint8_t		mtd_number;
	uint8_t		valid;		/* 1 = valid, 0 = invalid */
	uint8_t		reserved;
	uint8_t		lid_info_size;
	char		lid_info[64];	/* code level */
	__be32		update_date;	/* YYYYMMDD */
	__be16		update_time;	/* HHMM */
	__be16		phylum_len;
	uint8_t		lid_phylum[];
};

/* Approximate LID size */
#define MASTER_LID_SIZE		0x5000
/*
 * Note:
 *  Doc indicates non-SP LIDs size is 0-8MB. However
 *  in reality marker LID size less than 4k. Allocating
 *  8k to give some breathing space.
 */
#define MARKER_LID_SIZE         0x00002000

/* Common marker LID no */
#define P_COM_MARKER_LID_ID	0x80A00001
#define T_COM_MARKER_LID_ID	(P_COM_MARKER_LID_ID | ADJUST_T_SIDE_LID_NO)

/*
 * Common marker LID structure
 *
 * Note that we are populating only required sections,
 * not all ADF sections in common marker LID.
 */
struct com_marker_header {
	__be32		version;
	__be32		MI_offset;	/* Offset to MI section */
	__be32		iseries_offset;
};

/* MI Keyword section */
struct com_marker_mi_section {
	__be32		MI_size;
	char		mi_keyword[40];	/* MI Keyword */
	char		lst_disrupt_fix_lvl[3];
	char		skip[21];	/* Skip not interested fields */
	__be32		adf_offset;	/* Offset to ADF section */
};

/* Additional Data Fields */
struct com_marker_adf_sec {
	__be32		adf_cnt;	/* ADF count */
	char		adf_data[];	/* ADF data */
};

/* ADF common header */
struct com_marker_adf_header {
	__be32		size;	/* Section size */
	__be32		name;	/* Section name */
};

/*
 * Service Pack Nomenclature ADF
 *
 * Service pack release name.
 */
#define ADF_NAME_SP	0x53504E4D	/* SPNM */
struct com_marker_adf_sp
{
	struct com_marker_adf_header header;
	__be32		sp_name_offset;	/* Offset from start of ADF */
	__be32		sp_name_size;
	__be32		skip[4];	/* Skip rest of fields */
};

/*
 * Firmware IP Protection ADF
 *
 * Service Pack flags and GA date.
 */
#define ADF_NAME_FW_IP	0x46495050	/* FIPP */
struct com_marker_fw_ip {
	struct com_marker_adf_header header;
	__be32		sp_flag_offset;	/* Offset from start of ADF */
	__be32		sp_flag_size;
	__be32		sp_ga_offset;	/* Offset from start of ADF*/
	__be32		sp_ga_size;
};

#endif /* __CODEUPDATE_H */
