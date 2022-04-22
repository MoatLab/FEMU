/*******************************************************************************

  Intel(R) 82576 Virtual Function Linux driver
  Copyright(c) 1999 - 2008 Intel Corporation.

  This program is free software; you can redistribute it and/or modify it
  under the terms and conditions of the GNU General Public License,
  version 2, as published by the Free Software Foundation.

  This program is distributed in the hope it will be useful, but WITHOUT
  ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
  FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
  more details.

  You should have received a copy of the GNU General Public License along with
  this program; if not, write to the Free Software Foundation, Inc.,
  51 Franklin St - Fifth Floor, Boston, MA 02110-1301 USA.

  The full GNU General Public License is included in this distribution in
  the file called "COPYING".

  Contact Information:
  Linux NICS <linux.nics@intel.com>
  e1000-devel Mailing List <e1000-devel@lists.sourceforge.net>
  Intel Corporation, 5200 N.E. Elam Young Parkway, Hillsboro, OR 97124-6497

*******************************************************************************/

FILE_LICENCE ( GPL2_ONLY );

#ifndef _IGBVF_VF_H_
#define _IGBVF_VF_H_

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <byteswap.h>
#include <errno.h>
#include <ipxe/pci.h>
#include <ipxe/malloc.h>
#include <ipxe/if_ether.h>
#include <ipxe/io.h>
#include <ipxe/ethernet.h>
#include <ipxe/iobuf.h>
#include <ipxe/netdevice.h>

#include "igbvf_osdep.h"
#include "igbvf_regs.h"
#include "igbvf_defines.h"

struct e1000_hw;

#define E1000_DEV_ID_82576_VF                 0x10CA
#define E1000_DEV_ID_I350_VF                  0x1520

#define E1000_VF_INIT_TIMEOUT 200 /* Number of retries to clear RSTI */

/* Additional Descriptor Control definitions */
#define E1000_TXDCTL_QUEUE_ENABLE  0x02000000 /* Enable specific Tx Queue */
#define E1000_RXDCTL_QUEUE_ENABLE  0x02000000 /* Enable specific Rx Queue */

/* SRRCTL bit definitions */
#define E1000_SRRCTL_BSIZEPKT_SHIFT                     10 /* Shift _right_ */
#define E1000_SRRCTL_BSIZEHDRSIZE_MASK                  0x00000F00
#define E1000_SRRCTL_BSIZEHDRSIZE_SHIFT                 2  /* Shift _left_ */
#define E1000_SRRCTL_DESCTYPE_LEGACY                    0x00000000
#define E1000_SRRCTL_DESCTYPE_ADV_ONEBUF                0x02000000
#define E1000_SRRCTL_DESCTYPE_HDR_SPLIT                 0x04000000
#define E1000_SRRCTL_DESCTYPE_HDR_SPLIT_ALWAYS          0x0A000000
#define E1000_SRRCTL_DESCTYPE_HDR_REPLICATION           0x06000000
#define E1000_SRRCTL_DESCTYPE_HDR_REPLICATION_LARGE_PKT 0x08000000
#define E1000_SRRCTL_DESCTYPE_MASK                      0x0E000000
#define E1000_SRRCTL_DROP_EN                            0x80000000

#define E1000_SRRCTL_BSIZEPKT_MASK      0x0000007F
#define E1000_SRRCTL_BSIZEHDR_MASK      0x00003F00

/* Interrupt Defines */
#define E1000_EICR     0x01580  /* Ext. Interrupt Cause Read - R/clr */
#define E1000_EITR(_n) (0x01680 + ((_n) << 2))
#define E1000_EICS     0x01520  /* Ext. Interrupt Cause Set - W0 */
#define E1000_EIMS     0x01524  /* Ext. Interrupt Mask Set/Read - RW */
#define E1000_EIMC     0x01528  /* Ext. Interrupt Mask Clear - WO */
#define E1000_EIAC     0x0152C  /* Ext. Interrupt Auto Clear - RW */
#define E1000_EIAM     0x01530  /* Ext. Interrupt Ack Auto Clear Mask - RW */
#define E1000_IVAR0    0x01700  /* Interrupt Vector Allocation (array) - RW */
#define E1000_IVAR_MISC 0x01740 /* IVAR for "other" causes - RW */
#define E1000_IVAR_VALID        0x80

/* Receive Descriptor - Advanced */
union e1000_adv_rx_desc {
	struct {
		u64 pkt_addr;             /* Packet buffer address */
		u64 hdr_addr;             /* Header buffer address */
	} read;
	struct {
		struct {
			union {
				u32 data;
				struct {
					u16 pkt_info; /* RSS type, Packet type */
					u16 hdr_info; /* Split Header,
						       * header buffer length */
				} hs_rss;
			} lo_dword;
			union {
				u32 rss;          /* RSS Hash */
				struct {
					u16 ip_id;    /* IP id */
					u16 csum;     /* Packet Checksum */
				} csum_ip;
			} hi_dword;
		} lower;
		struct {
			u32 status_error;     /* ext status/error */
			u16 length;           /* Packet length */
			u16 vlan;             /* VLAN tag */
		} upper;
	} wb;  /* writeback */
};

#define E1000_RXDADV_HDRBUFLEN_MASK      0x7FE0
#define E1000_RXDADV_HDRBUFLEN_SHIFT     5

/* Transmit Descriptor - Advanced */
union e1000_adv_tx_desc {
	struct {
		u64 buffer_addr;    /* Address of descriptor's data buf */
		u32 cmd_type_len;
		u32 olinfo_status;
	} read;
	struct {
		u64 rsvd;       /* Reserved */
		u32 nxtseq_seed;
		u32 status;
	} wb;
};

/* Adv Transmit Descriptor Config Masks */
#define E1000_ADVTXD_DTYP_CTXT    0x00200000 /* Advanced Context Descriptor */
#define E1000_ADVTXD_DTYP_DATA    0x00300000 /* Advanced Data Descriptor */
#define E1000_ADVTXD_DCMD_EOP     0x01000000 /* End of Packet */
#define E1000_ADVTXD_DCMD_IFCS    0x02000000 /* Insert FCS (Ethernet CRC) */
#define E1000_ADVTXD_DCMD_RS      0x08000000 /* Report Status */
#define E1000_ADVTXD_DCMD_DEXT    0x20000000 /* Descriptor extension (1=Adv) */
#define E1000_ADVTXD_DCMD_VLE     0x40000000 /* VLAN pkt enable */
#define E1000_ADVTXD_DCMD_TSE     0x80000000 /* TCP Seg enable */
#define E1000_ADVTXD_PAYLEN_SHIFT    14 /* Adv desc PAYLEN shift */

/* Context descriptors */
struct e1000_adv_tx_context_desc {
	u32 vlan_macip_lens;
	u32 seqnum_seed;
	u32 type_tucmd_mlhl;
	u32 mss_l4len_idx;
};

#define E1000_ADVTXD_MACLEN_SHIFT    9  /* Adv ctxt desc mac len shift */
#define E1000_ADVTXD_TUCMD_IPV4    0x00000400  /* IP Packet Type: 1=IPv4 */
#define E1000_ADVTXD_TUCMD_L4T_TCP 0x00000800  /* L4 Packet TYPE of TCP */
#define E1000_ADVTXD_L4LEN_SHIFT     8  /* Adv ctxt L4LEN shift */
#define E1000_ADVTXD_MSS_SHIFT      16  /* Adv ctxt MSS shift */

enum e1000_mac_type {
	e1000_undefined = 0,
	e1000_vfadapt,
	e1000_num_macs  /* List is 1-based, so subtract 1 for true count. */
};

struct e1000_vf_stats {
	u64 base_gprc;
	u64 base_gptc;
	u64 base_gorc;
	u64 base_gotc;
	u64 base_mprc;
	u64 base_gotlbc;
	u64 base_gptlbc;
	u64 base_gorlbc;
	u64 base_gprlbc;

	u32 last_gprc;
	u32 last_gptc;
	u32 last_gorc;
	u32 last_gotc;
	u32 last_mprc;
	u32 last_gotlbc;
	u32 last_gptlbc;
	u32 last_gorlbc;
	u32 last_gprlbc;

	u64 gprc;
	u64 gptc;
	u64 gorc;
	u64 gotc;
	u64 mprc;
	u64 gotlbc;
	u64 gptlbc;
	u64 gorlbc;
	u64 gprlbc;
};

#include "igbvf_mbx.h"

struct e1000_mac_operations {
	/* Function pointers for the MAC. */
	s32  (*init_params)(struct e1000_hw *);
	s32  (*check_for_link)(struct e1000_hw *);
	void (*clear_vfta)(struct e1000_hw *);
	s32  (*get_bus_info)(struct e1000_hw *);
	s32  (*get_link_up_info)(struct e1000_hw *, u16 *, u16 *);
	void (*update_mc_addr_list)(struct e1000_hw *, u8 *, u32);
	s32  (*reset_hw)(struct e1000_hw *);
	s32  (*init_hw)(struct e1000_hw *);
	s32  (*setup_link)(struct e1000_hw *);
	void (*write_vfta)(struct e1000_hw *, u32, u32);
	void (*mta_set)(struct e1000_hw *, u32);
	void (*rar_set)(struct e1000_hw *, u8*, u32);
	s32  (*read_mac_addr)(struct e1000_hw *);
};

struct e1000_mac_info {
	struct e1000_mac_operations ops;
	u8 addr[6];
	u8 perm_addr[6];

	enum e1000_mac_type type;

	u16 mta_reg_count;
	u16 rar_entry_count;

	bool get_link_status;
};

enum e1000_bus_type {
	e1000_bus_type_unknown = 0,
	e1000_bus_type_pci,
	e1000_bus_type_pcix,
	e1000_bus_type_pci_express,
	e1000_bus_type_reserved
};

enum e1000_bus_speed {
	e1000_bus_speed_unknown = 0,
	e1000_bus_speed_33,
	e1000_bus_speed_66,
	e1000_bus_speed_100,
	e1000_bus_speed_120,
	e1000_bus_speed_133,
	e1000_bus_speed_2500,
	e1000_bus_speed_5000,
	e1000_bus_speed_reserved
};

enum e1000_bus_width {
	e1000_bus_width_unknown = 0,
	e1000_bus_width_pcie_x1,
	e1000_bus_width_pcie_x2,
	e1000_bus_width_pcie_x4 = 4,
	e1000_bus_width_pcie_x8 = 8,
	e1000_bus_width_32,
	e1000_bus_width_64,
	e1000_bus_width_reserved
};

struct e1000_bus_info {
	enum e1000_bus_type type;
	enum e1000_bus_speed speed;
	enum e1000_bus_width width;

	u16 func;
	u16 pci_cmd_word;
};

struct e1000_mbx_operations {
	s32 (*init_params)(struct e1000_hw *hw);
	s32 (*read)(struct e1000_hw *, u32 *, u16,  u16);
	s32 (*write)(struct e1000_hw *, u32 *, u16, u16);
	s32 (*read_posted)(struct e1000_hw *, u32 *, u16,  u16);
	s32 (*write_posted)(struct e1000_hw *, u32 *, u16, u16);
	s32 (*check_for_msg)(struct e1000_hw *, u16);
	s32 (*check_for_ack)(struct e1000_hw *, u16);
	s32 (*check_for_rst)(struct e1000_hw *, u16);
};

struct e1000_mbx_stats {
	u32 msgs_tx;
	u32 msgs_rx;

	u32 acks;
	u32 reqs;
	u32 rsts;
};

struct e1000_mbx_info {
	struct e1000_mbx_operations ops;
	struct e1000_mbx_stats stats;
	u32 timeout;
	u32 usec_delay;
	u16 size;
};

struct e1000_dev_spec_vf {
	u32	vf_number;
	u32	v2p_mailbox;
};

struct e1000_hw {
	void *back;

	u8 __iomem *hw_addr;
	u8 __iomem *flash_address;
	unsigned long io_base;

	struct e1000_mac_info  mac;
	struct e1000_bus_info  bus;
	struct e1000_mbx_info mbx;

	union {
		struct e1000_dev_spec_vf	vf;
	} dev_spec;

	u16 device_id;
	u16 subsystem_vendor_id;
	u16 subsystem_device_id;
	u16 vendor_id;

	u8  revision_id;
};

enum e1000_promisc_type {
	e1000_promisc_disabled = 0,   /* all promisc modes disabled */
	e1000_promisc_unicast = 1,    /* unicast promiscuous enabled */
	e1000_promisc_multicast = 2,  /* multicast promiscuous enabled */
	e1000_promisc_enabled = 3,    /* both uni and multicast promisc */
	e1000_num_promisc_types
};

/* These functions must be implemented by drivers */
s32  igbvf_read_pcie_cap_reg(struct e1000_hw *hw, u32 reg, u16 *value);
void igbvf_vfta_set_vf(struct e1000_hw *, u16, bool);
void igbvf_rlpml_set_vf(struct e1000_hw *, u16);
s32 igbvf_promisc_set_vf(struct e1000_hw *, enum e1000_promisc_type);
#endif /* _IGBVF_VF_H_ */
