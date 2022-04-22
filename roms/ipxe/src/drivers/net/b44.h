/*
 * Copyright (c) 2008 Stefan Hajnoczi <stefanha@gmail.com>
 * Copyright (c) 2008 Pantelis Koukousoulas <pktoss@gmail.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of the
 * License, or any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA.
 *
 * This driver is a port of the b44 linux driver version 1.01
 *
 * Copyright (c) 2002 David S. Miller <davem@redhat.com>
 * Copyright (c) Pekka Pietikainen <pp@ee.oulu.fi>
 * Copyright (C) 2006 Broadcom Corporation.
 *
 * Some ssb bits copied from version 2.0 of the b44 driver
 * Copyright (c) Michael Buesch
 *
 * Copyright (c) a lot of people too. Please respect their work.
 */

FILE_LICENCE ( GPL2_OR_LATER );

#ifndef _B44_H
#define _B44_H

/* BCM44xx Register layout */
#define	B44_DEVCTRL		0x0000UL /* Device Control */
#define  DEVCTRL_MPM		0x00000040 /* MP PME Enable (B0 only) */
#define  DEVCTRL_PFE		0x00000080 /* Pattern Filtering Enable */
#define  DEVCTRL_IPP		0x00000400 /* Internal EPHY Present */
#define  DEVCTRL_EPR		0x00008000 /* EPHY Reset */
#define  DEVCTRL_PME		0x00001000 /* PHY Mode Enable */
#define  DEVCTRL_PMCE		0x00002000 /* PHY Mode Clocks Enable */
#define  DEVCTRL_PADDR		0x0007c000 /* PHY Address */
#define  DEVCTRL_PADDR_SHIFT	18
#define B44_BIST_STAT		0x000CUL /* Built-In Self-Test Status */
#define B44_WKUP_LEN		0x0010UL /* Wakeup Length */
#define  WKUP_LEN_P0_MASK	0x0000007f /* Pattern 0 */
#define  WKUP_LEN_D0		0x00000080
#define  WKUP_LEN_P1_MASK	0x00007f00 /* Pattern 1 */
#define  WKUP_LEN_P1_SHIFT	8
#define  WKUP_LEN_D1		0x00008000
#define  WKUP_LEN_P2_MASK	0x007f0000 /* Pattern 2 */
#define  WKUP_LEN_P2_SHIFT	16
#define  WKUP_LEN_D2		0x00000000
#define  WKUP_LEN_P3_MASK	0x7f000000 /* Pattern 3 */
#define  WKUP_LEN_P3_SHIFT	24
#define  WKUP_LEN_D3		0x80000000
#define  WKUP_LEN_DISABLE	0x80808080
#define  WKUP_LEN_ENABLE_TWO	0x80800000
#define  WKUP_LEN_ENABLE_THREE	0x80000000
#define B44_ISTAT		0x0020UL /* Interrupt Status */
#define  ISTAT_LS		0x00000020 /* Link Change (B0 only) */
#define  ISTAT_PME		0x00000040 /* Power Management Event */
#define  ISTAT_TO		0x00000080 /* General Purpose Timeout */
#define  ISTAT_DSCE		0x00000400 /* Descriptor Error */
#define  ISTAT_DATAE		0x00000800 /* Data Error */
#define  ISTAT_DPE		0x00001000 /* Descr. Protocol Error */
#define  ISTAT_RDU		0x00002000 /* Receive Descr. Underflow */
#define  ISTAT_RFO		0x00004000 /* Receive FIFO Overflow */
#define  ISTAT_TFU		0x00008000 /* Transmit FIFO Underflow */
#define  ISTAT_RX		0x00010000 /* RX Interrupt */
#define  ISTAT_TX		0x01000000 /* TX Interrupt */
#define  ISTAT_EMAC		0x04000000 /* EMAC Interrupt */
#define  ISTAT_MII_WRITE	0x08000000 /* MII Write Interrupt */
#define  ISTAT_MII_READ		0x10000000 /* MII Read Interrupt */
#define  ISTAT_ERRORS           (ISTAT_DSCE|ISTAT_DATAE|ISTAT_DPE|\
                                 ISTAT_RDU|ISTAT_RFO|ISTAT_TFU)
#define B44_IMASK		0x0024UL /* Interrupt Mask */
#define  IMASK_DEF		(ISTAT_ERRORS | ISTAT_RX | ISTAT_TX)
#define  IMASK_DISABLE          0
#define B44_GPTIMER		0x0028UL /* General Purpose Timer */
#define B44_ADDR_LO		0x0088UL /* ENET Address Lo (B0 only) */
#define B44_ADDR_HI		0x008CUL /* ENET Address Hi (B0 only) */
#define B44_FILT_ADDR		0x0090UL /* ENET Filter Address */
#define B44_FILT_DATA		0x0094UL /* ENET Filter Data */
#define B44_TXBURST		0x00A0UL /* TX Max Burst Length */
#define B44_RXBURST		0x00A4UL /* RX Max Burst Length */
#define B44_MAC_CTRL		0x00A8UL /* MAC Control */
#define  MAC_CTRL_CRC32_ENAB	0x00000001 /* CRC32 Generation Enable */
#define  MAC_CTRL_PHY_PDOWN	0x00000004 /* Onchip EPHY Powerdown */
#define  MAC_CTRL_PHY_EDET	0x00000008 /* Onchip EPHY Energy Detected*/
#define  MAC_CTRL_PHY_LEDCTRL	0x000000e0 /* Onchip EPHY LED Control */
#define  MAC_CTRL_PHY_LEDCTRL_SHIFT 5
#define B44_MAC_FLOW		0x00ACUL /* MAC Flow Control */
#define  MAC_FLOW_RX_HI_WATER	0x000000ff /* Receive FIFO HI Water Mark */
#define  MAC_FLOW_PAUSE_ENAB	0x00008000 /* Enbl Pause Frm Generation */
#define B44_RCV_LAZY		0x0100UL /* Lazy Interrupt Control */
#define  RCV_LAZY_TO_MASK	0x00ffffff /* Timeout */
#define  RCV_LAZY_FC_MASK	0xff000000 /* Frame Count */
#define  RCV_LAZY_FC_SHIFT	24
#define B44_DMATX_CTRL		0x0200UL /* DMA TX Control */
#define  DMATX_CTRL_ENABLE	0x00000001 /* Enable */
#define  DMATX_CTRL_SUSPEND	0x00000002 /* Suepend Request */
#define  DMATX_CTRL_LPBACK	0x00000004 /* Loopback Enable */
#define  DMATX_CTRL_FAIRPRIOR	0x00000008 /* Fair Priority */
#define  DMATX_CTRL_FLUSH	0x00000010 /* Flush Request */
#define B44_DMATX_ADDR		0x0204UL /* DMA TX Descriptor Ring Addr */
#define B44_DMATX_PTR		0x0208UL /* DMA TX Last Posted Desc. */
#define B44_DMATX_STAT		0x020CUL /* DMA TX Cur Actve Desc. + Sts */
#define  DMATX_STAT_CDMASK	0x00000fff /* Current Descriptor Mask */
#define  DMATX_STAT_SMASK	0x0000f000 /* State Mask */
#define  DMATX_STAT_SDISABLED	0x00000000 /* State Disabled */
#define  DMATX_STAT_SACTIVE	0x00001000 /* State Active */
#define  DMATX_STAT_SIDLE	0x00002000 /* State Idle Wait */
#define  DMATX_STAT_SSTOPPED	0x00003000 /* State Stopped */
#define  DMATX_STAT_SSUSP	0x00004000 /* State Suspend Pending */
#define  DMATX_STAT_EMASK	0x000f0000 /* Error Mask */
#define  DMATX_STAT_ENONE	0x00000000 /* Error None */
#define  DMATX_STAT_EDPE	0x00010000 /* Error Desc. Protocol Error */
#define  DMATX_STAT_EDFU	0x00020000 /* Error Data FIFO Underrun */
#define  DMATX_STAT_EBEBR	0x00030000 /* Bus Error on Buffer Read */
#define  DMATX_STAT_EBEDA	0x00040000 /* Bus Error on Desc. Access */
#define  DMATX_STAT_FLUSHED	0x00100000 /* Flushed */
#define B44_DMARX_CTRL		0x0210UL /* DMA RX Control */
#define  DMARX_CTRL_ENABLE	0x00000001 /* Enable */
#define  DMARX_CTRL_ROMASK	0x000000fe /* Receive Offset Mask */
#define  DMARX_CTRL_ROSHIFT	1 	   /* Receive Offset Shift */
#define B44_DMARX_ADDR		0x0214UL /* DMA RX Descriptor Ring Addr */
#define B44_DMARX_PTR		0x0218UL /* DMA RX Last Posted Desc */
#define B44_DMARX_STAT		0x021CUL /* Cur Active Desc. + Status */
#define  DMARX_STAT_CDMASK	0x00000fff /* Current Descriptor Mask */
#define  DMARX_STAT_SMASK	0x0000f000 /* State Mask */
#define  DMARX_STAT_SDISABLED	0x00000000 /* State Disbaled */
#define  DMARX_STAT_SACTIVE	0x00001000 /* State Active */
#define  DMARX_STAT_SIDLE	0x00002000 /* State Idle Wait */
#define  DMARX_STAT_SSTOPPED	0x00003000 /* State Stopped */
#define  DMARX_STAT_EMASK	0x000f0000 /* Error Mask */
#define  DMARX_STAT_ENONE	0x00000000 /* Error None */
#define  DMARX_STAT_EDPE	0x00010000 /* Error Desc. Protocol Error */
#define  DMARX_STAT_EDFO	0x00020000 /* Error Data FIFO Overflow */
#define  DMARX_STAT_EBEBW	0x00030000 /* Error on Buffer Write */
#define  DMARX_STAT_EBEDA	0x00040000 /* Bus Error on Desc. Access */
#define B44_DMAFIFO_AD		0x0220UL /* DMA FIFO Diag Address */
#define  DMAFIFO_AD_OMASK	0x0000ffff /* Offset Mask */
#define  DMAFIFO_AD_SMASK	0x000f0000 /* Select Mask */
#define  DMAFIFO_AD_SXDD	0x00000000 /* Select Transmit DMA Data */
#define  DMAFIFO_AD_SXDP	0x00010000 /* Sel Transmit DMA Pointers */
#define  DMAFIFO_AD_SRDD	0x00040000 /* Select Receive DMA Data */
#define  DMAFIFO_AD_SRDP	0x00050000 /* Sel Receive DMA Pointers */
#define  DMAFIFO_AD_SXFD	0x00080000 /* Select Transmit FIFO Data */
#define  DMAFIFO_AD_SXFP	0x00090000 /* Sel Transmit FIFO Pointers */
#define  DMAFIFO_AD_SRFD	0x000c0000 /* Select Receive FIFO Data */
#define  DMAFIFO_AD_SRFP	0x000c0000 /* Sel Receive FIFO Pointers */
#define B44_DMAFIFO_LO		0x0224UL /* DMA FIFO Diag Low Data */
#define B44_DMAFIFO_HI		0x0228UL /* DMA FIFO Diag High Data */
#define B44_RXCONFIG		0x0400UL /* EMAC RX Config */
#define  RXCONFIG_DBCAST	0x00000001 /* Disable Broadcast */
#define  RXCONFIG_ALLMULTI	0x00000002 /* Accept All Multicast */
#define  RXCONFIG_NORX_WHILE_TX	0x00000004 /* Rcv Disble While TX */
#define  RXCONFIG_PROMISC	0x00000008 /* Promiscuous Enable */
#define  RXCONFIG_LPBACK	0x00000010 /* Loopback Enable */
#define  RXCONFIG_FLOW		0x00000020 /* Flow Control Enable */
#define  RXCONFIG_FLOW_ACCEPT	0x00000040 /* Accept UFC Frame */
#define  RXCONFIG_RFILT		0x00000080 /* Reject Filter */
#define B44_RXMAXLEN		0x0404UL /* EMAC RX Max Packet Length */
#define B44_TXMAXLEN		0x0408UL /* EMAC TX Max Packet Length */
#define B44_MDIO_CTRL		0x0410UL /* EMAC MDIO Control */
#define  MDIO_CTRL_MAXF_MASK	0x0000007f /* MDC Frequency */
#define  MDIO_CTRL_PREAMBLE	0x00000080 /* MII Preamble Enable */
#define B44_MDIO_DATA		0x0414UL /* EMAC MDIO Data */
#define  MDIO_DATA_DATA		0x0000ffff /* R/W Data */
#define  MDIO_DATA_TA_MASK	0x00030000 /* Turnaround Value */
#define  MDIO_DATA_TA_SHIFT	16
#define  MDIO_TA_VALID		2
#define  MDIO_DATA_RA_MASK	0x007c0000 /* Register Address */
#define  MDIO_DATA_RA_SHIFT	18
#define  MDIO_DATA_PMD_MASK	0x0f800000 /* Physical Media Device */
#define  MDIO_DATA_PMD_SHIFT	23
#define  MDIO_DATA_OP_MASK	0x30000000 /* Opcode */
#define  MDIO_DATA_OP_SHIFT	28
#define  MDIO_OP_WRITE		1
#define  MDIO_OP_READ		2
#define  MDIO_DATA_SB_MASK	0xc0000000 /* Start Bits */
#define  MDIO_DATA_SB_SHIFT	30
#define  MDIO_DATA_SB_START	0x40000000 /* Start Of Frame */
#define B44_EMAC_IMASK		0x0418UL /* EMAC Interrupt Mask */
#define B44_EMAC_ISTAT		0x041CUL /* EMAC Interrupt Status */
#define  EMAC_INT_MII		0x00000001 /* MII MDIO Interrupt */
#define  EMAC_INT_MIB		0x00000002 /* MIB Interrupt */
#define  EMAC_INT_FLOW		0x00000003 /* Flow Control Interrupt */
#define B44_CAM_DATA_LO		0x0420UL /* EMAC CAM Data Low */
#define B44_CAM_DATA_HI		0x0424UL /* EMAC CAM Data High */
#define  CAM_DATA_HI_VALID	0x00010000 /* Valid Bit */
#define B44_CAM_CTRL		0x0428UL /* EMAC CAM Control */
#define  CAM_CTRL_ENABLE	0x00000001 /* CAM Enable */
#define  CAM_CTRL_MSEL		0x00000002 /* Mask Select */
#define  CAM_CTRL_READ		0x00000004 /* Read */
#define  CAM_CTRL_WRITE		0x00000008 /* Read */
#define  CAM_CTRL_INDEX_MASK	0x003f0000 /* Index Mask */
#define  CAM_CTRL_INDEX_SHIFT	16
#define  CAM_CTRL_BUSY		0x80000000 /* CAM Busy */
#define B44_ENET_CTRL		0x042CUL /* EMAC ENET Control */
#define  ENET_CTRL_ENABLE	0x00000001 /* EMAC Enable */
#define  ENET_CTRL_DISABLE	0x00000002 /* EMAC Disable */
#define  ENET_CTRL_SRST		0x00000004 /* EMAC Soft Reset */
#define  ENET_CTRL_EPSEL	0x00000008 /* External PHY Select */
#define B44_TX_CTRL		0x0430UL /* EMAC TX Control */
#define  TX_CTRL_DUPLEX		0x00000001 /* Full Duplex */
#define  TX_CTRL_FMODE		0x00000002 /* Flow Mode */
#define  TX_CTRL_SBENAB		0x00000004 /* Single Backoff Enable */
#define  TX_CTRL_SMALL_SLOT	0x00000008 /* Small Slottime */
#define B44_TX_HIWMARK		0x0434UL /* EMAC TX High Watermark */
#define  TX_HIWMARK_DEFLT	56  /* Default used in all drivers */
#define B44_MIB_CTRL		0x0438UL /* EMAC MIB Control */
#define  MIB_CTRL_CLR_ON_READ	0x00000001 /* Autoclear on Read */
#define B44_TX_GOOD_O		0x0500UL /* MIB TX Good Octets */
#define B44_TX_GOOD_P		0x0504UL /* MIB TX Good Packets */
#define B44_TX_O		0x0508UL /* MIB TX Octets */
#define B44_TX_P		0x050CUL /* MIB TX Packets */
#define B44_TX_BCAST		0x0510UL /* MIB TX Broadcast Packets */
#define B44_TX_MCAST		0x0514UL /* MIB TX Multicast Packets */
#define B44_TX_64		0x0518UL /* MIB TX <= 64 byte Packets */
#define B44_TX_65_127		0x051CUL /* MIB TX 65 to 127 byte Pkts */
#define B44_TX_128_255		0x0520UL /* MIB TX 128 to 255 byte Pkts */
#define B44_TX_256_511		0x0524UL /* MIB TX 256 to 511 byte Pkts */
#define B44_TX_512_1023		0x0528UL /* MIB TX 512 to 1023 byte Pkts */
#define B44_TX_1024_MAX		0x052CUL /* MIB TX 1024 to max byte Pkts */
#define B44_TX_JABBER		0x0530UL /* MIB TX Jabber Packets */
#define B44_TX_OSIZE		0x0534UL /* MIB TX Oversize Packets */
#define B44_TX_FRAG		0x0538UL /* MIB TX Fragment Packets */
#define B44_TX_URUNS		0x053CUL /* MIB TX Underruns */
#define B44_TX_TCOLS		0x0540UL /* MIB TX Total Collisions */
#define B44_TX_SCOLS		0x0544UL /* MIB TX Single Collisions */
#define B44_TX_MCOLS		0x0548UL /* MIB TX Multiple Collisions */
#define B44_TX_ECOLS		0x054CUL /* MIB TX Excessive Collisions */
#define B44_TX_LCOLS		0x0550UL /* MIB TX Late Collisions */
#define B44_TX_DEFERED		0x0554UL /* MIB TX Defered Packets */
#define B44_TX_CLOST		0x0558UL /* MIB TX Carrier Lost */
#define B44_TX_PAUSE		0x055CUL /* MIB TX Pause Packets */
#define B44_RX_GOOD_O		0x0580UL /* MIB RX Good Octets */
#define B44_RX_GOOD_P		0x0584UL /* MIB RX Good Packets */
#define B44_RX_O		0x0588UL /* MIB RX Octets */
#define B44_RX_P		0x058CUL /* MIB RX Packets */
#define B44_RX_BCAST		0x0590UL /* MIB RX Broadcast Packets */
#define B44_RX_MCAST		0x0594UL /* MIB RX Multicast Packets */
#define B44_RX_64		0x0598UL /* MIB RX <= 64 byte Packets */
#define B44_RX_65_127		0x059CUL /* MIB RX 65 to 127 byte Pkts */
#define B44_RX_128_255		0x05A0UL /* MIB RX 128 to 255 byte Pkts */
#define B44_RX_256_511		0x05A4UL /* MIB RX 256 to 511 byte Pkts */
#define B44_RX_512_1023		0x05A8UL /* MIB RX 512 to 1023 byte Pkts */
#define B44_RX_1024_MAX		0x05ACUL /* MIB RX 1024 to max byte Pkts */
#define B44_RX_JABBER		0x05B0UL /* MIB RX Jabber Packets */
#define B44_RX_OSIZE		0x05B4UL /* MIB RX Oversize Packets */
#define B44_RX_FRAG		0x05B8UL /* MIB RX Fragment Packets */
#define B44_RX_MISS		0x05BCUL /* MIB RX Missed Packets */
#define B44_RX_CRCA		0x05C0UL /* MIB RX CRC Align Errors */
#define B44_RX_USIZE		0x05C4UL /* MIB RX Undersize Packets */
#define B44_RX_CRC		0x05C8UL /* MIB RX CRC Errors */
#define B44_RX_ALIGN		0x05CCUL /* MIB RX Align Errors */
#define B44_RX_SYM		0x05D0UL /* MIB RX Symbol Errors */
#define B44_RX_PAUSE		0x05D4UL /* MIB RX Pause Packets */
#define B44_RX_NPAUSE		0x05D8UL /* MIB RX Non-Pause Packets */

/* Sonics Silicon backplane register definitions */
#define B44_SBIMSTATE		0x0F90UL /* SB Initiator Agent State */
#define  SBIMSTATE_PC		0x0000000f /* Pipe Count */
#define  SBIMSTATE_AP_MASK	0x00000030 /* Arbitration Priority */
#define  SBIMSTATE_AP_BOTH	0x00000000 /* both timeslices and token */
#define  SBIMSTATE_AP_TS	0x00000010 /* Use timeslices only */
#define  SBIMSTATE_AP_TK	0x00000020 /* Use token only */
#define  SBIMSTATE_AP_RSV	0x00000030 /* Reserved */
#define  SBIMSTATE_IBE		0x00020000 /* In Band Error */
#define  SBIMSTATE_TO		0x00040000 /* Timeout */
#define  SBIMSTATE_BAD      ( SBIMSTATE_IBE | SBIMSTATE_TO )
#define B44_SBINTVEC		0x0F94UL /* SB Interrupt Mask */
#define  SBINTVEC_PCI		0x00000001 /* Enable interrupts for PCI */
#define  SBINTVEC_ENET0		0x00000002 /* Enable ints for enet 0 */
#define  SBINTVEC_ILINE20	0x00000004 /* Enable ints for iline20 */
#define  SBINTVEC_CODEC		0x00000008 /* Enable ints for v90 codec */
#define  SBINTVEC_USB		0x00000010 /* Enable intts for usb */
#define  SBINTVEC_EXTIF		0x00000020 /* Enable ints for ext i/f */
#define  SBINTVEC_ENET1		0x00000040 /* Enable ints for enet 1 */
#define B44_SBTMSLOW		0x0F98UL /* SB Target State Low */
#define  SBTMSLOW_RESET		0x00000001 /* Reset */
#define  SBTMSLOW_REJECT	0x00000002 /* Reject */
#define  SBTMSLOW_CLOCK		0x00010000 /* Clock Enable */
#define  SBTMSLOW_FGC		0x00020000 /* Force Gated Clocks On */
#define  SBTMSLOW_PE		0x40000000 /* Power Management Enable */
#define  SBTMSLOW_BE		0x80000000 /* BIST Enable */
#define B44_SBTMSHIGH		0x0F9CUL /* SB Target State High */
#define  SBTMSHIGH_SERR		0x00000001 /* S-error */
#define  SBTMSHIGH_INT		0x00000002 /* Interrupt */
#define  SBTMSHIGH_BUSY		0x00000004 /* Busy */
#define  SBTMSHIGH_GCR		0x20000000 /* Gated Clock Request */
#define  SBTMSHIGH_BISTF	0x40000000 /* BIST Failed */
#define  SBTMSHIGH_BISTD	0x80000000 /* BIST Done */
#define B44_SBIDHIGH		0x0FFCUL /* SB Identification High */
#define  SBIDHIGH_RC_MASK	0x0000000f /* Revision Code */
#define  SBIDHIGH_CC_MASK	0x0000fff0 /* Core Code */
#define  SBIDHIGH_CC_SHIFT	4
#define  SBIDHIGH_VC_MASK	0xffff0000 /* Vendor Code */
#define  SBIDHIGH_VC_SHIFT	16

/* SSB PCI config space registers.  */
#define SSB_PMCSR		0x44
#define  SSB_PE			0x100
#define	SSB_BAR0_WIN		0x80
#define	SSB_BAR1_WIN		0x84
#define	SSB_SPROM_CONTROL	0x88
#define	SSB_BAR1_CONTROL	0x8c

/* SSB core and host control registers.  */
#define SSB_CONTROL		0x0000UL
#define SSB_ARBCONTROL		0x0010UL
#define SSB_ISTAT		0x0020UL
#define SSB_IMASK		0x0024UL
#define SSB_MBOX		0x0028UL
#define SSB_BCAST_ADDR		0x0050UL
#define SSB_BCAST_DATA		0x0054UL
#define SSB_PCI_TRANS_0		0x0100UL
#define SSB_PCI_TRANS_1		0x0104UL
#define SSB_PCI_TRANS_2		0x0108UL
#define SSB_SPROM		0x0800UL

#define SSB_PCI_MEM		0x00000000
#define SSB_PCI_IO		0x00000001
#define SSB_PCI_CFG0		0x00000002
#define SSB_PCI_CFG1		0x00000003
#define SSB_PCI_PREF		0x00000004
#define SSB_PCI_BURST		0x00000008
#define SSB_PCI_MASK0		0xfc000000
#define SSB_PCI_MASK1		0xfc000000
#define SSB_PCI_MASK2		0xc0000000

/* 4400 PHY registers */
#define B44_MII_AUXCTRL		24	/* Auxiliary Control */
#define  MII_AUXCTRL_DUPLEX	0x0001  /* Full Duplex */
#define  MII_AUXCTRL_SPEED	0x0002  /* 1=100Mbps, 0=10Mbps */
#define  MII_AUXCTRL_FORCED	0x0004	/* Forced 10/100 */
#define B44_MII_ALEDCTRL	26	/* Activity LED */
#define  MII_ALEDCTRL_ALLMSK	0x7fff
#define B44_MII_TLEDCTRL	27	/* Traffic Meter LED */
#define  MII_TLEDCTRL_ENABLE	0x0040

/* RX/TX descriptor */
struct dma_desc {
	u32 ctrl; /* length of data and flags */
	u32 addr; /* address of data */
};

/* There are only 12 bits in the DMA engine for descriptor offsetting
 * so the table must be aligned on a boundary of this.
 */
#define B44_DMA_ALIGNMENT	4096

/* The DMA engine can only address the first gigabyte of address space
 */
#define B44_30BIT_DMA_MASK	0x3fffffff

#define DESC_CTRL_LEN		0x00001fff
#define DESC_CTRL_CMASK		0x0ff00000 /* Core specific bits */
#define DESC_CTRL_EOT		0x10000000 /* End of Table */
#define DESC_CTRL_IOC		0x20000000 /* Interrupt On Completion */
#define DESC_CTRL_EOF		0x40000000 /* End of Frame */
#define DESC_CTRL_SOF		0x80000000 /* Start of Frame */

struct rx_header {
	u16 len;
	u16 flags;
	u16 pad[12];
};
#define RX_HEADER_LEN	28

#define RX_FLAG_OFIFO	0x00000001 /* FIFO Overflow */
#define RX_FLAG_CRCERR	0x00000002 /* CRC Error */
#define RX_FLAG_SERR	0x00000004 /* Receive Symbol Error */
#define RX_FLAG_ODD	0x00000008 /* Frame has odd number of nibbles */
#define RX_FLAG_LARGE	0x00000010 /* Frame is > RX MAX Length */
#define RX_FLAG_MCAST	0x00000020 /* Dest is Multicast Address */
#define RX_FLAG_BCAST	0x00000040 /* Dest is Broadcast Address */
#define RX_FLAG_MISS	0x00000080 /* Received due to promisc mode */
#define RX_FLAG_LAST	0x00000800 /* Last buffer in frame */
#define RX_FLAG_ERRORS	(RX_FLAG_ODD | RX_FLAG_SERR |\
                         RX_FLAG_CRCERR | RX_FLAG_OFIFO)

/* Client Mode PCI memory access space (1 GB) */
#define SB_PCI_DMA              0x40000000

 /* Address of PCI core on BCM4400 cards */
#define BCM4400_PCI_CORE_ADDR   0x18002000

/* Hardware minimum and maximum for a single frame's data payload */
#define B44_MIN_MTU		60
#define B44_MAX_MTU		1500

#define B44_RING_SIZE           8
#define B44_RING_LAST           ( B44_RING_SIZE - 1 )

#define B44_RX_RING_LEN_BYTES	( sizeof bp->rx[0] * B44_RING_SIZE )
#define B44_TX_RING_LEN_BYTES	( sizeof bp->tx[0] * B44_RING_SIZE )

#define RX_PKT_OFFSET		30
#define RX_PKT_BUF_SZ		(1536 + RX_PKT_OFFSET + 64)

#define B44_FULL_RESET		1
#define B44_FULL_RESET_SKIP_PHY	2
#define B44_PARTIAL_RESET	3
#define B44_CHIP_RESET_FULL     4
#define B44_CHIP_RESET_PARTIAL  5

#define SSB_CORE_DOWN           ( SBTMSLOW_RESET | SBTMSLOW_REJECT )

#define B44_REGS_SIZE           8192

/** Driver private state */
struct b44_private {
	struct net_device *netdev;
	struct pci_device *pci;
	u8 *regs; /* memory-mapped registers */
	u8 phy_addr;

	struct dma_desc *tx;
	struct io_buffer *tx_iobuf[B44_RING_SIZE];
	u32 tx_cur; /* next available descriptor */
	u32 tx_dirty; /* oldest pending descriptor */

	struct dma_desc *rx;
	struct io_buffer *rx_iobuf[B44_RING_SIZE];
	u32 rx_cur; /* next descriptor to read */
};


static void ssb_core_reset ( struct b44_private *bp );
static void ssb_core_disable ( struct b44_private *bp );
static u32 ssb_pci_setup ( struct b44_private *bp, u32 cores );

static void b44_chip_reset ( struct b44_private *bp, int reset_kind );
static void b44_init_hw ( struct b44_private *bp, int reset_kind );
static void b44_cam_write ( struct b44_private *bp, u8 *data, int index );
static void b44_set_mac_addr ( struct b44_private *bp );
static void b44_set_rx_mode ( struct net_device *netdev );
static void b44_halt(struct b44_private *);

static int b44_phy_reset ( struct b44_private *bp );
static int b44_phy_write ( struct b44_private *bp, int reg, u32 val );
static int b44_phy_read ( struct b44_private *bp, int reg, u32 *val );

static int b44_init_tx_ring ( struct b44_private *bp );
static void b44_free_tx_ring ( struct b44_private *bp );
static int b44_init_rx_ring ( struct b44_private *bp );
static void b44_free_rx_ring ( struct b44_private *bp );
static void b44_rx_refill ( struct b44_private *bp, u32 pending );
static void b44_populate_rx_descriptor (struct b44_private *bp, u32 index);

static int b44_probe ( struct pci_device *pci );
static void b44_remove ( struct pci_device *pci );

static int b44_open ( struct net_device *netdev );
static void b44_close ( struct net_device *netdev );
static void b44_irq ( struct net_device *netdev, int enable );
static void b44_poll ( struct net_device *netdev );
static void b44_process_rx_packets ( struct b44_private *bp );
static int b44_transmit ( struct net_device *netdev,
                          struct io_buffer *iobuf );

static struct net_device_operations b44_operations;

#endif /* _B44_H */
