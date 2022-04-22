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

#ifndef _IGBVF_REGS_H_
#define _IGBVF_REGS_H_

#define E1000_CTRL     0x00000  /* Device Control - RW */
#define E1000_CTRL_DUP 0x00004  /* Device Control Duplicate (Shadow) - RW */
#define E1000_STATUS   0x00008  /* Device Status - RO */
#define E1000_EECD     0x00010  /* EEPROM/Flash Control - RW */
#define E1000_EERD     0x00014  /* EEPROM Read - RW */
#define E1000_CTRL_EXT 0x00018  /* Extended Device Control - RW */
#define E1000_FLA      0x0001C  /* Flash Access - RW */
#define E1000_MDIC     0x00020  /* MDI Control - RW */
#define E1000_SCTL     0x00024  /* SerDes Control - RW */
#define E1000_FCAL     0x00028  /* Flow Control Address Low - RW */
#define E1000_FCAH     0x0002C  /* Flow Control Address High -RW */
#define E1000_FEXT     0x0002C  /* Future Extended - RW */
#define E1000_FEXTNVM  0x00028  /* Future Extended NVM - RW */
#define E1000_FCT      0x00030  /* Flow Control Type - RW */
#define E1000_CONNSW   0x00034  /* Copper/Fiber switch control - RW */
#define E1000_VET      0x00038  /* VLAN Ether Type - RW */
#define E1000_ICR      0x000C0  /* Interrupt Cause Read - R/clr */
#define E1000_ITR      0x000C4  /* Interrupt Throttling Rate - RW */
#define E1000_ICS      0x000C8  /* Interrupt Cause Set - WO */
#define E1000_IMS      0x000D0  /* Interrupt Mask Set - RW */
#define E1000_IMC      0x000D8  /* Interrupt Mask Clear - WO */
#define E1000_IAM      0x000E0  /* Interrupt Acknowledge Auto Mask */
#define E1000_RCTL     0x00100  /* Rx Control - RW */
#define E1000_FCTTV    0x00170  /* Flow Control Transmit Timer Value - RW */
#define E1000_TXCW     0x00178  /* Tx Configuration Word - RW */
#define E1000_RXCW     0x00180  /* Rx Configuration Word - RO */
#define E1000_TCTL     0x00400  /* Tx Control - RW */
#define E1000_TCTL_EXT 0x00404  /* Extended Tx Control - RW */
#define E1000_TIPG     0x00410  /* Tx Inter-packet gap -RW */
#define E1000_TBT      0x00448  /* Tx Burst Timer - RW */
#define E1000_AIT      0x00458  /* Adaptive Interframe Spacing Throttle - RW */
#define E1000_LEDCTL   0x00E00  /* LED Control - RW */
#define E1000_EXTCNF_CTRL  0x00F00  /* Extended Configuration Control */
#define E1000_EXTCNF_SIZE  0x00F08  /* Extended Configuration Size */
#define E1000_PHY_CTRL     0x00F10  /* PHY Control Register in CSR */
#define E1000_PBA      0x01000  /* Packet Buffer Allocation - RW */
#define E1000_PBS      0x01008  /* Packet Buffer Size */
#define E1000_EEMNGCTL 0x01010  /* MNG EEprom Control */
#define E1000_EEARBC   0x01024  /* EEPROM Auto Read Bus Control */
#define E1000_FLASHT   0x01028  /* FLASH Timer Register */
#define E1000_EEWR     0x0102C  /* EEPROM Write Register - RW */
#define E1000_FLSWCTL  0x01030  /* FLASH control register */
#define E1000_FLSWDATA 0x01034  /* FLASH data register */
#define E1000_FLSWCNT  0x01038  /* FLASH Access Counter */
#define E1000_FLOP     0x0103C  /* FLASH Opcode Register */
#define E1000_I2CCMD   0x01028  /* SFPI2C Command Register - RW */
#define E1000_I2CPARAMS 0x0102C /* SFPI2C Parameters Register - RW */
#define E1000_WDSTP    0x01040  /* Watchdog Setup - RW */
#define E1000_SWDSTS   0x01044  /* SW Device Status - RW */
#define E1000_FRTIMER  0x01048  /* Free Running Timer - RW */
#define E1000_ERT      0x02008  /* Early Rx Threshold - RW */
#define E1000_FCRTL    0x02160  /* Flow Control Receive Threshold Low - RW */
#define E1000_FCRTH    0x02168  /* Flow Control Receive Threshold High - RW */
#define E1000_PSRCTL   0x02170  /* Packet Split Receive Control - RW */
#define E1000_RDFPCQ(_n)  (0x02430 + (0x4 * (_n)))
#define E1000_PBRTH    0x02458  /* PB Rx Arbitration Threshold - RW */
#define E1000_FCRTV    0x02460  /* Flow Control Refresh Timer Value - RW */
/* Split and Replication Rx Control - RW */
#define E1000_RDPUMB   0x025CC  /* DMA Rx Descriptor uC Mailbox - RW */
#define E1000_RDPUAD   0x025D0  /* DMA Rx Descriptor uC Addr Command - RW */
#define E1000_RDPUWD   0x025D4  /* DMA Rx Descriptor uC Data Write - RW */
#define E1000_RDPURD   0x025D8  /* DMA Rx Descriptor uC Data Read - RW */
#define E1000_RDPUCTL  0x025DC  /* DMA Rx Descriptor uC Control - RW */
#define E1000_RXCTL(_n)   (0x0C014 + (0x40 * (_n)))
#define E1000_RQDPC(_n)   (0x0C030 + (0x40 * (_n)))
#define E1000_RDTR     0x02820  /* Rx Delay Timer - RW */
#define E1000_RADV     0x0282C  /* Rx Interrupt Absolute Delay Timer - RW */
/*
 * Convenience macros
 *
 * Note: "_n" is the queue number of the register to be written to.
 *
 * Example usage:
 * E1000_RDBAL_REG(current_rx_queue)
 */
#define E1000_RDBAL(_n)      ((_n) < 4 ? (0x02800 + ((_n) * 0x100)) : \
                                         (0x0C000 + ((_n) * 0x40)))
#define E1000_RDBAH(_n)      ((_n) < 4 ? (0x02804 + ((_n) * 0x100)) : \
                                         (0x0C004 + ((_n) * 0x40)))
#define E1000_RDLEN(_n)      ((_n) < 4 ? (0x02808 + ((_n) * 0x100)) : \
                                         (0x0C008 + ((_n) * 0x40)))
#define E1000_SRRCTL(_n)     ((_n) < 4 ? (0x0280C + ((_n) * 0x100)) : \
                                         (0x0C00C + ((_n) * 0x40)))
#define E1000_RDH(_n)        ((_n) < 4 ? (0x02810 + ((_n) * 0x100)) : \
                                         (0x0C010 + ((_n) * 0x40)))
#define E1000_RDT(_n)        ((_n) < 4 ? (0x02818 + ((_n) * 0x100)) : \
                                         (0x0C018 + ((_n) * 0x40)))
#define E1000_RXDCTL(_n)     ((_n) < 4 ? (0x02828 + ((_n) * 0x100)) : \
                                         (0x0C028 + ((_n) * 0x40)))
#define E1000_TDBAL(_n)      ((_n) < 4 ? (0x03800 + ((_n) * 0x100)) : \
                                         (0x0E000 + ((_n) * 0x40)))
#define E1000_TDBAH(_n)      ((_n) < 4 ? (0x03804 + ((_n) * 0x100)) : \
                                         (0x0E004 + ((_n) * 0x40)))
#define E1000_TDLEN(_n)      ((_n) < 4 ? (0x03808 + ((_n) * 0x100)) : \
                                         (0x0E008 + ((_n) * 0x40)))
#define E1000_TDH(_n)        ((_n) < 4 ? (0x03810 + ((_n) * 0x100)) : \
                                         (0x0E010 + ((_n) * 0x40)))
#define E1000_TDT(_n)        ((_n) < 4 ? (0x03818 + ((_n) * 0x100)) : \
                                         (0x0E018 + ((_n) * 0x40)))
#define E1000_TXDCTL(_n)     ((_n) < 4 ? (0x03828 + ((_n) * 0x100)) : \
                                         (0x0E028 + ((_n) * 0x40)))
#define E1000_TARC(_n)       (0x03840 + (_n << 8))
#define E1000_DCA_TXCTRL(_n) (0x03814 + (_n << 8))
#define E1000_DCA_RXCTRL(_n) (0x02814 + (_n << 8))
#define E1000_TDWBAL(_n)     ((_n) < 4 ? (0x03838 + ((_n) * 0x100)) : \
                                         (0x0E038 + ((_n) * 0x40)))
#define E1000_TDWBAH(_n)     ((_n) < 4 ? (0x0383C + ((_n) * 0x100)) : \
                                         (0x0E03C + ((_n) * 0x40)))
#define E1000_RSRPD    0x02C00  /* Rx Small Packet Detect - RW */
#define E1000_RAID     0x02C08  /* Receive Ack Interrupt Delay - RW */
#define E1000_TXDMAC   0x03000  /* Tx DMA Control - RW */
#define E1000_KABGTXD  0x03004  /* AFE Band Gap Transmit Ref Data */
#define E1000_PSRTYPE(_i)       (0x05480 + ((_i) * 4))
#define E1000_RAL(_i)  (((_i) <= 15) ? (0x05400 + ((_i) * 8)) : \
                                       (0x054E0 + ((_i - 16) * 8)))
#define E1000_RAH(_i)  (((_i) <= 15) ? (0x05404 + ((_i) * 8)) : \
                                       (0x054E4 + ((_i - 16) * 8)))
#define E1000_IP4AT_REG(_i)     (0x05840 + ((_i) * 8))
#define E1000_IP6AT_REG(_i)     (0x05880 + ((_i) * 4))
#define E1000_WUPM_REG(_i)      (0x05A00 + ((_i) * 4))
#define E1000_FFMT_REG(_i)      (0x09000 + ((_i) * 8))
#define E1000_FFVT_REG(_i)      (0x09800 + ((_i) * 8))
#define E1000_FFLT_REG(_i)      (0x05F00 + ((_i) * 8))
#define E1000_TDFH     0x03410  /* Tx Data FIFO Head - RW */
#define E1000_TDFT     0x03418  /* Tx Data FIFO Tail - RW */
#define E1000_TDFHS    0x03420  /* Tx Data FIFO Head Saved - RW */
#define E1000_TDFTS    0x03428  /* Tx Data FIFO Tail Saved - RW */
#define E1000_TDFPC    0x03430  /* Tx Data FIFO Packet Count - RW */
#define E1000_TDPUMB   0x0357C  /* DMA Tx Descriptor uC Mail Box - RW */
#define E1000_TDPUAD   0x03580  /* DMA Tx Descriptor uC Addr Command - RW */
#define E1000_TDPUWD   0x03584  /* DMA Tx Descriptor uC Data Write - RW */
#define E1000_TDPURD   0x03588  /* DMA Tx Descriptor uC Data  Read  - RW */
#define E1000_TDPUCTL  0x0358C  /* DMA Tx Descriptor uC Control - RW */
#define E1000_DTXCTL   0x03590  /* DMA Tx Control - RW */
#define E1000_TIDV     0x03820  /* Tx Interrupt Delay Value - RW */
#define E1000_TADV     0x0382C  /* Tx Interrupt Absolute Delay Val - RW */
#define E1000_TSPMT    0x03830  /* TCP Segmentation PAD & Min Threshold - RW */
#define E1000_CRCERRS  0x04000  /* CRC Error Count - R/clr */
#define E1000_ALGNERRC 0x04004  /* Alignment Error Count - R/clr */
#define E1000_SYMERRS  0x04008  /* Symbol Error Count - R/clr */
#define E1000_RXERRC   0x0400C  /* Receive Error Count - R/clr */
#define E1000_MPC      0x04010  /* Missed Packet Count - R/clr */
#define E1000_SCC      0x04014  /* Single Collision Count - R/clr */
#define E1000_ECOL     0x04018  /* Excessive Collision Count - R/clr */
#define E1000_MCC      0x0401C  /* Multiple Collision Count - R/clr */
#define E1000_LATECOL  0x04020  /* Late Collision Count - R/clr */
#define E1000_COLC     0x04028  /* Collision Count - R/clr */
#define E1000_DC       0x04030  /* Defer Count - R/clr */
#define E1000_TNCRS    0x04034  /* Tx-No CRS - R/clr */
#define E1000_SEC      0x04038  /* Sequence Error Count - R/clr */
#define E1000_CEXTERR  0x0403C  /* Carrier Extension Error Count - R/clr */
#define E1000_RLEC     0x04040  /* Receive Length Error Count - R/clr */
#define E1000_XONRXC   0x04048  /* XON Rx Count - R/clr */
#define E1000_XONTXC   0x0404C  /* XON Tx Count - R/clr */
#define E1000_XOFFRXC  0x04050  /* XOFF Rx Count - R/clr */
#define E1000_XOFFTXC  0x04054  /* XOFF Tx Count - R/clr */
#define E1000_FCRUC    0x04058  /* Flow Control Rx Unsupported Count- R/clr */
#define E1000_PRC64    0x0405C  /* Packets Rx (64 bytes) - R/clr */
#define E1000_PRC127   0x04060  /* Packets Rx (65-127 bytes) - R/clr */
#define E1000_PRC255   0x04064  /* Packets Rx (128-255 bytes) - R/clr */
#define E1000_PRC511   0x04068  /* Packets Rx (255-511 bytes) - R/clr */
#define E1000_PRC1023  0x0406C  /* Packets Rx (512-1023 bytes) - R/clr */
#define E1000_PRC1522  0x04070  /* Packets Rx (1024-1522 bytes) - R/clr */
#define E1000_GPRC     0x04074  /* Good Packets Rx Count - R/clr */
#define E1000_BPRC     0x04078  /* Broadcast Packets Rx Count - R/clr */
#define E1000_MPRC     0x0407C  /* Multicast Packets Rx Count - R/clr */
#define E1000_GPTC     0x04080  /* Good Packets Tx Count - R/clr */
#define E1000_GORCL    0x04088  /* Good Octets Rx Count Low - R/clr */
#define E1000_GORCH    0x0408C  /* Good Octets Rx Count High - R/clr */
#define E1000_GOTCL    0x04090  /* Good Octets Tx Count Low - R/clr */
#define E1000_GOTCH    0x04094  /* Good Octets Tx Count High - R/clr */
#define E1000_RNBC     0x040A0  /* Rx No Buffers Count - R/clr */
#define E1000_RUC      0x040A4  /* Rx Undersize Count - R/clr */
#define E1000_RFC      0x040A8  /* Rx Fragment Count - R/clr */
#define E1000_ROC      0x040AC  /* Rx Oversize Count - R/clr */
#define E1000_RJC      0x040B0  /* Rx Jabber Count - R/clr */
#define E1000_MGTPRC   0x040B4  /* Management Packets Rx Count - R/clr */
#define E1000_MGTPDC   0x040B8  /* Management Packets Dropped Count - R/clr */
#define E1000_MGTPTC   0x040BC  /* Management Packets Tx Count - R/clr */
#define E1000_TORL     0x040C0  /* Total Octets Rx Low - R/clr */
#define E1000_TORH     0x040C4  /* Total Octets Rx High - R/clr */
#define E1000_TOTL     0x040C8  /* Total Octets Tx Low - R/clr */
#define E1000_TOTH     0x040CC  /* Total Octets Tx High - R/clr */
#define E1000_TPR      0x040D0  /* Total Packets Rx - R/clr */
#define E1000_TPT      0x040D4  /* Total Packets Tx - R/clr */
#define E1000_PTC64    0x040D8  /* Packets Tx (64 bytes) - R/clr */
#define E1000_PTC127   0x040DC  /* Packets Tx (65-127 bytes) - R/clr */
#define E1000_PTC255   0x040E0  /* Packets Tx (128-255 bytes) - R/clr */
#define E1000_PTC511   0x040E4  /* Packets Tx (256-511 bytes) - R/clr */
#define E1000_PTC1023  0x040E8  /* Packets Tx (512-1023 bytes) - R/clr */
#define E1000_PTC1522  0x040EC  /* Packets Tx (1024-1522 Bytes) - R/clr */
#define E1000_MPTC     0x040F0  /* Multicast Packets Tx Count - R/clr */
#define E1000_BPTC     0x040F4  /* Broadcast Packets Tx Count - R/clr */
#define E1000_TSCTC    0x040F8  /* TCP Segmentation Context Tx - R/clr */
#define E1000_TSCTFC   0x040FC  /* TCP Segmentation Context Tx Fail - R/clr */
#define E1000_IAC      0x04100  /* Interrupt Assertion Count */
#define E1000_ICRXPTC  0x04104  /* Interrupt Cause Rx Pkt Timer Expire Count */
#define E1000_ICRXATC  0x04108  /* Interrupt Cause Rx Abs Timer Expire Count */
#define E1000_ICTXPTC  0x0410C  /* Interrupt Cause Tx Pkt Timer Expire Count */
#define E1000_ICTXATC  0x04110  /* Interrupt Cause Tx Abs Timer Expire Count */
#define E1000_ICTXQEC  0x04118  /* Interrupt Cause Tx Queue Empty Count */
#define E1000_ICTXQMTC 0x0411C  /* Interrupt Cause Tx Queue Min Thresh Count */
#define E1000_ICRXDMTC 0x04120  /* Interrupt Cause Rx Desc Min Thresh Count */
#define E1000_ICRXOC   0x04124  /* Interrupt Cause Receiver Overrun Count */

#define E1000_VFGPRC   0x00F10
#define E1000_VFGORC   0x00F18
#define E1000_VFMPRC   0x00F3C
#define E1000_VFGPTC   0x00F14
#define E1000_VFGOTC   0x00F34
#define E1000_VFGOTLBC 0x00F50
#define E1000_VFGPTLBC 0x00F44
#define E1000_VFGORLBC 0x00F48
#define E1000_VFGPRLBC 0x00F40
#define E1000_PCS_CFG0    0x04200  /* PCS Configuration 0 - RW */
#define E1000_PCS_LCTL    0x04208  /* PCS Link Control - RW */
#define E1000_PCS_LSTAT   0x0420C  /* PCS Link Status - RO */
#define E1000_CBTMPC      0x0402C  /* Circuit Breaker Tx Packet Count */
#define E1000_HTDPMC      0x0403C  /* Host Transmit Discarded Packets */
#define E1000_CBRDPC      0x04044  /* Circuit Breaker Rx Dropped Count */
#define E1000_CBRMPC      0x040FC  /* Circuit Breaker Rx Packet Count */
#define E1000_RPTHC       0x04104  /* Rx Packets To Host */
#define E1000_HGPTC       0x04118  /* Host Good Packets Tx Count */
#define E1000_HTCBDPC     0x04124  /* Host Tx Circuit Breaker Dropped Count */
#define E1000_HGORCL      0x04128  /* Host Good Octets Received Count Low */
#define E1000_HGORCH      0x0412C  /* Host Good Octets Received Count High */
#define E1000_HGOTCL      0x04130  /* Host Good Octets Transmit Count Low */
#define E1000_HGOTCH      0x04134  /* Host Good Octets Transmit Count High */
#define E1000_LENERRS     0x04138  /* Length Errors Count */
#define E1000_SCVPC       0x04228  /* SerDes/SGMII Code Violation Pkt Count */
#define E1000_HRMPC       0x0A018  /* Header Redirection Missed Packet Count */
#define E1000_PCS_ANADV   0x04218  /* AN advertisement - RW */
#define E1000_PCS_LPAB    0x0421C  /* Link Partner Ability - RW */
#define E1000_PCS_NPTX    0x04220  /* AN Next Page Transmit - RW */
#define E1000_PCS_LPABNP  0x04224  /* Link Partner Ability Next Page - RW */
#define E1000_1GSTAT_RCV  0x04228  /* 1GSTAT Code Violation Packet Count - RW */
#define E1000_RXCSUM   0x05000  /* Rx Checksum Control - RW */
#define E1000_RLPML    0x05004  /* Rx Long Packet Max Length */
#define E1000_RFCTL    0x05008  /* Receive Filter Control*/
#define E1000_MTA      0x05200  /* Multicast Table Array - RW Array */
#define E1000_RA       0x05400  /* Receive Address - RW Array */
#define E1000_VFTA     0x05600  /* VLAN Filter Table Array - RW Array */
#define E1000_VT_CTL   0x0581C  /* VMDq Control - RW */
#define E1000_VFQA0    0x0B000  /* VLAN Filter Queue Array 0 - RW Array */
#define E1000_VFQA1    0x0B200  /* VLAN Filter Queue Array 1 - RW Array */
#define E1000_WUC      0x05800  /* Wakeup Control - RW */
#define E1000_WUFC     0x05808  /* Wakeup Filter Control - RW */
#define E1000_WUS      0x05810  /* Wakeup Status - RO */
#define E1000_MANC     0x05820  /* Management Control - RW */
#define E1000_IPAV     0x05838  /* IP Address Valid - RW */
#define E1000_IP4AT    0x05840  /* IPv4 Address Table - RW Array */
#define E1000_IP6AT    0x05880  /* IPv6 Address Table - RW Array */
#define E1000_WUPL     0x05900  /* Wakeup Packet Length - RW */
#define E1000_WUPM     0x05A00  /* Wakeup Packet Memory - RO A */
#define E1000_PBACL    0x05B68  /* MSIx PBA Clear - Read/Write 1's to clear */
#define E1000_FFLT     0x05F00  /* Flexible Filter Length Table - RW Array */
#define E1000_HOST_IF  0x08800  /* Host Interface */
#define E1000_FFMT     0x09000  /* Flexible Filter Mask Table - RW Array */
#define E1000_FFVT     0x09800  /* Flexible Filter Value Table - RW Array */

#define E1000_KMRNCTRLSTA 0x00034 /* MAC-PHY interface - RW */
#define E1000_MDPHYA      0x0003C /* PHY address - RW */
#define E1000_MANC2H      0x05860 /* Management Control To Host - RW */
#define E1000_SW_FW_SYNC  0x05B5C /* Software-Firmware Synchronization - RW */
#define E1000_CCMCTL      0x05B48 /* CCM Control Register */
#define E1000_GIOCTL      0x05B44 /* GIO Analog Control Register */
#define E1000_SCCTL       0x05B4C /* PCIc PLL Configuration Register */
#define E1000_GCR         0x05B00 /* PCI-Ex Control */
#define E1000_GCR2        0x05B64 /* PCI-Ex Control #2 */
#define E1000_GSCL_1    0x05B10 /* PCI-Ex Statistic Control #1 */
#define E1000_GSCL_2    0x05B14 /* PCI-Ex Statistic Control #2 */
#define E1000_GSCL_3    0x05B18 /* PCI-Ex Statistic Control #3 */
#define E1000_GSCL_4    0x05B1C /* PCI-Ex Statistic Control #4 */
#define E1000_FACTPS    0x05B30 /* Function Active and Power State to MNG */
#define E1000_SWSM      0x05B50 /* SW Semaphore */
#define E1000_FWSM      0x05B54 /* FW Semaphore */
#define E1000_SWSM2     0x05B58 /* Driver-only SW semaphore (not used by BOOT agents) */
#define E1000_DCA_ID    0x05B70 /* DCA Requester ID Information - RO */
#define E1000_DCA_CTRL  0x05B74 /* DCA Control - RW */
#define E1000_FFLT_DBG  0x05F04 /* Debug Register */
#define E1000_HICR      0x08F00 /* Host Interface Control */

/* RSS registers */
#define E1000_CPUVEC    0x02C10 /* CPU Vector Register - RW */
#define E1000_MRQC      0x05818 /* Multiple Receive Control - RW */
#define E1000_IMIR(_i)      (0x05A80 + ((_i) * 4))  /* Immediate Interrupt */
#define E1000_IMIREXT(_i)   (0x05AA0 + ((_i) * 4))  /* Immediate Interrupt Ext*/
#define E1000_IMIRVP    0x05AC0 /* Immediate Interrupt Rx VLAN Priority - RW */
#define E1000_MSIXBM(_i)    (0x01600 + ((_i) * 4)) /* MSI-X Allocation Register
                                                    * (_i) - RW */
#define E1000_MSIXTADD(_i)  (0x0C000 + ((_i) * 0x10)) /* MSI-X Table entry addr
                                                       * low reg - RW */
#define E1000_MSIXTUADD(_i) (0x0C004 + ((_i) * 0x10)) /* MSI-X Table entry addr
                                                       * upper reg - RW */
#define E1000_MSIXTMSG(_i)  (0x0C008 + ((_i) * 0x10)) /* MSI-X Table entry
                                                       * message reg - RW */
#define E1000_MSIXVCTRL(_i) (0x0C00C + ((_i) * 0x10)) /* MSI-X Table entry
                                                       * vector ctrl reg - RW */
#define E1000_MSIXPBA    0x0E000 /* MSI-X Pending bit array */
#define E1000_RETA(_i)  (0x05C00 + ((_i) * 4)) /* Redirection Table - RW */
#define E1000_RSSRK(_i) (0x05C80 + ((_i) * 4)) /* RSS Random Key - RW */
#define E1000_RSSIM     0x05864 /* RSS Interrupt Mask */
#define E1000_RSSIR     0x05868 /* RSS Interrupt Request */

#endif /* _IGBVF_REGS_H_ */
