#!/usr/bin/env python3

import sys
import ppc
import re

# Mnemonic PHB_ESR - Address Offset 0x0C80 - phbErrorStatusRegister
phb_esr_bits = [
	(0, "ETU/RSB Request Address Error"),
	(1, "Fundamental A Request Address Error"),
	(2, "Fundamental A Request Size/Alignment Error"),
	(3, "Fundamental A PCI CFG Addr/Size Error"),
	(4, "Fundamental A IODA Table Access Error"),
	(5, "Fundamental A Internal Registers Parity Error"),
	(6, "PHB Error Registers Request Address Error"),
	(7, "PHB Error Registers Request Size/Alignment Error"),
	(8, "Fundamental B Request Address Error"),
	(9, "Fundamental B Request Size/Alignment Error"),
	(10, "Fundamental B Internal Registers Parity Error"),
	(11, "Internal Bus Logic Bad PCIE Macro Request Address"),
	(12, "Debug Request Address Error"),
	(13, "Debug Request Size/Alignment Error"),
	(14, "Debug Internal Registers Parity Error"),
	(15, "Internal Bus Logic State Machine One-Hot Error"),
	(16, "UV Page Request Address Error"),
	(17, "UV Page Request Size/Alignment Error"),
	(18, "UV Page Internal Registers Parity Error"),
	(20, "RXE_ARB OR Error Status"),
	(21, "RXE_MRG OR Error Status"),
	(22, "RXE_TCE OR Error Status"),
	(23, "TXE OR Error Status"),
	(24, "pcie_etu_regb_err_inf"),
	(25, "pcie_etu_regb_err_erc"),
	(26, "pcie_etu_regb_err_fat"),
	(27, "bus_regs_req_wr_data_p_e"),
	(28, "SCOM HV Indirect Access Error"),
	(29, "SCOM UV Indirect Access Error"),
	(30, "SCOM Internal Registers Parity Error"),
	(31, "SCOM Satellite Finite State Machine Error"),
]

# Mnemonic TXE_ESR  - Address Offset 0x0D00 - txeFirstErrorStatus
txe_esr_bits = [
	(0, "AIB Command Invalid"),
	(2, "AIB Address Decode Error"),
	(3, "AIB Size Invalid"),
	(4, "AIB Cmd Ctrls Parity Error"),
	(5, "AIB Data Ctrls Parity Error"),
	(8, "AIB Alignment Error"),
	(9, "AIB Cmd Bus Parity Error"),
	(10, "AIB Data Bus UE ECC Error"),
	(11, "AIB Data Ctrls Sequence Error"),
	(12, "AIB Data Bus CE ECC Error"),
	(13, "TCE Rd Response DAT_ERR Indication"),
	(14, "AIB Command Credits Error"),
	(15, "AIB Data Credits Error"),
	(16, "BLIF Controls Parity Error"),
	(17, "CFG Write Error CA or UR response"),
	(18, "BLIF Forward Progress Timeout"),
	(19, "MMIO RD Pending Error"),
	(20, "MMIO WR Pending Error"),
	(21, "MMIO CFG Pending Error"),
	(22, "MMIO Write DAT_ERR Indication"),
	(23, "CI Store Data Fifo Error"),
	(24, "CFG Enable Error, RRB"),
	(25, "CFG Size Error"),
	(26, "CFG Bus Address Error"),
	(27, "CFG Link Down Error"),
	(28, "PAPR TXE Injection Error Triggered"),
	(29, "CFG Write Request Timeout"),
	(30, "PAPR TXE Injection Error Triggered"),
	(36, "CI Trigger Buffer ECC Correctable Error"),
	(37, "CI Trigger Buffer ECC Uncorrectable Error"),
	(38, "CI Trigger Buffer Stage Data Parity Error"),
	(40, "MMIO BAR Table (MBT) Parity Error"),
	(42, "MMIO Domain Table (MDT) ECC Correctable Error"),
	(43, "MMIO Domain Table (MDT) ECC Uncorrectable Error"),
	(44, "MMIO Domain Table (MDT) Stage Parity Error"),
	(45, "MMIO Domain Table (MDT) Stage Valid Error"),
	(46, "AIB Data Special Uncorrectable Error (SUE)"),
	(47, "MMIO Domain Table (MDT)"),
	(48, "P2P Store Data Fifo Error"),
	(49, "EPAT Table Parity Error"),
	(50, "MMIO Cmd Parity Error"),
	(51, "BLIF1 Reg Parity Error"),
	(52, "P2P1 Reg Parity Error"),
	(53, "P2P WR Pending Error"),
	(54, "CRW Onehot Error"),
	(55, "CRW Pending Error"),
	(56, "RRB Parity Error"),
	(57, "RRB Size/Alignment Error"),
	(58, "s_bad_addr_e_q"),
	(59, "s_req_size_align_e_q"),
]

# Mnemonic RXE_ARB_ESR - Address Offset 0x0D80 - phbRxeArbErrorStatus
rxe_arb_bits = [
	(0, "BLIF Inbound CA Completion Error"),
	(1, "BLIF Inbound UR Completion Error"),
	(2, "MSI Size Error"),
	(3, "MSI Address Alignment Error"),
	(5, "BLIF Inbound Header ECC Correctable (CE)"),
	(6, "BLIF Inbound Header ECC Uncorrectable (UE)"),
	(7, "ARB Stage Valid Error"),
	(8, "TCE Tag Release Unused"),
	(9, "TCE Tag Used, Not Free"),
	(10, "ARB MMIO Buffer Overflow"),
	(11, "ARB MMIO Buffer Underflow"),
	(12, "ARB MMIO Internal Parity Error"),
	(13, "ARB DMA Buffer Overflow"),
	(14, "ARB DMA Buffer Underflow"),
	(15, "ARB DMA Internal Parity Error"),
	(16, "BLIF Header Control Bits Parity Error"),
	(17, "BLIF Data Control Bits Parity Error"),
	(18, "BLIF Unsupported Request (UR) Error"),
	(19, "BLIF Completion Timeout Error"),
	(20, "SEID Table ECC Correctable (CE)"),
	(21, "SEID Table ECC Uncorrectable (UE)"),
	(22, "NBW Size Error"),
	(23, "DEC IODA Table Fatal Error"),
	(24, "TLP Poisoned Error"),
	(25, "MIST ECC Correctable Error"),
	(26, "IODA TVT Entry Invalid"),
	(27, "MSI PE# Mismatch"),
	(28, "IODA TVT Address"),
	(29, "TVT ECC Correctable Error"),
	(30, "TVT ECC Uncorrectable Error"),
	(31, "MIST ECC Uncorrectable Error"),
	(32, "PELT-V BAR Disabled Error"),
	(33, "IODA Table Parity Error"),
	(34, "PCT Timeout"),
	(35, "PCT Unexpected Completion"),
	(36, "PCT Parity Error"),
	(37, "DEC Stage Valid Error"),
	(38, "DEC Stage Parity Error"),
	(39, "PAPR Inbound Injection Error Triggered"),
	(40, "DMA/MSI: RTE PE Number"),
	(41, "RTT BAR Disabled Error"),
	(42, "RTC Internal Parity Error"),
	(43, "RTC Queue Overflow"),
	(44, "RTC Queue Underflow"),
	(45, "RTC Stage Valid Error"),
	(46, "RTC RCAM Bad State Error"),
	(47, "RTC RCAM Multiple Hit Error"),
	(48, "RRB Parity Error"),
	(49, "RRB request Size / Alignment Error"),
	(50, "s_bad_addr_e_q"),
	(51, "s_req_size_align_e_q"),
	(54, "Discontiguous DMA Write Fragmentation"),
	(55, "LIST Table Parity Error"),
	(56, "LKP PEST Data Queue Error"),
	(57, "PCIE Fatal Error Message Received"),
	(58, "PCIE Nonfatal Error Message Received"),
	(59, "PCIE Correctable Error Message Received"),
]

#Mnemonic RXE_MRG_ESR - Address Offset 0x0E00, phbRxeMrgErrorStatus
rxe_mrg_bits = [
	(8, "MRG TMB Allocation Error"),
	(9, "MRG TMB Response Invalid"),
	(10, "MRG TMB Response Ready Error"),
	(11, "MRG MMIO Queue Overflow Error"),
	(12, "MRG MMIO Queue Underflow Error"),
	(13, "MRG MMIO Internal Parity Error"),
	(14, "MRG DMA Queue Overflow Error"),
	(15, "MRG DMA Queue Underflow Error"),
	(16, "MRG DMA Internal Parity Error"),
	(17, "MRG Migration Register Table"),
	(18, "MRG Migration Register Table"),
	(20, "s_bad_addr_e_q"),
	(21, "s_req_size_align_e_q"),
	(22, "RRB Parity Error"),
	(23, "RRB request Size / Alignment Error"),
	(24, "DSP AIB TX Timeout Error"),
	(25, "Reserved (vA4.1)"),
	(26, "DSP AIB TX CMD Credit Parity Error"),
	(28, "DSP AIB TX DAT Credit Parity Error"),
	(30, "DSP Command Credit Overflow Error"),
	(31, "DSP Command Credit Underflow Error"),
	(32, "DSP Command Credit Parity Error"),
	(33, "DSP Data Credit Overflow Error"),
	(34, "DSP Data Credit Underflow Error"),
	(35, "DSP Data Credit Parity Error"),
	(36, "DSP Completion State Machine One-Hot Error"),
	(37, "DSP Write Thread State Machine One-Hot Error"),
	(38, "DSP DMA Secure Address Error (vA4.2)"),
	(39, "DSP MSI Interrupt Notification Secure Address"),
	(40, "DSP TREQ ECC Correctable Error"),
	(41, "DSP TREQ ECC Uncorrectable Error"),
	(42, "DSP MMIO Queue Overflow Error"),
	(43, "DSP MMIO Queue Underflow Error"),
	(44, "DSP MMIO Internal Parity Error"),
	(45, "DSP DMA Queue Overflow Error"),
	(46, "DSP DMA Queue Underflow Error"),
	(47, "DSP DMA Internal Parity Error"),
	(48, "DSP Read Thread State Machine One-Hot Error"),
	(49, "DSP Table State Machine One-Hot Error"),
	(50, "DSP NBW State Machine One-Hot Error"),
	(51, "DSP TSM PEST BAR Disabled Error"),
	(56, "IPD ECC Correctable Error"),
	(57, "IPD ECC Uncorrectable Error"),
	(58, "ICPLD ECC Correctable Error"),
	(59, "ICPLD ECC Uncorrectable Error"),
	(60, "NBWD ECC Correctable Error"),
	(61, "NBWD ECC Uncorrectable Error"),
	(63, "pb_etu_ai_rx_raise_fence"),
]


# Mnemonic RXE_TCE_ESR -  Address Offset 0x0E80 - phbRxeTceErrorStatus
rxe_tce_bits = [
	(0, "TCE CMP Internal Parity Error"),
	(1, "TCE Request Page Access Error"),
	(2, "TCE Response Page Access Error"),
	(3, "TCE CMP Queue Overflow"),
	(4, "TCE CMP Queue Underflow"),
	(5, "TCE Secure Address Error"),
	(6, "TCE Cache Bad State Error"),
	(7, "TCE Cache Multi-Way Hit Error"),
	(8, "TCE Request Timeout Error"),
	(9, "TCE TCR ECC Correctable Error"),
	(10, "TCE TCR ECC Uncorrectable Error"),
	(11, "TCE TDR ECC Correctable Error"),
	(12, "TCE TDR ECC Uncorrectable Error"),
	(13, "TCE Unexpected Response Error"),
	(14, "RRB Parity Error"),
	(15, "RRB request Size / Alignment Error"),
	(16, "TCE RES Internal Parity Error"),
	(17, "s_bad_addr_e_q"),
	(18, "s_req_size_align_e_q"),
	(19, "TCE RES Queue Overflow"),
	(20, "TCE RES Queue Underflow"),
	(21, "TCE Response Data Parity Error"),
	(22, "TCE TCLB CAM Bad State Error"),
	(23, "TCE TCLB CAM Multi-Hit Error"),
	(24, "TCE Kill Internal Parity Error"),
	(25, "TCE THASH Array ECC Correctable Error"),
	(26, "TCE THASH Array ECC Uncorrectable Error"),
	(27, "TCE TCLB TDAT ECC Correctable Error"),
	(28, "TCE TCLB TDAT ECC Uncorrectable Error"),
	(29, "TCE Kill State Machine One-Hot Error"),
	(30, "TCE Kill Queue Overflow"),
	(31, "TCE Kill Queue Underflow"),
	(32, "TCE Request Secure Address Register"),
	(33, "TCE Response Secure Address Register"),
]


#Mnemonic PBL_ESR  - Address Offset 0x1900 - phbPblErrorStatus
pbl_esr_bits = [
	(0, "pb_err_p_fe_tlif_rx_par_e Parity error detected on TLIF Receive interface."),
	(1, "pb_err_p_fe_tlif_tx_par_e Parity error detected on TLIF Transmit interface."),
	(2, "pb_err_p_fe_blif_out_par_e"),
	(3, "pb_err_p_fe_blif_in_par_e"),
	(4, "pb_err_p_fe_int_par_e"),
	(5, "pb_err_p_fe_toc_cred_e"),
	(6, "pb_err_p_fe_ocf_par_e"),
	(7, "pb_err_p_fe_ocf_prot_e"),
	(12, "pb_err_p_fe_pct_erq_overflow_e"),
	(13, "pb_err_p_fe_pct_erq_underflow_e"),
	(14, "pb_err_p_fe_pct_onp_tags_rls_unused_e"),
	(15, "pb_err_p_fe_pct_onp_tags_used_notfree_e"),
	(16, "pb_err_p_fe_pct_onp_tags_used_unexp_e"),
	(17, "pb_err_p_fe_bct_onp_tags_rls_unused_e"),
	(18, "pb_err_p_fe_bct_onp_tags_used_notfree_e"),
	(19, "pb_err_p_fe_ib_bct_rd_inv"),
	(20, "pb_err_p_fe_ob_buffer_overflow_e"),
	(21, "pb_err_p_fe_ob_buffer_underflow_e"),
	(22, "pb_err_p_fe_ib_buffer_overflow_e"),
	(23, "pb_err_p_fe_ib_buffer_underflow_e"),
	(24, "pb_err_p_fe_ib_d_ecc_ue"),
	(25, "pb_err_p_fe_ib_h_ecc_ue"),
	(26, "pb_err_p_fe_ob_d_ecc_ue"),
	(27, "pb_err_p_fe_ob_h_ecc_ue"),
	(28, "pb_err_p_fe_ocf_ecc_ue"),
	(32, "pb_err_p_fe_tx_pst_discard_e"),
	(33, "pb_err_p_inf_tx_npst_discard_e"),
	(34, "pb_err_p_fe_nbw_tlp_e"),
	(36, "pb_err_p_fe_pci_rcv_cpl_ca_e"),
	(37, "pb_err_p_fe_pci_rcv_cpl_crs_e"),
	(38, "pb_err_p_fe_pci_rcv_cpl_rsvd_e"),
	(39, "pb_err_p_fe_pci_rcv_cpl_ur_e"),
	(40, "pb_err_p_fe_pci_rcv_ecrc_e"),
	(41, "pb_err_p_fe_pci_rcv_malf_tlp_e"),
	(42, "pb_err_p_fe_pci_rcv_overflow_e"),
	(43, "pb_err_p_fe_pci_rcv_poisoned_tlp_e"),
	(44, "pb_err_p_fe_pci_rcv_unexp_cpl_e"),
	(45, "pb_err_p_fe_pci_rcv_unsup_req_e"),
	(46, "pb_err_p_fe_pci_sig_cpl_abort_e"),
	(47, "pb_err_p_fe_pci_sig_cpl_timeout_e"),
	(48, "pb_err_p_fe_pci_sig_poisoned_tlp_e"),
	(52, "pb_err_p_inf_out_trans_to_pst_e"),
	(53, "pb_err_p_inf_out_trans_to_npst_e"),
	(54, "pb_err_p_inf_out_trans_to_cpl_e"),
	(56, "pb_err_p_inf_ib_d_ecc_ce"),
	(57, "pb_err_p_inf_ib_h_ecc_ce"),
	(58, "pb_err_p_inf_ob_d_ecc_ce"),
	(59, "pb_err_p_inf_ob_h_ecc_ce"),
	(60, "pb_err_p_inf_ocf_ecc_ce"),
	(62, "PBL Bad Register Address Error"),
	(63, "PBL Register Parity Error"),
]

# Mnemonic REGB_ESR - Address Offset 0x1C00 - phbRegbErrorStatus
regb_esr_bits = [
	(0, "REGB Internal Register Parity Error"),
	(1, "PBL Internal Register Parity Error"),
	(2, "Invalid Address Decode Error"),
	(3, "Register Access Invalid Address+Size Error"),
	(5, "Register State Machine or Other Internal Error"),
	(6, "PCI CFG Core Registers Parity Error"),
	(7, "Register access to CFG core while in reset error."),
	(8, "PCIE Link Down"),
	(9, "PCIE Link Up"),
	(10, "PCIE Link Auto Bandwidth Event Status"),
	(11, "PCIE Link BW Management Event Status"),
	(25, "PBL Error Trap: INF Error"),
	(26, "PBL Error Trap: ERC Error"),
	(27, "PBL Error Trap: FAT Error"),
	(28, "tldlpo_dl_mon_rxreceivererror(0)"),
	(29, "tldlpo_dl_mon_rxreceivererror(1)"),
	(30, "tldlpo_dl_mon_rxreceivererror(2)"),
	(32, "DL_EC08_BADDLLP"),
	(33, "DL_EC08_BADTLP"),
	(34, "DL_EC08_DLLPE"),
	(35, "DL_EC08_RECEIVERERROR"),
	(36, "DL_EC08_ REPLAYROLLOVER"),
	(37, "DL_EC08_REPLAYTIMEOUT"),
	(39, "DL_INTERNALERROR"),
	(40, "DL_LB_ERROR"),
	(41, "DL_RX_MALFORMED"),
	(42, "DL_RX_NULLIFY"),
	(43, "DL_RX_OVERFLOW"),
	(44, "DL_TX_CORRERROR"),
	(45, "DL_TX_UNCORRERROR"),
	(46, "TL_EC08_FCPE"),
	(48, "Replay ECC Correctable Error (CE)"),
	(49, "Replay ECC UnCorrectable Error (UE)"),
	(50, "Bad DLLP Error Count Saturated"),
	(51, "Bad TLP Error Count Saturated"),
	(52, "Receiver Error Count Saturated"),
	(53, "DLLPE Error Count Saturated"),
	(58, "pbl_ptl_dl_al_rx_initcredit_p_e"),
	(59, "pbl_ptl_dl_al_rx_updatecredit_p_e"),
	(60, "PTL Core DLIF Protocol Error"),
	(61, "PTL Core TLIF Protocol Error"),
	(62, "PTL Core Internal Parity Error"),
]

# FIXME: use the long desc
nfir_bits = [
	(0, "bar_pe"), # One of the BARs or BAR Mask Register parity error.
	(1, "nonbar_pe"), # Any non-BAR parity error.
	(2, "PB_to_PEC_ce"), # ECC correctable error off of outbound SMP interconnect.
	(3, "PB_to_PEC_ue"), # ECC uncorrectable error off of outbound SMP interconnect.
	(4, "PB_to_PEC_sue"), # ECC special uncorrectable error off of outbound SMP interconnect
	(5, "ary_ecc_ce"), # ECC correctable error on an internal array.
	(6, "ary_ecc_ue"), # ECC uncorrectable error on an internal array.
	(7, "ary_ecc_sue"), # ECC special uncorrectable error on an internal array.
	(8, "register_array_pe"), # Parity error on an internal register file.
	(9, "pb_interface_pe"), # Parity error on the PB interface (address/aTag/tTag/rTAG).
	(10, "pb_data_hang_errors"), # Any SMP interconnect data hang poll error (only checked for CI stores).
	(11, "pb_hang_errors"), # Any SMP interconnect command hang error (domestic address range).
	(12, "rd_are_errors"), # SMP interconnect address error (ARE) detected by a DMA read.
	(13, "nonrd_are_errors"), # SMP interconnect address error detected by a DMA write or an interrupt engine.
	(14, "pci_hang_error"), # PBCQ detected that the PCI load, store, EOI, or DMA read response did not make forward progress.
	(15, "pci_clock_error"), # PBCQ has detected that the PCI clock has stopped.
	(16, "PFIR_freeze"), # This is the freeze signal from the PFIR freeze output.
	(17, "hw_errors"), # Any miscellaneous hardware error.
	(18, "UnsolicitiedPBData"), # The PEC received data with an rTAG matching a queue that was not expecting data or too much data was received.
	(19, "UnExpectedCResp"), # PEC received an unexpected combined response.
	(20, "InvalidCResp"), # PEC received an invalid combined response.
	(21, "PBUnsupportedSize"), # PEC received a CI load/store that hits a BAR but is an unsupported size or address alignment.
]

pfir_bits = [
	(0, "register_pe"), # PBAIB register parity error.
	(1, "hardware_error"), # Hardware error.
	(2, "AIB_intf_error"), # AIB interface error.
	(3, "ETU_Reset_error"), # ETU reset error.
	(4, "PEC_scom_error"), # Common PEC SCOM error.
	(5, "scomfir_error0"), # SCOM Error bit 0
	(6, "scomfir_error1"), # SCOM Error bit 1
]

class PHBError:
    reg_bits = {
        "NEST FIR": nfir_bits,
        "PCI FIR": pfir_bits,
        "phbErrorStatus": phb_esr_bits,
        "phbTxeErrorStatus": txe_esr_bits,
        "phbRxeArbErrorStatus": rxe_arb_bits,
        "phbRxeMrgErrorStatus": rxe_mrg_bits,
        "phbRxeTceErrorStatus": rxe_tce_bits,
        "phbRegbErrorStatus": regb_esr_bits,
        "phbPblErrorStatus": pbl_esr_bits,
    }

    def __str__(self):
        s = ""
        for k, v in self.regs.items():
            s += "{:30s} - {:#018x} - {}\n".format(k, v, ppc.setbits(v))
        return s

    def __init__(self, timestamp = 0):
        self.timestamp = timestamp
        self.pest = []
        self.regs = {}

    # NB: Value is a str, FIXME: Work out how to use python's type annotations
    def set_reg(self, reg, value):
        reg = reg.replace(" ", "")
        if not self.regs.get(reg):
            self.regs[reg] = value
            return True
        return False

    def get_reg(self, reg):
        reg = reg.replace(" ", "")
        v = self.regs.get(reg)
        if v:
            return v
        return 0

    # NB: pest entries should be inserted in sort order, but it might be a good
    # idea to explicitly sort them by PE number
    def set_pest(self, pe, pesta, pestb):
        self.pest.append((pe, pesta, pestb))

    def get_pest(self, pe_number):
        for pe, a, b in self.pest:
            if pe == pe_number:
                return (a, b)
        return None

    def header(self):
        return self.timestamp

    # TODO: move the formatting out of here and into the main loop
    def show_errs(self):
        out = ""
        for reg_name,reg_bits in self.reg_bits.items():
            reg_value = self.get_reg(reg_name)
            parts = reg_name.split("Error");
            if len(parts) > 1:
                first_name = "{:s}FirstError{:s}".format(parts[0], parts[1])
                first_value = self.get_reg(first_name)

                # skiboot spells it wrong, so check Frst too
                if first_value == 0:
                    frst_name = "{:s}FrstError{:s}".format(parts[0], parts[1])
                    first_value = self.get_reg(frst_name)
            else:
                first_value = 0

            if reg_value == 0:
                continue
            out += "{} = {:016x}:\n".format(reg_name, reg_value);

            for bit in reg_bits:
                if ppc.ppcbit(bit[0]) & reg_value:
                    bang = "!" if (ppc.ppcbit(bit[0]) & reg_value & first_value) == ppc.ppcbit(bit[0]) else ""
                    out += "{:s}\t{:2d} - {}\n".format(bang, bit[0], bit[1])
            out += "\n"

        if len(self.pest) == 0:
            return out

        out += "PEST entries:\n"
        for pe, pesta, pestb in self.pest:
            out += "\tPEST[{:03x}] = {:016x} {:016x}\n".format(pe, pesta, pestb)

        return out



def parse_opal_log(log_text):
    # Patterns to match:
    #
    # [  938.249526636,3] PHB#0030[8:0]:        NEST FIR WOF=0000800000000000
    # [  938.250657886,3] PHB#0030[8:0]:               slotStatus = 00402000
    # [  938.254305278,3] PHB#0030[8:0]:                PEST[511] = 3740002a01000000 0000000000000000
    #
    phblog_re = re.compile("" +
        "^\[\s*[\d.,]+] " +           # skiboot log header
        "(PHB#....\[.:.]):" +       # PHB name
        "\s+" +                     # whitespace between the PHB and register name
        "([^:=]+)" +                 # register name, NB: this might have some trailing WS
        "=\s*" +                 # the '=' seperating name and value, along with the whitespace
        "([a-fA-F\d ]+)")           # register value(s)

    # this alone isn't really sufficent. There's a few cases that can cause a register
    # dump to be generated (e.g. when the link is retrained we do a reg dump)
    new_log_marker = re.compile("" +
        "^\[ [\d.,]+] " +
        "(PHB#....\[.:.]): " +
        "PHB Freeze/Fence detected !")

    # Store the current register set for each PHB. Keep in mind that we can have register
    # dumps from different PHBs being interleaved in the register log.
    current = {}

    # list discovered error logs
    error_logs = []

    # Match things and split them on a per-PHB basis. We can get multiple PHB error logs
    # printed interleaved in the skiboot log if there are multiple PHBs frozen.
    for l in log_text.split("\n"):
        m = new_log_marker.match(l)
        if not m:
            m = phblog_re.match(l)
        if not m:
            continue

        match = m.groups()
        phb = match[0]

        # new log marker, save the current log and create a new one to store register values in
        log = current.get(phb)
        if not log:
            current[phb] = PHBError(l);
        elif len(match) == 1:
            error_logs.append(current[phb])
            current[phb] = PHBError(l) # create a new log object
            log = current[phb]

        if len(match) > 1:
            if match[1].find("PEST") >= 0: # PEST entry
                # NB: unlike .match() .search() scans the whole string
                m = re.search("PEST\[([\da-fA-F]+)] = ([\da-fA-F]+) ([\da-fA-F]+)", l)
                pe, pesta, pestb = [int(i, 16) for i in m.groups()]
                current[phb].set_pest(pe, pesta, pestb)
            else: # Normal register
                name = match[1].strip()
                value = int(match[2].strip(), 16)

                ok = current[phb].set_reg(name, value)

                # If we have duplicate registers then we're in a new log context
                # so stash the current one and init a new one.
                if not ok:
                    error_logs.append(current[phb])
                    current[phb] = PHBError(l)
                    current[phb].set_reg(name, value)

    # save all the logs we're still processing
    for k,v in current.items():
        error_logs.append(v)

    return error_logs


'''
Mar 25 10:01:49 localhost kernel: PHB4 PHB#48 Diag-data (Version: 1)
Mar 25 10:01:49 localhost kernel: brdgCtl:    00000002
Mar 25 10:01:49 localhost kernel: RootSts:    00010020 00402000 a1030008 00100107 00002000
Mar 25 10:01:49 localhost kernel: RootErrSts: 00000000 00000000 00000001
Mar 25 10:01:49 localhost kernel: PhbSts:     0000001c00000000 0000001c00000000
Mar 25 10:01:49 localhost kernel: Lem:        0000000100280000 0000000000000000 0000000100000000
Mar 25 10:01:49 localhost kernel: PhbErr:     0000088000000000 0000008000000000 2148000098000240 a008400000000000
Mar 25 10:01:49 localhost kernel: RxeArbErr:  4000200000000000 0000200000000000 02409fde30000000 0000000000000000
Mar 25 10:01:49 localhost kernel: PblErr:     0000000001000000 0000000001000000 0000000000000000 0000000000000000
Mar 25 10:01:49 localhost kernel: PcieDlp:    0000000000000000 0000000000000000 ffff000000000000
Mar 25 10:01:49 localhost kernel: RegbErr:    0000004a10000800 0000000810000000 8800003c00000000 0000000007011000
Mar 25 10:01:49 localhost kernel: PE[1fd] A/B: a440002a05000000 8000000000000000
'''

def parse_kernel_log(log_text):
    reg8  = "([0-9a-fA-F]{8})"
    reg16 = "([0-9a-fA-F]{16})"

    # TODO: pick up the AER stuff the kernel logs too?
    # NB: The register names used for set_reg are the skiboot register names, not the kernel.
    # TODO: check these for completeness / accuracy. I might have missed something
    register_patterns = [
        (re.compile("brdgCtl:    {}"            .format(reg8)), "brdgCtl"),
        (re.compile("RootSts:    {} {} {} {} {}".format(reg8, reg8, reg8, reg8, reg8)),
                    'deviceStatus', 'slotStatus', 'linkStatus', 'devCmdStatus', 'devSecStatus'),
        (re.compile("RootErrSts: {} {} {}"      .format(reg8, reg8, reg8)),
                    'rootErrorStatus', 'uncorrErrorStatus', 'corrErrorStatus'),
        (re.compile("PhbSts:     {} {}"         .format(reg16, reg16)), "phbPlssr", "phbCsr"),
        (re.compile("nFir:       {} {} {}"      .format(reg16, reg16, reg16)), "nFir", "nFirMask", "nFirWOF"),
        (re.compile("Lem:        {} {} {}"      .format(reg16, reg16, reg16)), "lemFir", "lemErrorMask", "lemWOF"),
        (re.compile("PhbErr:     {} {} {} {}"   .format(reg16, reg16, reg16, reg16)),
                    "phbErrorStatus", "phbFirstErrorStatus", "phbErrorLog0", "phbErrorLog1"),
        (re.compile("PhbTxeErr:  {} {} {} {}"    .format(reg16, reg16, reg16, reg16)),
                    "phbPhbTxeErrorStatus", "phbPhbTxeFirstErrorStatus", "phbPhbTxeErrorLog0", "phbTxeErrorLog1"),
        (re.compile("RxeArbErr:  {} {} {} {}"    .format(reg16, reg16, reg16, reg16)),
                    "phbRxeArbErrorStatus", "phbRxeArbFirstErrorStatus", "phbRxeArbErrorLog0", "phbRxeArbErrorLog1"),
        (re.compile("RxeMrgErr:  {} {} {} {}"    .format(reg16, reg16, reg16, reg16)),
                    "phbRxeMrgErrorStatus", "phbRxeMrgFirstErrorStatus", "phbRxeMrgErrorLog0", "phbRxeMrgErrorLog1"),
        (re.compile("RxeTceErr:  {} {} {} {}"    .format(reg16, reg16, reg16, reg16)),
                    "phbRxeTceErrorStatus", "phbRxeTceFirstErrorStatus", "phbRxeTceErrorLog0", "phbRxeTceErrorLog1"),
        (re.compile("PblErr:     {} {} {} {}"    .format(reg16, reg16, reg16, reg16)),
                    "phbPblErrorStatus", "phbPblFirstErrorStatus", "phbPblErrorLog0", "phbPblErrorLog1"),
        (re.compile("PcieDlp:    {} {} {}"       .format(reg16, reg16, reg16)),
                    "phbPcieDlpErrorLog1", "phbPcieDlpErrorLog2", "phbPcieDlpErrorStatus"),
        (re.compile("RegbErr:    {} {} {} {}"    .format(reg16, reg16, reg16, reg16)),
                    "phbRegbErrorStatus", "phbRegbFirstErrorStatus", "phbRegbErrorLog0", "phbRegbErrorLog1"),
    ]

    header_pattern = re.compile("PHB4 PHB#[0-9]+ Diag-data") # match header
    pe_pattern = re.compile("PE\[{}\] A/B: {} {}".format("([ 0-9a-fA-F]{3})", reg16, reg16)) # the PE number is three hex digits

    logs = []
    log = PHBError("");

    # pretty nasty but since interpreting the kernel logs requires context I
    # don't have any better ideas
    for l in log_text.split("\n"):
        m = header_pattern.search(l)
        if m: # start a new log
            logs.append(log)
            log = PHBError(l)
            continue

        for p,*names in register_patterns:
            m = p.search(l)
            if not m:
                continue
            for name, val in zip(names, m.groups()):
                log.set_reg(name, int(val, 16))
            break

        m = pe_pattern.search(l)
        if m:
            pe = int(m.groups()[0], 16)
            pesta = int(m.groups()[1], 16)
            pestb = int(m.groups()[2], 16)
            log.set_pest(pe, pesta, pestb)

    logs.append(log)

    return logs

def main(argv):
    if len(argv) < 2:
        print("Usage: {} <log file>".format(argv[0]));
        return

    try:
        log_text = open(argv[1]).read();
    except Exception as err:
        print(err)
        sys.exit(1)

    logs = parse_opal_log(log_text);
    logs.extend(parse_kernel_log(log_text))

    for err in logs:
        print("==== PHB Register dump found ====")
        print("")
        print(err.header())
        print("")
        print(err.show_errs())

if __name__ == "__main__":
    main(sys.argv)
