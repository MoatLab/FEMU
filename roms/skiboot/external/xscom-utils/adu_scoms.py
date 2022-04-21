#!/usr/bin/python
# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
#
# Python library for in-band SCom access
# (based on xscom-utils from OPAL firmware)
#
# Copyright 2018 IBM Corp.

import os, sys, struct, getopt

class XSCom(object):
	def __init__(self):
		self.name = "xscom"
		self.base = "/sys/kernel/debug/powerpc/scom/"
		self.enabled = False
		self.setup = False
		self.chips = []
		self.dirs = []
		self.key_val_bin = {}
		self.file = "/access"

		if os.path.exists(self.base):
			self.enabled = True

		if not self.scan_chips():
			raise ValueError

	def scan_chips(self):
		if not self.enabled:
			print("Not supported")
			return False

		for i in os.listdir(self.base):
			if os.path.isdir(self.base+i):
				self.dirs.append(i)
				self.chips.append(int(i,16))

		for i in  self.dirs:
			try:
				b = open(self.base+i+self.file, "rb+")
				self.key_val_bin[int(i,16)] = b
			except:
				print("Count not open"+self.base+i+self.file)
				return False

		self.setup = True
		return True

	def is_supported(self):
		return self.enabled

	def get_chip_ids(self):
		return list(self.key_val_bin.keys())

	def mangle_addr(self, addr):
		tmp = (addr & 0xf000000000000000) >> 4
		addr = (addr & 0x00ffffffffffffff)
		addr = addr | tmp
		return (addr << 3)

	def xscom_read(self, chip_id, addr):
		if not isinstance(chip_id, int) or not isinstance(addr, int):
			print("xscom_read: Input paramater type mismatch")
			return -1

		if chip_id not in self.key_val_bin:
			print("Invalid Chip id")
			return -1

		saddr = self.mangle_addr(addr)
		fd = self.key_val_bin.get(chip_id)
		fd.seek(saddr, 0)
		return struct.unpack('Q',fd.read(8))[0]

	def xscom_read_spl(self, chip_id, addr):
		if not isinstance(chip_id, int) or not isinstance(addr, int):
			print("xscom_read: Input paramater type mismatch")
			return -1

		if chip_id not in self.key_val_bin:
			print("Invalid Chip id")
			return -1

		saddr = self.mangle_addr(addr)
		fd = self.key_val_bin.get(chip_id)
		fd.seek(saddr, 0)
		val = struct.unpack('Q',fd.read(8))[0]
		fd.close()
		try:
			b = open(self.key_val_path.get(chip_id), "rb+")
		except:
			print("Reopen failed")
			return val
		self.key_val_bin[chip_id] = b
		return val

	def xscom_write(self, chip_id, addr, val):
		if chip_id not in self.key_val_bin:
			print("Invalid Chip id")
			return -1

		c = struct.pack('Q',val)
		saddr = self.mangle_addr(addr)
		fd = self.key_val_bin.get(chip_id)

		try:
			fd.seek(saddr, 0)
			fd.write(c)
			# write again just to be sure
			fd.seek(saddr, 0)
			fd.write(c)
		except:
			print("Write() error")
			return -1

	def xscom_read_ex(self, ex_target_id, addr):
		if not isinstance(ex_target_id, int) or not isinstance(addr, int):
			print("xscom_read_ex: Input paramater type mismatch")
			return -1

		chip_id = ex_target_id >> 4
		addr |= (ex_target_id & 0xf) << 24;
		return self.xscom_read(chip_id, addr, val);

	def xscom_write_ex(self, ex_target_id, addr, val):
		chip_id = ex_target_id >> 4
		addr |= (ex_target_id & 0xf) << 24;
		return self.xscom_write(chip_id, addr, val)

class GetSCom(object):
	def __init__(self):
		self.name = "getscom"
		self.backend = XSCom()
		self.listchip = False
		self.chip_id = 0
		self.chips = False
		self.addr = 0
		self.flg_addr = False

		if not self.backend.is_supported():
			print("In-Band SCom not supported Exiting....")
			raise ValueError

	def set_chip(self, chip_id):
		self.chip_id = chip_id
		self.chips = True

	def set_addr(self, scom_addr):
		self.addr = scom_addr
		self.flg_addr = True

	def print_usage(self):
		print("usage: getscom [-c|--chip chip-id] addr")
		print("       getscom -l|--list-chips")
		print("       getscom -h|--help")
		sys.exit(0)


	def chip_info(self, chip_id):
		val = self.backend.xscom_read(chip_id, 0xf000f)
		if val < 0:
			print("Error in scom read")
			raise ValueError

		c_id = val >> 44
		id = c_id & 0xff
		if id == 0xef:
			name = "P8E (Murano) processor"
		elif id == 0xea:
			name = "P8 (Venice) processor"
		elif id == 0xd3:
			name = "P8NVL (Naples) processor"
		elif id == 0xd1:
			name = "P9 (Nimbus) processor"
		elif id == 0xd4:
			name = "P9 (Cumulus) processor"
		elif id == 0xd9:
			name = "P9P (Axone) processor"
		elif id == 0xda:
			name = "P10 processor"
		elif id == 0xe9:
			name = "Centaur memory buffer"
		else:
			name = "Unknown ID 0x%x"%id

		print(("%08x | DD%s.%s | %s"%(chip_id, ((c_id >> 16) & 0xf), ((c_id >> 8) & 0xf), name)))

	def parse_args(self):
		try:
			optlist, sys.argv = getopt.getopt(sys.argv[1:], "lhc:", ["chip", "list-chips", "help"])
		except getopt.GetoptError as err:
			print(str(err))
			self.print_usage()
			sys.exit(0)

		if len(optlist) == 0:
			self.print_usage()
			sys.exit(0)

		for opt, arg in optlist:
			if opt in [ "-h", "--help"]:
				self.print_usage()
				sys.exit(0)

			elif opt in [ "-l", "--list-chips"]:
				self.listchip = True

			elif opt in ["-c", "--chip"]:
				self.chip_id = int(arg, 16)
				self.chips = True

		if sys.argv:
			self.addr =  int(sys.argv.pop(), 16)
			self.flg_addr = True

		if self.listchip:
			print("Chip ID  | Rev   | Chip type")
			print("---------|-------|-----------")
			for i in self.backend.get_chip_ids():
				self.chip_info(i)

			sys.exit(0)

	def run_command(self):
		if self.chips and self.flg_addr:
			print(hex(self.backend.xscom_read(self.chip_id, self.addr)))

	def list_chips(self):
		print("Chip ID  | Rev   | Chip type")
		print("---------|-------|-----------")
		for i in self.backend.get_chip_ids():
			self.chip_info(i)

		raise ValueError

	def execute(self, chip_id, addr):
		return self.backend.xscom_read(chip_id, addr)

	def execute_spl(self, chip_id, addr):
		return self.backend.xscom_read_spl(chip_id, addr)

class PutSCom(object):
	def __init__(self):
		self.name = "putscom"
		self.backend = XSCom()
		self.chip_id = 0
		self.chips = False
		self.addr = 0
		self.value = 0

		if not self.backend.is_supported():
			print("In-Band SCom not supported Exiting....")
			raise ValueError

	def set_addr(self, addr):
		self.addr = addr

	def set_value(self, value):
		self.value = value

	def print_usage(self):
		print("usage: putscom [-c|--chip chip-id] addr value")
		print("       putscom -h|--help")
		sys.exit(0)

	def parse_args(self):
		try:
			optlist, sys.argv = getopt.getopt(sys.argv[1:], "hc:", ["chip", "help"])
		except getopt.GetoptError as err:
			print(str(err))
			self.print_usage()
			sys.exit(0)

		if len(optlist) == 0:
			self.print_usage()
			sys.exit(0)

		for opt, arg in optlist:
			if opt in [ "-h", "--help"]:
				self.print_usage()
				sys.exit(0)

			elif opt in ["-c", "--chip"]:
				self.chip_id = int(arg, 16)
				self.chips = True

		if sys.argv:
			self.value =  int(sys.argv.pop(), 16)
			self.addr =  int(sys.argv.pop(), 16)

		if self.chips:
			self.backend.xscom_write(self.chip_id, self.addr, self.value)

	def run_command(self):
		if self.chips:
			self.backend.xscom_write(self.chip_id, self.addr, self.value)

	def execute(self, chip_id, addr, value):
		self.backend.xscom_write(chip_id, addr, value)

