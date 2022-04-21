#!/usr/bin/env python
# Script to remove EXEC flag from an ELF file
#
# Copyright (C) 2020  Kevin O'Connor <kevin@koconnor.net>
#
# This file may be distributed under the terms of the GNU GPLv3 license.
import optparse

FLAG_OFFSET = 16

def main():
    # Parse command-line arguments
    usage = "%prog <input_file> <output_file>"
    opts = optparse.OptionParser(usage)
    options, args = opts.parse_args()
    if len(args) != 2:
        opts.error("Incorrect number of arguments")
    infilename, outfilename = args
    # Read input
    f = open(infilename, "rb")
    srcdata = f.read()
    f.close()
    # Update
    outdata = bytearray(srcdata)
    outdata[FLAG_OFFSET] = 0x01 # change ET_EXEC to ET_REL
    # Write output
    f = open(outfilename, "wb")
    f.write(outdata)
    f.close()

if __name__ == '__main__':
    main()
