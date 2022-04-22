#
#  Copyright (c) 2011-2021, Arm Limited. All rights reserved.
#
#  SPDX-License-Identifier: BSD-2-Clause-Patent
#

from arm_ds.debugger_v1 import Debugger
from arm_ds.debugger_v1 import DebugException

from console_loader import load_symbol_from_console

import re, sys, getopt

import edk2_debugger

# Reload external classes
reload(edk2_debugger)

def usage():
    print "-v,--verbose"
    print "-a,--all: Load all symbols"
    print "-l,--report=: Filename for the EDK2 report log"
    print "-m,--sysmem=(base,size): System Memory region"
    print "-f,--fv=(base,size): Firmware region"
    print "-r,--rom=(base,size): ROM region"
    print "-i,--input=: Filename for the EDK2 console output"
    print "-o,--objdump=: Path to the objdump tool"

verbose = False
load_all = False
report_file = None
input_file = None
objdump = None
regions = []
opts,args = getopt.getopt(sys.argv[1:], "hvar:i:o:vm:vr:vf:v", ["help","verbose","all","report=","sysmem=","rom=","fv=","input=","objdump="])
if (opts is None) or (not opts):
    report_file = '../../../report.log'
else:
    region_reg = re.compile("\((.*),(.*)\)")
    base_reg = re.compile("(.*)")

    for o,a in opts:
        region_type = None
        regex = None
        m = None
        if o in ("-h","--help"):
            usage()
            sys.exit()
        elif o in ("-v","--verbose"):
            verbose = True
        elif o in ("-a","--all"):
            load_all = True
        elif o in ("-l","--report"):
            report_file = a
        elif o in ("-m","--sysmem"):
            region_type = edk2_debugger.ArmPlatformDebugger.REGION_TYPE_SYSMEM
            regex = region_reg
        elif o in ("-f","--fv"):
            region_type = edk2_debugger.ArmPlatformDebugger.REGION_TYPE_FV
            regex = region_reg
        elif o in ("-r","--rom"):
            region_type = edk2_debugger.ArmPlatformDebugger.REGION_TYPE_ROM
            regex = region_reg
        elif o in ("-i","--input"):
            input_file = a
        elif o in ("-o", "--objdump"):
            objdump = a
        else:
            assert False, "Unhandled option (%s)" % o

        if region_type:
            m = regex.match(a)
            if m:
                if regex.groups == 1:
                    regions.append((region_type,int(m.group(1),0),0))
                else:
                    regions.append((region_type,int(m.group(1),0),int(m.group(2),0)))
            else:
                if regex.groups == 1:
                    raise Exception('cmd_load_symbols', "Expect a base address")
                else:
                    raise Exception('cmd_load_symbols', "Expect a region format as (base,size)")

# Debugger object for accessing the debugger
debugger = Debugger()

# Initialisation commands
ec = debugger.getExecutionContext(0)
ec.getExecutionService().stop()
ec.getExecutionService().waitForStop()
# in case the execution context reference is out of date
ec = debugger.getExecutionContext(0)

try:
    armplatform_debugger = edk2_debugger.ArmPlatformDebugger(ec, report_file, regions, verbose)

    if load_all:
        armplatform_debugger.load_all_symbols()
    else:
        armplatform_debugger.load_current_symbols()
except IOError, (ErrorNumber, ErrorMessage):
    print "Error: %s" % ErrorMessage
except Exception, (ErrorClass, ErrorMessage):
    print "Error(%s): %s" % (ErrorClass, ErrorMessage)
except DebugException, de:
    print "DebugError: %s" % (de.getMessage())

if input_file:
    load_symbol_from_console(ec, input_file, objdump, verbose)
