\ *****************************************************************************
\ * Copyright (c) 2011 IBM Corporation
\ * All rights reserved.
\ * This program and the accompanying materials
\ * are made available under the terms of the BSD License
\ * which accompanies this distribution, and is available at
\ * http://www.opensource.org/licenses/bsd-license.php
\ *
\ * Contributors:
\ *     IBM Corporation - initial implementation
\ ****************************************************************************/

\ 2 MiB FDT buffer size is enough to accommodate 255 CPU cores
\ and 16 TiB of maxmem specification.
200000 CONSTANT cas-buffer-size
: ibm,client-architecture-support         ( vec -- err? )
    \ Store require parameters in nvram
    \ to come back to right boot device
    \ Allocate memory for H_CALL
    cas-buffer-size alloc-mem             ( vec memaddr )
    dup 0= IF
        ." out of memory during ibm,client-architecture-support" cr
	2drop TRUE
	EXIT
    THEN
    swap over cas-buffer-size             ( memaddr vec memaddr size )
    \ make h_call to hypervisor
    hv-cas 0= IF                          ( memaddr )
	dup l@ 1 >= IF                    \ Version number >= 1
	    \ Make required changes
	    " /" find-node set-node
	    dup 4 + fdt-init
	    fdt-check-header
	    fdt-struct fdt-fix-cas-node
	    fdt-fix-cas-success NOT       ( memaddr err? )
	ELSE
	    FALSE
	THEN
    ELSE
	TRUE
    THEN
    >r cas-buffer-size free-mem r>
;
