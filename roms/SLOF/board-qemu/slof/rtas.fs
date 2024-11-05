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

\ KVM/qemu RTAS

\ rtas control block

371 cp

STRUCT
    /l field rtas>token
    /l field rtas>nargs
    /l field rtas>nret
    /l field rtas>args0
    /l field rtas>args1
    /l field rtas>args2
    /l field rtas>args3
    /l field rtas>args4
    /l field rtas>args5
    /l field rtas>args6
    /l field rtas>args7
    /l C * field rtas>args
    /l field rtas>bla
CONSTANT /rtas-control-block

CREATE rtas-cb /rtas-control-block allot
rtas-cb /rtas-control-block erase

0 VALUE rtas-base
0 VALUE rtas-size
0 VALUE rtas-node

s" /rtas" find-node to rtas-node
373 cp

: enter-rtas ( -- )
    rtas-cb rtas-base 0 rtas-base call-c drop
;

: rtas-get-token ( str len -- token | 0 )
    rtas-node get-package-property IF 0 ELSE drop l@ THEN
;

#include <rtas/rtas-reboot.fs>
#include <rtas/rtas-cpu.fs>

: rtas-set-tce-bypass ( unit enable -- )
    " ibm,set-tce-bypass" rtas-get-token rtas-cb rtas>token l!
    2 rtas-cb rtas>nargs l!
    0 rtas-cb rtas>nret l!
    rtas-cb rtas>args1 l!
    rtas-cb rtas>args0 l!
    enter-rtas
;

: rtas-quiesce ( -- )
    fdt-flatten-tree
    dup hv-update-dt ?dup IF
        \ Ignore hcall not implemented error, print error otherwise
        dup -2 <> IF ." HV-UPDATE-DT error: " . cr ELSE drop THEN
    THEN
    fdt-flatten-tree-free
    " quiesce" rtas-get-token rtas-cb rtas>token l!
    0 rtas-cb rtas>nargs l!
    0 rtas-cb rtas>nret l!
    enter-rtas
;


0 value puid

: rtas-do-config-@ ( config-addr size -- value)
    [ s" ibm,read-pci-config" rtas-get-token ] LITERAL rtas-cb rtas>token l!
    4 rtas-cb rtas>nargs l!
    2 rtas-cb rtas>nret l!
    ( addr size ) rtas-cb rtas>args3 l!
    puid rtas-cb rtas>args2 l!
    puid 20 rshift rtas-cb rtas>args1 l!
    ( addr ) rtas-cb rtas>args0 l!
    enter-rtas
    rtas-cb rtas>args4 l@ dup IF
        \ Do not warn on error as this is part of the
	\ normal PCI probing pass
	drop ffffffff
    ELSE
	drop rtas-cb rtas>args5 l@
    THEN
;

: rtas-do-config-! ( value config-addr size )
    [ s" ibm,write-pci-config" rtas-get-token ] LITERAL rtas-cb rtas>token l!
    5 rtas-cb rtas>nargs l!
    1 rtas-cb rtas>nret l!
    ( value addr size ) rtas-cb rtas>args3 l!
    puid rtas-cb rtas>args2 l!
    puid 20 rshift rtas-cb rtas>args1 l!
    ( value addr ) rtas-cb rtas>args0 l!
    ( value ) rtas-cb rtas>args4 l!
    enter-rtas
    rtas-cb rtas>args5 l@ dup IF
    	    ." RTAS write config err " . cr
    ELSE drop THEN
;

: rtas-config-b@ ( config-addr -- value )
  1 rtas-do-config-@ ff and
;
: rtas-config-b! ( value config-addr -- )
  1 rtas-do-config-!
;
: rtas-config-w@ ( config-addr -- value )
  2 rtas-do-config-@ ffff and
;
: rtas-config-w! ( value config-addr -- )
  2 rtas-do-config-!
;
: rtas-config-l@ ( config-addr -- value )
  4 rtas-do-config-@ ffffffff and
;
: rtas-config-l! ( value config-addr -- )
  4 rtas-do-config-!
;

: of-start-cpu rtas-start-cpu ;

' power-off to halt
' rtas-system-reboot to reboot

\ Methods of the rtas node proper
rtas-node set-node

: open true ;
: close ;

: store-rtas-loc ( adr )
    s" /rtas" find-node >r
    encode-int s" slof,rtas-base" r@ set-property
    rtas-size encode-int s" slof,rtas-size" r> set-property
;

: instantiate-rtas ( adr -- entry )
    dup store-rtas-loc
    dup rtas-base swap rtas-size move
;

hv-rtas-get
s" rtas-size" rtas-node get-property
IF
    dup encode-int s" rtas-size" rtas-node set-property
ELSE
    decode-int nip nip
    over 2dup < IF ." No enough space for RTAS: " . . cr abort THEN
    2drop
THEN
to rtas-size
to rtas-base

device-end

374 cp
