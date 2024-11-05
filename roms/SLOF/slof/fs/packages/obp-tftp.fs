\ *****************************************************************************
\ * Copyright (c) 2004, 2008 IBM Corporation
\ * All rights reserved.
\ * This program and the accompanying materials
\ * are made available under the terms of the BSD License
\ * which accompanies this distribution, and is available at
\ * http://www.opensource.org/licenses/bsd-license.php
\ *
\ * Contributors:
\ *     IBM Corporation - initial implementation
\ ****************************************************************************/

s" obp-tftp" device-name

: open ( -- okay? ) 
    true
;

: load ( addr -- size )
    s" bootargs" get-chosen 0= IF 0 0 THEN >r >r
    s" bootpath" get-chosen 0= IF 0 0 THEN >r >r

    \ Set bootpath to current device
    my-parent ihandle>phandle node>path encode-string
    s" bootpath" set-chosen

    \ Determine the maximum size that we can load:
    dup paflof-start < IF
        paflof-start
    ELSE
        MIN-RAM-SIZE
    THEN                                  ( addr endaddr )
    over -                                ( addr maxlen )

    \ Add OBP-TFTP Bootstring argument, e.g. "10.128.0.1,bootrom.bin,10.128.40.1"
    my-args
    net-load dup 0< IF drop 0 THEN

    r> r> over IF s" bootpath" set-chosen ELSE 2drop THEN
    r> r> over IF s" bootargs" set-chosen ELSE 2drop THEN
;

: close ( -- )
;

: ping  ( -- )
    my-args net-ping
;
