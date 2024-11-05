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

defer set-boot-device
defer add-boot-device

: add-boot-aliases ( str -- )
    2dup add-boot-device               ( $str )
    MAX-ALIAS 1 DO
	2dup i $cathex 2dup              ( $str $strN $strN )
	find-alias 0 > IF                ( $str $strN false | $result )
	    drop strdup add-boot-device  ( $str )
	ELSE 2drop THEN
    LOOP
    2drop
;

\ strict boot order is enabled if the last word in qemu,boot-list is "HALT".
: is-strict-boot?  ( bl-str bl-len -- strict? )
    dup 4 > IF
        + 5 - 5 s"  HALT" str=
    ELSE
        s" HALT" str=
    THEN
;

: qemu-read-bootlist ( -- )
   \ See if QEMU has set exact boot device list
   " qemu,boot-list" get-chosen IF
      1-                                 \ Ignore the trailing NUL character
      2dup set-boot-device
      is-strict-boot? IF EXIT THEN
   ELSE
      0 0 set-boot-device
   THEN

   " qemu,boot-device" get-chosen not IF
      \ No boot list set from qemu, so check nvram
      " boot-device" evaluate swap drop 0= IF
         \ Not set in nvram too, set default disk/cdrom alias
         " disk" add-boot-aliases
         " cdrom" add-boot-aliases
         " net" add-boot-aliases
      THEN
      EXIT
   THEN

   0 ?DO
       dup i + c@ CASE
           0        OF ENDOF
           [char] a OF ENDOF
           [char] b OF ENDOF
           [char] c OF " disk"  add-boot-aliases ENDOF
           [char] d OF " cdrom" add-boot-aliases ENDOF
           [char] n OF " net"   add-boot-aliases ENDOF
       ENDCASE cr
   LOOP
   drop
;

' qemu-read-bootlist to read-bootlist
