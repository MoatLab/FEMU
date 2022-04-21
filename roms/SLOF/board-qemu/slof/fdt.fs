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

0 VALUE fdt-debug
TRUE VALUE fdt-cas-fix?
0 VALUE fdt-cas-pass
0 VALUE fdt-generation#

: fdt-update-from-fdt ( -- )
  fdt-generation# encode-int s" slof,from-fdt" property
;

\ Bail out if no fdt
fdt-start 0 = IF -1 throw THEN

struct
  4 field >fdth_magic
  4 field >fdth_tsize
  4 field >fdth_struct_off
  4 field >fdth_string_off
  4 field >fdth_rsvmap_off
  4 field >fdth_version
  4 field >fdth_compat_vers
  4 field >fdth_boot_cpu
  4 field >fdth_string_size
  4 field >fdth_struct_size
constant /fdth

h# d00dfeed constant OF_DT_HEADER
h#        1 constant OF_DT_BEGIN_NODE
h#        2 constant OF_DT_END_NODE
h#        3 constant OF_DT_PROP
h#        4 constant OF_DT_NOP
h#        9 constant OF_DT_END

\ Create some variables early
0 value fdt-start-addr
0 value fdt-struct
0 value fdt-strings

: fdt-init ( fdt-start -- )
    dup to fdt-start-addr
    dup dup >fdth_struct_off l@ + to fdt-struct
    dup dup >fdth_string_off l@ + to fdt-strings
    drop
;
fdt-start fdt-init

\ Dump fdt header for all to see and check FDT validity
: fdt-check-header ( -- )
    fdt-start-addr dup 0 = IF
        ." No flat device tree !" cr drop -1 throw EXIT THEN
    hex
    fdt-debug IF
        ." Flat device tree header at 0x" dup . s" :" type cr
        ."  magic            : 0x" dup >fdth_magic l@ . cr
        ."  total size       : 0x" dup >fdth_tsize l@ . cr
        ."  offset to struct : 0x" dup >fdth_struct_off l@ . cr
        ."  offset to strings: 0x" dup >fdth_string_off l@ . cr
        ."  offset to rsvmap : 0x" dup >fdth_rsvmap_off l@ . cr
        ."  version          : " dup >fdth_version l@ decimal . hex cr
        ."  last compat vers : " dup >fdth_compat_vers l@ decimal . hex cr
        dup >fdth_version l@ 2 >= IF
            ."  boot CPU         : 0x" dup >fdth_boot_cpu l@ . cr
        THEN
        dup >fdth_version l@ 3 >= IF
            ."  strings size     : 0x" dup >fdth_string_size l@ . cr
        THEN
        dup >fdth_version l@ 11 >= IF
            ."  struct size      : 0x" dup >fdth_struct_size l@ . cr
        THEN
    THEN
    dup >fdth_magic l@ OF_DT_HEADER <> IF
        ." Flat device tree has incorrect magic value !" cr
	drop -1 throw EXIT
    THEN
    dup >fdth_version l@ 10 < IF
        ." Flat device tree has usupported version !" cr
	drop -1 throw EXIT
    THEN

    drop
;
fdt-check-header

\ Fetch next tag, skip nops and increment address
: fdt-next-tag ( addr -- nextaddr tag )
  0	       	      	 	( dummy tag on stack for loop )
  BEGIN
    drop			( drop previous tag )
    dup l@			( read new tag )
    swap 4 + swap		( increment addr )
  dup OF_DT_NOP <> UNTIL 	( loop until not nop )
;

\ Parse unit name and advance addr
: fdt-fetch-unit ( addr -- addr $name )
  dup from-cstring	       \  get string size
  2dup + 1 + 3 + fffffffc and -rot
;

\ Update unit with information from the reg property...
\ ... this is required for the PCI nodes for example.
: fdt-reg-unit ( prop-addr prop-len -- )
      decode-phys               ( prop-addr' prop-len' phys.lo ... phys.hi )
      set-unit                  ( prop-addr' prop-len' )
      2drop
;

\ Lookup a string by index
: fdt-fetch-string ( index -- str-addr str-len )
  fdt-strings + dup from-cstring
;

: fdt-create-dec  s" decode-unit" $CREATE , DOES> @ hex64-decode-unit ;
: fdt-create-enc  s" encode-unit" $CREATE , DOES> @ hex64-encode-unit ;

\ Check whether array contains an zero-terminated ASCII string:
: fdt-prop-is-string?  ( addr len -- string? )
   dup 1 < IF 2drop FALSE EXIT THEN                \ Check for valid length
   1-
   2dup + c@ 0<> IF 2drop FALSE EXIT THEN          \ Check zero-termination
   test-string
;

\ Encode fdt property to OF property
: fdt-encode-prop  ( addr len -- pa ps )
   2dup fdt-prop-is-string? IF
      1- encode-string
   ELSE
      encode-bytes
   THEN
;

\ Method to unflatten a node
: fdt-unflatten-node ( start -- end )
  \ this can and will recurse
  recursive

  \ Get & check first tag of node ( addr -- addr)
  fdt-next-tag dup OF_DT_BEGIN_NODE <> IF
    s" Weird tag 0x" type . " at start of node" type cr
    -1 throw
  THEN drop

  new-device

  \ Parse name, split unit address
  fdt-fetch-unit
  dup 0 = IF drop drop " /" THEN
  40 left-parse-string
  \ Set name
  device-name

  \ Set preliminary unit address - might get overwritten by reg property
  dup IF
     " #address-cells" get-parent get-package-property IF
        2drop
     ELSE
        decode-int nip nip
	hex-decode-unit
	set-unit
     THEN
  ELSE 2drop THEN

  \ Iterate sub tags
  BEGIN
    fdt-next-tag dup OF_DT_END_NODE <>
  WHILE
    dup OF_DT_PROP = IF
      \ Found property
      drop dup			( drop tag, dup addr     : a1 a1 )
      dup l@ dup rot 4 +	( fetch size, stack is   : a1 s s a2)
      dup l@ swap 4 +		( fetch nameid, stack is : a1 s s i a3 )
      rot			( we now have: a1 s i a3 s )
      fdt-encode-prop rot	( a1 s pa ps i)
      fdt-fetch-string		( a1 s pa ps na ns )
      2dup s" reg" str= IF
          2swap 2dup fdt-reg-unit 2swap
      THEN
      property
      + 8 + 3 + fffffffc and
    ELSE dup OF_DT_BEGIN_NODE = IF
      drop			( drop tag )
      4 -
      fdt-unflatten-node
    ELSE
      drop -1 throw
    THEN THEN
  REPEAT drop \ drop tag

  \ Create encode/decode unit
  " #address-cells" get-node get-package-property IF ELSE
    decode-int dup fdt-create-dec fdt-create-enc 2drop
  THEN

  fdt-update-from-fdt

  finish-device  
;

\ Start unflattening
: fdt-unflatten-tree
    fdt-debug IF
        ." Unflattening device tree..." cr THEN
    fdt-struct fdt-unflatten-node drop
    fdt-debug IF
        ." Done !" cr THEN
;
fdt-unflatten-tree

\ Find memory size
: fdt-parse-memory
    \ XXX FIXME Handle more than one memory node, and deal
    \     with RMA vs. full access
    " /memory@0" find-device
    " reg" get-node get-package-property IF throw -1 THEN

    \ XXX FIXME Assume one entry only in "reg" property for now
    decode-phys 2drop decode-phys
    my-#address-cells 1 > IF 20 << or THEN
    
    fdt-debug IF
        dup ." Memory size: " . cr
    THEN
    \ claim.fs already released the memory between 0 and MIN-RAM-SIZE,
    \ so we've got only to release the remaining memory now:
    MIN-RAM-SIZE swap MIN-RAM-SIZE - release
    2drop device-end
;
fdt-parse-memory


\ Claim fdt memory and reserve map
: fdt-claim-reserve
    fdt-start-addr
    dup dup >fdth_tsize l@ 0 claim drop
    dup >fdth_rsvmap_off l@ +
    BEGIN
        dup dup x@ swap 8 + x@
	dup 0 <>
    WHILE
	fdt-debug IF
	    2dup swap ." Reserve map entry: " . ." : " . cr
	THEN
	0 claim drop
	10 +
    REPEAT drop drop drop
;
fdt-claim-reserve 


\ The following functions are use to replace the FDT phandle and
\ linux,phandle properties with our own OF1275 phandles...

\ This is used to check whether we successfully replaced a phandle value
0 VALUE (fdt-phandle-replaced)

\ Replace phandle value in "interrupt-map" property
: fdt-replace-interrupt-map  ( old new prop-addr prop-len -- old new )
   BEGIN
      dup                    ( old new prop-addr prop-len prop-len )
   WHILE
      \ This is a little bit ugly ... we're accessing the property at
      \ hard-coded offsets instead of analyzing it completely...
      swap dup 10 +          ( old new prop-len prop-addr prop-addr+10 )
      dup l@ 5 pick = IF
          \ it matches the old phandle value!
          3 pick swap l!
          TRUE TO (fdt-phandle-replaced)
      ELSE
          drop
      THEN
      ( old new prop-len prop-addr )
      1c + swap 1c -
      ( old new new-prop-addr new-prop-len )
   REPEAT
   2drop
;

: (fdt-replace-phandles) ( old new propname propnamelen node -- )
    get-property IF 2drop EXIT THEN
    BEGIN
        dup
    WHILE                   ( old new prop-addr prop-len )
        over l@
        4 pick = IF
            2 pick 2 pick l! \ replace old with new in place
            TRUE TO (fdt-phandle-replaced)
        THEN
        4 - swap 4 + swap
    REPEAT
    2drop 2drop
;

: (phandle>node) ( phandle current -- node|0 )
    dup s" phandle" rot get-property 0= IF
	decode-int nip nip ( phandle current phandle-prop )
	2 pick = IF
	    fdt-debug IF ."        Found phandle; " dup . ."  <= " over . cr THEN
	    nip            ( current )
	    EXIT
	THEN
    ELSE
	dup s" linux-phandle" rot get-property 0= IF
	    decode-int nip nip ( phandle current phandle-prop )
	    2 pick = IF
		fdt-debug IF ."        Found linux-phandle; " dup . ."  <= " over . cr THEN
		nip            ( current )
		EXIT
	    THEN
	THEN
    THEN
    child BEGIN
	dup
    WHILE
	2dup
	RECURSE
	?dup 0<> IF
	    nip nip
	    EXIT
	THEN
	PEER
    REPEAT
    2drop 0
;

: phandle>node ( phandle -- node ) s" /" find-node (phandle>node)  ;

: (fdt-patch-phandles) ( prop-addr prop-len -- )
    BEGIN
        dup
    WHILE                   ( prop-addr prop-len )
        over l@ phandle>node
	?dup 0<> IF
	    fdt-debug IF ."     ### Patching phandle=" 2 pick l@ . cr THEN
	    2 pick l!
            TRUE TO (fdt-phandle-replaced)
        THEN
        4 - swap 4 + swap
    REPEAT
    2drop
;

: (fdt-patch-interrupt-map) ( prop-addr prop-len -- )
    \ interrupt-controller phandle is expected to be the same accross the map
    over 10 + l@ phandle>node ?dup 0= IF 2drop EXIT THEN
    -rot
    fdt-debug IF ."      ### Patching interrupt-map: " over 10 + l@ . ."  => " 2 pick . cr THEN

    TRUE TO (fdt-phandle-replaced)
    BEGIN
        dup
    WHILE                   ( newph prop-addr prop-len )
	2 pick 2 pick 10 + l!
        1c - swap 1c  + swap
    REPEAT
    3drop
;

: fdt-patch-phandles ( prop-addr prop-len nameadd namelen -- )
   2dup s" interrupt-map" str= IF 2drop (fdt-patch-interrupt-map) EXIT THEN
   2dup s" interrupt-parent" str= IF 2drop (fdt-patch-phandles) EXIT THEN
   2dup s" ibm,gpu" str= IF 2drop (fdt-patch-phandles) EXIT THEN
   2dup s" ibm,npu" str= IF 2drop (fdt-patch-phandles) EXIT THEN
   2dup s" ibm,nvlink" str= IF 2drop (fdt-patch-phandles) EXIT THEN
   2dup s" memory-region" str= IF 2drop (fdt-patch-phandles) EXIT THEN
   4drop
;

\ Replace one phandle "old" with a phandle "new" in "node" and recursively
\ in its child nodes:
: fdt-replace-all-phandles ( old new node -- )
   \ ." Replacing in " dup node>path type cr
   >r
   s" interrupt-map" r@ get-property 0= IF
      ( old new prop-addr prop-len  R: node )
      fdt-replace-interrupt-map
   THEN

   2dup s" interrupt-parent" r@ (fdt-replace-phandles)
   2dup s" ibm,gpu" r@ (fdt-replace-phandles)
   2dup s" ibm,npu" r@ (fdt-replace-phandles)
   2dup s" ibm,nvlink" r@ (fdt-replace-phandles)
   2dup s" memory-region" r@ (fdt-replace-phandles)

   \ ... add more properties that have to be fixed here ...
   r>
   \ Now recurse over all child nodes:       ( old new node )
   child BEGIN
      dup
   WHILE
      3dup RECURSE
      PEER
   REPEAT
   3drop
;

\ Replace one FDT phandle "val" with a OF1275 phandle "node" in the
\ whole tree:
: fdt-update-phandle ( val node -- )
   >r
   FALSE TO (fdt-phandle-replaced)
   r@ s" /" find-node               ( val node root )
   fdt-replace-all-phandles
   (fdt-phandle-replaced) IF
      r@ set-node
      s" phandle" delete-property
      s" linux,phandle" delete-property
   ELSE
      diagnostic-mode? IF
         cr ." Warning: Did not replace phandle in " r@ node>path type cr
      THEN
   THEN
r> drop
;

\ Check whether a node has "phandle" or "linux,phandle" properties
\ and replace them:
: fdt-fix-node-phandle  ( node -- )
   >r
   s" phandle" r@ get-property 0= IF
      decode-int nip nip
      \ ." found phandle: " dup . cr
      r@ fdt-update-phandle
   THEN
   r> drop
;

\ Recursively walk through all nodes to fix their phandles:
: fdt-fix-phandles  ( node -- )
   \ ." fixing phandles of " dup node>path type cr
   dup fdt-fix-node-phandle
   child BEGIN
      dup
   WHILE
      dup RECURSE
      PEER
   REPEAT
   drop
   device-end
;

: str=phandle? ( s len -- true|false )
    2dup s" phandle" str= >r
    s" linux,phandle" str=
    r> or
;

: fdt-cas-finish-device ( -- )
    " reg" get-node get-package-property IF ELSE fdt-reg-unit THEN
    get-node finish-device set-node
;

: (fdt-fix-cas-node) ( start -- end )
    recursive
    fdt-next-tag dup OF_DT_BEGIN_NODE <> IF
	." Error " cr
	false to fdt-cas-fix?
	EXIT
    THEN drop
    fdt-fetch-unit		    ( a1 $name )
    dup 0 = IF drop drop " /" THEN
    40 left-parse-string
    2swap ?dup 0 <> IF
	nip
	1 + + \ Add the string len +@
    ELSE
	drop
    THEN

    fdt-cas-pass 0= IF
	\ The guest might have asked to change the interrupt controller
	\ type. It doesn't make sense to merge the new node and the
	\ existing "interrupt-controller" node in this case. Delete the
	\ latter. A brand new one will be created with the appropriate
	\ properties and unit name.
	2dup " interrupt-controller" find-substr 0= IF
	    " interrupt-controller" find-node ?dup 0 <> IF
		fdt-debug IF ." Deleting existing node: " dup .node cr THEN
		delete-node
	    THEN
	THEN
    THEN
    2dup find-node ?dup 0 <> IF
	set-node
	fdt-debug IF ." Setting node: " 2dup type cr THEN
	2drop
	\ newnode?=0: updating the existing node, i.e. pass1 adds only phandles
	0
    ELSE
	fdt-cas-pass 0 <> IF
	    \ We could not find the node added in the previous pass,
	    \ most likely because it is hotplug-under-hotplug case
	    \ (such as PCI brigde under bridge) when missing new node methods
	    \ such as "decode-unit" are critical.
	    \ Reboot when detect such case which is expected as it is a part of
	    \ ibm,client-architecture-support.
	    ." Cannot handle FDT update for the " 2dup type
	    ."  node, rebooting" cr
	    reset-all
	THEN
	fdt-debug IF ." Creating node: " 2dup type cr THEN
	new-device
	2dup " @" find-substr nip
	device-name
	\ newnode?=1: adding new node, i.e. pass1 adds all properties,
	\ most importantly "reg". After reading properties, we call
	\ "fdt-cas-finish-device" which sets the unit address from "reg".
	1
    THEN
    swap			( newnode? a1 )

    fdt-debug IF ." Current  now: " pwd  get-node ."  = " . cr THEN
    fdt-cas-pass 0= IF
	fdt-update-from-fdt
    THEN
    BEGIN
	fdt-next-tag dup OF_DT_END_NODE <>
    WHILE
				( newnode? a1 tag )
	dup OF_DT_PROP = IF
	    drop dup		( newnode? a1 a1 )
	    dup l@ dup rot 4 +	( newnode? a1 s s a2)
	    dup l@ swap 4 +	( newnode? a1 s s i a3 )
	    rot			( newnode? a1 s i a3 s )
	    fdt-encode-prop rot	( newnode? a1 s pa ps i)
	    fdt-fetch-string	( newnode? a1 s pa ps na ns )

	    fdt-cas-pass CASE
	    0 OF
		2dup str=phandle? 7 pick or IF
		    fdt-debug IF 4dup ."   Property: " type ." =" swap ." @" . ."  " .d ."  bytes" cr THEN
		    property
		ELSE
		    4drop
		THEN
	    ENDOF
	    1 OF
		2dup str=phandle? not IF
		    fdt-debug IF 4dup ."   Property: "  type ." =" swap ." @" . ."  " .d ."  bytes" cr THEN
		    4dup fdt-patch-phandles
		    property
		ELSE
		    4drop
		THEN
	    ENDOF
	    2 OF
		2dup str=phandle? IF
		    fdt-debug IF 4dup ."   Deleting: " type ." =" swap ." @" . ."  " .d ."  bytes" cr THEN
		    delete-property
		    2drop
		ELSE
		    4drop
		THEN
	    ENDOF
	    ENDCASE

	    + 8 + 3 + fffffffc and
	ELSE		( newnode? a1 tag )
	    dup OF_DT_BEGIN_NODE = IF
		2 pick IF
		    rot drop 0 -rot
		    fdt-cas-finish-device
		    fdt-debug IF ." Finished node: " pwd  get-node ."  = " . cr THEN
		THEN
		drop			( a1 )
		4 -
		(fdt-fix-cas-node)
		get-parent set-node
	    ELSE
		." Error " cr
		drop
		false to fdt-cas-fix?
		EXIT
	    THEN
	THEN
    REPEAT
			( newnode? a1 tag )
    drop
    swap		( a1 newnode? )
    IF
	fdt-cas-finish-device
	fdt-debug IF ." Finished subnode: " pwd  get-node ."  = " . cr THEN
    THEN
;

: alias-dev-path ( xt -- dev-path len )
    link> execute decode-string	2swap 2drop
;

: alias-name ( xt -- alias-name len )
    link> >name name>string
;

: fdt-cas-alias-obsolete? ( xt -- true|false )
    alias-dev-path find-node 0=
;

: (fdt-cas-delete-obsolete-aliases) ( xt -- )
    dup IF
	dup @
	recurse
	dup alias-name s" name" str= IF ELSE
	    dup fdt-cas-alias-obsolete? IF
		fdt-debug IF ." Deleting obsolete alias: " dup alias-name type ."  -> " dup alias-dev-path type cr THEN
		dup alias-name
		delete-property
	    THEN
	THEN
    THEN
    drop
;

: fdt-cas-delete-obsolete-aliases ( -- )
    s" /aliases" find-device
    get-node node>properties @ cell+ @ (fdt-cas-delete-obsolete-aliases)
    device-end
;

: fdt-cas-node-obsolete? ( node -- true|false)
    s" slof,from-fdt" rot get-package-property IF
	\ Not a QEMU originated node
	false
    ELSE
	decode-int nip nip fdt-generation# <
    THEN
;

: (fdt-cas-search-obsolete-nodes) ( node -- )
    dup child
    BEGIN
	dup
    WHILE
	dup recurse
	peer
    REPEAT
    drop
    dup fdt-cas-node-obsolete? IF
        fdt-debug IF dup ." Deleting obsolete node: " dup .node ." = " . cr THEN
        dup delete-node
    THEN
    drop
;

: fdt-cas-delete-obsolete-nodes ( -- )
    s" /" find-device get-node (fdt-cas-search-obsolete-nodes)
    fdt-cas-delete-obsolete-aliases
;

: fdt-fix-cas-node ( start -- )
    fdt-generation# 1+ to fdt-generation#
    0 to fdt-cas-pass dup (fdt-fix-cas-node) drop \ Add phandles
    fdt-cas-delete-obsolete-nodes                 \ Delete removed devices
    1 to fdt-cas-pass dup (fdt-fix-cas-node) drop \ Patch+add other properties
    2 to fdt-cas-pass dup (fdt-fix-cas-node) drop \ Delete phandles from pass 0
    drop
;

: fdt-fix-cas-success
    fdt-cas-fix?
;

s" /" find-node fdt-fix-phandles
