\ *****************************************************************************
\ * Copyright (c) 2017 IBM Corporation
\ * All rights reserved.
\ * This program and the accompanying materials
\ * are made available under the terms of the BSD License
\ * which accompanies this distribution, and is available at
\ * http://www.opensource.org/licenses/bsd-license.php
\ ****************************************************************************/

0 VALUE fdtfl-debug

VARIABLE fdtfl-struct
VARIABLE fdtfl-struct-here
VARIABLE fdtfl-strings
VARIABLE fdtfl-strings-cache
VARIABLE fdtfl-strings-here
VARIABLE fdtfl-strings-reused \ debug only
VARIABLE fdlfl-ms \ debug only

: fdt-skip-string ( cur -- cur ) zcount + char+  4 #aligned ;

: zstring=  ( str len zstr -- flag )
    2dup + c@ 0<> IF
        3drop false
        EXIT
    THEN
    swap comp 0=
;

: fdt-find-string ( name namelen -- nameoff true | false )
    fdtfl-strings @
    BEGIN
        dup fdtfl-strings-cache @ <
    WHILE
        3dup zstring= IF
            nip nip             ( curstr )
            fdtfl-strings @ -
            true
            EXIT
        THEN
        fdt-skip-string
    REPEAT
    3drop
    false
;

: fdt-str-allot ( len -- ) fdtfl-strings-here @ + to fdtfl-strings-here ;
: fdt-str-c, ( char -- ) fdtfl-strings-here @ 1 fdt-str-allot c! ;
: fdt-str-align  ( -- )
    fdtfl-strings-here @
    dup dup 4 #aligned swap -   ( here bytes-to-erase )
    dup -rot
    erase
    fdt-str-allot
;
: fdt-str-bytes, ( data len -- ) fdtfl-strings-here @ over fdt-str-allot swap move ;
: fdt-str-ztr, ( str len -- ) fdt-str-bytes, 0 fdt-str-c, ;

: fdt-add-string ( name namelen -- nameoff )
    fdtfl-strings-here @ -rot
    fdt-str-ztr,
    fdt-str-align
    fdtfl-strings @ -
;

: fdt-get-string ( name namelen -- nameoff )
    2dup fdt-find-string IF
        -rot 2drop
        fdtfl-debug IF
           1 fdtfl-strings-reused +!
        THEN
        EXIT
    THEN
    fdt-add-string
;

: fdt-allot ( len -- ) fdtfl-struct-here @ + to fdtfl-struct-here ;
: fdt-c, ( char -- ) fdtfl-struct-here @ 1 fdt-allot c! ;
: fdt-align  ( -- )
    fdtfl-struct-here @
    dup dup 4 #aligned swap -   ( here bytes-to-erase )
    dup -rot
    erase
    fdt-allot
;
: fdt-bytes, ( data len -- ) fdtfl-struct-here @ over fdt-allot swap move ;
: fdt-ztr, ( str len -- ) fdt-bytes, 0 fdt-c, ;
: fdt-l, ( token -- ) fdtfl-struct-here @ l! /l fdt-allot ;

: fdt-begin-node ( phandle -- )
    OF_DT_BEGIN_NODE fdt-l,
    dup device-tree @ = IF drop s" " ELSE node>qname THEN
    fdt-ztr,
    fdt-align
;

: fdt-end-node ( -- ) OF_DT_END_NODE fdt-l, ;

: fdt-prop ( prop len name namelen -- )
    OF_DT_PROP fdt-l,

    \ get string offset
    fdt-get-string      ( prop len nameoff )

    \ store len and nameoff
    over fdt-l,
    fdt-l,              ( prop len )

    \ now store the bytes
    fdt-bytes,
    fdt-align
;

: fdt-end ( -- ) OF_DT_END fdt-l, ;

: fdt-copy-property ( link -- )
    dup link> execute
    rot
    link>name name>string
    2dup s" name" str= IF 4drop EXIT THEN \ skipping useless "name"
    fdt-prop
;

: for-all-words ( wid xt -- ) \ xt has sig ( lfa -- )
    >r
    cell+ @ BEGIN dup WHILE dup r@ execute @ REPEAT
    r> 2drop
;

: fdt-copy-properties ( phandle -- )
   dup encode-int s" phandle" fdt-prop
   node>properties @
   ['] fdt-copy-property for-all-words
;

: fdt-copy-node ( node --  )
    fdtfl-debug 1 > IF dup node>path type cr THEN
    dup fdt-begin-node
    dup fdt-copy-properties
    child BEGIN dup WHILE dup recurse peer REPEAT
    drop
    fdt-end-node
;

: fdtfl-strings-preload ( -- )
    s" reg" fdt-add-string drop
    s" status" fdt-add-string drop
    s" 64-bit" fdt-add-string drop
    s" phandle" fdt-add-string drop
    s" ibm,vmx" fdt-add-string drop
    s" ibm,dfp" fdt-add-string drop
    s" slb-size" fdt-add-string drop
    s" ibm,purr" fdt-add-string drop
    s" vendor-id" fdt-add-string drop
    s" device-id" fdt-add-string drop
    s" min-grant" fdt-add-string drop
    s" class-code" fdt-add-string drop
    s" compatible" fdt-add-string drop
    s" interrupts" fdt-add-string drop
    s" cpu-version" fdt-add-string drop
    s" #size-cells" fdt-add-string drop
    s" ibm,req#msi" fdt-add-string drop
    s" revision-id" fdt-add-string drop
    s" device_type" fdt-add-string drop
    s" max-latency" fdt-add-string drop
    s" ibm,chip-id" fdt-add-string drop
    s" ibm,pft-size" fdt-add-string drop
    s" ibm,slb-size" fdt-add-string drop
    s" devsel-speed" fdt-add-string drop
    s" ibm,loc-code" fdt-add-string drop
    s" subsystem-id" fdt-add-string drop
    s" d-cache-size" fdt-add-string drop
    s" i-cache-size" fdt-add-string drop
    s" #address-cells" fdt-add-string drop
    s" clock-frequency" fdt-add-string drop
    s" cache-line-size" fdt-add-string drop
    s" ibm,pa-features" fdt-add-string drop
    s" ibm,my-drc-index" fdt-add-string drop
    s" d-cache-line-size" fdt-add-string drop
    s" i-cache-line-size" fdt-add-string drop
    s" assigned-addresses" fdt-add-string drop
    s" d-cache-block-size" fdt-add-string drop
    s" i-cache-block-size" fdt-add-string drop
    s" timebase-frequency" fdt-add-string drop
    s" subsystem-vendor-id" fdt-add-string drop
    s" ibm,segment-page-sizes" fdt-add-string drop
    s" ibm,ppc-interrupt-server#s" fdt-add-string drop
    s" ibm,processor-segment-sizes" fdt-add-string drop
    s" ibm,ppc-interrupt-gserver#s" fdt-add-string drop
;

: fdt-append-blob ( bytes cur blob -- cur )
    3dup -rot swap move
    drop +
;

: fdt-flatten-tree ( -- tree )
    100000 alloc-mem dup fdtfl-struct-here ! fdtfl-struct !
    100000 alloc-mem dup fdtfl-strings-here ! fdtfl-strings !

    fdtfl-debug IF
        0 fdtfl-strings-reused !
        milliseconds fdlfl-ms !
    THEN

    \ Preload strings cache
    fdtfl-strings-preload
    fdtfl-strings-here @ fdtfl-strings-cache !
    \ Render the blobs
    device-tree @ fdt-copy-node
    fdt-end

    \ Calculate strings and struct sizes
    fdtfl-struct-here @ fdtfl-struct @ -
    fdtfl-strings-here @ fdtfl-strings @ - ( struct-len strings-len )

    2dup + /fdth +
    10 + \ Reserve 16 bytes for an empty reserved block

    fdtfl-debug IF
        3dup
        ." FDTsize=" .d ." Strings=" .d ." Struct=" .d
        ." Reused str=" fdtfl-strings-reused @ .d
        milliseconds fdlfl-ms @ - .d ." ms"
        cr
    THEN

    \ Allocate flatten DT blob
    dup alloc-mem                   ( struct-len strings-len total-len fdt )
    >r                              ( struct-len strings-len total-len r: fdt )

    \ Write header
    OF_DT_HEADER        r@ >fdth_magic l!
    dup                 r@ >fdth_tsize l!
    /fdth 10 + 2 pick + r@ >fdth_struct_off l!
    /fdth 10 +          r@ >fdth_string_off l!
    /fdth               r@ >fdth_rsvmap_off l!
    11                  r@ >fdth_version l!
    10                  r@ >fdth_compat_vers l!
    chosen-cpu-unit     r@ >fdth_boot_cpu l!
    over                r@ >fdth_string_size l!
    2 pick              r@ >fdth_struct_size l!
                                    ( struct-len strings-len total-len r: fdt )

    drop                            ( struct-len strings-len r: fdt )
    r@ /fdth +                      ( struct-len strings-len cur r: fdt )

    \ Write the reserved entry
    0 over ! cell+ 0 over ! cell+

    \ Write strings and struct blobs
    fdtfl-strings @ fdt-append-blob
    fdtfl-struct @ fdt-append-blob
    drop

    \ Free temporary blobs
    fdtfl-struct @ 100000 free-mem
    fdtfl-strings @ 100000 free-mem

    \ Return fdt
    r>
;

: fdt-flatten-tree-free ( tree )
    dup >fdth_tsize l@ free-mem
;
