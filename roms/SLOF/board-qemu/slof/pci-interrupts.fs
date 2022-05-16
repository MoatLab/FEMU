
: pci-gen-irq-map-one ( prop-addr prop-len slot pin -- prop-addr prop-len )
    2dup + 1- 3 and 1+          ( prop-addr prop-len slot pin parentpin )
    >r >r                       ( prop-addr prop-len slot R: parentpin pin )

    \ Child slot#
    B lshift encode-int+        ( prop-addr prop-len R: parentpin pin )
    \ Child 64bit BAR (not really used)
    0 encode-64+
    \ Child pin#
    r> encode-int+              ( prop-addr prop-len R: parentpin )

    \ Parent phandle
    get-parent encode-int+

    \ Parent slot#
    get-node >space
    pci-addr2dev B lshift       ( prop-addr prop-len parent-slot R: parentpin )
    encode-int+
    \ Parent 64bit BAR (not really used)
    0 encode-64+
    \ Parent pin
    r> encode-int+              ( prop-addr prop-len R: )
;

: pci-gen-irq-entry ( prop-addr prop-len config-addr -- prop-addr prop-len )
    pci-addr2dev                ( prop-addr prop-len slot )
    -rot                        ( slot prop-addr prop-len )
    5 1 DO
        2 pick i                ( slot prop-addr prop-len slot pin )
        pci-gen-irq-map-one
    LOOP
    rot drop
;

: pci-set-irq-line ( config-addr -- )
    drop
;
