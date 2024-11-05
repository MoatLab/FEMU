\
\ Fcode payload for QEMU VGA graphics card
\
\ This is the Forth source for an Fcode payload to initialise
\ the QEMU VGA graphics card.
\
\ (C) Copyright 2013 Mark Cave-Ayland
\

fcode-version3

\
\ Dictionary lookups for words that don't have an FCode
\

: (find-xt)   \ ( str len -- xt | -1 )
  $find if
    exit
  else
    -1
  then
;

" openbios-video-width" (find-xt) cell+ value openbios-video-width-xt
" openbios-video-height" (find-xt) cell+ value openbios-video-height-xt
" depth-bits" (find-xt) cell+ value depth-bits-xt
" line-bytes" (find-xt) cell+ value line-bytes-xt

: openbios-video-width openbios-video-width-xt @ ;
: openbios-video-height openbios-video-height-xt @ ;
: depth-bits depth-bits-xt @ ;
: line-bytes line-bytes-xt @ ;

" fb8-fillrect" (find-xt) value fb8-fillrect-xt
: fb8-fillrect fb8-fillrect-xt execute ;

" fw-cfg-read-file" (find-xt) value fw-cfg-read-file-xt
: fw-cfg-read-file fw-cfg-read-file-xt execute ;

\
\ IO port words
\

" ioc!" (find-xt) value ioc!-xt
" iow!" (find-xt) value iow!-xt

: ioc! ioc!-xt execute ;
: iow! iow!-xt execute ;

" le-w!" (find-xt) value le-w!-xt

: le-w! le-w!-xt execute ;

\
\ PCI
\

" pci-bar>pci-addr" (find-xt) value pci-bar>pci-addr-xt
: pci-bar>pci-addr pci-bar>pci-addr-xt execute ;

h# 10 constant cfg-bar0    \ Framebuffer BAR
h# 18 constant cfg-bar2    \ QEMU MMIO ioport BAR
-1 value fb-addr
-1 value mmio-addr

\
\ VGA registers
\

h# 3c0 constant vga-addr
h# 3c8 constant dac-write-addr
h# 3c9 constant dac-data-addr

defer vga-ioc!

: vga-legacy-ioc!  ( val addr )
  ioc! 
;

: vga-mmio-ioc!  ( val addr )
  h# 3c0 - h# 400 + mmio-addr + c!
;

: vga-color!  ( r g b index -- )
  \ Set the VGA colour registers
  dac-write-addr vga-ioc! rot
  2 >> dac-data-addr vga-ioc! swap
  2 >> dac-data-addr vga-ioc!
  2 >> dac-data-addr vga-ioc!
;

\
\ VBE registers
\

h# 0 constant VBE_DISPI_INDEX_ID
h# 1 constant VBE_DISPI_INDEX_XRES
h# 2 constant VBE_DISPI_INDEX_YRES
h# 3 constant VBE_DISPI_INDEX_BPP
h# 4 constant VBE_DISPI_INDEX_ENABLE
h# 5 constant VBE_DISPI_INDEX_BANK
h# 6 constant VBE_DISPI_INDEX_VIRT_WIDTH
h# 7 constant VBE_DISPI_INDEX_VIRT_HEIGHT
h# 8 constant VBE_DISPI_INDEX_X_OFFSET
h# 9 constant VBE_DISPI_INDEX_Y_OFFSET
h# a constant VBE_DISPI_INDEX_NB

h# 0 constant VBE_DISPI_DISABLED
h# 1 constant VBE_DISPI_ENABLED

\
\ Bochs VBE register writes
\

defer vbe-iow!

: vbe-legacy-iow!  ( val addr -- )
  h# 1ce iow!
  h# 1d0 iow!
;

: vbe-mmio-iow!  ( val addr -- )
  1 lshift h# 500 + mmio-addr + cr .s cr le-w!
;

\
\ Initialise Bochs VBE mode
\

: vbe-init  ( -- )
  h# 0 vga-addr vga-ioc!    \ Enable blanking
  VBE_DISPI_DISABLED VBE_DISPI_INDEX_ENABLE vbe-iow!
  h# 0 VBE_DISPI_INDEX_X_OFFSET vbe-iow!
  h# 0 VBE_DISPI_INDEX_Y_OFFSET vbe-iow!
  openbios-video-width VBE_DISPI_INDEX_XRES vbe-iow!
  openbios-video-height VBE_DISPI_INDEX_YRES vbe-iow!
  depth-bits VBE_DISPI_INDEX_BPP vbe-iow!
  VBE_DISPI_ENABLED VBE_DISPI_INDEX_ENABLE vbe-iow!
  h# 0 vga-addr vga-ioc!
  h# 20 vga-addr vga-ioc!   \ Disable blanking
;

\
\ PCI BAR mapping
\

: map-fb ( -- )
  cfg-bar0 pci-bar>pci-addr if   \ ( pci-addr.lo pci-addr.mid pci-addr.hi size )
    " pci-map-in" $call-parent
    to fb-addr
  then
;

: map-mmio ( -- )
  cfg-bar2 pci-bar>pci-addr if   \ ( pci-addr.lo pci-addr.mid pci-addr.hi size )
    " pci-map-in" $call-parent
    to mmio-addr
  then
;

\
\ Legacy IO port or QEMU MMIO accesses
\
\ legacy: use standard VGA ioport registers
\ MMIO: use QEMU PCI MMIO VGA registers
\
\ If building for QEMU, default to MMIO access since it allows
\ programming of the VGA card regardless of its position in the
\ PCI topology
\

[IFDEF] CONFIG_QEMU
['] vga-mmio-ioc! to vga-ioc!
['] vbe-mmio-iow! to vbe-iow!
[ELSE]
['] vga-legacy-ioc! to vga-ioc!
['] vbe-legacy-iow! to vbe-iow!
[THEN]

\
\ Publically visible words
\

external

[IFDEF] CONFIG_MOL
defer mol-color!

\ Hook for MOL (see packages/molvideo.c)
\
\ Perhaps for neatness this there should be a separate molvga.fs
\ but let's leave it here for now.

: color!  ( r g b index -- )
  mol-color!
;

[ELSE]

\ Standard VGA

: color!  ( r g b index -- )
  vga-color!
;

[THEN]

: fill-rectangle  ( color_ind x y width height -- )
  fb8-fillrect
;

: dimensions  ( -- width height )
  openbios-video-width
  openbios-video-height
;

: set-colors  ( table start count -- )
  0 do
    over dup        \ ( table start table table )
    c@ swap 1+      \ ( table start r table-g )
    dup c@ swap 1+  \ ( table start r g table-b )
    c@ 3 pick       \ ( table start r g b index )
    color!          \ ( table start )
    1+
    swap 3 + swap   \ ( table+3 start+1 )
  loop
;

\
\ Cancel Bochs VBE mode
\

: vbe-deinit ( -- )
  \ Switching VBE on and off clears the framebuffer
  VBE_DISPI_DISABLED VBE_DISPI_INDEX_ENABLE vbe-iow!
  VBE_DISPI_ENABLED VBE_DISPI_INDEX_ENABLE vbe-iow!
  VBE_DISPI_DISABLED VBE_DISPI_INDEX_ENABLE vbe-iow!
;

headerless

\
\ Installation
\

: qemu-vga-driver-install ( -- )
  mmio-addr -1 = if
    map-mmio vbe-init
  then
  fb-addr -1 = if
    map-fb fb-addr to frame-buffer-adr
    default-font set-font

    frame-buffer-adr encode-int " address" property

    openbios-video-width openbios-video-height over char-width / over char-height /
    fb8-install
  then
;

: qemu-vga-driver-init
  openbios-video-width encode-int " width" property
  openbios-video-height encode-int " height" property
  depth-bits encode-int " depth" property
  line-bytes encode-int " linebytes" property

  \ Is the VGA NDRV driver enabled? (PPC only)
  " /options" find-package drop s" vga-ndrv?" rot get-package-property not if
    decode-string 2swap 2drop    \ ( addr len )
    s" true" drop -rot comp 0= if
      \ Embed NDRV driver via fw-cfg if it exists
      " ndrv/qemu_vga.ndrv" fw-cfg-read-file if
        encode-string " driver,AAPL,MacOS,PowerPC" property
      then
    then
  then

  ['] qemu-vga-driver-install is-install
;

qemu-vga-driver-init

end0
