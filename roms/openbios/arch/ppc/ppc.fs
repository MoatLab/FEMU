include config.fs

\ -------------------------------------------------------------------------
\ registers 
\ -------------------------------------------------------------------------

: %cr saved-context h# 7 cells + @ ;
: %ctr saved-context h# 6 cells + @ ;
: %lr saved-context h# 1 cells + @ ;
\ 0 value %msr
\ 0 value %srr0
\ 0 value %srr1
\ 0 value %pc							\ should be an alias for %srr0

: %r0 saved-context h# 3 cells + @ ;
: %r1 saved-context h# 0 cells + @ ;
: %r2 saved-context h# 4 cells + @ ;
: %r3 saved-context h# 5 cells + @ ;
: %r4 saved-context h# 9 cells + @ ;
: %r5 saved-context h# a cells + @ ;
: %r6 saved-context h# b cells + @ ;
: %r7 saved-context h# c cells + @ ;
: %r8 saved-context h# d cells + @ ;
: %r9 saved-context h# e cells + @ ;
: %r10 saved-context h# f cells + @ ;
: %r11 saved-context h# 10 cells + @ ;
: %r12 saved-context h# 11 cells + @ ;
: %r13 saved-context h# 12 cells + @ ;
: %r14 saved-context h# 13 cells + @ ;
: %r15 saved-context h# 14 cells + @ ;
: %r16 saved-context h# 15 cells + @ ;
: %r17 saved-context h# 16 cells + @ ;
: %r18 saved-context h# 17 cells + @ ;
: %r19 saved-context h# 18 cells + @ ;
: %r20 saved-context h# 19 cells + @ ;
: %r21 saved-context h# 1a cells + @ ;
: %r22 saved-context h# 1b cells + @ ;
: %r23 saved-context h# 1c cells + @ ;
: %r24 saved-context h# 1d cells + @ ;
: %r25 saved-context h# 1e cells + @ ;
: %r26 saved-context h# 1f cells + @ ;
: %r27 saved-context h# 20 cells + @ ;
: %r28 saved-context h# 21 cells + @ ;
: %r29 saved-context h# 22 cells + @ ;
: %r30 saved-context h# 23 cells + @ ;
: %r31 saved-context h# 24 cells + @ ;

: %xer saved-context h# 8 cells + @ ;
\ 0 value %sprg0
\ 0 value %sprg1
\ 0 value %sprg2
\ 0 value %sprg3

: .registers
  cr
  s" %cr: " type %cr u. cr
  s" %ctr: " type %ctr u. cr
  s" %lr: " type %lr u. cr
  s" %r0: " type %r0 u. cr
  s" %r1: " type %r1 u. cr
  s" %r2: " type %r2 u. cr
  s" %r3: " type %r3 u. cr
  s" %r4: " type %r4 u. cr
  s" %r5: " type %r5 u. cr
  s" %r6: " type %r6 u. cr
  s" %r7: " type %r7 u. cr
  s" %r8: " type %r8 u. cr
  s" %r9: " type %r9 u. cr
  s" %r10: " type %r10 u. cr
  s" %r11: " type %r11 u. cr
  s" %r12: " type %r12 u. cr
  s" %r13: " type %r13 u. cr
  s" %r14: " type %r14 u. cr
  s" %r15: " type %r15 u. cr
  s" %r16: " type %r16 u. cr
  s" %r17: " type %r17 u. cr
  s" %r18: " type %r18 u. cr
  s" %r19: " type %r19 u. cr
  s" %r20: " type %r20 u. cr
  s" %r21: " type %r21 u. cr
  s" %r22: " type %r22 u. cr
  s" %r23: " type %r23 u. cr
  s" %r24: " type %r24 u. cr
  s" %r25: " type %r25 u. cr
  s" %r26: " type %r26 u. cr
  s" %r27: " type %r27 u. cr
  s" %r28: " type %r28 u. cr
  s" %r29: " type %r29 u. cr
  s" %r30: " type %r30 u. cr
  s" %r31: " type %r31 u. cr
;

\ -------------------------------------------------------------------------
\ Load VGA FCode driver blob
\ -------------------------------------------------------------------------

[IFDEF] CONFIG_DRIVER_VGA
  -1 value vga-driver-fcode
  " QEMU,VGA.bin" $encode-file to vga-driver-fcode
[THEN]

\ -------------------------------------------------------------------------
\ other
\ -------------------------------------------------------------------------

\ Set by BootX when booting Mac OS X
defer spin
