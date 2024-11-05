include config.fs

\ SPARC32 cpu registers

: %g0 0 ;
: %g1 saved-context h# 14 + @ ;
: %g2 saved-context h# 18 + @ ;
: %g3 saved-context h# 1c + @ ;
: %g4 saved-context h# 20 + @ ;
: %g5 saved-context h# 24 + @ ;
: %g6 saved-context h# 28 + @ ;
: %g7 saved-context h# 2c + @ ;

: %psr saved-context @ ;
: %wim saved-context h# 4 + @ ;
: %pc saved-context h# 250 + @ ;

: set-pc ( addr )
  saved-context h# 250 +
  !
;

: .globals
  cr
  s" %psr: " type %psr u. cr
  s" %wim: " type %wim u. cr
  s" %pc: " type %pc u. cr
  s" %g0: " type %g0 u. cr
  s" %g1: " type %g1 u. cr
  s" %g2: " type %g2 u. cr
  s" %g3: " type %g3 u. cr
  s" %g4: " type %g4 u. cr
  s" %g5: " type %g5 u. cr
  s" %g6: " type %g6 u. cr
  s" %g7: " type %g7 u. cr
;

\ Local registers
\ WARNING: currently only window 0 (current window) supported

: %o0 saved-context h# 30 + @ ;
: %o1 saved-context h# 34 + @ ;
: %o2 saved-context h# 38 + @ ;
: %o3 saved-context h# 3c + @ ;
: %o4 saved-context h# 40 + @ ;
: %o5 saved-context h# 44 + @ ;
: %o6 saved-context h# 48 + @ ;
: %o7 saved-context h# 4c + @ ;

: %l0 saved-context h# 50 + @ ;
: %l1 saved-context h# 54 + @ ;
: %l2 saved-context h# 58 + @ ;
: %l3 saved-context h# 5c + @ ;
: %l4 saved-context h# 60 + @ ;
: %l5 saved-context h# 64 + @ ;
: %l6 saved-context h# 68 + @ ;
: %l7 saved-context h# 6c + @ ;

: %i0 saved-context h# 70 + @ ;
: %i1 saved-context h# 74 + @ ;
: %i2 saved-context h# 78 + @ ;
: %i3 saved-context h# 7c + @ ;
: %i4 saved-context h# 80 + @ ;
: %i5 saved-context h# 84 + @ ;
: %i6 saved-context h# 88 + @ ;
: %i7 saved-context h# 8c + @ ;

: .locals
  cr
  s" %o0: " type %o0 u. cr
  s" %o1: " type %o1 u. cr
  s" %o2: " type %o2 u. cr
  s" %o3: " type %o3 u. cr
  s" %o4: " type %o4 u. cr
  s" %o5: " type %o5 u. cr
  s" %o6: " type %o6 u. cr
  s" %o7: " type %o7 u. cr
  cr
  s" %l0: " type %l0 u. cr
  s" %l1: " type %l1 u. cr
  s" %l2: " type %l2 u. cr
  s" %l3: " type %l3 u. cr
  s" %l4: " type %l4 u. cr
  s" %l5: " type %l5 u. cr
  s" %l6: " type %l6 u. cr
  s" %l7: " type %l7 u. cr
  cr
  s" %i0: " type %i0 u. cr
  s" %i1: " type %i1 u. cr
  s" %i2: " type %i2 u. cr
  s" %i3: " type %i3 u. cr
  s" %i4: " type %i4 u. cr
  s" %i5: " type %i5 u. cr
  s" %i6: " type %i6 u. cr
  s" %i7: " type %i7 u. cr
;

: .registers
  .globals .locals
;
