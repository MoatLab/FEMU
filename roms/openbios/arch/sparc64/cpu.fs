include config.fs

\ SPARC64 trap registers

: %tl-c saved-context h# c8 + @ ;
: %tba saved-context h# 4e0 + @ ;

: tl-offset ( level -- offset )
  h# 20 * h# 4f0 h# 60 +  swap - ;
;

: %tpc ( level -- n ) tl-offset saved-context + @ ;
: %tnpc ( level -- n ) tl-offset saved-context + h# 8 + @ ;
: %tstate ( level -- n ) tl-offset saved-context + h# 10 + @ ;
: %tt ( level -- n ) tl-offset saved-context + h# 18 + @ ;

: .trap-registers
  cr
  s" %tba: " type %tba u. cr
  s" %tl-c: " type %tl-c u. cr
  s" %tpc: " type %tl-c %tpc u. cr
  s" %tnpc: " type %tl-c %tnpc u. cr
  s" %tstate: " type %tl-c %tstate u. cr
  s" %tt: " type %tl-c %tt u. cr
;

: trap? %tl-c 0 > if true else false then ;

\ SPARC64 cpu registers

: %g0 0 ;
: %g1 saved-context h# 30 + @ ;
: %g2 saved-context h# 38 + @ ;
: %g3 saved-context h# 40 + @ ;
: %g4 saved-context h# 48 + @ ;
: %g5 saved-context h# 50 + @ ;
: %g6 saved-context h# 58 + @ ;
: %g7 saved-context h# 60 + @ ;

: %pc
  trap? if
    %tl-c %tpc
  else
    saved-context h# 4d0 + @
  then
;

: %npc
  trap? if
    %tl-c %tnpc
  else
    saved-context h# 4d8 + @
  then
;

: set-pc ( addr )
  saved-context h# 4d0 +
  !
;

: %pstate saved-context h# b0 + @ ;
: %y saved-context h# b8 + @ ;

: %cwp saved-context @ ;
: %cansave saved-context h# 8 + @ ;
: %canrestore saved-context h# 10 + @ ;
: %otherwin saved-context h# 18 + @ ;
: %wstate saved-context h# 20 + @ ;
: %cleanwin saved-context h# 28 + @ ;

: .globals
  cr
  s" %pstate: " type %pstate u. cr
  s" %y: " type %y u. cr
  s" %pc: " type %pc u. cr
  s" %npc: " type %npc u. cr
  s" %cwp: " type %cwp u. cr
  s" %cansave: " type %cansave u. cr
  s" %canrestore: " type %canrestore u. cr
  s" %otherwin: " type %otherwin u. cr
  s" %wstate: " type %wstate u. cr
  s" %cleanwin: " type %cleanwin u. cr
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

: %o0 saved-context h# 70 + @ ;
: %o1 saved-context h# 78 + @ ;
: %o2 saved-context h# 80 + @ ;
: %o3 saved-context h# 88 + @ ;
: %o4 saved-context h# 90 + @ ;
: %o5 saved-context h# 98 + @ ;
: %o6 saved-context h# a0 + @ ;
: %o7 saved-context h# a8 + @ ;

: %l0 saved-context h# d0 + @ ;
: %l1 saved-context h# d8 + @ ;
: %l2 saved-context h# e0 + @ ;
: %l3 saved-context h# e8 + @ ;
: %l4 saved-context h# f0 + @ ;
: %l5 saved-context h# f8 + @ ;
: %l6 saved-context h# 100 + @ ;
: %l7 saved-context h# 108 + @ ;

: %i0 saved-context h# 110 + @ ;
: %i1 saved-context h# 118 + @ ;
: %i2 saved-context h# 120 + @ ;
: %i3 saved-context h# 128 + @ ;
: %i4 saved-context h# 130 + @ ;
: %i5 saved-context h# 138 + @ ;
: %i6 saved-context h# 140 + @ ;
: %i7 saved-context h# 148 + @ ;

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

\ Debugger support
defer debugger-hook

: init-debugger-hook ( xt )
  dup to debugger-hook
;

\ Used by Milax
variable warning
