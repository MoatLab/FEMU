\ tag: misc useful functions
\ 
\ Misc useful functions
\ 
\ Copyright (C) 2003 Samuel Rydh
\ 
\ See the file "COPYING" for further information about
\ the copyright and warranty status of this work.
\ 

\ compare c-string with (str len) pair 
: comp0 ( cstr str len -- 0|-1|1 )
  3dup
  comp ?dup if >r 3drop r> exit then
  nip + c@ 0<> if 1 else 0 then
;

\ returns 0 if the strings match
: strcmp ( str1 len1 str2 len2 -- 0|1 )
  rot over <> if 3drop 1 exit then
  comp if 1 else 0 then 
;
  
: strchr ( str len char -- where|0 )
  >r
  begin
    1- dup 0>=
  while
    ( str len )
    over c@ r@ = if r> 2drop exit then
    swap 1+ swap
  repeat
  r> 3drop 0
;

: cstrlen ( cstr -- len )
  dup
  begin dup c@ while 1+ repeat
  swap -
;

: strdup ( str len -- newstr len )
  dup if
    dup >r
    dup alloc-mem dup >r swap move
    r> r>
  else
    2drop 0 0
  then
;

: dict-strdup ( str len -- dict-addr len )
  dup here swap allot null-align
  swap 2dup >r >r move r> r>
;

\ -----------------------------------------------------
\ string copy and cat variants
\ -----------------------------------------------------

: tmpstrcat ( addr2 len2 addr1 len1 tmpbuf -- buf len1+len2 tmpbuf+l1+l2 )
  \ save return arguments
  dup 2 pick + 4 pick + >r      ( R: buf+l1+l2 )
  over 4 pick + >r
  dup >r
  \ copy...
  2dup + >r
  swap move r> swap move
  r> r> r>
;

: tmpstrcpy ( addr1 len1 tmpbuf -- tmpbuf len1 tmpbuf+len1 )
  swap 2dup >r >r move
  r> r> 2dup +
;



\ -----------------------------------------------------
\ number to string conversion
\ -----------------------------------------------------

: numtostr ( num buf -- buf len )
  swap rdepth -rot
  ( rdepth buf num )
  begin
    base @ u/mod swap
    \ dup 0< if base @ + then
    dup a < if ascii 0 else ascii a a - then + >r
    ?dup 0=
  until

  rdepth rot - 0
  ( buf len cnt )
  begin
    r> over 4 pick + c!
    1+ 2dup <=
  until
  drop
;

: tohexstr ( num buf -- buf len )
  base @ hex -rot numtostr rot base !
;

: toudecstr ( num buf -- buf len )
  base @ decimal -rot numtostr rot base !
;

: todecstr ( num buf -- buf len )
  over 0< if
    swap negate over ascii - over c! 1+
    ( buf num buf+1 )
    toudecstr 1+ nip
  else
    toudecstr
  then
;


\ -----------------------------------------------------
\ string to number conversion
\ -----------------------------------------------------

\ parse ints "hi,...,lo" separated by comma
: parse-ints ( str len num -- val.lo .. val.hi )
  -rot 2 pick -rot
  begin
    rot 1- -rot 2 pick 0>=
  while
    ( num n str len )
    2dup ascii , strchr ?dup if
      ( num n str len p )
      1+ -rot
      2 pick 2 pick -    ( num n p str len len1+1 )
      dup -rot -         ( num n p str len1+1 len2 )
      -rot 1-            ( num n p len2 str len1 )
    else
      0 0 2swap
    then
    $number if 0 then >r
  repeat
  3drop

  ( num )
  begin 1- dup 0>= while r> swap repeat
  drop
;

: parse-2int ( str len -- val.lo val.hi )
  2 parse-ints
;

: parse-nhex ( str len num -- values )
  base @ >r hex parse-ints r> base !
;

: parse-hex ( str len -- value )
  1 parse-nhex
;

\ -----------------------------------------------------
\ miscellaneous functions
\ -----------------------------------------------------

: rot13 ( c - c )
  dup upc [char] A [char] M between if d# 13 + exit then
  dup upc [char] N [char] Z between if d# 13 - then
;

: rot13-str ( str len -- newstr len )
  strdup 2dup bounds ?do i c@ rot13 i c! loop
;
