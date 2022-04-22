\   qemu specific initialization code
\
\   Copyright (C) 2005 Stefan Reinauer
\
\   This program is free software; you can redistribute it and/or
\   modify it under the terms of the GNU General Public License
\   as published by the Free Software Foundation
\


\ -------------------------------------------------------------------------
\ initialization
\ -------------------------------------------------------------------------

: make-openable ( path )
  find-dev if
    begin ?dup while
      \ install trivial open and close methods
      dup active-package! is-open
      parent
    repeat
  then
;

: preopen ( chosen-str node-path )
  2dup make-openable

  " /chosen" find-device
  open-dev ?dup if
    encode-int 2swap property
  else
    2drop
  then
;

\ preopen device nodes (and store the ihandles under /chosen)
:noname
  " rtc" " rtc" preopen
  " memory" " /memory" preopen
; SYSTEM-initializer


\ use the tty interface if available
: activate-tty-interface
  " /packages/terminal-emulator" find-dev if drop
  then
;

variable keyboard-phandle 0 keyboard-phandle !

: (find-keyboard-device) ( phandle -- )
  recursive
  keyboard-phandle @ 0= if  \ Return first match
    >dn.child @
    begin ?dup while
      dup dup " device_type" rot get-package-property 0= if
        drop dup cstrlen
        " keyboard" strcmp 0= if
          dup to keyboard-phandle
        then
      then
      (find-keyboard-device)
      >dn.peer @
    repeat
  else
    drop
  then
;

\ create the keyboard devalias 
:noname
  device-tree @ (find-keyboard-device)
  keyboard-phandle @ if
    active-package
    " /aliases" find-device
    keyboard-phandle @ get-package-path 2dup
    encode-string " kbd" property
    encode-string " keyboard" property
    active-package!  
  then
; SYSTEM-initializer

\ -------------------------------------------------------------------------
\ pre-booting
\ -------------------------------------------------------------------------

: update-chosen
  " /chosen" find-device
  stdin @ encode-int " stdin" property
  stdout @ encode-int " stdout" property
  device-end
;

:noname
  set-defaults
; PREPOST-initializer

\ -------------------------------------------------------------------------
\ copyright property handling
\ -------------------------------------------------------------------------

: insert-copyright-property
  \ As required for MacOS 9 and below
  " Pbclevtug 1983-2001 Nccyr Pbzchgre, Vap. GUVF ZRFFNTR SBE PBZCNGVOVYVGL BAYL"
  rot13-str encode-string " copyright"
  " /" find-package if
    " set-property" $find if
      execute
    else
      3drop drop
    then
  then
;

: delete-copyright-property
  \ Remove copyright property created above
  active-package
  " /" find-package if
      active-package!
      " copyright" delete-property
  then
  active-package!
;

: (exit)
  \ Clean up before returning to the interpreter
  delete-copyright-property
;

\ -------------------------------------------------------------------------
\ Adler-32 wrapper
\ -------------------------------------------------------------------------

: adler32 ( adler buf len -- checksum )
  " (adler32)" $find if
    execute
  else
    ." Can't find " ( adler32-name ) type cr
    3drop 0
  then
;
