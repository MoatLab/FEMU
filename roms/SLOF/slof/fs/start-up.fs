\ *****************************************************************************
\ * Copyright (c) 2004, 2008 IBM Corporation
\ * All rights reserved.
\ * This program and the accompanying materials
\ * are made available under the terms of the BSD License
\ * which accompanies this distribution, and is available at
\ * http://www.opensource.org/licenses/bsd-license.php
\ *
\ * Contributors:
\ *     IBM Corporation - initial implementation
\ ****************************************************************************/

: (boot) ( -- )
   s" Executing following boot-command: "
   boot-command $cat nvramlog-write-string-cr
   s" boot-command" evaluate      \ get boot command
   ['] evaluate catch ?dup IF     \ and execute it
      ." boot attempt returned: "
      abort"-str @ count type cr
      nip nip                     \ drop string from 1st evaluate
      throw
   THEN
;

\ Note: The following ESC sequences has to be handled:
\     1B 4F 50
\     1B 5B 31 31 7E

\ Reads and converts the function key.
\ key = F1 -- n = 1
: (function-key) ( -- n )
   key? IF
      key CASE
	 50  OF 1 ENDOF
	 7e  OF 1 ENDOF
	 dup OF 0 ENDOF
      ENDCASE
   THEN
;

\ Checks if an ESC sequence occurs.
: (esc-sequence) ( -- n )
   key? IF
      key CASE
	  4f  OF (function-key) ENDOF
	  5b  OF
	     key key (function-key) ENDOF
	  dup OF 0 ENDOF
       ENDCASE
   THEN
;

: (s-pressed) ( -- )
   s" An 's' has been pressed. Entering Open Firmware Prompt"
   nvramlog-write-string-cr
;

: (t-pressed) ( -- )
   s" /ibm,vtpm" find-node ?dup IF
      s" vtpm-menu" rot $call-static
   THEN
;

: (boot?) ( -- )
   \ last step before we boot we give up physical presence on the TPM
   s" /ibm,vtpm" find-node ?dup IF
      s" leave-firmware" rot $call-static
   THEN

   of-prompt? not auto-boot? and IF
      (boot)
   THEN
;


\ Watchdog will be rearmed during load if use-load-watchdog variable is TRUE
TRUE VALUE use-load-watchdog?


: boot-menu-start
    boot-menu ?dup IF
       s" boot " 2swap $cat
       ['] evaluate catch ?dup IF
           ." boot attempt returned: "
           abort"-str @ count type cr
           throw
       THEN
       0 0 load-list 2!
    THEN
;

: boot-menu-enabled? ( -- true|false )
   s" qemu,boot-menu" get-chosen IF
      decode-int 1 = IF
         2drop TRUE EXIT
      THEN
      2drop
   THEN
   FALSE
;

: f12-pressed?
   34 = >r 32 = r> and IF
      TRUE
   ELSE
      FALSE
   THEN
;

: start-it ( -- )
   key? IF
      key CASE
	 [char] s  OF (s-pressed) ENDOF
	 [char] t  OF (t-pressed) (boot?) ENDOF
	 1b        OF
	     (esc-sequence) CASE
		 1   OF
                        console-clean-fifo
                        f12-pressed? boot-menu-enabled? and IF
		           boot-menu-start
                        ELSE
                           (boot?)
                        THEN
                     ENDOF
		 dup OF (boot?) ENDOF
	     ENDCASE
	 ENDOF
	 dup OF (boot?) ENDOF
      ENDCASE
   ELSE
      (boot?)
   THEN

   disable-watchdog  FALSE to use-load-watchdog?
   .banner
;
