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

false VALUE scsi-supp-present?

: scsi-xt-err ." SCSI-ERROR (Intern) " ;
' scsi-xt-err VALUE scsi-open-xt        \ preset with an invalid token

\ *************************************
\ utility to show all active word-lists
\ *************************************
: .wordlists      ( -- )
   get-order      ( -- wid1 .. widn n )
   dup space 28 emit .d ." word lists : "
   0 DO
      . 08 emit 2c emit
   LOOP
   08 emit                 \ 'bs'
   29 emit                 \ ')'
   cr space 28 emit
   ." Context: " context dup .
   @ 5b emit . 8 emit 5d emit
   space
   ." / Current: " current .
   cr
;

\ ****************************************************************************
\ open scsi-support by adding a new word list on top of search path
\ first check if scsi-support.fs must be included (first call)
\ when open use execution pointer to access version in new word list
\ ****************************************************************************
: scsi-open  ( -- )
   scsi-supp-present? NOT
   IF
      s" scsi-support.fs" included  ( xt-open )
      to scsi-open-xt               (  )
      true to scsi-supp-present?
   THEN
   scsi-open-xt execute
;
