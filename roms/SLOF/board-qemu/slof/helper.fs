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

: slof-build-id  ( -- str len )
   flash-header 10 + dup from-cstring a min
;

: slof-revision s" 001" ;

: read-version-and-date
   flash-header 0= IF
   s"  " encode-string
   ELSE
   flash-header 10 + 10
   here swap rmove
   here 10
   s" , " $cat
   bdate2human $cat encode-string THEN
;

: invert-region-cs ( addr len cellsize -- )
   >r over swap r@ rshift r> swap 1 hv-logical-memop drop
;

: invert-region ( addr len -- )
   2dup or 7 and CASE
      0 OF 3 invert-region-cs ENDOF
      4 OF 2 invert-region-cs ENDOF
      3 and
      2 OF 1 invert-region-cs ENDOF
      dup OF 0 invert-region-cs ENDOF
   ENDCASE
;
