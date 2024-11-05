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

: banner
   cr ."   Type 'boot' and press return to continue booting the system."
   cr ."   Type 'reset-all' and press return to reboot the system."
   cr cr
;

: .banner banner console-clean-fifo ;
