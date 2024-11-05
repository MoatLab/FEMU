\ ****************************************************************************/
\ * Copyright (c) 2019 IBM Corporation
\ * All rights reserved.
\ * This program and the accompanying materials
\ * are made available under the terms of the BSD License
\ * which accompanies this distribution, and is available at
\ * http://www.opensource.org/licenses/bsd-license.php
\ *
\ * Contributors:
\ *     IBM Corporation - initial implementation
\ ****************************************************************************/

\ DMA memory allocation functions
: dma-alloc ( size -- virt )
   s" dma-alloc" $call-parent
;

: dma-free ( virt size -- )
   s" dma-free" $call-parent
;

: dma-map-in ( virt size cacheable? -- devaddr )
   s" dma-map-in" $call-parent
;

: dma-map-out ( virt devaddr size -- )
   s" dma-map-out" $call-parent
;
