/*
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA.
 *
 * You can also choose to distribute this program under the terms of
 * the Unmodified Binary Distribution Licence (as given in the file
 * COPYING.UBDL), provided that you have satisfied its requirements.
 */

FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL );

#include <config/general.h>

/** @file
 *
 * HTTP extensions
 *
 */

PROVIDE_REQUIRING_SYMBOL();

/*
 * Drag in HTTP extensions
 */
#ifdef HTTP_AUTH_BASIC
REQUIRE_OBJECT ( httpbasic );
#endif
#ifdef HTTP_AUTH_DIGEST
REQUIRE_OBJECT ( httpdigest );
#endif
#ifdef HTTP_AUTH_NTLM
REQUIRE_OBJECT ( httpntlm );
#endif
#ifdef HTTP_ENC_PEERDIST
REQUIRE_OBJECT ( peerdist );
#endif
#ifdef HTTP_HACK_GCE
REQUIRE_OBJECT ( httpgce );
#endif
