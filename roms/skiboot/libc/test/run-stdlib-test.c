// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
/*
 * Copyright 2013-2015 IBM Corp.
 *
 * This file is run with the skiboot libc files rather than system libc.
 * This means we have a bit of "fun" with actually executing the tests on
 * the host.
 * Patches to make this less ugly are very welcome.
 */

#include <config.h>
#include <stdarg.h>

#include "../stdlib/atoi.c"
#include "../stdlib/atol.c"
#include "../stdlib/error.c"
#include "../stdlib/rand.c"
#include "../stdlib/strtol.c"
#include "../stdlib/strtoul.c"
