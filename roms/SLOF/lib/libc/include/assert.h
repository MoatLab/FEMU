/*****************************************************************************
 * assert() macro definition
 *
 * Copyright 2018 Red Hat, Inc.
 *
 * This program and the accompanying materials are made available under
 * the terms of the BSD License which accompanies this distribution, and
 * is available at http://www.opensource.org/licenses/bsd-license.php
 *
 * Contributors:
 *     Thomas Huth, Red Hat Inc. - initial implementation
 *****************************************************************************/

#ifndef SLIMLINE_ASSERT_H
#define SLIMLINE_ASSERT_H

#ifdef NDEBUG

#define assert(cond) (void)

#else

#define assert(cond) \
	do { \
		if (!(cond)) { \
			fprintf(stderr, \
				"ERROR: Assertion '" #cond "' failed!\n" \
				"(function %s, file " __FILE__ ", line %i)\n", \
				__func__, __LINE__); \
			while (1) {} \
		} \
	}  while (0)

#endif

#endif /* SLIMLINE_ASSERT_H */
