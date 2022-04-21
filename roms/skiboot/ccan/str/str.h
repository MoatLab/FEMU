/* CC0 (Public domain) - see LICENSE file for details */
#ifndef CCAN_STR_H
#define CCAN_STR_H
#include "config.h"
#include <string.h>
#include <stdbool.h>
#include <limits.h>
#include <ctype.h>

/**
 * streq - Are two strings equal?
 * @a: first string
 * @b: first string
 *
 * This macro is arguably more readable than "!strcmp(a, b)".
 *
 * Example:
 *	if (streq(somestring, ""))
 *		printf("String is empty!\n");
 */
#define streq(a,b) (strcmp((a),(b)) == 0)

/**
 * strstarts - Does this string start with this prefix?
 * @str: string to test
 * @prefix: prefix to look for at start of str
 *
 * Example:
 *	if (strstarts(somestring, "foo"))
 *		printf("String %s begins with 'foo'!\n", somestring);
 */
#define strstarts(str,prefix) (strncmp((str),(prefix),strlen(prefix)) == 0)

/**
 * strends - Does this string end with this postfix?
 * @str: string to test
 * @postfix: postfix to look for at end of str
 *
 * Example:
 *	if (strends(somestring, "foo"))
 *		printf("String %s end with 'foo'!\n", somestring);
 */
static inline bool strends(const char *str, const char *postfix)
{
	if (strlen(str) < strlen(postfix))
		return false;

	return streq(str + strlen(str) - strlen(postfix), postfix);
}

/**
 * stringify - Turn expression into a string literal
 * @expr: any C expression
 *
 * Example:
 *	#define PRINT_COND_IF_FALSE(cond) \
 *		((cond) || printf("%s is false!", stringify(cond)))
 */
#define stringify(expr)		stringify_1(expr)
/* Double-indirection required to stringify expansions */
#define stringify_1(expr)	#expr

/**
 * strcount - Count number of (non-overlapping) occurrences of a substring.
 * @haystack: a C string
 * @needle: a substring
 *
 * Example:
 *      assert(strcount("aaa aaa", "a") == 6);
 *      assert(strcount("aaa aaa", "ab") == 0);
 *      assert(strcount("aaa aaa", "aa") == 2);
 */
size_t strcount(const char *haystack, const char *needle);

/**
 * STR_MAX_CHARS - Maximum possible size of numeric string for this type.
 * @type_or_expr: a pointer or integer type or expression.
 *
 * This provides enough space for a nul-terminated string which represents the
 * largest possible value for the type or expression.
 *
 * Note: The implementation adds extra space so hex values or negative
 * values will fit (eg. sprintf(... "%p"). )
 *
 * Example:
 *	char str[STR_MAX_CHARS(int)];
 *
 *	sprintf(str, "%i", 7);
 */
#define STR_MAX_CHARS(type_or_expr)				\
	((sizeof(type_or_expr) * CHAR_BIT + 8) / 9 * 3 + 2	\
	 + STR_MAX_CHARS_TCHECK_(type_or_expr))

#if HAVE_TYPEOF
/* Only a simple type can have 0 assigned, so test that. */
#define STR_MAX_CHARS_TCHECK_(type_or_expr)		\
	({ typeof(type_or_expr) x = 0; (void)x; 0; })
#else
#define STR_MAX_CHARS_TCHECK_(type_or_expr) 0
#endif

/* These checks force things out of line, hence they are under DEBUG. */
#ifdef CCAN_STR_DEBUG
#if HAVE_TYPEOF
/* With GNU magic, we can make const-respecting standard string functions. */
#undef strstr
#undef strchr
#undef strrchr

/* + 0 is needed to decay array into pointer. */
#define strstr(haystack, needle)					\
	((typeof((haystack) + 0))str_strstr((haystack), (needle)))
#define strchr(haystack, c)					\
	((typeof((haystack) + 0))str_strchr((haystack), (c)))
#define strrchr(haystack, c)					\
	((typeof((haystack) + 0))str_strrchr((haystack), (c)))
#endif
#endif /* CCAN_STR_DEBUG */

#endif /* CCAN_STR_H */
