// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
/* Copyright 2017 IBM Corp. */

#include "config.h"

#include <regex.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sysexits.h>

#include "ccan/short_types/short_types.h"
#include "container-utils.h"
#include "container.h"

extern char *progname;

extern bool verbose, debug;
extern int wrap;


void hex_print(char *lead, unsigned char *buffer, size_t buflen)
{
	unsigned int i, indent = 4;
	char prelead[100];
	const char *pad;
	int col;

	snprintf(prelead, 100, "--> %s: ", progname);

	pad = (((strlen(prelead) + strlen(lead)) % 2) == 0) ? "" : " ";
	wrap = ((wrap % 2) == 0) ? wrap : wrap - 1;
	indent = ((indent % 2) == 0) ? indent : indent - 1;
	col = fprintf(stdout, "%s%s%s", prelead, lead, pad);
	for (i = 1; i < buflen + 1; i++) {
		fprintf(stdout, "%02x", buffer[i - 1]);
		col = col + 2;
		if (((col % wrap) == 0) && (i < buflen)) {
			fprintf(stdout, "\n%*c", indent, ' ');
			col = indent;
		}
	}
	fprintf(stdout, "\n");
}

void verbose_print(char *lead, unsigned char *buffer, size_t buflen)
{
	if (verbose)
		hex_print(lead, buffer, buflen);
}

void debug_print(char *lead, unsigned char *buffer, size_t buflen)
{
	if (debug)
		hex_print(lead, buffer, buflen);
}

/**
 * Validate hexadecimal ASCII input of a given length.
 * - len is the byte len of the resulting value, not the len of the hexascii.
 * - len = 0 means validate input of arbitrary length.
*/
int isValidHex(char *input, int len) {
	int r;
	size_t maxlen = 512; // sane limit
	regex_t regexpr;
	char pattern[48];
	char multiplier[8];
	bool result = false;

	if ((strnlen(input, maxlen) > maxlen * 2) || (len > (int) maxlen))
		die(EX_DATAERR, "input exceeded max length: %lu", maxlen);

	if (len > 0)
		sprintf(multiplier, "{%d}", len * 2); // allow this (byte) len only
	else
		sprintf(multiplier, "+"); // unlimited

	sprintf(pattern, "^(0x|0X)?[a-fA-F0-9]%s$", multiplier);

	if ((r = regcomp(&regexpr, pattern, REG_EXTENDED | REG_NOSUB)))
		die(EX_SOFTWARE, "%s", "failure to compile regex");

	if (!(r = regexec(&regexpr, input, 0, NULL, 0)))
		result = true;

	regfree(&regexpr);
	return result;
}

/**
 * Validate ASCII input up to a given length.
 * - len is the expected len of the ascii input.
 * - len = 0 means validate input of arbitrary length.
 * - NOTE: not all ascii chars are allowed here.
 */
int isValidAscii(char *input, int len) {
	int r;
	size_t maxlen = 256; // sane limit
	regex_t regexpr;
	char pattern[48];
	char multiplier[8];
	bool result = false;

	if ((strnlen(input, maxlen) > maxlen) || (len > (int) maxlen))
		die(EX_DATAERR, "input exceeded max length: %lu", maxlen);

	if (len > 0)
		sprintf(multiplier, "{,%d}", len);  // allow *up to* this len
	else
		sprintf(multiplier, "+"); // unlimited

	sprintf(pattern, "^[a-zA-Z0-9_+-]%s$", multiplier);

	if ((r = regcomp(&regexpr, pattern, REG_EXTENDED | REG_NOSUB)))
		die(EX_SOFTWARE, "%s", "failure to compile regex");

	if (!(r = regexec(&regexpr, input, 0, NULL, 0)))
		result = true;

	regfree(&regexpr);
	return result;
}
