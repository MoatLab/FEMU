/*
 * Unit test of the NAND profile file parser (hw/femu/nand/nand-profile.c):
 * the base keys, and the optional source line of each value.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "qemu/osdep.h"
#include "hw/femu/nand/nand-profile.h"

/* a valid file; @extra goes after the header, @tail at the end */
static char *np_file(const char *extra, const char *tail)
{
    return g_strdup_printf("femu_nand_profile = 1\n"
                           "%s"
                           "name = t\n"
                           "nand_type = tlc\n"
                           "read_ns = 40000\n"
                           "program_ns = 200000\n"
                           "erase_ns = 2000000\n"
                           "cmd_addr_ns = 0\n"
                           "xfer_ns = 0\n"
                           "status_ns = 0\n"
                           "%s", extra, tail);
}

/* parse @buf; on failure return the message, on success NULL */
static char *np_parse(const char *buf, NandProfile *p)
{
    g_autofree char *copy = g_strdup(buf);
    char *err = NULL;

    if (nand_profile_parse("t.nprof", copy, p, &err)) {
        g_assert_null(err);
        return NULL;
    }
    g_assert_nonnull(err);
    return err;
}

/* @buf must fail with a message that holds @want */
static void np_refused(const char *buf, const char *want)
{
    NandProfile p;
    g_autofree char *err = np_parse(buf, &p);

    g_assert_nonnull(err);
    if (!strstr(err, want)) {
        g_test_message("got: %s", err);
    }
    g_assert_nonnull(strstr(err, want));
}

static void test_old_file(void)
{
    g_autofree char *f = np_file("", "");
    NandProfile p;

    g_assert_null(np_parse(f, &p));
    g_assert_cmpint(p.read_ns, ==, 40000);
    for (int i = 0; i < NAND_PROFILE_VALUES; i++) {
        g_assert_cmpint(p.val[i].line, ==, i + 3);
        g_assert_cmpint(p.val[i].source_line, ==, 0);
        g_assert_cmpstr(p.val[i].source, ==, "");
    }
}

/* a source before and after its value; ';', '#' and '=' are text */
static void test_source_lines(void)
{
    g_autofree char *f = np_file("source.read_ns = Table 12; p. 34 #a=b\n",
                                 "  source.status_ns\t=\t#123\tx \r\n");
    NandProfile p;

    g_assert_null(np_parse(f, &p));
    g_assert_cmpstr(p.val[1].source, ==, "Table 12; p. 34 #a=b");
    g_assert_cmpint(p.val[1].source_line, ==, 2);
    g_assert_cmpint(p.val[1].line, ==, 5);
    g_assert_cmpstr(p.val[6].source, ==, "#123\tx");
    g_assert_cmpint(p.val[6].source_line, ==, 11);
    g_assert_cmpint(p.val[0].source_line, ==, 0);
}

/* 255 bytes fit; 256 do not; a 2-byte character counts as 2 */
static void test_source_length(void)
{
    g_autofree char *t255 = g_strnfill(255, 'x');
    g_autofree char *t256 = g_strnfill(256, 'x');
    g_autofree char *x253 = g_strnfill(253, 'x');
    g_autofree char *x254 = g_strnfill(254, 'x');
    g_autofree char *u255 = g_strconcat(x253, "\xc3\xa9", NULL);
    g_autofree char *u256 = g_strconcat(x254, "\xc3\xa9", NULL);
    g_autofree char *l1 = g_strdup_printf("source.read_ns = %s\n", t255);
    g_autofree char *l2 = g_strdup_printf("source.read_ns = %s\n", t256);
    g_autofree char *l3 = g_strdup_printf("source.read_ns = %s\n", u255);
    g_autofree char *l4 = g_strdup_printf("source.read_ns = %s\n", u256);
    g_autofree char *f1 = np_file(l1, "");
    g_autofree char *f2 = np_file(l2, "");
    g_autofree char *f3 = np_file(l3, "");
    g_autofree char *f4 = np_file(l4, "");
    NandProfile p;

    g_assert_null(np_parse(f1, &p));
    g_assert_cmpuint(strlen(p.val[1].source), ==, 255);
    np_refused(f2, "1 to 255 bytes");
    g_assert_null(np_parse(f3, &p));
    g_assert_cmpstr(p.val[1].source, ==, u255);
    np_refused(f4, "1 to 255 bytes");
}

static void test_source_refused(void)
{
    const char *cases[][2] = {
        { "source.read_ns =\n", "1 to 255 bytes" },
        { "source.read_ns =   " "\n", "1 to 255 bytes" },
        { "source.read_ns = a\nsource.read_ns = a\n", "given twice" },
        { "source.name = x\n", "not a value key" },
        { "source.femu_nand_profile = x\n", "not a value key" },
        { "source. = x\n", "not a value key" },
        { "source.READ_NS = x\n", "not a value key" },
        { "source.foo = x\n", "not a value key" },
        { "source.read_ns x\n", "expected source.KEY = TEXT" },
        { "source.read_ns = \xff\xfe\n", "not UTF-8" },
        { "source.read_ns = a\x01" "b\n", "control byte" },
        { "source.read_ns = a\x7f" "b\n", "control byte" },
        { "source.read_ns = a\rb\n", "control byte" },
        { "source. read_ns = x\n", "not a value key" },
        { "source.\tread_ns = x\n", "not a value key" },
    };

    for (int i = 0; i < ARRAY_SIZE(cases); i++) {
        g_autofree char *f = np_file(cases[i][0], "");

        np_refused(f, cases[i][1]);
    }
    /* the error names the file and the line */
    {
        g_autofree char *f = np_file("source.foo = x\n", "");
        NandProfile p;
        g_autofree char *err = np_parse(f, &p);

        g_assert_nonnull(strstr(err, "t.nprof:2:"));
        g_assert_nonnull(strstr(err, "'foo'"));
    }
    {
        g_autofree char *f = np_file("source.read_ns x\n", "");
        NandProfile p;
        g_autofree char *err = np_parse(f, &p);

        g_assert_nonnull(strstr(err, "t.nprof:2:"));
        g_assert_nonnull(strstr(err, "'source.read_ns x'"));
    }
}

/* the header comes first, also before a source line */
static void test_header_rules(void)
{
    g_autofree char *body = np_file("", "");
    g_autofree char *src_first = g_strconcat("source.read_ns = x\n", body,
                                             NULL);
    g_autofree char *bom = g_strconcat("\xef\xbb\xbf", body, NULL);

    np_refused(src_first, "the first key must be femu_nand_profile, not "
               "'source.read_ns'");
    np_refused(bom, "unknown key");
    {
        g_autofree char *f = g_strconcat("femu_nand_profile = 01\n",
                                         body + strlen("femu_nand_profile = "
                                                       "1\n"), NULL);
        np_refused(f, "version '01' is not supported");
    }
}

/* each value in canonical form, whatever its spelling in the file */
static void test_value_text(void)
{
    g_autofree char *f = g_strdup("femu_nand_profile = 1\n"
                                  "name = t\n"
                                  "status_ns = 0\n"
                                  "read_ns = 0040000\n"
                                  "nand_type = qlc\n"
                                  "program_ns = 200000 ; a comment\n"
                                  "erase_ns = 2000000\n"
                                  "cmd_addr_ns = 00\n"
                                  "xfer_ns = 7\n");
    const char *want[NAND_PROFILE_VALUES] = {
        "qlc", "40000", "200000", "2000000", "0", "7", "0",
    };
    const char *keys[NAND_PROFILE_VALUES] = {
        "nand_type", "read_ns", "program_ns", "erase_ns", "cmd_addr_ns",
        "xfer_ns", "status_ns",
    };
    NandProfile p;

    g_assert_null(np_parse(f, &p));
    for (int i = 0; i < NAND_PROFILE_VALUES; i++) {
        g_autofree char *v = nand_profile_value_text(&p, i);

        g_assert_cmpstr(nand_profile_value_key(i), ==, keys[i]);
        g_assert_cmpstr(v, ==, want[i]);
    }
    g_assert_cmpint(p.val[6].line, ==, 3);
    g_assert_cmpint(p.val[1].line, ==, 4);
}

/* @key = @val in a valid file: true when the parser takes it */
static bool np_takes(const char *key, const char *val)
{
    g_autofree char *f = np_file("", "");
    g_autofree char *want = g_strdup_printf("\n%s = ", key);
    char *at = strstr(f, want);
    char *eol = strchr(at + 1, '\n');
    g_autofree char *nf = NULL;
    NandProfile p;
    g_autofree char *err = NULL;

    *at = '\0';
    nf = g_strdup_printf("%s\n%s = %s%s", f, key, val, eol);
    err = np_parse(nf, &p);
    return !err;
}

/* each time key: array times from 1 ns, bus phases from 0 ns */
static void test_each_bound(void)
{
    static const char *const keys[] = {
        "read_ns", "program_ns", "erase_ns", "cmd_addr_ns", "xfer_ns",
        "status_ns",
    };

    for (int i = 0; i < ARRAY_SIZE(keys); i++) {
        g_assert_cmpint(np_takes(keys[i], "0"), ==, i >= 3);
        g_assert_true(np_takes(keys[i], "1"));
        g_assert_true(np_takes(keys[i], "2147483647"));
        g_assert_false(np_takes(keys[i], "2147483648"));
        g_assert_false(np_takes(keys[i], "-1"));
    }
}

/* the number bounds of the base keys */
static void test_value_bounds(void)
{
    const char *cases[][2] = {
        { "read_ns = 0", "read_ns must be a whole number" },
        { "read_ns = 2147483648", "read_ns must be a whole number" },
        { "read_ns = -1", "read_ns must be a whole number" },
        { "read_ns = 1x", "read_ns must be a whole number" },
        { "xfer_ns = 2147483648", "xfer_ns must be a whole number" },
    };

    for (int i = 0; i < ARRAY_SIZE(cases); i++) {
        g_autofree char *f = np_file("", "");
        const char *key = cases[i][0];
        size_t klen = strcspn(key, " ");
        g_autofree char *k = g_strndup(key, klen);
        char *at = strstr(f, k);
        char *eol = strchr(at, '\n');
        g_autofree char *nf = NULL;

        *at = '\0';
        nf = g_strconcat(f, key, eol, NULL);
        np_refused(nf, cases[i][1]);
    }
    {
        g_autofree char *f = np_file("", "");
        NandProfile p;
        char *at = strstr(f, "xfer_ns = 0");
        g_autofree char *nf = NULL;

        *at = '\0';
        nf = g_strconcat(f, "xfer_ns = 2147483647\nstatus_ns = 0\n", NULL);
        g_assert_null(np_parse(nf, &p));
        g_assert_cmpint(p.xfer_ns, ==, INT32_MAX);
    }
}

int main(int argc, char **argv)
{
    g_test_init(&argc, &argv, NULL);
    g_test_add_func("/femu/nand-profile/old-file", test_old_file);
    g_test_add_func("/femu/nand-profile/source-lines", test_source_lines);
    g_test_add_func("/femu/nand-profile/source-length", test_source_length);
    g_test_add_func("/femu/nand-profile/source-refused", test_source_refused);
    g_test_add_func("/femu/nand-profile/header", test_header_rules);
    g_test_add_func("/femu/nand-profile/value-text", test_value_text);
    g_test_add_func("/femu/nand-profile/value-bounds", test_value_bounds);
    g_test_add_func("/femu/nand-profile/each-bound", test_each_bound);
    return g_test_run();
}
