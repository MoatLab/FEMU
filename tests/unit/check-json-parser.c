/*
 * Unit tests for JSON Parser error recovery
 *
 * Copyright 2026 Red Hat
 * Author: Paolo Bonzini <pbonzini@redhat.com>
 *
 * This work is licensed under the terms of the GNU LGPL, version 2.1 or later.
 * See the COPYING.LIB file in the top-level directory.
 */

/*
 * Missing tests:
 * - multiple JSON values in a single stream
 * - multiple invocations of json_message_parser_feed()
 *   (does not really matter much because of how
 *   json_lexer_feed() is implemented)
 * - most JSON types are only covered by check-json.c.
 */

#include "qemu/osdep.h"

#include "qapi/error.h"
#include "qobject/qbool.h"
#include "qobject/json-parser.h"

typedef struct ParseResult {
    int errors;
    QObject *result;
} ParseResult;

static void parse_emit(void *opaque, QObject *json, Error *err)
{
    ParseResult *r = opaque;

    g_assert_cmpint(!json, !=, !err);
    if (err) {
        r->errors++;
        error_free(err);
    } else {
        g_assert_null(r->result);
        r->result = json;
    }
}

static ParseResult do_parse(const char *input)
{
    ParseResult r = { 0, NULL };
    JSONMessageParser parser;

    json_message_parser_init(&parser, parse_emit, &r, NULL);
    json_message_parser_feed(&parser, input, strlen(input));
    json_message_parser_flush(&parser);
    json_message_parser_destroy(&parser);
    return r;
}

static void check_result(const char *input, int expected_errors,
                         QType expected_type)
{
    ParseResult r = do_parse(input);

    g_assert_cmpint(r.errors, ==, expected_errors);
    g_assert_nonnull(r.result);
    g_assert_cmpint(qobject_type(r.result), ==, expected_type);
    qobject_unref(r.result);
}

static void check_result_error(const char *input, int expected_errors)
{
    ParseResult r = do_parse(input);

    g_assert_cmpint(r.errors, ==, expected_errors);
    g_assert_null(r.result);
}

static void test_simple(void)
{
    check_result("false", 0, QTYPE_QBOOL);
}

static void test_whitespace(void)
{
    check_result(" false", 0, QTYPE_QBOOL);
}

static void test_extra_closing_braces(void)
{
    check_result("}}false", 2, QTYPE_QBOOL);
}

static void test_bad_dict(void)
{
    check_result("{ 'abc' }false", 1, QTYPE_QBOOL);
}

static void test_trailing_comma(void)
{
    check_result("[ 'abc', ]false", 1, QTYPE_QBOOL);
}

static void test_lexer_recovery(void)
{
    check_result("\f{}", 1, QTYPE_QDICT);
    check_result("\f[]", 1, QTYPE_QLIST);
    check_result("\f:false", 2, QTYPE_QBOOL);
    check_result("\f,false", 2, QTYPE_QBOOL);

    /*
     * Alphabetic characters do not start a new parsing.  This is
     * slightly weird but it keeps the lexer simple and works well for
     * QMP (where valid input is a sequence of dictionaries).
     */
    check_result_error("\ffalse", 1);
    check_result_error("\f'str'", 1);
    check_result_error("\f\"str\"", 1);
}

static void test_lexer_recovery_nested(void)
{
    check_result("{[{\f{}", 1, QTYPE_QDICT);
    check_result("{[{\f[]", 1, QTYPE_QLIST);
    check_result("{[{\f:false", 2, QTYPE_QBOOL);
    check_result("{[{\f,false", 2, QTYPE_QBOOL);

    /*
     * As in test_lexer_recovery, these do not produce a successful
     * parse after \f.
     */
    check_result_error("{[{\ffalse", 1);
    check_result_error("{[{\f'str'", 1);
    check_result_error("{[{\f\"str\"", 1);
}

static void test_nested(void)
{
    check_result("[{'a']}false", 1, QTYPE_QBOOL);
}

static void test_nested_multiple(void)
{
    check_result("[{'a']}[{'a']}false", 2, QTYPE_QBOOL);
}

int main(int argc, char **argv)
{
    g_test_init(&argc, &argv, NULL);

    g_test_add_func("/json-parser/simple", test_simple);
    g_test_add_func("/json-parser/whitespace", test_whitespace);
    g_test_add_func("/json-parser/error-recovery/extra-closing-braces", test_extra_closing_braces);
    g_test_add_func("/json-parser/error-recovery/bad-dict", test_bad_dict);
    g_test_add_func("/json-parser/error-recovery/trailing-comma", test_trailing_comma);
    g_test_add_func("/json-parser/error-recovery/lexer", test_lexer_recovery);
    g_test_add_func("/json-parser/error-recovery/lexer/nested", test_lexer_recovery_nested);
    g_test_add_func("/json-parser/error-recovery/nested", test_nested);
    g_test_add_func("/json-parser/error-recovery/nested/multiple", test_nested_multiple);

    return g_test_run();
}
