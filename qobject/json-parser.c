/*
 * JSON Parser
 *
 * Copyright IBM, Corp. 2009
 *
 * Authors:
 *  Anthony Liguori   <aliguori@us.ibm.com>
 *
 * This work is licensed under the terms of the GNU LGPL, version 2.1 or later.
 * See the COPYING.LIB file in the top-level directory.
 *
 */

#include "qemu/osdep.h"
#include "qemu/ctype.h"
#include "qemu/cutils.h"
#include "qemu/unicode.h"
#include "qapi/error.h"
#include "qobject/qbool.h"
#include "qobject/qdict.h"
#include "qobject/qlist.h"
#include "qobject/qnull.h"
#include "qobject/qnum.h"
#include "qobject/qstring.h"
#include "json-parser-int.h"

/*
 * The JSON parser is a push parser, returning a completed top-level
 * object, an error, or NULL (if the object is incomplete and no error
 * happened) after every token.  Therefore it has an explicit
 * representation of its parser stack; each stack entry consists of a
 * parser state and a QObject:
 * - a QList, for an array that is being added to
 * - a QDict, for a dictionary that is being added to
 * - a QString, for the key of the next pair that will be added to a QDict
 *
 * The stack represents an arbitrary nesting of arrays and dictionaries
 * (whose next key has been parsed); it can also have a dictionary whose
 * next key has not been parsed, but that can only happen at the top level.
 * Because of this, the stack contents are always of the form
 * "(QList | QDict QString)* QDict?".
 *
 * An empty stack represents the beginning of the parsing process, with
 * start state BEFORE_VALUE.
 */

typedef enum JSONParserState {
    AFTER_LCURLY,
    AFTER_LSQUARE,
    BEFORE_KEY,
    BEFORE_VALUE,
    END_OF_KEY,
    END_OF_VALUE,
} JSONParserState;

typedef struct JSONParserStackEntry {
    /*
     * State when the container is completed or, for the top of the stack,
     * entry state for the next token.
     */
    JSONParserState state;

    /*
     * A QString with the last parsed key, or a QList/QDict for the current
     * container.
     */
    QObject *partial;
} JSONParserStackEntry;

/*
 * This is the JSON grammar that's parsed, with the state transition and
 * action at each point of the grammar.  While this is not a formal
 * description, "-> action" represents the pseudocode of the action
 * and "-> STATE" sets the top stack entry's state to STATE.
 *
 * The state alone is enough to tell you what to parse; the state plus
 * the type of the top of stack tells you which action to take.
 *
 * // The initial state is BEFORE_VALUE.
 * input :=  value         -> END_OF_VALUE -> return parsed value
 *           (input | END_OF_INPUT)
 *
 * // entered on BEFORE_VALUE; after any of these rules are processed, the
 * // parser has completed a QObject and is in the END_OF_VALUE state.
 * //
 * // When the parser reaches the END_OF_VALUE state, it examines the
 * // top of the stack to see if it's coming from "input" (stack empty),
 * // "array_items" (TOS is a QList) or "dict_pairs" (TOS is a QString; the
 * // item below will be a QDict).  It then proceeds with the corresponding
 * // actions, which will be one of:
 * // - return parsed value
 * // - add value to QList
 * // - pop QString with the key, add key/value to the QDict
 * value := literal        -> END_OF_VALUE
 *        | '['            -> push empty QList -> AFTER_LSQUARE
 *           after_lsquare -> END_OF_VALUE
 *        | '{'            -> push empty QDict -> AFTER_LCURLY
 *           after_lcurly  -> END_OF_VALUE
 *
 * // non-recursive values, entered on BEFORE_VALUE
 * literal := INTEGER      -> END_OF_VALUE
 *       | FLOAT           -> END_OF_VALUE
 *       | KEYWORD         -> END_OF_VALUE
 *       | STRING          -> END_OF_VALUE
 *       | INTERP          -> END_OF_VALUE
 *
 * // entered on AFTER_LSQUARE
 * after_lsquare := ']'    -> pop completed QList -> END_OF_VALUE
 *         | ϵ             -> BEFORE_VALUE
 *           array_items   -> END_OF_VALUE
 *
 * // entered on BEFORE_VALUE, with TOS being a QList
 * array_items := value    -> add value to QList -> END_OF_VALUE
 *         (']'            -> pop completed QList -> END_OF_VALUE
 *          | ','          -> BEFORE_VALUE
 *            array_items) -> END_OF_VALUE
 *
 * // entered on AFTER_LCURLY
 * after_lcurly := '}'     -> pop completed QDict -> END_OF_VALUE
 *         | ϵ             -> BEFORE_KEY
 *           dict_pairs    -> END_OF_VALUE
 *
 * // entered on BEFORE_KEY, with TOS being a QDict
 * dict_pairs := (STRING | INTERP) -> push QString -> END_OF_KEY
 *         ':'             -> BEFORE_VALUE
 *         value           -> pop QString + add pair to QDict -> END_OF_VALUE
 *         ('}'            -> pop completed QDict -> END_OF_VALUE
 *          | ','          -> BEFORE_KEY
 *            dict_pairs)  -> END_OF_VALUE
 *
 * Parse errors ignore the token.  json_parser_reset() can be
 * called to restart parsing from scratch, with an empty stack.
 */

#define BUG_ON(cond) assert(!(cond))

static inline JSONParserStackEntry *current_entry(JSONParserContext *ctxt)
{
    return g_queue_peek_tail(ctxt->stack);
}

static void push_entry(JSONParserContext *ctxt, QObject *partial,
                       JSONParserState state)
{
    JSONParserStackEntry *entry = g_new(JSONParserStackEntry, 1);
    entry->partial = partial;
    entry->state = state;
    g_queue_push_tail(ctxt->stack, entry);
}

/* Drop the top entry and return the new top entry.  */
static JSONParserStackEntry *pop_entry(JSONParserContext *ctxt)
{
    JSONParserStackEntry *entry = g_queue_pop_tail(ctxt->stack);
    g_free(entry);
    return current_entry(ctxt);
}

/**
 * Error handler
 */
static void G_GNUC_PRINTF(3, 4) parse_error(JSONParserContext *ctxt,
                                            const JSONToken *token,
                                            const char *msg, ...)
{
    va_list ap;
    char message[1024];

    if (ctxt->err) {
        return;
    }
    va_start(ap, msg);
    vsnprintf(message, sizeof(message), msg, ap);
    va_end(ap);
    error_setg(&ctxt->err, "%d:%d: JSON parse error, %s",
               token->y, token->x, message);
}

static int cvt4hex(const char *s)
{
    int cp, i;

    cp = 0;
    for (i = 0; i < 4; i++) {
        if (!qemu_isxdigit(s[i])) {
            return -1;
        }
        cp <<= 4;
        if (s[i] >= '0' && s[i] <= '9') {
            cp |= s[i] - '0';
        } else if (s[i] >= 'a' && s[i] <= 'f') {
            cp |= 10 + s[i] - 'a';
        } else if (s[i] >= 'A' && s[i] <= 'F') {
            cp |= 10 + s[i] - 'A';
        } else {
            return -1;
        }
    }
    return cp;
}

/**
 * parse_string(): Parse a JSON string
 *
 * From RFC 8259 "The JavaScript Object Notation (JSON) Data
 * Interchange Format":
 *
 *    char = unescaped /
 *        escape (
 *            %x22 /          ; "    quotation mark  U+0022
 *            %x5C /          ; \    reverse solidus U+005C
 *            %x2F /          ; /    solidus         U+002F
 *            %x62 /          ; b    backspace       U+0008
 *            %x66 /          ; f    form feed       U+000C
 *            %x6E /          ; n    line feed       U+000A
 *            %x72 /          ; r    carriage return U+000D
 *            %x74 /          ; t    tab             U+0009
 *            %x75 4HEXDIG )  ; uXXXX                U+XXXX
 *    escape = %x5C              ; \
 *    quotation-mark = %x22      ; "
 *    unescaped = %x20-21 / %x23-5B / %x5D-10FFFF
 *
 * Extensions over RFC 8259:
 * - Extra escape sequence in strings:
 *   0x27 (apostrophe) is recognized after escape, too
 * - Single-quoted strings:
 *   Like double-quoted strings, except they're delimited by %x27
 *   (apostrophe) instead of %x22 (quotation mark), and can't contain
 *   unescaped apostrophe, but can contain unescaped quotation mark.
 *
 * Note:
 * - Encoding is modified UTF-8.
 * - Invalid Unicode characters are rejected.
 * - Control characters \x00..\x1F are rejected by the lexer.
 */
static QString *parse_string(JSONParserContext *ctxt, const JSONToken *token)
{
    const char *ptr = token->str;
    GString *str;
    char quote;
    const char *beg;
    int cp, trailing;
    char *end;
    ssize_t len;
    char utf8_buf[5];

    assert(*ptr == '"' || *ptr == '\'');
    quote = *ptr++;
    str = g_string_new(NULL);

    while (*ptr != quote) {
        assert(*ptr);
        switch (*ptr) {
        case '\\':
            beg = ptr++;
            switch (*ptr++) {
            case '"':
                g_string_append_c(str, '"');
                break;
            case '\'':
                g_string_append_c(str, '\'');
                break;
            case '\\':
                g_string_append_c(str, '\\');
                break;
            case '/':
                g_string_append_c(str, '/');
                break;
            case 'b':
                g_string_append_c(str, '\b');
                break;
            case 'f':
                g_string_append_c(str, '\f');
                break;
            case 'n':
                g_string_append_c(str, '\n');
                break;
            case 'r':
                g_string_append_c(str, '\r');
                break;
            case 't':
                g_string_append_c(str, '\t');
                break;
            case 'u':
                cp = cvt4hex(ptr);
                ptr += 4;

                /* handle surrogate pairs */
                if (cp >= 0xD800 && cp <= 0xDBFF
                    && ptr[0] == '\\' && ptr[1] == 'u') {
                    /* leading surrogate followed by \u */
                    cp = 0x10000 + ((cp & 0x3FF) << 10);
                    trailing = cvt4hex(ptr + 2);
                    if (trailing >= 0xDC00 && trailing <= 0xDFFF) {
                        /* followed by trailing surrogate */
                        cp |= trailing & 0x3FF;
                        ptr += 6;
                    } else {
                        cp = -1; /* invalid */
                    }
                }

                if (mod_utf8_encode(utf8_buf, sizeof(utf8_buf), cp) < 0) {
                    parse_error(ctxt, token,
                                "%.*s is not a valid Unicode character",
                                (int)(ptr - beg), beg);
                    goto out;
                }
                g_string_append(str, utf8_buf);
                break;
            default:
                parse_error(ctxt, token, "invalid escape sequence in string");
                goto out;
            }
            break;
        case '%':
            if (ctxt->ap) {
                if (ptr[1] != '%') {
                    parse_error(ctxt, token, "can't interpolate into string");
                    goto out;
                }
                ptr++;
            }
            /* fall through */
        default:
            cp = mod_utf8_codepoint(ptr, 6, &end);
            if (cp < 0) {
                parse_error(ctxt, token, "invalid UTF-8 sequence in string");
                goto out;
            }
            ptr = end;
            len = mod_utf8_encode(utf8_buf, sizeof(utf8_buf), cp);
            assert(len >= 0);
            g_string_append(str, utf8_buf);
        }
    }

    return qstring_from_gstring(str);

out:
    g_string_free(str, true);
    return NULL;
}

/* Terminals  */

static QObject *parse_keyword(JSONParserContext *ctxt, const JSONToken *token)
{
    assert(token && token->type == JSON_KEYWORD);

    if (!strcmp(token->str, "true")) {
        return QOBJECT(qbool_from_bool(true));
    } else if (!strcmp(token->str, "false")) {
        return QOBJECT(qbool_from_bool(false));
    } else if (!strcmp(token->str, "null")) {
        return QOBJECT(qnull());
    }
    parse_error(ctxt, token, "invalid keyword '%s'", token->str);
    return NULL;
}

static QObject *parse_interpolation(JSONParserContext *ctxt,
                                    const JSONToken *token)
{
    assert(token && token->type == JSON_INTERP);

    if (!strcmp(token->str, "%p")) {
        return va_arg(*ctxt->ap, QObject *);
    } else if (!strcmp(token->str, "%i")) {
        return QOBJECT(qbool_from_bool(va_arg(*ctxt->ap, int)));
    } else if (!strcmp(token->str, "%d")) {
        return QOBJECT(qnum_from_int(va_arg(*ctxt->ap, int)));
    } else if (!strcmp(token->str, "%ld")) {
        return QOBJECT(qnum_from_int(va_arg(*ctxt->ap, long)));
    } else if (!strcmp(token->str, "%lld")) {
        return QOBJECT(qnum_from_int(va_arg(*ctxt->ap, long long)));
    } else if (!strcmp(token->str, "%" PRId64)) {
        return QOBJECT(qnum_from_int(va_arg(*ctxt->ap, int64_t)));
    } else if (!strcmp(token->str, "%u")) {
        return QOBJECT(qnum_from_uint(va_arg(*ctxt->ap, unsigned int)));
    } else if (!strcmp(token->str, "%lu")) {
        return QOBJECT(qnum_from_uint(va_arg(*ctxt->ap, unsigned long)));
    } else if (!strcmp(token->str, "%llu")) {
        return QOBJECT(qnum_from_uint(va_arg(*ctxt->ap, unsigned long long)));
    } else if (!strcmp(token->str, "%" PRIu64)) {
        return QOBJECT(qnum_from_uint(va_arg(*ctxt->ap, uint64_t)));
    } else if (!strcmp(token->str, "%s")) {
        return QOBJECT(qstring_from_str(va_arg(*ctxt->ap, const char *)));
    } else if (!strcmp(token->str, "%f")) {
        return QOBJECT(qnum_from_double(va_arg(*ctxt->ap, double)));
    }
    parse_error(ctxt, token, "invalid interpolation '%s'", token->str);
    return NULL;
}

static QObject *parse_literal(JSONParserContext *ctxt, const JSONToken *token)
{
    assert(token);

    switch (token->type) {
    case JSON_STRING:
        return QOBJECT(parse_string(ctxt, token));
    case JSON_INTEGER: {
        /*
         * Represent JSON_INTEGER as QNUM_I64 if possible, else as
         * QNUM_U64, else as QNUM_DOUBLE.  Note that qemu_strtoi64()
         * and qemu_strtou64() fail with ERANGE when it's not
         * possible.
         *
         * qnum_get_int() will then work for any signed 64-bit
         * JSON_INTEGER, qnum_get_uint() for any unsigned 64-bit
         * integer, and qnum_get_double() both for any JSON_INTEGER
         * and any JSON_FLOAT (with precision loss for integers beyond
         * 53 bits)
         */
        int ret;
        int64_t value;
        uint64_t uvalue;

        ret = qemu_strtoi64(token->str, NULL, 10, &value);
        if (!ret) {
            return QOBJECT(qnum_from_int(value));
        }
        assert(ret == -ERANGE);

        if (token->str[0] != '-') {
            ret = qemu_strtou64(token->str, NULL, 10, &uvalue);
            if (!ret) {
                return QOBJECT(qnum_from_uint(uvalue));
            }
            assert(ret == -ERANGE);
        }
    }
    /* fall through to JSON_FLOAT */
    case JSON_FLOAT:
        /* FIXME dependent on locale; a pervasive issue in QEMU */
        /* FIXME our lexer matches RFC 8259 in forbidding Inf or NaN,
         * but those might be useful extensions beyond JSON */
        return QOBJECT(qnum_from_double(strtod(token->str, NULL)));
    default:
        abort();
    }
}

/* Parsing state machine  */

static QObject *parse_begin_value(JSONParserContext *ctxt,
                                  const JSONToken *token)
{
    switch (token->type) {
    case JSON_LCURLY:
        push_entry(ctxt, QOBJECT(qdict_new()), AFTER_LCURLY);
        return NULL;
    case JSON_LSQUARE:
        push_entry(ctxt, QOBJECT(qlist_new()), AFTER_LSQUARE);
        return NULL;
    case JSON_INTERP:
        return parse_interpolation(ctxt, token);
    case JSON_INTEGER:
    case JSON_FLOAT:
    case JSON_STRING:
        return parse_literal(ctxt, token);
    case JSON_KEYWORD:
        return parse_keyword(ctxt, token);
    default:
        parse_error(ctxt, token, "expecting value");
        return NULL;
    }
}

static QObject *parse_token(JSONParserContext *ctxt, const JSONToken *token)
{
    JSONParserStackEntry *entry;
    JSONParserState state;
    QString *key;
    QObject *key_obj = NULL, *value = NULL;

    entry = current_entry(ctxt);
    state = entry ? entry->state : BEFORE_VALUE;
    switch (state) {
    case AFTER_LCURLY:
        /* Grab '}' for empty object or fall through to BEFORE_KEY */
        assert(qobject_type(entry->partial) == QTYPE_QDICT);
        if (token->type == JSON_RCURLY) {
            value = entry->partial;
            entry = pop_entry(ctxt);
            break;
        }
        entry->state = BEFORE_KEY;
        /* fall through */

    case BEFORE_KEY:
        /* Expecting object key */
        assert(qobject_type(entry->partial) == QTYPE_QDICT);
        if (token->type != JSON_STRING && token->type != JSON_INTERP) {
            parse_error(ctxt, token, "expecting key");
            return NULL;
        }

        key_obj = parse_begin_value(ctxt, token);
        if (!key_obj) {
            /* Parse error already reported */
        } else if (qobject_type(key_obj) != QTYPE_QSTRING) {
            /* An interpolation was valid syntactically but not %s */
            parse_error(ctxt, token, "key is not a string in object");
        } else {
            /* Store key in a special entry on the stack */
            push_entry(ctxt, key_obj, END_OF_KEY);
        }
        return NULL;

    case END_OF_KEY:
        /* Expecting ':' after key */
        assert(qobject_type(entry->partial) == QTYPE_QSTRING);
        if (token->type == JSON_COLON) {
            entry->state = BEFORE_VALUE;
        } else {
            parse_error(ctxt, token, "expecting ':'");
        }
        return NULL;

    case AFTER_LSQUARE:
        /* Grab ']' for empty array or fall through to BEFORE_VALUE */
        assert(qobject_type(entry->partial) == QTYPE_QLIST);
        if (token->type == JSON_RSQUARE) {
            value = entry->partial;
            entry = pop_entry(ctxt);
            break;
        }
        entry->state = BEFORE_VALUE;
        /* fall through */

    case BEFORE_VALUE:
        /* Expecting value */
        assert(!entry || qobject_type(entry->partial) != QTYPE_QDICT);
        value = parse_begin_value(ctxt, token);
        if (!value) {
            /* Error or '['/'{' */
            return NULL;
        }
        /* Return value or insert it into a container */
        break;

    case END_OF_VALUE:
        /* Grab ',' or ']' for array; ',' or '}' for object */
        if (qobject_to(QList, entry->partial)) {
            /* Array */
            if (token->type != JSON_RSQUARE) {
                if (token->type == JSON_COMMA) {
                    entry->state = BEFORE_VALUE;
                } else {
                    parse_error(ctxt, token, "expected ',' or ']'");
                }
                return NULL;
            }
        } else if (qobject_to(QDict, entry->partial)) {
            /* Object */
            if (token->type != JSON_RCURLY) {
                if (token->type == JSON_COMMA) {
                    entry->state = BEFORE_KEY;
                } else {
                    parse_error(ctxt, token, "expected ',' or '}'");
                }
                return NULL;
            }
        } else {
            g_assert_not_reached();
        }

        /* Got ']' or '}'; return full value or insert into parent container */
        value = entry->partial;
        entry = pop_entry(ctxt);
        break;
    }

    assert(value);
    if (entry == NULL) {
        /* Parse stack now empty, the top-level value is complete.  */
        return value;
    }

    /*
     * Parse stack is not empty and entry->partial is the top of stack.
     * It's a QString with the key (and a QDict is below it) if we're
     * parsing an object, or a QList if we're parsing an array.
     */
    key = qobject_to(QString, entry->partial);
    if (key) {
        const char *key_str;
        QDict *dict;

        /* Pop off key, and store (key, value) in QDict.  */
        entry = pop_entry(ctxt);
        dict = qobject_to(QDict, entry->partial);
        assert(dict);
        key_str = qstring_get_str(key);
        if (qdict_haskey(dict, key_str)) {
            parse_error(ctxt, token, "duplicate key");
            qobject_unref(value);
            return NULL;
        }
        qdict_put_obj(dict, key_str, value);
        qobject_unref(key);
    } else {
        /* Array, just store value in the QList.  */
        qlist_append_obj(qobject_to(QList, entry->partial), value);
    }

    entry->state = END_OF_VALUE;
    return NULL;
}


void json_parser_reset(JSONParserContext *ctxt)
{
    JSONParserStackEntry *entry;

    ctxt->err = NULL;
    while ((entry = g_queue_pop_tail(ctxt->stack)) != NULL) {
        qobject_unref(entry->partial);
        g_free(entry);
    }
}

void json_parser_init(JSONParserContext *ctxt, va_list *ap)
{
    ctxt->stack = g_queue_new();
    ctxt->ap = ap;
    json_parser_reset(ctxt);
}

void json_parser_destroy(JSONParserContext *ctxt)
{
    json_parser_reset(ctxt);
    g_queue_free(ctxt->stack);
    ctxt->stack = NULL;
}

/*
 * Advance the parser based on the token that is passed.
 * Return the finished top-level value if the token completes it, else
 * NULL.
 * Once an error is returned, the function must not be called again
 * without first resetting the parser.
 */
QObject *json_parser_feed(JSONParserContext *ctxt, const JSONToken *token,
                          Error **errp)
{
    QObject *result = NULL;

    assert(!ctxt->err);
    switch (token->type) {
    case JSON_ERROR:
        parse_error(ctxt, token, "stray '%s'", token->str);
        break;

    case JSON_END_OF_INPUT:
        /* Check for premature end of input */
        if (!g_queue_is_empty(ctxt->stack)) {
            parse_error(ctxt, token, "premature end of input");
        }
        break;

    default:
        result = parse_token(ctxt, token);
        break;
    }

    error_propagate(errp, ctxt->err);
    return result;
}
