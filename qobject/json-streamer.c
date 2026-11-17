/*
 * JSON parser - callback interface and error recovery
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
#include "qapi/error.h"
#include "json-parser-int.h"

#define MAX_TOKEN_SIZE (64ULL << 20)
#define MAX_TOKEN_COUNT (2ULL << 20)
#define MAX_NESTING (1 << 10)

void json_message_process_token(JSONLexer *lexer, GString *input,
                                JSONTokenType type, int x, int y)
{
    JSONMessageParser *parser = container_of(lexer, JSONMessageParser, lexer);
    Error *err = NULL;

    parser->token_size += input->len;
    parser->token_count++;

    /* Detect message boundaries for error recovery purposes.  */
    switch (type) {
    case JSON_LCURLY:
        parser->brace_count++;
        break;
    case JSON_RCURLY:
        if (!parser->brace_count) {
            goto end_error_recovery;
        }
        parser->brace_count--;
        break;
    case JSON_LSQUARE:
        parser->bracket_count++;
        break;
    case JSON_RSQUARE:
        if (!parser->bracket_count) {
            goto end_error_recovery;
        }
        parser->bracket_count--;
        break;
    case JSON_ERROR:
    end_error_recovery:
        /*
         * We come here due to receiving either JSON_ERROR or a
         * JSON_R{CURLY,SQUARE}) that is known to be unbalanced.
         * If in error recovery, end it immediately.  If not in
         * error recovery, json_parser_feed() will raise an error
         * but error recovery won't be entered at all.
         */
        parser->brace_count = 0;
        parser->bracket_count = 0;
        break;
    default:
        break;
    }

    if (parser->error) {
        /* error recovery, eat tokens until parentheses balance */
    } else {
        /*
         * Safety consideration, we limit total memory allocated per object
         * and the maximum nesting depth that a message can force.
         */
        if (parser->token_size >= MAX_TOKEN_SIZE) {
            error_setg(&err, "JSON token size limit exceeded");
        } else if (parser->token_count > MAX_TOKEN_COUNT) {
            error_setg(&err, "JSON token count limit exceeded");
        } else if (parser->bracket_count + parser->brace_count > MAX_NESTING) {
            error_setg(&err, "JSON nesting depth limit exceeded");
        } else {
            JSONToken token = (JSONToken) {
                .type = type,
                .x = x,
                .y = y,
                .str = input->str
            };
            QObject *json = json_parser_feed(&parser->parser, &token, &err);
            if (json) {
                parser->emit(parser->opaque, json, NULL);
            }
        }

        if (err) {
            parser->emit(parser->opaque, NULL, err);
            /* start recovery */
            parser->error = true;
        }
    }

    if ((parser->brace_count == 0 && parser->bracket_count == 0)
        || type == JSON_END_OF_INPUT) {
        json_parser_reset(&parser->parser);
        parser->error = false;
        parser->brace_count = 0;
        parser->bracket_count = 0;
        parser->token_count = 0;
        parser->token_size = 0;
    }
}

void json_message_parser_init(JSONMessageParser *parser,
                              void (*emit)(void *opaque, QObject *json,
                                           Error *err),
                              void *opaque, va_list *ap)
{
    parser->emit = emit;
    parser->opaque = opaque;
    parser->error = false;
    parser->brace_count = 0;
    parser->bracket_count = 0;
    parser->token_count = 0;
    parser->token_size = 0;

    json_parser_init(&parser->parser, ap);
    json_lexer_init(&parser->lexer, !!ap);
}

void json_message_parser_feed(JSONMessageParser *parser,
                             const char *buffer, size_t size)
{
    json_lexer_feed(&parser->lexer, buffer, size);
}

void json_message_parser_flush(JSONMessageParser *parser)
{
    json_lexer_flush(&parser->lexer);
}

void json_message_parser_destroy(JSONMessageParser *parser)
{
    json_lexer_destroy(&parser->lexer);
    json_parser_destroy(&parser->parser);
}
