/*
 * Copyright (C) 2025 ASPEED Technology Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <stdint.h>
#include <stdarg.h>
#include <uart_console.h>

static struct uart_console sys_ucons;

static void uputc(char c)
{
    if (!sys_ucons.uputc) {
        return;
    }

    if (c == '\n') {
        sys_ucons.uputc('\r');
    }

    sys_ucons.uputc(c);
}

static void uputs(const char *s)
{
    for (int i = 0; s[i]; i++) {
        uputc(s[i]);
    }
}

static void uputx(uint64_t val, int width)
{
    char hex[17];
    const char *digits = "0123456789abcdef";
    int pos = 16;

    hex[pos] = '\0';
    if (val == 0 && width == 0) {
        uputc('0');
        return;
    }

    while (val && pos > 0) {
        hex[--pos] = digits[val & 0xF];
        val >>= 4;
    }

    while (16 - pos < width && pos > 0) {
        hex[--pos] = '0';
    }

    uputs(&hex[pos]);
}

static void uputd(int64_t val)
{
    /* Enough for "-9223372036854775808" */
    char buf[21];
    int i = 0;
    uint64_t uval;

    if (val < 0) {
        uputc('-');
        uval = (uint64_t)(-val);
    } else {
        uval = (uint64_t)val;
    }

    do {
        buf[i++] = '0' + (uval % 10);
        uval /= 10;
    } while (uval > 0);

    while (i-- > 0) {
        uputc(buf[i]);
    }
}

int uprintf(const char *fmt, ...)
{
    va_list va;
    int count = 0;

    va_start(va, fmt);

    while (*fmt) {
        if (*fmt == '%') {
            /* Move past '%' */
            fmt++;

            /* Handle padding like %016lx */
            int width = 0;

            if (*fmt == '0') {
                fmt++;
                while (*fmt >= '0' && *fmt <= '9') {
                    width = width * 10 + (*fmt - '0');
                    fmt++;
                }
            }

            /* Detect length modifier */
            int is_long = 0;
            int is_longlong = 0;

            if (*fmt == 'l') {
                fmt++;
                if (*fmt == 'l') {
                    is_longlong = 1;
                    fmt++;
                } else {
                    is_long = 1;
                }
            }

            if (*fmt == '\0') {
                break;
            }

            switch (*fmt) {
            case 's': {
                const char *str = va_arg(va, const char *);
                while (*str) {
                    uputc(*str++);
                    count++;
                }
                break;
            }
            case 'x': {
                uint64_t val;
                if (is_longlong) {
                    val = va_arg(va, unsigned long long);
                } else if (is_long) {
                    val = va_arg(va, unsigned long);
                } else {
                    val = va_arg(va, unsigned int);
                }
                /* Assume uputx handles zero-padding */
                uputx(val, width);
                break;
            }
            case 'd': {
                int val = va_arg(va, int);
                /* Print signed decimal */
                uputd(val);
                break;
            }
            case '%': {
                uputc('%');
                count++;
                break;
            }
            default:
                uputc('%');
                uputc(*fmt);
                count += 2;
                break;
            }
        } else {
            uputc(*fmt);
            count++;
        }

        fmt++;
    }

    va_end(va);
    return count;
}

int uart_console_register(struct uart_console *ucons)
{
    if (!ucons || sys_ucons.uputc) {
        return 1;
    }

    sys_ucons.uputc = ucons->uputc;

    return 0;
}

