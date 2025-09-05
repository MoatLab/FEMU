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

#ifndef __AST27X0_INCLUDE_UART_CONSOLE_H__
#define __AST27X0_INCLUDE_UART_CONSOLE_H__

struct uart_console {
    void (*uputc)(unsigned char c);
};

int uart_console_register(struct uart_console *ucons);
int uprintf(const char *fmt, ...);

#endif /* __AST27X0_INCLUDE_UART_CONSOLE_H__ */
