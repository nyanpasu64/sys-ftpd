// This file is under the terms of the unlicense (https://github.com/DavidBuchanan314/ftpd/blob/master/LICENSE)

#define ENABLE_LOGGING 1
#include "console.h"
#include <arpa/inet.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* this is a lot easier when you have a real console */

int should_log = 0;

void console_init(void)
{
    stdout = stderr = NULL;
}

static const char INDENT_BUF[] = "                                                                ";
static const size_t MAX_INDENT = sizeof(INDENT_BUF) - 1;
static const char* const INDENT_END = INDENT_BUF + MAX_INDENT;

void _indent_print(size_t indent, const char* fmt, va_list ap)
{
    if (!should_log)
        return;
    if (!stdout)
        stdout = stderr = fopen("/config/sys-ftpd/logs/ftpd.log", "a");

    if (indent > MAX_INDENT)
        indent = MAX_INDENT;
    fputs(INDENT_END - indent, stdout);
    vprintf(fmt, ap);
}

void console_print(const char* fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    _indent_print(4, fmt, ap);
    va_end(ap);
}

void indent_print(size_t indent, const char* fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    _indent_print(indent, fmt, ap);
    va_end(ap);
}

void debug_print(const char* fmt, ...)
{
    if (!should_log)
        return;

#ifdef ENABLE_LOGGING
    if (!stderr)
        stdout = stderr = fopen("/config/sys-ftpd/logs/ftpd.log", "a");

    va_list ap;
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
#endif
}

void console_flush(void)
{
    if (!should_log)
        return;
    fclose(stdout);
    stdout = stderr = NULL;
}
