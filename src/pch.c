/* Copyright (c) Microsoft Corporation.
   Licensed under the MIT License. */

#include "pch.h"

int LOG_LEVEL = 1;
// When you are using pre-compiled headers, this source file is necessary for compilation to succeed.
void WriteLog(
    int level,
    int line,
    const char *file,
    const char *function,
    const char *format,
    ...)
{
    if (level > LOG_LEVEL)
    {
        return;
    }

    va_list arglist;
    va_start(arglist, format);
    const char *shortFilename = file;
    for (int i = 0; i <= 1; i++)
    {
        const char *p = strrchr(file, i == 0 ? '/' : '\\');
        if (p != NULL)
        {
            p++;
            if (*p != '\0' && p > shortFilename)
            {
                shortFilename = p;
            }
        }
    }
    fprintf(stderr, "[%c] %s %s(%d) ",
           level == LogLevel_Error ? 'e' : level == LogLevel_Info ? 'i'
                                                                  : 'd',
           function,
           shortFilename,
           line);
    vfprintf(stderr, format, arglist);
    va_end(arglist);
    fprintf(stderr, "\n");
}
