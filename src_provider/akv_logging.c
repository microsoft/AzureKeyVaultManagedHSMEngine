/* Copyright (c) Microsoft Corporation.
   Licensed under the MIT License. */

#include "akv_provider_shared.h"

int LOG_LEVEL = LogLevel_Info;

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

    char levelChar = '?';
    switch (level)
    {
    case LogLevel_Error:
        levelChar = 'e';
        break;
    case LogLevel_Info:
        levelChar = 'i';
        break;
    case LogLevel_Debug:
        levelChar = 'd';
        break;
    case LogLevel_Trace:
        levelChar = 't';
        break;
    default:
        levelChar = '?';
        break;
    }

    fprintf(stderr, "[%c] %s %s(%d) ",
            levelChar,
            function,
            shortFilename,
            line);
    vfprintf(stderr, format, arglist);
    va_end(arglist);
    fprintf(stderr, "\n");
}

void akv_provider_set_log_level(int level)
{
    LOG_LEVEL = level;
}
