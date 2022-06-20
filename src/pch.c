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
    // if (level > LOG_LEVEL)
    // {
    //     return;
    // }

    FILE *filepntr = 0;
    //fopen("/var/log/nginx/akv_error.log", "aw+");

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
    time_t t;
    struct tm * timeinfo;
    time(&t);
    timeinfo = localtime(&t);
    if (filepntr != 0){
        fprintf(filepntr, "[%c] [%d:%d:%d] %s %s(%d) ",
            level == LogLevel_Error ? 'e' : level == LogLevel_Info ? 'i'
                                                                    : 'd',
            timeinfo->tm_hour,
            timeinfo->tm_min,
            timeinfo->tm_sec,
            function,
            shortFilename,
            line);
        vfprintf(filepntr, format, arglist);
        vfprintf(filepntr, "\n", arglist);
        fclose(filepntr);
    }
    // va_end(arglist);
}
