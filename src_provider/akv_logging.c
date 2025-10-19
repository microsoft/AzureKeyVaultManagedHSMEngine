/* Copyright (c) Microsoft Corporation.
   Licensed under the MIT License. */

#include "akv_provider_shared.h"

int LOG_LEVEL = LogLevel_Info;
static FILE *log_file = NULL;

void WriteLog(
    int level,
    int line,
    const char *file,
    const char *function,
    const char *format,
    ...)
{
    char message[1024];
    char formatted[1280];
    size_t formatted_len = 0;
    FILE *stderr_target = stderr;

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

    vsnprintf(message, sizeof(message), format, arglist);
    va_end(arglist);

    snprintf(formatted,
             sizeof(formatted),
             "[%c] %s %s(%d) %s\n",
             levelChar,
             function,
             shortFilename,
             line,
             message);

    formatted[sizeof(formatted) - 1] = '\0';
    formatted_len = strlen(formatted);

    fwrite(formatted, 1, formatted_len, stderr_target);
    fflush(stderr_target);

    if (log_file != NULL)
    {
        fwrite(formatted, 1, formatted_len, log_file);
        fflush(log_file);
    }
}

void akv_provider_set_log_level(int level)
{
    LOG_LEVEL = level;
}

int akv_provider_set_log_file(const char *path)
{
    if (log_file != NULL)
    {
        fclose(log_file);
        log_file = NULL;
    }

    if (path == NULL || *path == '\0')
    {
        return 1;
    }

    {
        FILE *handle = NULL;
        if (fopen_s(&handle, path, "a") != 0 || handle == NULL)
        {
            fprintf(stderr, "[!] akv_provider_set_log_file failed to open %s\n", path);
            return 0;
        }
        log_file = handle;
    }

    setvbuf(log_file, NULL, _IONBF, 0);
    return 1;
}

void akv_provider_close_log_file(void)
{
    if (log_file != NULL)
    {
        fclose(log_file);
        log_file = NULL;
    }
}
