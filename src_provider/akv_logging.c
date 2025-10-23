/* Copyright (c) Microsoft Corporation.
   Licensed under the MIT License. */

#include "akv_provider_shared.h"
#include <time.h>

int LOG_LEVEL = LogLevel_Info;
static FILE *log_file = NULL;

static void GetTimestamp(char *buffer, size_t buffer_len)
{
    if (buffer == NULL || buffer_len == 0)
    {
        return;
    }

    buffer[0] = '\0';

    time_t now = time(NULL);
    if (now == (time_t)-1)
    {
        return;
    }

    struct tm tm_now;
#if defined(_WIN32)
    if (localtime_s(&tm_now, &now) != 0)
    {
        return;
    }
#else
    if (localtime_r(&now, &tm_now) == NULL)
    {
        return;
    }
#endif

    if (strftime(buffer, buffer_len, "%Y-%m-%d %H:%M:%S", &tm_now) == 0)
    {
        buffer[0] = '\0';
    }
}

void WriteLog(
    int level,
    int line,
    const char *file,
    const char *function,
    const char *format,
    ...)
{
    char message[1024];
    char formatted[1312];
    size_t formatted_len = 0;

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

    char timestamp[32];
    GetTimestamp(timestamp, sizeof(timestamp));

    const char *timestamp_value = (timestamp[0] != '\0') ? timestamp : "-";

    snprintf(formatted,
             sizeof(formatted),
             "%s [%c] %s %s(%d) %s\n",
             timestamp_value,
             levelChar,
             function,
             shortFilename,
             line,
             message);

    formatted[sizeof(formatted) - 1] = '\0';
    formatted_len = strlen(formatted);

    FILE *output_sink = (log_file != NULL) ? log_file : stderr;
    fwrite(formatted, 1, formatted_len, output_sink);
    fflush(output_sink);
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
