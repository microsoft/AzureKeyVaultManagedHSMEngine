/* Copyright (c) Microsoft Corporation.
   Licensed under the MIT License. */

#include "pch.h"

#define AKV_CMD_DEBUG_LEVEL ENGINE_CMD_BASE
const ENGINE_CMD_DEFN akv_cmd_defns[] = {
    {AKV_CMD_DEBUG_LEVEL,
     "debug",
     "debug (0=OFF, else=ON)",
     ENGINE_CMD_FLAG_NUMERIC},

    {0, NULL, NULL, 0},
};

int akv_ctrl(ENGINE *e, int cmd, long i, void *p, void (*f)(void))
{
    int ret = 1;
    if (akv_idx == -1)
    {
        return 0;
    }

    switch (cmd)
    {
    case AKV_CMD_DEBUG_LEVEL:
        if ((int)i == 0)
        {
            LOG_LEVEL = LogLevel_Info;
        }
        else
        {
            LOG_LEVEL = LogLevel_Debug;
        }
        break;

    default:
        ret = 0;
    }

    return ret;
}
