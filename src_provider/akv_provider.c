/* Copyright (c) Microsoft Corporation.
   Licensed under the MIT License. */

#include "akv_provider_shared.h"

static const OSSL_PARAM akv_param_types[] = {
    OSSL_PARAM_utf8_ptr(OSSL_PROV_PARAM_NAME, NULL, 0),
    OSSL_PARAM_utf8_ptr(OSSL_PROV_PARAM_VERSION, NULL, 0),
    OSSL_PARAM_utf8_ptr(OSSL_PROV_PARAM_BUILDINFO, NULL, 0),
    OSSL_PARAM_END};

static const OSSL_ALGORITHM *akv_query_operation(void *provctx, int operation_id, int *no_cache)
{
    (void)provctx;
    (void)operation_id;
    (void)no_cache;
    return NULL;
}

static const OSSL_PARAM *akv_gettable_params(void *provctx)
{
    (void)provctx;
    return akv_param_types;
}

static int akv_get_params(void *provctx, OSSL_PARAM params[])
{
    (void)provctx;
    OSSL_PARAM *p = NULL;

    if ((p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_NAME)) != NULL)
    {
        if (!OSSL_PARAM_set_utf8_ptr(p, "Azure Key Vault Provider (MVP)"))
        {
            return 0;
        }
    }

    if ((p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_VERSION)) != NULL)
    {
        if (!OSSL_PARAM_set_utf8_ptr(p, "0.1.0"))
        {
            return 0;
        }
    }

    if ((p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_BUILDINFO)) != NULL)
    {
        if (!OSSL_PARAM_set_utf8_ptr(p, "Azure Key Vault Provider MVP"))
        {
            return 0;
        }
    }

    return 1;
}

static void akv_teardown(void *provctx)
{
    (void)provctx;
}

static const OSSL_DISPATCH akv_dispatch_table[] = {
    {OSSL_FUNC_PROVIDER_GETTABLE_PARAMS, (void (*)(void))akv_gettable_params},
    {OSSL_FUNC_PROVIDER_GET_PARAMS, (void (*)(void))akv_get_params},
    {OSSL_FUNC_PROVIDER_QUERY_OPERATION, (void (*)(void))akv_query_operation},
    {OSSL_FUNC_PROVIDER_TEARDOWN, (void (*)(void))akv_teardown},
    {0, NULL}};

AKV_PROVIDER_EXPORT int OSSL_provider_init(const OSSL_CORE_HANDLE *handle, const OSSL_DISPATCH *in, const OSSL_DISPATCH **out, void **provctx)
{
    (void)handle;
    (void)in;

    *provctx = NULL;
    *out = akv_dispatch_table;
    Log(LogLevel_Info, "Azure Key Vault Provider (MVP) initialized");
    return 1;
}
