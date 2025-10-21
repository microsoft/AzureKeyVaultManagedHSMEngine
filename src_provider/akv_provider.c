/* Copyright (c) Microsoft Corporation.
   Licensed under the MIT License. */

#include "akv_provider_shared.h"
#include "akv_provider_internal.h"

#include <openssl/core_object.h>
#include <openssl/x509.h>

typedef struct akv_store_ctx_st
{
    AKV_PROVIDER_CTX *provctx;
    char *keyvault_name;
    char *key_name;
    char *key_version;
    int exhausted;
} AKV_STORE_CTX;

static const OSSL_PARAM akv_param_types[] = {
    OSSL_PARAM_utf8_ptr(OSSL_PROV_PARAM_NAME, NULL, 0),
    OSSL_PARAM_utf8_ptr(OSSL_PROV_PARAM_VERSION, NULL, 0),
    OSSL_PARAM_utf8_ptr(OSSL_PROV_PARAM_BUILDINFO, NULL, 0),
    OSSL_PARAM_END};

static void akv_store_ctx_free(AKV_STORE_CTX *ctx)
{
    Log(LogLevel_Trace, "akv_store_ctx_free ctx=%p", (void *)ctx);
    if (ctx == NULL)
    {
        Log(LogLevel_Debug, "akv_store_ctx_free skipped (null ctx)");
        return;
    }

    free(ctx->keyvault_name);
    free(ctx->key_name);
    free(ctx->key_version);
    free(ctx);
    Log(LogLevel_Debug, "akv_store_ctx_free complete");
}

static void akv_log_curl_get_key_url(const AKV_STORE_CTX *ctx)
{
    char url[1024] = {0};
    int written = 0;

    Log(LogLevel_Trace, "akv_log_curl_get_key_url ctx=%p", (const void *)ctx);

    if (ctx == NULL || ctx->keyvault_name == NULL || ctx->key_name == NULL)
    {
        Log(LogLevel_Debug, "akv_log_curl_get_key_url skipped (incomplete metadata)");
        return;
    }

    if (ctx->key_version != NULL && ctx->key_version[0] != '\0')
    {
        written = snprintf(url,
                           sizeof(url),
                           "https://%s.managedhsm.azure.net/keys/%s/%s",
                           ctx->keyvault_name,
                           ctx->key_name,
                           ctx->key_version);
    }
    else
    {
        written = snprintf(url,
                           sizeof(url),
                           "https://%s.managedhsm.azure.net/keys/%s",
                           ctx->keyvault_name,
                           ctx->key_name);
    }

    if (written < 0 || (size_t)written >= sizeof(url))
    {
        Log(LogLevel_Debug, "akv_log_curl_get_key_url skipped (url truncated)");
        return;
    }

    Log(LogLevel_Info, "curl.c AkvGetKey URL: %s", url);
}

static int akv_casecmpn(const char *lhs, const char *rhs, size_t count)
{
    int result = 0;
    size_t i;

    Log(LogLevel_Trace, "akv_casecmpn lhs=%p rhs=%p count=%zu", (const void *)lhs, (const void *)rhs, count);
    for (i = 0; i < count; ++i)
    {
        unsigned char lc = (unsigned char)lhs[i];
        unsigned char rc = (unsigned char)rhs[i];
        int l = tolower(lc);
        int r = tolower(rc);
        if (l != r)
        {
            result = l - r;
            goto end;
        }
        if (lhs[i] == '\0' || rhs[i] == '\0')
        {
            break;
        }
    }

end:
    Log(LogLevel_Debug, "akv_casecmpn -> %d", result);
    return result;
}

static int akv_has_case_prefix(const char *input, const char *prefix)
{
    size_t prefix_len;

    Log(LogLevel_Trace, "akv_has_case_prefix input=%p prefix=%p", (const void *)input, (const void *)prefix);

    if (input == NULL || prefix == NULL)
    {
        Log(LogLevel_Debug, "akv_has_case_prefix -> 0 (null input)");
        return 0;
    }

    prefix_len = strlen(prefix);
    {
        int match = akv_casecmpn(input, prefix, prefix_len) == 0;
        Log(LogLevel_Debug, "akv_has_case_prefix -> %d", match);
        return match;
    }
}

static int akv_dup_string(char **dst, const char *src)
{
    size_t len;

    Log(LogLevel_Trace, "akv_dup_string dst=%p src=%p", (void *)dst, (const void *)src);

    if (dst == NULL)
    {
        Log(LogLevel_Debug, "akv_dup_string -> 0 (dst null)");
        return 0;
    }

    if (src == NULL)
    {
        *dst = NULL;
        Log(LogLevel_Debug, "akv_dup_string -> 1 (src null)");
        return 1;
    }

    len = strlen(src);
    *dst = (char *)malloc(len + 1);
    if (*dst == NULL)
    {
        Log(LogLevel_Debug, "akv_dup_string -> 0 (alloc failed)");
        return 0;
    }
    memcpy(*dst, src, len);
    (*dst)[len] = '\0';
    Log(LogLevel_Debug, "akv_dup_string -> 1 (copied %zu bytes)", len);
    return 1;
}

static int akv_set_string(char **dst, const char *src)
{
    char *tmp = NULL;

    Log(LogLevel_Trace, "akv_set_string dst=%p src=%p", (void *)dst, (const void *)src);

    if (!akv_dup_string(&tmp, src))
    {
        Log(LogLevel_Debug, "akv_set_string -> 0 (dup failed)");
        return 0;
    }

    free(*dst);
    *dst = tmp;
    Log(LogLevel_Debug, "akv_set_string -> 1");
    return 1;
}

static int akv_parse_uri_keyvalue(const char *uri, char **vault, char **name, char **version)
{
    const char *cursor;
    char *work = NULL;
    char *token;
    int ok = 0;
    int type_validated = 0;

    Log(LogLevel_Trace,
        "akv_parse_uri_keyvalue uri=%s vault_ptr=%p name_ptr=%p version_ptr=%p",
        uri != NULL ? uri : "(null)",
        (void *)vault,
        (void *)name,
        (void *)version);

    if (vault == NULL || name == NULL || version == NULL)
    {
        Log(LogLevel_Debug, "akv_parse_uri_keyvalue -> 0 (null out param)");
        return 0;
    }

    *vault = NULL;
    *name = NULL;
    *version = NULL;

    if (!akv_has_case_prefix(uri, "akv:"))
    {
        Log(LogLevel_Debug, "akv_parse_uri_keyvalue -> 0 (missing akv prefix)");
        goto cleanup;
    }

    cursor = uri + 4;
    if (!akv_dup_string(&work, cursor))
    {
        Log(LogLevel_Debug, "akv_parse_uri_keyvalue -> 0 (dup cursor failed)");
        goto cleanup;
    }
    if (work == NULL)
    {
        Log(LogLevel_Debug, "akv_parse_uri_keyvalue -> 0 (empty work buffer)");
        goto cleanup;
    }

    token = work;
    while (token != NULL && *token != '\0')
    {
        char *equals = strchr(token, '=');
        char *next = strchr(token, ',');
        if (next != NULL)
        {
            *next = '\0';
        }
        if (equals != NULL)
        {
            *equals = '\0';
            ++equals;
            if (strcasecmp(token, "keyvault_type") == 0 || strcasecmp(token, "type") == 0)
            {
                if (equals == NULL || *equals == '\0' || strcasecmp(equals, "managedhsm") != 0)
                {
                    Log(LogLevel_Debug, "akv_parse_uri_keyvalue -> 0 (unsupported keyvault type)");
                    goto cleanup;
                }
                type_validated = 1;
            }
            else if (strcasecmp(token, "keyvault_name") == 0 || strcasecmp(token, "vault") == 0)
            {
                if (!akv_set_string(vault, equals))
                {
                    Log(LogLevel_Debug, "akv_parse_uri_keyvalue -> 0 (set vault failed)");
                    goto cleanup;
                }
            }
            else if (strcasecmp(token, "key_name") == 0 || strcasecmp(token, "name") == 0)
            {
                if (!akv_set_string(name, equals))
                {
                    Log(LogLevel_Debug, "akv_parse_uri_keyvalue -> 0 (set name failed)");
                    goto cleanup;
                }
            }
            else if (strcasecmp(token, "key_version") == 0 || strcasecmp(token, "version") == 0)
            {
                if (!akv_set_string(version, equals))
                {
                    Log(LogLevel_Debug, "akv_parse_uri_keyvalue -> 0 (set version failed)");
                    goto cleanup;
                }
            }
        }
        if (next == NULL)
        {
            break;
        }
        token = next + 1;
    }

    if (!type_validated)
    {
        /* Treat missing type as managedhsm by default for legacy URIs without an explicit token. */
        type_validated = 1;
    }

    ok = (type_validated && *vault != NULL && *name != NULL) ? 1 : 0;
    if (!ok)
    {
        Log(LogLevel_Debug, "akv_parse_uri_keyvalue missing required fields");
    }
    else
    {
        Log(LogLevel_Debug,
            "akv_parse_uri_keyvalue parsed vault=%s name=%s version=%s",
            *vault != NULL ? *vault : "(null)",
            *name != NULL ? *name : "(null)",
            *version != NULL ? *version : "(null)");
    }

cleanup:
    if (work != NULL)
    {
        free(work);
        work = NULL;
    }
    if (!ok)
    {
        free(*vault);
        free(*name);
        free(*version);
        *vault = NULL;
        *name = NULL;
        *version = NULL;
    }
    Log(LogLevel_Debug, "akv_parse_uri_keyvalue -> %d", ok);
    return ok;
}

static int akv_parse_uri_simple(const char *uri, char **vault, char **name)
{
    const char *cursor;
    const char *sep;
    size_t vault_len;
    int ok = 0;

    Log(LogLevel_Trace,
        "akv_parse_uri_simple uri=%s vault_ptr=%p name_ptr=%p",
        uri != NULL ? uri : "(null)",
        (void *)vault,
        (void *)name);

    if (vault == NULL || name == NULL)
    {
        Log(LogLevel_Debug, "akv_parse_uri_simple -> 0 (null out param)");
        return 0;
    }

    if (!akv_has_case_prefix(uri, "managedhsm:"))
    {
        Log(LogLevel_Debug, "akv_parse_uri_simple -> 0 (missing managedhsm prefix)");
        goto cleanup;
    }

    cursor = uri + strlen("managedhsm:");
    sep = strchr(cursor, ':');
    if (sep == NULL)
    {
        Log(LogLevel_Debug, "akv_parse_uri_simple -> 0 (missing separator)");
        goto cleanup;
    }

    vault_len = (size_t)(sep - cursor);
    *vault = NULL;
    *name = NULL;

    *vault = (char *)malloc(vault_len + 1);
    if (*vault == NULL)
    {
        Log(LogLevel_Debug, "akv_parse_uri_simple -> 0 (alloc vault failed)");
        goto cleanup;
    }
    memcpy(*vault, cursor, vault_len);
    (*vault)[vault_len] = '\0';

    cursor = sep + 1;
    if (!akv_dup_string(name, cursor))
    {
        free(*vault);
        *vault = NULL;
        Log(LogLevel_Debug, "akv_parse_uri_simple -> 0 (dup name failed)");
        goto cleanup;
    }

    ok = 1;
    Log(LogLevel_Debug,
        "akv_parse_uri_simple parsed vault=%s name=%s",
        *vault != NULL ? *vault : "(null)",
        *name != NULL ? *name : "(null)");

cleanup:
    if (!ok)
    {
        free(*vault);
        free(*name);
        *vault = NULL;
        *name = NULL;
    }
    Log(LogLevel_Debug, "akv_parse_uri_simple -> %d", ok);
    return ok;
}
static void *akv_store_open(void *provctx, const char *uri)
{
    AKV_STORE_CTX *ctx = NULL;

    Log(LogLevel_Trace, "akv_store_open provctx=%p uri=%s", provctx, uri != NULL ? uri : "(null)");

    ctx = (AKV_STORE_CTX *)calloc(1, sizeof(AKV_STORE_CTX));
    if (ctx == NULL)
    {
        Log(LogLevel_Error, "akv_store_open allocation failed for URI %s", uri != NULL ? uri : "(null)");
        Log(LogLevel_Debug, "akv_store_open -> NULL (alloc failed)");
        return NULL;
    }

    ctx->provctx = (AKV_PROVIDER_CTX *)provctx;

    if (!akv_parse_uri_keyvalue(uri, &ctx->keyvault_name, &ctx->key_name, &ctx->key_version))
    {
        if (!akv_parse_uri_simple(uri, &ctx->keyvault_name, &ctx->key_name))
        {
            akv_store_ctx_free(ctx);
            Log(LogLevel_Debug, "akv_store_open -> NULL (parsing failed)");
            return NULL;
        }
    }

    ctx->exhausted = 0;
    Log(LogLevel_Debug,
        "akv_store_open -> %p (vault=%s name=%s version=%s)",
        (void *)ctx,
        ctx->keyvault_name != NULL ? ctx->keyvault_name : "(null)",
        ctx->key_name != NULL ? ctx->key_name : "(null)",
        ctx->key_version != NULL ? ctx->key_version : "(null)");
    return ctx;
}

static void *akv_store_attach(void *provctx, OSSL_CORE_BIO *in)
{
    Log(LogLevel_Trace, "akv_store_attach provctx=%p bio=%p", provctx, (void *)in);
    (void)provctx;
    (void)in;
    Log(LogLevel_Debug, "akv_store_attach -> NULL (not supported)");
    return NULL;
}

static const OSSL_PARAM *akv_store_settable_ctx_params(void *provctx)
{
    Log(LogLevel_Trace, "akv_store_settable_ctx_params provctx=%p", provctx);
    static const OSSL_PARAM params[] = {
        OSSL_PARAM_END};
    (void)provctx;
    Log(LogLevel_Debug, "akv_store_settable_ctx_params -> %p", (const void *)params);
    return params;
}

static int akv_store_set_ctx_params(void *loaderctx, const OSSL_PARAM params[])
{
    Log(LogLevel_Trace, "akv_store_set_ctx_params loaderctx=%p params=%p", loaderctx, (const void *)params);
    (void)loaderctx;
    (void)params;
    Log(LogLevel_Debug, "akv_store_set_ctx_params -> 1 (no-op)");
    return 1;
}

static int akv_store_load(void *loaderctx, OSSL_CALLBACK *object_cb, void *object_cbarg, OSSL_PASSPHRASE_CALLBACK *pw_cb, void *pw_cbarg)
{
    AKV_STORE_CTX *ctx = (AKV_STORE_CTX *)loaderctx;
    MemoryStruct token = {0};
    EVP_PKEY *key = NULL;
    AKV_KEY *akv_key = NULL;
    const char *data_type = NULL;
    int object_type = OSSL_OBJECT_PKEY;
    AKV_KEY *keyref = NULL;
    OSSL_PARAM params[4];
    int cb_result = 0;

    Log(LogLevel_Trace,
        "akv_store_load ctx=%p object_cb=%p object_cbarg=%p pw_cb=%p pw_cbarg=%p",
        (void *)ctx,
        (void *)object_cb,
        object_cbarg,
        (void *)pw_cb,
        pw_cbarg);

    (void)pw_cb;
    (void)pw_cbarg;

    if (ctx == NULL || ctx->exhausted)
    {
        Log(LogLevel_Debug, "akv_store_load -> 0 (null or exhausted context)");
        return 0;
    }

    if (!GetAccessTokenFromEnv(&token))
    {
        Log(LogLevel_Error, "Failed to obtain access token for managedhsm://%s/%s",
            ctx->keyvault_name != NULL ? ctx->keyvault_name : "(null)",
            ctx->key_name != NULL ? ctx->key_name : "(null)");
        Log(LogLevel_Debug, "akv_store_load -> 0 (GetAccessTokenFromEnv failed)");
        goto cleanup;
    }

    akv_log_curl_get_key_url(ctx);

    key = AkvGetKey(ctx->keyvault_name, ctx->key_name, &token);
    if (key == NULL)
    {
        Log(LogLevel_Error, "Failed to retrieve key material for %s", ctx->key_name);
        Log(LogLevel_Debug, "akv_store_load -> 0 (AkvGetKey failed)");
        goto cleanup;
    }

    akv_key = akv_key_new(ctx->provctx);
    if (akv_key == NULL)
    {
        Log(LogLevel_Error, "Failed to allocate provider key container");
        Log(LogLevel_Debug, "akv_store_load -> 0 (akv_key_new failed)");
        goto cleanup;
    }

    if (!akv_key_set_metadata(akv_key, ctx->keyvault_name, ctx->key_name, ctx->key_version))
    {
        Log(LogLevel_Error, "Failed to set key metadata for %s", ctx->key_name);
        Log(LogLevel_Debug, "akv_store_load -> 0 (akv_key_set_metadata failed)");
        goto cleanup;
    }

    akv_key_set_public(akv_key, key);
    key = NULL;

    if (EVP_PKEY_is_a(akv_key->public_key, "RSA"))
    {
        data_type = "RSA";
    }
    else if (EVP_PKEY_is_a(akv_key->public_key, "EC"))
    {
        data_type = "EC";
    }
    else
    {
        Log(LogLevel_Error, "Unsupported key type encountered in store load");
        Log(LogLevel_Debug, "akv_store_load -> 0 (unsupported key type)");
        goto cleanup;
    }

    keyref = akv_key;
    params[0] = OSSL_PARAM_construct_int(OSSL_OBJECT_PARAM_TYPE, &object_type);
    params[1] = OSSL_PARAM_construct_utf8_string(OSSL_OBJECT_PARAM_DATA_TYPE, (char *)data_type, 0);
    params[2] = OSSL_PARAM_construct_octet_string(OSSL_OBJECT_PARAM_REFERENCE, &keyref, sizeof(keyref));
    params[3] = OSSL_PARAM_construct_end();

    if (!object_cb(params, object_cbarg))
    {
        Log(LogLevel_Debug, "akv_store_load -> 0 (object callback failed)");
        goto cleanup;
    }

    ctx->exhausted = 1;
    akv_key = NULL;
    cb_result = 1;
    Log(LogLevel_Debug, "akv_store_load delivered key reference for %s", ctx->key_name);

cleanup:
    if (token.memory != NULL)
    {
        free(token.memory);
    }
    if (key != NULL)
    {
        EVP_PKEY_free(key);
    }
    if (akv_key != NULL)
    {
        akv_key_free(akv_key);
    }

    if (cb_result == 0 && ctx != NULL)
    {
        /* Stop the loader from retrying endlessly after a fatal fetch error. */
        ctx->exhausted = 1;
    }

    Log(LogLevel_Debug, "akv_store_load -> %d", cb_result);
    return cb_result;
}

static int akv_store_eof(void *loaderctx)
{
    AKV_STORE_CTX *ctx = (AKV_STORE_CTX *)loaderctx;
    int eof = 0;

    Log(LogLevel_Trace, "akv_store_eof ctx=%p", loaderctx);
    eof = (ctx == NULL || ctx->exhausted) ? 1 : 0;
    Log(LogLevel_Debug, "akv_store_eof -> %d", eof);
    return eof;
}

static int akv_store_close(void *loaderctx)
{
    Log(LogLevel_Trace, "akv_store_close ctx=%p", loaderctx);
    akv_store_ctx_free((AKV_STORE_CTX *)loaderctx);
    Log(LogLevel_Debug, "akv_store_close -> 1");
    return 1;
}

static const OSSL_DISPATCH akv_store_functions[] = {
    {OSSL_FUNC_STORE_OPEN, (void (*)(void))akv_store_open},
    {OSSL_FUNC_STORE_ATTACH, (void (*)(void))akv_store_attach},
    {OSSL_FUNC_STORE_SETTABLE_CTX_PARAMS, (void (*)(void))akv_store_settable_ctx_params},
    {OSSL_FUNC_STORE_SET_CTX_PARAMS, (void (*)(void))akv_store_set_ctx_params},
    {OSSL_FUNC_STORE_LOAD, (void (*)(void))akv_store_load},
    {OSSL_FUNC_STORE_EOF, (void (*)(void))akv_store_eof},
    {OSSL_FUNC_STORE_CLOSE, (void (*)(void))akv_store_close},
    {0, NULL}};

static const OSSL_ALGORITHM akv_store_algs[] = {
    {"managedhsm", "provider=akv_provider", akv_store_functions, "Azure Managed HSM store"},
    {NULL, NULL, NULL, NULL}};

static const OSSL_ALGORITHM akv_keymgmt_algs[] = {
    {"RSA:rsaEncryption", "provider=akv_provider", akv_rsa_keymgmt_functions, "Azure Key Vault RSA key management"},
    {"EC:id-ecPublicKey", "provider=akv_provider", akv_ec_keymgmt_functions, "Azure Key Vault EC key management"},
    {NULL, NULL, NULL, NULL}};

static const OSSL_ALGORITHM akv_signature_algs[] = {
    {"RSA:rsaEncryption:rsaSignature", "provider=akv_provider", akv_rsa_signature_functions, "Azure Key Vault RSA signature"}, /* publish both keymgmt and signature aliases so listing finds us */
    {"ECDSA", "provider=akv_provider", akv_ecdsa_signature_functions, "Azure Key Vault ECDSA signature"},
    {NULL, NULL, NULL, NULL}};

static const OSSL_ALGORITHM akv_asym_cipher_algs[] = {
    {"RSA:rsaEncryption", "provider=akv_provider", akv_rsa_asym_cipher_functions, "Azure Key Vault RSA asymmetric cipher"},
    {NULL, NULL, NULL, NULL}};

static const OSSL_ALGORITHM *akv_query_operation(void *provctx, int operation_id, int *no_cache)
{
    const OSSL_ALGORITHM *result = NULL;

    Log(LogLevel_Trace, "akv_query_operation provctx=%p operation_id=%d no_cache_ptr=%p", provctx, operation_id, (void *)no_cache);

    (void)provctx;
    if (no_cache != NULL)
    {
        *no_cache = 0;
    }

    switch (operation_id)
    {
    case OSSL_OP_STORE:
        result = akv_store_algs;
        break;
    case OSSL_OP_KEYMGMT:
        result = akv_keymgmt_algs;
        break;
    case OSSL_OP_SIGNATURE:
        result = akv_signature_algs;
        break;
    case OSSL_OP_ASYM_CIPHER:
        result = akv_asym_cipher_algs;
        break;
    default:
        result = NULL;
        break;
    }

    Log(LogLevel_Debug, "akv_query_operation -> %p", (const void *)result);
    return result;
}

static const OSSL_PARAM *akv_gettable_params(void *provctx)
{
    Log(LogLevel_Trace, "akv_gettable_params provctx=%p", provctx);
    (void)provctx;
    Log(LogLevel_Debug, "akv_gettable_params -> %p", (const void *)akv_param_types);
    return akv_param_types;
}

/* By default, our providers are always in a happy state */
static int ossl_prov_is_running(void)
{
    int running = 1;
    Log(LogLevel_Trace, "ossl_prov_is_running");
    Log(LogLevel_Debug, "ossl_prov_is_running -> %d", running);
    return running;
}

static int akv_get_params(void *provctx, OSSL_PARAM params[])
{
    int ok = 1;
    (void)provctx;
    OSSL_PARAM *p = NULL;

    Log(LogLevel_Trace, "akv_get_params provctx=%p params=%p", provctx, (void *)params);

    p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_NAME);
    if (p != NULL && !OSSL_PARAM_set_utf8_ptr(p, "Azure Managed HSM Provider"))
    {
        Log(LogLevel_Debug, "akv_get_params failed to set provider name");
        ok = 0;
        goto end;
    }

    p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_VERSION);
    if (p != NULL && !OSSL_PARAM_set_utf8_ptr(p, "0.1.0"))
    {
        Log(LogLevel_Debug, "akv_get_params failed to set provider version");
        ok = 0;
        goto end;
    }

    p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_BUILDINFO);
    if (p != NULL && !OSSL_PARAM_set_utf8_ptr(p, "Azure Managed HSM Provider"))
    {
        Log(LogLevel_Debug, "akv_get_params failed to set build info");
        ok = 0;
        goto end;
    }

    p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_STATUS);
    if (p != NULL && !OSSL_PARAM_set_int(p, ossl_prov_is_running()))
    {
        Log(LogLevel_Debug, "akv_get_params failed to set status");
        ok = 0;
        goto end;
    }

end:
    Log(LogLevel_Debug, "akv_get_params -> %d", ok);
    return ok;
}

static void akv_teardown(void *provctx)
{
    AKV_PROVIDER_CTX *ctx = (AKV_PROVIDER_CTX *)provctx;
    Log(LogLevel_Trace, "akv_teardown provctx=%p", provctx);
    akv_provider_close_log_file();
    free(ctx);
    Log(LogLevel_Debug, "akv_teardown complete");
}

static const OSSL_DISPATCH akv_dispatch_table[] = {
    {OSSL_FUNC_PROVIDER_GETTABLE_PARAMS, (void (*)(void))akv_gettable_params},
    {OSSL_FUNC_PROVIDER_GET_PARAMS, (void (*)(void))akv_get_params},
    {OSSL_FUNC_PROVIDER_QUERY_OPERATION, (void (*)(void))akv_query_operation},
    {OSSL_FUNC_PROVIDER_TEARDOWN, (void (*)(void))akv_teardown},
    {0, NULL}};

AKV_PROVIDER_EXPORT int OSSL_provider_init(const OSSL_CORE_HANDLE *handle, const OSSL_DISPATCH *in, const OSSL_DISPATCH **out, void **provctx)
{
    AKV_PROVIDER_CTX *ctx = NULL;

    Log(LogLevel_Trace,
        "OSSL_provider_init handle=%p in=%p out_ptr=%p provctx_ptr=%p",
        (const void *)handle,
        (const void *)in,
        (const void *)out,
        (void *)provctx);

    (void)in;

    if (out == NULL || provctx == NULL)
    {
        Log(LogLevel_Error, "OSSL_provider_init received null output pointers");
        Log(LogLevel_Debug, "OSSL_provider_init -> 0 (bad arguments)");
        return 0;
    }

    ctx = (AKV_PROVIDER_CTX *)calloc(1, sizeof(AKV_PROVIDER_CTX));
    if (ctx == NULL)
    {
        Log(LogLevel_Error, "OSSL_provider_init failed to allocate provider context");
        Log(LogLevel_Debug, "OSSL_provider_init -> 0 (alloc failed)");
        return 0;
    }

    ctx->core = handle;

    int log_level_override = 0;
    int log_level_override_set = 0;

    {
        const char *env = getenv("AKV_LOG_LEVEL");
        if (env != NULL)
        {
            log_level_override = atoi(env);
            log_level_override_set = 1;
        }
    }

    {
        const char *path = getenv("AKV_LOG_FILE");
        if (path != NULL && path[0] != '\0')
        {
            if (akv_provider_set_log_file(path))
            {
                Log(LogLevel_Info, "AKV log file set to %s via environment", path);
            }
            else
            {
                Log(LogLevel_Error, "Failed to open AKV log file at %s", path);
            }
        }
    }

    if (log_level_override_set)
    {
        akv_provider_set_log_level(log_level_override);
        Log(LogLevel_Info, "AKV log level set to %d via environment", log_level_override);
    }

    *provctx = ctx;
    *out = akv_dispatch_table;
    Log(LogLevel_Debug, "OSSL_provider_init -> 1 (ctx=%p)", (void *)ctx);
    Log(LogLevel_Debug, "Azure Key Vault Provider (MVP) initialized");
    return 1;
}
