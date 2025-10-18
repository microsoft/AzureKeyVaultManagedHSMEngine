/* Copyright (c) Microsoft Corporation.
   Licensed under the MIT License. */

#include "akv_provider_shared.h"
#include "akv_provider_internal.h"

#include <openssl/core_object.h>
#include <openssl/x509.h>

typedef struct akv_store_ctx_st
{
    AKV_PROVIDER_CTX *provctx;
    char *keyvault_type;
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
    if (ctx == NULL)
    {
        return;
    }

    free(ctx->keyvault_type);
    free(ctx->keyvault_name);
    free(ctx->key_name);
    free(ctx->key_version);
    free(ctx);
}

static int akv_casecmpn(const char *lhs, const char *rhs, size_t count)
{
    size_t i;
    for (i = 0; i < count; ++i)
    {
        unsigned char lc = (unsigned char)lhs[i];
        unsigned char rc = (unsigned char)rhs[i];
        int l = tolower(lc);
        int r = tolower(rc);
        if (l != r)
        {
            return l - r;
        }
        if (lhs[i] == '\0' || rhs[i] == '\0')
        {
            break;
        }
    }
    return 0;
}

static int akv_has_case_prefix(const char *input, const char *prefix)
{
    size_t prefix_len;

    if (input == NULL || prefix == NULL)
    {
        return 0;
    }

    prefix_len = strlen(prefix);
    return akv_casecmpn(input, prefix, prefix_len) == 0;
}

static int akv_dup_string(char **dst, const char *src)
{
    size_t len;

    if (src == NULL)
    {
        *dst = NULL;
        return 1;
    }

    len = strlen(src);
    *dst = (char *)malloc(len + 1);
    if (*dst == NULL)
    {
        return 0;
    }
    memcpy(*dst, src, len);
    (*dst)[len] = '\0';
    return 1;
}

static int akv_set_string(char **dst, const char *src)
{
    char *tmp = NULL;

    if (!akv_dup_string(&tmp, src))
    {
        return 0;
    }

    free(*dst);
    *dst = tmp;
    return 1;
}

static int akv_parse_uri_keyvalue(const char *uri, char **type, char **vault, char **name, char **version)
{
    const char *cursor;
    char *work = NULL;
    char *token;

    *type = NULL;
    *vault = NULL;
    *name = NULL;
    *version = NULL;

    if (!akv_has_case_prefix(uri, "akv:"))
    {
        return 0;
    }

    cursor = uri + 4;
    if (!akv_dup_string(&work, cursor))
    {
        return 0;
    }
    if (work == NULL)
    {
        return 0;
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
                if (!akv_set_string(type, equals))
                {
                    goto error;
                }
            }
            else if (strcasecmp(token, "keyvault_name") == 0 || strcasecmp(token, "vault") == 0)
            {
                if (!akv_set_string(vault, equals))
                {
                    goto error;
                }
            }
            else if (strcasecmp(token, "key_name") == 0 || strcasecmp(token, "name") == 0)
            {
                if (!akv_set_string(name, equals))
                {
                    goto error;
                }
            }
            else if (strcasecmp(token, "key_version") == 0 || strcasecmp(token, "version") == 0)
            {
                if (!akv_set_string(version, equals))
                {
                    goto error;
                }
            }
        }
        if (next == NULL)
        {
            break;
        }
        token = next + 1;
    }

    free(work);
    return (*type != NULL && *vault != NULL && *name != NULL) ? 1 : 0;

error:
    free(work);
    free(*type);
    free(*vault);
    free(*name);
    free(*version);
    *type = NULL;
    *vault = NULL;
    *name = NULL;
    *version = NULL;
    return 0;
}

static int akv_parse_uri_simple(const char *uri, char **type, char **vault, char **name)
{
    const char *cursor;
    const char *sep;
    size_t vault_len;

    if (!akv_has_case_prefix(uri, "managedhsm:"))
    {
        return 0;
    }

    cursor = uri + strlen("managedhsm:");
    sep = strchr(cursor, ':');
    if (sep == NULL)
    {
        return 0;
    }

    vault_len = (size_t)(sep - cursor);
    *type = NULL;
    *vault = NULL;
    *name = NULL;

    if (!akv_dup_string(type, "managedHsm"))
    {
        return 0;
    }

    *vault = (char *)malloc(vault_len + 1);
    if (*vault == NULL)
    {
        free(*type);
        *type = NULL;
        return 0;
    }
    memcpy(*vault, cursor, vault_len);
    (*vault)[vault_len] = '\0';

    cursor = sep + 1;
    if (!akv_dup_string(name, cursor))
    {
        free(*type);
        *type = NULL;
        free(*vault);
        *vault = NULL;
        return 0;
    }

    return 1;
}
static void *akv_store_open(void *provctx, const char *uri)
{
    AKV_STORE_CTX *ctx = NULL;

    ctx = (AKV_STORE_CTX *)calloc(1, sizeof(AKV_STORE_CTX));
    if (ctx == NULL)
    {
        return NULL;
    }

    ctx->provctx = (AKV_PROVIDER_CTX *)provctx;

    if (!akv_parse_uri_keyvalue(uri, &ctx->keyvault_type, &ctx->keyvault_name, &ctx->key_name, &ctx->key_version))
    {
        if (!akv_parse_uri_simple(uri, &ctx->keyvault_type, &ctx->keyvault_name, &ctx->key_name))
        {
            akv_store_ctx_free(ctx);
            return NULL;
        }
    }

    ctx->exhausted = 0;
    return ctx;
}

static void *akv_store_attach(void *provctx, OSSL_CORE_BIO *in)
{
    (void)provctx;
    (void)in;
    return NULL;
}

static const OSSL_PARAM *akv_store_settable_ctx_params(void *provctx)
{
    static const OSSL_PARAM params[] = {
        OSSL_PARAM_END};
    (void)provctx;
    return params;
}

static int akv_store_set_ctx_params(void *loaderctx, const OSSL_PARAM params[])
{
    (void)loaderctx;
    (void)params;
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

    (void)pw_cb;
    (void)pw_cbarg;

    if (ctx == NULL || ctx->exhausted)
    {
        return 0;
    }

    if (!GetAccessTokenFromIMDS(ctx->keyvault_type, &token))
    {
        Log(LogLevel_Error, "Failed to obtain access token for %s", ctx->keyvault_type);
        goto cleanup;
    }

    key = AkvGetKey(ctx->keyvault_type, ctx->keyvault_name, ctx->key_name, &token);
    if (key == NULL)
    {
        Log(LogLevel_Error, "Failed to retrieve key material for %s", ctx->key_name);
        goto cleanup;
    }

    akv_key = akv_key_new(ctx->provctx);
    if (akv_key == NULL)
    {
        Log(LogLevel_Error, "Failed to allocate provider key container");
        goto cleanup;
    }

    if (!akv_key_set_metadata(akv_key, ctx->keyvault_type, ctx->keyvault_name, ctx->key_name, ctx->key_version))
    {
        Log(LogLevel_Error, "Failed to set key metadata for %s", ctx->key_name);
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
        goto cleanup;
    }

    keyref = akv_key;
    params[0] = OSSL_PARAM_construct_int(OSSL_OBJECT_PARAM_TYPE, &object_type);
    params[1] = OSSL_PARAM_construct_utf8_string(OSSL_OBJECT_PARAM_DATA_TYPE, (char *)data_type, 0);
    params[2] = OSSL_PARAM_construct_octet_string(OSSL_OBJECT_PARAM_REFERENCE, &keyref, sizeof(keyref));
    params[3] = OSSL_PARAM_construct_end();

    if (!object_cb(params, object_cbarg))
    {
        goto cleanup;
    }

    ctx->exhausted = 1;
    akv_key = NULL;
    cb_result = 1;

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

    return cb_result;
}

static int akv_store_eof(void *loaderctx)
{
    AKV_STORE_CTX *ctx = (AKV_STORE_CTX *)loaderctx;
    return ctx == NULL || ctx->exhausted;
}

static int akv_store_close(void *loaderctx)
{
    akv_store_ctx_free((AKV_STORE_CTX *)loaderctx);
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
    {"akv,managedhsm", "provider=akv_provider", akv_store_functions, "Azure Key Vault store"},
    {NULL, NULL, NULL, NULL}};

static const OSSL_ALGORITHM akv_keymgmt_algs[] = {
    {"RSA:rsaEncryption", "provider=akv_provider", akv_rsa_keymgmt_functions, "Azure Key Vault RSA key management"},
    {"EC:id-ecPublicKey", "provider=akv_provider", akv_ec_keymgmt_functions, "Azure Key Vault EC key management"},
    {NULL, NULL, NULL, NULL}};

static const OSSL_ALGORITHM akv_signature_algs[] = {
    {"RSA:rsaEncryption", "provider=akv_provider", akv_rsa_signature_functions, "Azure Key Vault RSA signature"},
    {"ECDSA", "provider=akv_provider", akv_ecdsa_signature_functions, "Azure Key Vault ECDSA signature"},
    {NULL, NULL, NULL, NULL}};

static const OSSL_ALGORITHM akv_asym_cipher_algs[] = {
    {"RSA:rsaEncryption", "provider=akv_provider", akv_rsa_asym_cipher_functions, "Azure Key Vault RSA asymmetric cipher"},
    {NULL, NULL, NULL, NULL}};

static const OSSL_ALGORITHM *akv_query_operation(void *provctx, int operation_id, int *no_cache)
{
    (void)provctx;
    if (no_cache != NULL)
    {
        *no_cache = 0;
    }

    switch (operation_id)
    {
    case OSSL_OP_STORE:
        return akv_store_algs;
    case OSSL_OP_KEYMGMT:
        return akv_keymgmt_algs;
    case OSSL_OP_SIGNATURE:
        return akv_signature_algs;
    case OSSL_OP_ASYM_CIPHER:
        return akv_asym_cipher_algs;
    default:
        return NULL;
    }
}

static const OSSL_PARAM *akv_gettable_params(void *provctx)
{
    (void)provctx;
    return akv_param_types;
}

/* By default, our providers are always in a happy state */
static int ossl_prov_is_running(void)
{
    return 1;
}

static int akv_get_params(void *provctx, OSSL_PARAM params[])
{
    (void)provctx;
    OSSL_PARAM *p = NULL;

    p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_NAME);
    if (p != NULL && !OSSL_PARAM_set_utf8_ptr(p, "Azure Managed HSM Provider"))
    {
        return 0;
    }

    p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_VERSION);
    if (p != NULL && !OSSL_PARAM_set_utf8_ptr(p, "0.1.0"))
    {
        return 0;
    }

    p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_BUILDINFO);
    if (p != NULL && !OSSL_PARAM_set_utf8_ptr(p, "Azure Managed HSM Provider"))
    {
        return 0;
    }

    p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_STATUS);
    if (p != NULL && !OSSL_PARAM_set_int(p, ossl_prov_is_running()))
    {
        return 0;
    }

    return 1;
}

static void akv_teardown(void *provctx)
{
    AKV_PROVIDER_CTX *ctx = (AKV_PROVIDER_CTX *)provctx;
    free(ctx);
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

    (void)in;

    ctx = (AKV_PROVIDER_CTX *)calloc(1, sizeof(AKV_PROVIDER_CTX));
    if (ctx == NULL)
    {
        return 0;
    }

    ctx->core = handle;

    *provctx = ctx;
    *out = akv_dispatch_table;
    Log(LogLevel_Info, "Azure Key Vault Provider (MVP) initialized");
    return 1;
}
