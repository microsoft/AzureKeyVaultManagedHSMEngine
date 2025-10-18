/* Copyright (c) Microsoft Corporation.
   Licensed under the MIT License. */

#include "akv_provider_internal.h"

#define AKV_CHECK_ALLOC(ptr) \
    do                        \
    {                         \
        if ((ptr) == NULL)    \
        {                     \
            return 0;         \
        }                     \
    } while (0)

static int akv_dup_string(char **dst, const char *src)
{
    char *tmp = NULL;

    if (dst == NULL)
    {
        return 0;
    }

    if (src == NULL)
    {
        free(*dst);
        *dst = NULL;
        return 1;
    }

    tmp = (char *)malloc(strlen(src) + 1);
    if (tmp == NULL)
    {
        return 0;
    }

    memcpy(tmp, src, strlen(src) + 1);
    free(*dst);
    *dst = tmp;
    return 1;
}

AKV_KEY *akv_key_new(AKV_PROVIDER_CTX *provctx)
{
    AKV_KEY *key = (AKV_KEY *)calloc(1, sizeof(AKV_KEY));
    if (key == NULL)
    {
        return NULL;
    }

    key->provctx = provctx;
    return key;
}

void akv_key_free(AKV_KEY *key)
{
    if (key == NULL)
    {
        return;
    }

    if (key->public_key != NULL)
    {
        EVP_PKEY_free(key->public_key);
        key->public_key = NULL;
    }

    free(key->keyvault_type);
    free(key->keyvault_name);
    free(key->key_name);
    free(key->key_version);

    free(key);
}

int akv_key_set_metadata(AKV_KEY *key, const char *type, const char *vault, const char *name, const char *version)
{
    if (key == NULL)
    {
        return 0;
    }

    if (!akv_dup_string(&key->keyvault_type, type))
    {
        return 0;
    }
    if (!akv_dup_string(&key->keyvault_name, vault))
    {
        return 0;
    }
    if (!akv_dup_string(&key->key_name, name))
    {
        return 0;
    }
    if (!akv_dup_string(&key->key_version, version))
    {
        return 0;
    }

    return 1;
}

void akv_key_set_public(AKV_KEY *key, EVP_PKEY *pkey)
{
    if (key == NULL)
    {
        return;
    }

    if (key->public_key != NULL)
    {
        EVP_PKEY_free(key->public_key);
    }

    key->public_key = pkey;
}

static int akv_key_has_private(const AKV_KEY *key)
{
    return key != NULL && key->keyvault_type != NULL && key->keyvault_name != NULL && key->key_name != NULL;
}

static void *akv_keymgmt_new(void *provctx)
{
    return akv_key_new((AKV_PROVIDER_CTX *)provctx);
}

static void akv_keymgmt_free(void *vkey)
{
    akv_key_free((AKV_KEY *)vkey);
}

static void *akv_keymgmt_load(const void *reference, size_t reference_sz)
{
    AKV_KEY *key = NULL;

    if (reference == NULL || reference_sz != sizeof(key))
    {
        return NULL;
    }

    key = *(AKV_KEY **)reference;
    *(AKV_KEY **)reference = NULL;
    return key;
}

static int akv_keymgmt_has(const void *vkey, int selection)
{
    const AKV_KEY *key = (const AKV_KEY *)vkey;

    if (key == NULL)
    {
        return 0;
    }

    if ((selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0 && key->public_key == NULL)
    {
        return 0;
    }

    if ((selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0 && !akv_key_has_private(key))
    {
        return 0;
    }

    return 1;
}

static int akv_keymgmt_match(const void *vkey1, const void *vkey2, int selection)
{
    const AKV_KEY *key1 = (const AKV_KEY *)vkey1;
    const AKV_KEY *key2 = (const AKV_KEY *)vkey2;

    if (key1 == NULL || key2 == NULL)
    {
        return 0;
    }

    if ((selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0)
    {
        if (key1->public_key == NULL || key2->public_key == NULL)
        {
            return 0;
        }

        if (EVP_PKEY_eq(key1->public_key, key2->public_key) <= 0)
        {
            return 0;
        }
    }

    if ((selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0)
    {
        if (!akv_key_has_private(key1) || !akv_key_has_private(key2))
        {
            return 0;
        }

        if (key1->keyvault_type == NULL || key2->keyvault_type == NULL)
        {
            return 0;
        }

        if (strcasecmp(key1->keyvault_type, key2->keyvault_type) != 0 ||
            strcasecmp(key1->keyvault_name, key2->keyvault_name) != 0 ||
            strcasecmp(key1->key_name, key2->key_name) != 0)
        {
            return 0;
        }

        if (key1->key_version != NULL || key2->key_version != NULL)
        {
            if (key1->key_version == NULL || key2->key_version == NULL)
            {
                return 0;
            }
            if (strcasecmp(key1->key_version, key2->key_version) != 0)
            {
                return 0;
            }
        }
    }

    return 1;
}

static int akv_keymgmt_get_params(void *vkey, OSSL_PARAM params[])
{
    AKV_KEY *key = (AKV_KEY *)vkey;

    if (key == NULL || key->public_key == NULL)
    {
        return 0;
    }

    if (params == NULL)
    {
        return 1;
    }

    if (EVP_PKEY_get_params(key->public_key, params) <= 0)
    {
        return 0;
    }

    return 1;
}

static const OSSL_PARAM *akv_rsa_keymgmt_gettable_params(void *provctx)
{
    static OSSL_PARAM params[] = {
        OSSL_PARAM_int(OSSL_PKEY_PARAM_BITS, NULL),
        OSSL_PARAM_int(OSSL_PKEY_PARAM_SECURITY_BITS, NULL),
        OSSL_PARAM_int(OSSL_PKEY_PARAM_MAX_SIZE, NULL),
        OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_DEFAULT_DIGEST, NULL, 0),
        OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_MANDATORY_DIGEST, NULL, 0),
        OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_N, NULL, 0),
        OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_E, NULL, 0),
        OSSL_PARAM_END};

    (void)provctx;
    return params;
}

static const OSSL_PARAM *akv_ec_keymgmt_gettable_params(void *provctx)
{
    static OSSL_PARAM params[] = {
        OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME, NULL, 0),
        OSSL_PARAM_int(OSSL_PKEY_PARAM_BITS, NULL),
        OSSL_PARAM_int(OSSL_PKEY_PARAM_SECURITY_BITS, NULL),
        OSSL_PARAM_int(OSSL_PKEY_PARAM_MAX_SIZE, NULL),
        OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_MANDATORY_DIGEST, NULL, 0),
        OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PUB_KEY, NULL, 0),
        OSSL_PARAM_BN(OSSL_PKEY_PARAM_EC_PUB_X, NULL, 0),
        OSSL_PARAM_BN(OSSL_PKEY_PARAM_EC_PUB_Y, NULL, 0),
        OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY, NULL, 0),
        OSSL_PARAM_END};

    (void)provctx;
    return params;
}

static int akv_keymgmt_set_params(void *vkey, const OSSL_PARAM params[])
{
    AKV_KEY *key = (AKV_KEY *)vkey;

    if (key == NULL || key->public_key == NULL)
    {
        return 0;
    }

    if (params == NULL)
    {
        return 1;
    }

    if (EVP_PKEY_set_params(key->public_key, (OSSL_PARAM *)params) <= 0)
    {
        return 0;
    }

    return 1;
}

static const OSSL_PARAM *akv_rsa_keymgmt_settable_params(void *provctx)
{
    static OSSL_PARAM params[] = {
        OSSL_PARAM_END};

    (void)provctx;
    return params;
}

static const OSSL_PARAM *akv_ec_keymgmt_settable_params(void *provctx)
{
    static OSSL_PARAM params[] = {
        OSSL_PARAM_END};

    (void)provctx;
    return params;
}

static int akv_keymgmt_export(void *vkey, int selection, OSSL_CALLBACK *cb, void *cbarg)
{
    AKV_KEY *key = (AKV_KEY *)vkey;
    OSSL_PARAM *params = NULL;
    int ok = 0;

    if (key == NULL || key->public_key == NULL)
    {
        return 0;
    }

    if (EVP_PKEY_todata(key->public_key, selection, &params) <= 0)
    {
        return 0;
    }

    ok = cb(params, cbarg);
    OSSL_PARAM_free(params);
    return ok;
}

static const OSSL_PARAM *akv_rsa_keymgmt_eximport_types(int selection)
{
    static const OSSL_PARAM rsa_public_key_types[] = {
        OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_N, NULL, 0),
        OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_E, NULL, 0),
        OSSL_PARAM_END};

    if ((selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0)
    {
        return rsa_public_key_types;
    }

    return NULL;
}

static const OSSL_PARAM *akv_ec_keymgmt_eximport_types(int selection)
{
    static const OSSL_PARAM ecc_public_key_types[] = {
        OSSL_PARAM_BN(OSSL_PKEY_PARAM_EC_PUB_X, NULL, 0),
        OSSL_PARAM_BN(OSSL_PKEY_PARAM_EC_PUB_Y, NULL, 0),
        OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME, NULL, 0),
        OSSL_PARAM_END};

    if ((selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0)
    {
        return ecc_public_key_types;
    }

    return NULL;
}

static int akv_keymgmt_import_common(AKV_KEY *key, const char *algorithm, int selection, const OSSL_PARAM params[])
{
    EVP_PKEY_CTX *ctx = NULL;
    EVP_PKEY *tmp = NULL;
    int ok = 0;

    if (key == NULL)
    {
        return 0;
    }

    ctx = EVP_PKEY_CTX_new_from_name(NULL, algorithm, NULL);
    if (ctx == NULL)
    {
        goto end;
    }

    if (EVP_PKEY_fromdata_init(ctx) <= 0)
    {
        goto end;
    }

    if (EVP_PKEY_fromdata(ctx, &tmp, selection, (OSSL_PARAM *)params) <= 0)
    {
        goto end;
    }

    akv_key_set_public(key, tmp);
    tmp = NULL;
    ok = 1;

end:
    if (ctx != NULL)
    {
        EVP_PKEY_CTX_free(ctx);
    }
    if (tmp != NULL)
    {
        EVP_PKEY_free(tmp);
    }
    return ok;
}

static int akv_rsa_keymgmt_import(void *vkey, int selection, const OSSL_PARAM params[])
{
    return akv_keymgmt_import_common((AKV_KEY *)vkey, "RSA", selection, params);
}

static int akv_ec_keymgmt_import(void *vkey, int selection, const OSSL_PARAM params[])
{
    return akv_keymgmt_import_common((AKV_KEY *)vkey, "EC", selection, params);
}

static const char *akv_rsa_keymgmt_query(int operation_id)
{
    if (operation_id == OSSL_OP_SIGNATURE)
    {
        return "RSA";
    }
    if (operation_id == OSSL_OP_ASYM_CIPHER)
    {
        return "RSA";
    }
    return NULL;
}

static const char *akv_ec_keymgmt_query(int operation_id)
{
    if (operation_id == OSSL_OP_SIGNATURE)
    {
        return "ECDSA";
    }
    return NULL;
}

const OSSL_DISPATCH akv_rsa_keymgmt_functions[] = {
    {OSSL_FUNC_KEYMGMT_NEW, (void (*)(void))akv_keymgmt_new},
    {OSSL_FUNC_KEYMGMT_FREE, (void (*)(void))akv_keymgmt_free},
    {OSSL_FUNC_KEYMGMT_LOAD, (void (*)(void))akv_keymgmt_load},
    {OSSL_FUNC_KEYMGMT_HAS, (void (*)(void))akv_keymgmt_has},
    {OSSL_FUNC_KEYMGMT_MATCH, (void (*)(void))akv_keymgmt_match},
    {OSSL_FUNC_KEYMGMT_GET_PARAMS, (void (*)(void))akv_keymgmt_get_params},
    {OSSL_FUNC_KEYMGMT_GETTABLE_PARAMS, (void (*)(void))akv_rsa_keymgmt_gettable_params},
    {OSSL_FUNC_KEYMGMT_SET_PARAMS, (void (*)(void))akv_keymgmt_set_params},
    {OSSL_FUNC_KEYMGMT_SETTABLE_PARAMS, (void (*)(void))akv_rsa_keymgmt_settable_params},
    {OSSL_FUNC_KEYMGMT_IMPORT, (void (*)(void))akv_rsa_keymgmt_import},
    {OSSL_FUNC_KEYMGMT_IMPORT_TYPES, (void (*)(void))akv_rsa_keymgmt_eximport_types},
    {OSSL_FUNC_KEYMGMT_EXPORT, (void (*)(void))akv_keymgmt_export},
    {OSSL_FUNC_KEYMGMT_EXPORT_TYPES, (void (*)(void))akv_rsa_keymgmt_eximport_types},
    {OSSL_FUNC_KEYMGMT_QUERY_OPERATION_NAME, (void (*)(void))akv_rsa_keymgmt_query},
    {0, NULL}};

const OSSL_DISPATCH akv_ec_keymgmt_functions[] = {
    {OSSL_FUNC_KEYMGMT_NEW, (void (*)(void))akv_keymgmt_new},
    {OSSL_FUNC_KEYMGMT_FREE, (void (*)(void))akv_keymgmt_free},
    {OSSL_FUNC_KEYMGMT_LOAD, (void (*)(void))akv_keymgmt_load},
    {OSSL_FUNC_KEYMGMT_HAS, (void (*)(void))akv_keymgmt_has},
    {OSSL_FUNC_KEYMGMT_MATCH, (void (*)(void))akv_keymgmt_match},
    {OSSL_FUNC_KEYMGMT_GET_PARAMS, (void (*)(void))akv_keymgmt_get_params},
    {OSSL_FUNC_KEYMGMT_GETTABLE_PARAMS, (void (*)(void))akv_ec_keymgmt_gettable_params},
    {OSSL_FUNC_KEYMGMT_SET_PARAMS, (void (*)(void))akv_keymgmt_set_params},
    {OSSL_FUNC_KEYMGMT_SETTABLE_PARAMS, (void (*)(void))akv_ec_keymgmt_settable_params},
    {OSSL_FUNC_KEYMGMT_IMPORT, (void (*)(void))akv_ec_keymgmt_import},
    {OSSL_FUNC_KEYMGMT_IMPORT_TYPES, (void (*)(void))akv_ec_keymgmt_eximport_types},
    {OSSL_FUNC_KEYMGMT_EXPORT, (void (*)(void))akv_keymgmt_export},
    {OSSL_FUNC_KEYMGMT_EXPORT_TYPES, (void (*)(void))akv_ec_keymgmt_eximport_types},
    {OSSL_FUNC_KEYMGMT_QUERY_OPERATION_NAME, (void (*)(void))akv_ec_keymgmt_query},
    {0, NULL}};
