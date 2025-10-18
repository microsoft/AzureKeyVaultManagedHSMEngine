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

/* Duplicate a string while taking ownership of the destination slot. */
static int akv_dup_string(char **dst, const char *src)
{
    char *tmp = NULL;
    size_t len = 0;

    Log(LogLevel_Trace, "akv_dup_string dst=%p src=%p", (void *)dst, (const void *)src);

    if (dst == NULL)
    {
        Log(LogLevel_Debug, "akv_dup_string -> 0 (dst null)");
        return 0;
    }

    if (src == NULL)
    {
        free(*dst);
        *dst = NULL;
        Log(LogLevel_Debug, "akv_dup_string -> 1 (cleared destination)");
        return 1;
    }

    tmp = (char *)malloc(strlen(src) + 1);
    if (tmp == NULL)
    {
        Log(LogLevel_Debug, "akv_dup_string -> 0 (alloc failed)");
        return 0;
    }

    len = strlen(src);
    memcpy(tmp, src, len + 1);
    free(*dst);
    *dst = tmp;
    Log(LogLevel_Debug, "akv_dup_string -> 1 (copied %zu bytes)", len);
    return 1;
}

AKV_KEY *akv_key_new(AKV_PROVIDER_CTX *provctx)
{
    AKV_KEY *key = (AKV_KEY *)calloc(1, sizeof(AKV_KEY));
    Log(LogLevel_Trace, "akv_key_new provctx=%p", (void *)provctx);
    if (key == NULL)
    {
        Log(LogLevel_Error, "akv_key_new allocation failed");
        Log(LogLevel_Debug, "akv_key_new -> NULL");
        return NULL;
    }

    key->provctx = provctx;
    Log(LogLevel_Debug, "akv_key_new -> %p", (void *)key);
    return key;
}

void akv_key_free(AKV_KEY *key)
{
    Log(LogLevel_Trace, "akv_key_free key=%p", (void *)key);
    if (key == NULL)
    {
        Log(LogLevel_Debug, "akv_key_free skipped (null key)");
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
    Log(LogLevel_Debug, "akv_key_free complete");
}

int akv_key_set_metadata(AKV_KEY *key, const char *type, const char *vault, const char *name, const char *version)
{
    Log(LogLevel_Trace,
        "akv_key_set_metadata key=%p type=%s vault=%s name=%s version=%s",
        (void *)key,
        type != NULL ? type : "(null)",
        vault != NULL ? vault : "(null)",
        name != NULL ? name : "(null)",
        version != NULL ? version : "(null)");
    if (key == NULL)
    {
        Log(LogLevel_Debug, "akv_key_set_metadata -> 0 (null key)");
        return 0;
    }

    if (!akv_dup_string(&key->keyvault_type, type))
    {
        Log(LogLevel_Debug, "akv_key_set_metadata -> 0 (type copy failed)");
        return 0;
    }
    if (!akv_dup_string(&key->keyvault_name, vault))
    {
        Log(LogLevel_Debug, "akv_key_set_metadata -> 0 (vault copy failed)");
        return 0;
    }
    if (!akv_dup_string(&key->key_name, name))
    {
        Log(LogLevel_Debug, "akv_key_set_metadata -> 0 (name copy failed)");
        return 0;
    }
    if (!akv_dup_string(&key->key_version, version))
    {
        Log(LogLevel_Debug, "akv_key_set_metadata -> 0 (version copy failed)");
        return 0;
    }

    Log(LogLevel_Debug,
        "akv_key_set_metadata cached id type=%s vault=%s name=%s version=%s",
        key->keyvault_type != NULL ? key->keyvault_type : "(null)",
        key->keyvault_name != NULL ? key->keyvault_name : "(null)",
        key->key_name != NULL ? key->key_name : "(null)",
        key->key_version != NULL ? key->key_version : "(null)");

    return 1;
}

void akv_key_set_public(AKV_KEY *key, EVP_PKEY *pkey)
{
    Log(LogLevel_Trace, "akv_key_set_public key=%p pkey=%p", (void *)key, (void *)pkey);
    if (key == NULL)
    {
        Log(LogLevel_Debug, "akv_key_set_public ignored (null key)");
        return;
    }

    if (key->public_key != NULL)
    {
        EVP_PKEY_free(key->public_key);
    }

    key->public_key = pkey;
    Log(LogLevel_Debug, "akv_key_set_public attached EVP_PKEY %p to key %p", (void *)pkey, (void *)key);
}

static int akv_key_has_private(const AKV_KEY *key)
{
    Log(LogLevel_Trace, "akv_key_has_private key=%p", (const void *)key);
    int result = key != NULL &&
                 key->keyvault_type != NULL &&
                 key->keyvault_name != NULL &&
                 key->key_name != NULL;
    Log(LogLevel_Debug, "akv_key_has_private -> %d", result);
    return result;
}

static void *akv_keymgmt_new(void *provctx)
{
    Log(LogLevel_Trace, "akv_keymgmt_new provctx=%p", provctx);
    void *result = akv_key_new((AKV_PROVIDER_CTX *)provctx);
    Log(LogLevel_Debug, "akv_keymgmt_new -> %p", result);
    return result;
}

static void akv_keymgmt_free(void *vkey)
{
    Log(LogLevel_Trace, "akv_keymgmt_free key=%p", vkey);
    akv_key_free((AKV_KEY *)vkey);
    Log(LogLevel_Debug, "akv_keymgmt_free complete for %p", vkey);
}

static void *akv_keymgmt_load(const void *reference, size_t reference_sz)
{
    AKV_KEY *key = NULL;

    Log(LogLevel_Trace, "akv_keymgmt_load reference=%p size=%zu", reference, reference_sz);

    if (reference == NULL || reference_sz != sizeof(key))
    {
        Log(LogLevel_Debug, "akv_keymgmt_load -> NULL (invalid reference)");
        return NULL;
    }

    key = *(AKV_KEY **)reference;
    *(AKV_KEY **)reference = NULL;
    Log(LogLevel_Debug, "akv_keymgmt_load -> %p", (void *)key);
    return key;
}

static int akv_keymgmt_has(const void *vkey, int selection)
{
    const AKV_KEY *key = (const AKV_KEY *)vkey;

    Log(LogLevel_Trace, "akv_keymgmt_has key=%p selection=0x%x", vkey, selection);

    if (key == NULL)
    {
        Log(LogLevel_Debug, "akv_keymgmt_has -> 0 (null key)");
        return 0;
    }

    if ((selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0 && key->public_key == NULL)
    {
        Log(LogLevel_Debug, "akv_keymgmt_has -> 0 (missing public key)");
        return 0;
    }

    if ((selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0 && !akv_key_has_private(key))
    {
        Log(LogLevel_Debug, "akv_keymgmt_has -> 0 (missing private metadata)");
        return 0;
    }

    Log(LogLevel_Debug, "akv_keymgmt_has -> 1");
    return 1;
}

static int akv_keymgmt_match(const void *vkey1, const void *vkey2, int selection)
{
    const AKV_KEY *key1 = (const AKV_KEY *)vkey1;
    const AKV_KEY *key2 = (const AKV_KEY *)vkey2;

    Log(LogLevel_Trace, "akv_keymgmt_match key1=%p key2=%p selection=0x%x", vkey1, vkey2, selection);

    if (key1 == NULL || key2 == NULL)
    {
        Log(LogLevel_Debug, "akv_keymgmt_match -> 0 (null input)");
        return 0;
    }

    if ((selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0)
    {
        if (key1->public_key == NULL || key2->public_key == NULL)
        {
            Log(LogLevel_Debug, "akv_keymgmt_match missing public key (sel=%d)", selection);
            return 0;
        }

        if (EVP_PKEY_eq(key1->public_key, key2->public_key) <= 0)
        {
            Log(LogLevel_Debug, "akv_keymgmt_match public key mismatch (sel=%d)", selection);
            return 0;
        }
    }

    if ((selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0)
    {
        if (!akv_key_has_private(key1) || !akv_key_has_private(key2))
        {
            Log(LogLevel_Debug, "akv_keymgmt_match private metadata missing (sel=%d)", selection);
            return 0;
        }

        if (key1->keyvault_type == NULL || key2->keyvault_type == NULL)
        {
            Log(LogLevel_Debug, "akv_keymgmt_match vault type missing (sel=%d)", selection);
            return 0;
        }

        if (strcasecmp(key1->keyvault_type, key2->keyvault_type) != 0 ||
            strcasecmp(key1->keyvault_name, key2->keyvault_name) != 0 ||
            strcasecmp(key1->key_name, key2->key_name) != 0)
        {
            Log(LogLevel_Debug, "akv_keymgmt_match vault identity mismatch (sel=%d)", selection);
            return 0;
        }

        if (key1->key_version != NULL || key2->key_version != NULL)
        {
            if (key1->key_version == NULL || key2->key_version == NULL)
            {
                Log(LogLevel_Debug, "akv_keymgmt_match version presence mismatch (sel=%d)", selection);
                return 0;
            }
            if (strcasecmp(key1->key_version, key2->key_version) != 0)
            {
                Log(LogLevel_Debug, "akv_keymgmt_match version mismatch (sel=%d)", selection);
                return 0;
            }
        }
    }

    Log(LogLevel_Debug, "akv_keymgmt_match -> 1");
    return 1;
}

static int akv_keymgmt_get_params(void *vkey, OSSL_PARAM params[])
{
    AKV_KEY *key = (AKV_KEY *)vkey;

    Log(LogLevel_Trace, "akv_keymgmt_get_params key=%p", vkey);

    if (key == NULL || key->public_key == NULL)
    {
        Log(LogLevel_Debug, "akv_keymgmt_get_params -> 0 (missing key)");
        return 0;
    }

    if (params == NULL)
    {
        Log(LogLevel_Debug, "akv_keymgmt_get_params -> 1 (no params requested)");
        return 1;
    }

    if (EVP_PKEY_get_params(key->public_key, params) <= 0)
    {
        Log(LogLevel_Debug, "akv_keymgmt_get_params -> 0 (EVP_PKEY_get_params failed)");
        return 0;
    }

    Log(LogLevel_Debug, "akv_keymgmt_get_params -> 1");
    return 1;
}

static const OSSL_PARAM *akv_rsa_keymgmt_gettable_params(void *provctx)
{
    Log(LogLevel_Trace, "akv_rsa_keymgmt_gettable_params provctx=%p", provctx);
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
    Log(LogLevel_Debug, "akv_rsa_keymgmt_gettable_params -> %p", (void *)params);
    return params;
}

static const OSSL_PARAM *akv_ec_keymgmt_gettable_params(void *provctx)
{
    Log(LogLevel_Trace, "akv_ec_keymgmt_gettable_params provctx=%p", provctx);
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
    Log(LogLevel_Debug, "akv_ec_keymgmt_gettable_params -> %p", (void *)params);
    return params;
}

static int akv_keymgmt_set_params(void *vkey, const OSSL_PARAM params[])
{
    AKV_KEY *key = (AKV_KEY *)vkey;

    Log(LogLevel_Trace, "akv_keymgmt_set_params key=%p params=%p", vkey, params);

    if (key == NULL || key->public_key == NULL)
    {
        Log(LogLevel_Debug, "akv_keymgmt_set_params -> 0 (missing key)");
        return 0;
    }

    if (params == NULL)
    {
        Log(LogLevel_Debug, "akv_keymgmt_set_params -> 1 (no params to set)");
        return 1;
    }

    if (EVP_PKEY_set_params(key->public_key, (OSSL_PARAM *)params) <= 0)
    {
        Log(LogLevel_Debug, "akv_keymgmt_set_params -> 0 (EVP_PKEY_set_params failed)");
        return 0;
    }

    Log(LogLevel_Debug, "akv_keymgmt_set_params -> 1");
    return 1;
}

static const OSSL_PARAM *akv_rsa_keymgmt_settable_params(void *provctx)
{
    Log(LogLevel_Trace, "akv_rsa_keymgmt_settable_params provctx=%p", provctx);
    static OSSL_PARAM params[] = {
        OSSL_PARAM_END};

    (void)provctx;
    Log(LogLevel_Debug, "akv_rsa_keymgmt_settable_params -> %p", (void *)params);
    return params;
}

static const OSSL_PARAM *akv_ec_keymgmt_settable_params(void *provctx)
{
    Log(LogLevel_Trace, "akv_ec_keymgmt_settable_params provctx=%p", provctx);
    static OSSL_PARAM params[] = {
        OSSL_PARAM_END};

    (void)provctx;
    Log(LogLevel_Debug, "akv_ec_keymgmt_settable_params -> %p", (void *)params);
    return params;
}

static int akv_keymgmt_export(void *vkey, int selection, OSSL_CALLBACK *cb, void *cbarg)
{
    AKV_KEY *key = (AKV_KEY *)vkey;
    OSSL_PARAM *params = NULL;
    int ok = 0;

    Log(LogLevel_Trace, "akv_keymgmt_export key=%p selection=0x%x cb=%p cbarg=%p", vkey, selection, (void *)cb, cbarg);

    if (key == NULL || key->public_key == NULL)
    {
        Log(LogLevel_Debug, "akv_keymgmt_export -> 0 (missing key)");
        return 0;
    }

    if (EVP_PKEY_todata(key->public_key, selection, &params) <= 0)
    {
        Log(LogLevel_Error, "akv_keymgmt_export failed to map key to params (sel=%d)", selection);
        Log(LogLevel_Debug, "akv_keymgmt_export -> 0 (todata failed)");
        return 0;
    }

    ok = cb(params, cbarg);
    OSSL_PARAM_free(params);
    Log(LogLevel_Debug, "akv_keymgmt_export -> %d", ok);
    return ok;
}

static const OSSL_PARAM *akv_rsa_keymgmt_eximport_types(int selection)
{
    Log(LogLevel_Trace, "akv_rsa_keymgmt_eximport_types selection=0x%x", selection);
    static const OSSL_PARAM rsa_public_key_types[] = {
        OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_N, NULL, 0),
        OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_E, NULL, 0),
        OSSL_PARAM_END};

    if ((selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0)
    {
        Log(LogLevel_Debug, "akv_rsa_keymgmt_eximport_types -> %p", (const void *)rsa_public_key_types);
        return rsa_public_key_types;
    }

    Log(LogLevel_Debug, "akv_rsa_keymgmt_eximport_types -> NULL");
    return NULL;
}

static const OSSL_PARAM *akv_ec_keymgmt_eximport_types(int selection)
{
    Log(LogLevel_Trace, "akv_ec_keymgmt_eximport_types selection=0x%x", selection);
    static const OSSL_PARAM ecc_public_key_types[] = {
        OSSL_PARAM_BN(OSSL_PKEY_PARAM_EC_PUB_X, NULL, 0),
        OSSL_PARAM_BN(OSSL_PKEY_PARAM_EC_PUB_Y, NULL, 0),
        OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME, NULL, 0),
        OSSL_PARAM_END};

    if ((selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0)
    {
        Log(LogLevel_Debug, "akv_ec_keymgmt_eximport_types -> %p", (const void *)ecc_public_key_types);
        return ecc_public_key_types;
    }

    Log(LogLevel_Debug, "akv_ec_keymgmt_eximport_types -> NULL");
    return NULL;
}

static int akv_keymgmt_import_common(AKV_KEY *key, const char *algorithm, int selection, const OSSL_PARAM params[])
{
    EVP_PKEY_CTX *ctx = NULL;
    EVP_PKEY *tmp = NULL;
    int ok = 0;

    Log(LogLevel_Trace,
        "akv_keymgmt_import_common key=%p algorithm=%s selection=0x%x params=%p",
        (void *)key,
        algorithm,
        selection,
        (const void *)params);

    if (key == NULL)
    {
        Log(LogLevel_Debug, "akv_keymgmt_import_common -> 0 (null key)");
        return 0;
    }

    ctx = EVP_PKEY_CTX_new_from_name(NULL, algorithm, NULL);
    if (ctx == NULL)
    {
        Log(LogLevel_Error, "akv_keymgmt_import_common failed to create ctx for %s", algorithm);
        goto end;
    }

    if (EVP_PKEY_fromdata_init(ctx) <= 0)
    {
        Log(LogLevel_Error, "akv_keymgmt_import_common fromdata_init failed for %s", algorithm);
        goto end;
    }

    if (EVP_PKEY_fromdata(ctx, &tmp, selection, (OSSL_PARAM *)params) <= 0)
    {
        Log(LogLevel_Error, "akv_keymgmt_import_common fromdata failed for %s (sel=%d)", algorithm, selection);
        goto end;
    }

    akv_key_set_public(key, tmp);
    tmp = NULL;
    Log(LogLevel_Debug, "akv_keymgmt_import_common imported %s key into %p", algorithm, (void *)key);
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
    Log(LogLevel_Debug, "akv_keymgmt_import_common -> %d", ok);
    return ok;
}

static int akv_rsa_keymgmt_import(void *vkey, int selection, const OSSL_PARAM params[])
{
    Log(LogLevel_Trace, "akv_rsa_keymgmt_import key=%p selection=0x%x params=%p", vkey, selection, (const void *)params);
    int result = akv_keymgmt_import_common((AKV_KEY *)vkey, "RSA", selection, params);
    Log(LogLevel_Debug, "akv_rsa_keymgmt_import -> %d", result);
    return result;
}

static int akv_ec_keymgmt_import(void *vkey, int selection, const OSSL_PARAM params[])
{
    Log(LogLevel_Trace, "akv_ec_keymgmt_import key=%p selection=0x%x params=%p", vkey, selection, (const void *)params);
    int result = akv_keymgmt_import_common((AKV_KEY *)vkey, "EC", selection, params);
    Log(LogLevel_Debug, "akv_ec_keymgmt_import -> %d", result);
    return result;
}

static const char *akv_rsa_keymgmt_query(int operation_id)
{
    Log(LogLevel_Trace, "akv_rsa_keymgmt_query operation_id=%d", operation_id);
    if (operation_id == OSSL_OP_SIGNATURE)
    {
        Log(LogLevel_Debug, "akv_rsa_keymgmt_query -> RSA (signature)");
        return "RSA";
    }
    if (operation_id == OSSL_OP_ASYM_CIPHER)
    {
        Log(LogLevel_Debug, "akv_rsa_keymgmt_query -> RSA (asym cipher)");
        return "RSA";
    }
    Log(LogLevel_Debug, "akv_rsa_keymgmt_query -> NULL");
    return NULL;
}

static const char *akv_ec_keymgmt_query(int operation_id)
{
    Log(LogLevel_Trace, "akv_ec_keymgmt_query operation_id=%d", operation_id);
    if (operation_id == OSSL_OP_SIGNATURE)
    {
        Log(LogLevel_Debug, "akv_ec_keymgmt_query -> ECDSA (signature)");
        return "ECDSA";
    }
    Log(LogLevel_Debug, "akv_ec_keymgmt_query -> NULL");
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
