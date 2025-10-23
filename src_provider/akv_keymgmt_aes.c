/* Copyright (c) Microsoft Corporation.
   Licensed under the MIT License. */

#include "akv_provider_internal.h"

/* AES key structure - simplified since we don't have local key material */
typedef struct akv_aes_key_st
{
    AKV_PROVIDER_CTX *provctx;
    char *keyvault_name;
    char *key_name;
    char *key_version;
    int key_bits;  /* Key size in bits (128, 192, 256) */
} AKV_AES_KEY;

/* Helper: duplicate string */
static int akv_aes_dup_string(char **dst, const char *src)
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

static void *akv_aes_keymgmt_new(void *provctx)
{
    AKV_AES_KEY *key = (AKV_AES_KEY *)calloc(1, sizeof(AKV_AES_KEY));
    
    Log(LogLevel_Trace, "akv_aes_keymgmt_new provctx=%p", provctx);
    
    if (key == NULL)
    {
        Log(LogLevel_Error, "akv_aes_keymgmt_new allocation failed");
        return NULL;
    }

    key->provctx = (AKV_PROVIDER_CTX *)provctx;
    key->key_bits = 256;  /* Default to AES-256 */
    
    Log(LogLevel_Debug, "akv_aes_keymgmt_new -> %p", (void *)key);
    return key;
}

static void akv_aes_keymgmt_free(void *vkey)
{
    AKV_AES_KEY *key = (AKV_AES_KEY *)vkey;
    
    Log(LogLevel_Trace, "akv_aes_keymgmt_free key=%p", vkey);
    
    if (key == NULL)
    {
        return;
    }

    free(key->keyvault_name);
    free(key->key_name);
    free(key->key_version);
    free(key);
    
    Log(LogLevel_Debug, "akv_aes_keymgmt_free complete");
}

static void *akv_aes_keymgmt_load(const void *reference, size_t reference_sz)
{
    AKV_AES_KEY *key = NULL;

    Log(LogLevel_Trace, "akv_aes_keymgmt_load reference=%p size=%zu", reference, reference_sz);

    if (reference == NULL || reference_sz != sizeof(key))
    {
        Log(LogLevel_Debug, "akv_aes_keymgmt_load -> NULL (invalid reference)");
        return NULL;
    }

    key = *(AKV_AES_KEY **)reference;
    *(AKV_AES_KEY **)reference = NULL;
    
    Log(LogLevel_Debug, "akv_aes_keymgmt_load -> %p", (void *)key);
    return key;
}

static int akv_aes_keymgmt_has(const void *vkey, int selection)
{
    const AKV_AES_KEY *key = (const AKV_AES_KEY *)vkey;

    Log(LogLevel_Trace, "akv_aes_keymgmt_has key=%p selection=0x%x", vkey, selection);

    if (key == NULL)
    {
        Log(LogLevel_Debug, "akv_aes_keymgmt_has -> 0 (null key)");
        return 0;
    }

    /* For symmetric keys, we support private key parameters (since the key is secret) and other parameters */
    if ((selection & (OSSL_KEYMGMT_SELECT_PRIVATE_KEY | OSSL_KEYMGMT_SELECT_OTHER_PARAMETERS)) != 0)
    {
        int result = (key->keyvault_name != NULL && key->key_name != NULL);
        Log(LogLevel_Debug, "akv_aes_keymgmt_has selection=0x%x -> %d", selection, result);
        return result;
    }

    Log(LogLevel_Debug, "akv_aes_keymgmt_has -> 0 (unsupported selection 0x%x)", selection);
    return 0;
}

static int akv_aes_keymgmt_match(const void *vkey1, const void *vkey2, int selection)
{
    const AKV_AES_KEY *key1 = (const AKV_AES_KEY *)vkey1;
    const AKV_AES_KEY *key2 = (const AKV_AES_KEY *)vkey2;

    Log(LogLevel_Trace, "akv_aes_keymgmt_match key1=%p key2=%p selection=0x%x", vkey1, vkey2, selection);

    (void)selection;

    if (key1 == NULL || key2 == NULL)
    {
        Log(LogLevel_Debug, "akv_aes_keymgmt_match -> 0 (null key)");
        return 0;
    }

    if (key1->keyvault_name == NULL || key2->keyvault_name == NULL ||
        key1->key_name == NULL || key2->key_name == NULL)
    {
        Log(LogLevel_Debug, "akv_aes_keymgmt_match -> 0 (missing metadata)");
        return 0;
    }

    int match = (strcmp(key1->keyvault_name, key2->keyvault_name) == 0 &&
                 strcmp(key1->key_name, key2->key_name) == 0 &&
                 ((key1->key_version == NULL && key2->key_version == NULL) ||
                  (key1->key_version != NULL && key2->key_version != NULL &&
                   strcmp(key1->key_version, key2->key_version) == 0)));

    Log(LogLevel_Debug, "akv_aes_keymgmt_match -> %d", match);
    return match;
}

/* Import wrapped key (unwrap operation) */
static int akv_aes_keymgmt_import(void *vkey, int selection, const OSSL_PARAM params[])
{
    AKV_AES_KEY *key = (AKV_AES_KEY *)vkey;
    const OSSL_PARAM *p;
    
    Log(LogLevel_Trace, "akv_aes_keymgmt_import key=%p selection=0x%x", vkey, selection);
    
    if (key == NULL)
    {
        Log(LogLevel_Error, "akv_aes_keymgmt_import: null key");
        return 0;
    }

    (void)selection;

    /* Get vault name */
    p = OSSL_PARAM_locate_const(params, "vault");
    if (p != NULL)
    {
        const char *vault = NULL;
        if (!OSSL_PARAM_get_utf8_string_ptr(p, &vault) || !akv_aes_dup_string(&key->keyvault_name, vault))
        {
            Log(LogLevel_Error, "akv_aes_keymgmt_import: failed to set vault name");
            return 0;
        }
    }

    /* Get key name */
    p = OSSL_PARAM_locate_const(params, "key");
    if (p != NULL)
    {
        const char *keyname = NULL;
        if (!OSSL_PARAM_get_utf8_string_ptr(p, &keyname) || !akv_aes_dup_string(&key->key_name, keyname))
        {
            Log(LogLevel_Error, "akv_aes_keymgmt_import: failed to set key name");
            return 0;
        }
    }

    /* Get key version (optional) */
    p = OSSL_PARAM_locate_const(params, "version");
    if (p != NULL)
    {
        const char *version = NULL;
        if (!OSSL_PARAM_get_utf8_string_ptr(p, &version) || !akv_aes_dup_string(&key->key_version, version))
        {
            Log(LogLevel_Error, "akv_aes_keymgmt_import: failed to set key version");
            return 0;
        }
    }

    /* Get key size */
    p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_BITS);
    if (p != NULL)
    {
        if (!OSSL_PARAM_get_int(p, &key->key_bits))
        {
            Log(LogLevel_Error, "akv_aes_keymgmt_import: failed to get key bits");
            return 0;
        }
    }

    Log(LogLevel_Debug, "akv_aes_keymgmt_import: vault=%s, key=%s, version=%s, bits=%d",
        key->keyvault_name ? key->keyvault_name : "(null)",
        key->key_name ? key->key_name : "(null)",
        key->key_version ? key->key_version : "(null)",
        key->key_bits);

    return 1;
}

/* Export types for import */
static const OSSL_PARAM *akv_aes_keymgmt_import_types(int selection)
{
    static const OSSL_PARAM import_types[] = {
        OSSL_PARAM_utf8_string("vault", NULL, 0),
        OSSL_PARAM_utf8_string("key", NULL, 0),
        OSSL_PARAM_utf8_string("version", NULL, 0),
        OSSL_PARAM_int(OSSL_PKEY_PARAM_BITS, NULL),
        OSSL_PARAM_END
    };

    Log(LogLevel_Trace, "akv_aes_keymgmt_import_types selection=0x%x", selection);
    (void)selection;
    return import_types;
}

/* Get key parameters */
static int akv_aes_keymgmt_get_params(void *vkey, OSSL_PARAM params[])
{
    AKV_AES_KEY *key = (AKV_AES_KEY *)vkey;
    OSSL_PARAM *p;

    Log(LogLevel_Trace, "akv_aes_keymgmt_get_params key=%p", vkey);

    if (key == NULL)
    {
        return 0;
    }

    p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_BITS);
    if (p != NULL && !OSSL_PARAM_set_int(p, key->key_bits))
    {
        return 0;
    }

    p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_SECURITY_BITS);
    if (p != NULL && !OSSL_PARAM_set_int(p, key->key_bits))
    {
        return 0;
    }

    p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_MAX_SIZE);
    if (p != NULL && !OSSL_PARAM_set_int(p, key->key_bits / 8))
    {
        return 0;
    }

    return 1;
}

static const OSSL_PARAM *akv_aes_keymgmt_gettable_params(void *provctx)
{
    static const OSSL_PARAM gettable[] = {
        OSSL_PARAM_int(OSSL_PKEY_PARAM_BITS, NULL),
        OSSL_PARAM_int(OSSL_PKEY_PARAM_SECURITY_BITS, NULL),
        OSSL_PARAM_int(OSSL_PKEY_PARAM_MAX_SIZE, NULL),
        OSSL_PARAM_END
    };

    (void)provctx;
    return gettable;
}

const OSSL_DISPATCH akv_aes_keymgmt_functions[] = {
    {OSSL_FUNC_KEYMGMT_NEW, (void (*)(void))akv_aes_keymgmt_new},
    {OSSL_FUNC_KEYMGMT_FREE, (void (*)(void))akv_aes_keymgmt_free},
    {OSSL_FUNC_KEYMGMT_LOAD, (void (*)(void))akv_aes_keymgmt_load},
    {OSSL_FUNC_KEYMGMT_HAS, (void (*)(void))akv_aes_keymgmt_has},
    {OSSL_FUNC_KEYMGMT_MATCH, (void (*)(void))akv_aes_keymgmt_match},
    {OSSL_FUNC_KEYMGMT_IMPORT, (void (*)(void))akv_aes_keymgmt_import},
    {OSSL_FUNC_KEYMGMT_IMPORT_TYPES, (void (*)(void))akv_aes_keymgmt_import_types},
    {OSSL_FUNC_KEYMGMT_GET_PARAMS, (void (*)(void))akv_aes_keymgmt_get_params},
    {OSSL_FUNC_KEYMGMT_GETTABLE_PARAMS, (void (*)(void))akv_aes_keymgmt_gettable_params},
    {0, NULL}
};
