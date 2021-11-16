/* Copyright (c) Microsoft Corporation.
   Licensed under the MIT License. */

#include "pch.h"

AKV_KEY *acquire_akv_key(
    const char *keyvault_type, // managedHsm or vault
    const char *keyvault_name,
    const char *key_name)
{
    assert(keyvault_type);
    assert(keyvault_name);
    assert(key_name);

    AKV_KEY *res = NULL;
    AKV_KEY *akv_key = OPENSSL_zalloc(sizeof(*akv_key));
    if (!akv_key)
    {
        AKVerr(AKV_F_ACQUIRE_AKV, AKV_R_ALLOC_FAILURE);
        goto cleanup;
    }

    /*akv info*/
    akv_key->keyvault_type = OPENSSL_zalloc(strlen(keyvault_type) + 1);
    memcpy(akv_key->keyvault_type, keyvault_type, strlen(keyvault_type) + 1);
    akv_key->keyvault_name = OPENSSL_zalloc(strlen(keyvault_name) + 1);
    memcpy(akv_key->keyvault_name, keyvault_name, strlen(keyvault_name) + 1);
    akv_key->key_name = OPENSSL_zalloc(strlen(key_name) + 1);
    memcpy(akv_key->key_name, key_name, strlen(key_name) + 1);

    res = akv_key;
    akv_key = NULL;
cleanup:
    if (akv_key)
        destroy_akv_key(akv_key);
    return res;
}

void destroy_akv_key(AKV_KEY *key)
{
    assert(key);
    if (key->keyvault_type)
        OPENSSL_free(key->keyvault_type);
    if (key->keyvault_name)
        OPENSSL_free(key->keyvault_name);
    if (key->key_name)
        OPENSSL_free(key->key_name);

    OPENSSL_free(key);
}
