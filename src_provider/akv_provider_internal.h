/* Copyright (c) Microsoft Corporation.
   Licensed under the MIT License. */

#ifndef AKV_PROVIDER_INTERNAL_H
#define AKV_PROVIDER_INTERNAL_H

#include "akv_provider_shared.h"

/* Forward declarations for provider subcomponents */

typedef struct akv_provider_ctx_st
{
    const OSSL_CORE_HANDLE *core;
} AKV_PROVIDER_CTX;

typedef struct akv_key_st
{
    AKV_PROVIDER_CTX *provctx;
    EVP_PKEY *public_key;
    char *keyvault_name;
    char *key_name;
    char *key_version;
} AKV_KEY;

/* Key management helpers */
AKV_KEY *akv_key_new(AKV_PROVIDER_CTX *provctx);
void akv_key_free(AKV_KEY *key);
int akv_key_set_metadata(AKV_KEY *key, const char *vault, const char *name, const char *version);
void akv_key_set_public(AKV_KEY *key, EVP_PKEY *pkey);

/* Dispatch tables exposed to the provider */
extern const OSSL_DISPATCH akv_rsa_keymgmt_functions[];
extern const OSSL_DISPATCH akv_ec_keymgmt_functions[];
extern const OSSL_DISPATCH akv_aes_keymgmt_functions[];
extern const OSSL_DISPATCH akv_rsa_signature_functions[];
extern const OSSL_DISPATCH akv_ecdsa_signature_functions[];
extern const OSSL_DISPATCH akv_rsa_asym_cipher_functions[];
extern const OSSL_DISPATCH akv_aes_asym_cipher_functions[];

#endif /* AKV_PROVIDER_INTERNAL_H */
