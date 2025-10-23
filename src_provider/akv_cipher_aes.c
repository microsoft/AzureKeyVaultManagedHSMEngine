/* Copyright (c) Microsoft Corporation.
   Licensed under the MIT License. */

#include "akv_provider_internal.h"

/* Forward declaration for AES key type */
typedef struct akv_aes_key_st
{
    AKV_PROVIDER_CTX *provctx;
    char *keyvault_name;
    char *key_name;
    char *key_version;
    int key_bits;
} AKV_AES_KEY;

typedef struct akv_aes_cipher_ctx_st
{
    AKV_PROVIDER_CTX *provctx;
    AKV_AES_KEY *key;
    char *algorithm;  /* "A128KW", "A192KW", "A256KW" */
} AKV_AES_CIPHER_CTX;

static void *akv_aes_cipher_newctx(void *provctx, const char *propq)
{
    AKV_AES_CIPHER_CTX *ctx = (AKV_AES_CIPHER_CTX *)calloc(1, sizeof(AKV_AES_CIPHER_CTX));
    
    (void)propq;
    
    Log(LogLevel_Trace, "akv_aes_cipher_newctx provctx=%p", provctx);
    
    if (ctx == NULL)
    {
        Log(LogLevel_Error, "akv_aes_cipher_newctx allocation failed");
        return NULL;
    }

    ctx->provctx = (AKV_PROVIDER_CTX *)provctx;
    ctx->algorithm = NULL;
    
    Log(LogLevel_Debug, "akv_aes_cipher_newctx -> %p", (void *)ctx);
    return ctx;
}

static void akv_aes_cipher_freectx(void *vctx)
{
    AKV_AES_CIPHER_CTX *ctx = (AKV_AES_CIPHER_CTX *)vctx;
    
    Log(LogLevel_Trace, "akv_aes_cipher_freectx ctx=%p", vctx);
    
    if (ctx == NULL)
    {
        return;
    }

    free(ctx->algorithm);
    free(ctx);
    
    Log(LogLevel_Debug, "akv_aes_cipher_freectx complete");
}

static void *akv_aes_cipher_dupctx(void *vctx)
{
    AKV_AES_CIPHER_CTX *ctx = (AKV_AES_CIPHER_CTX *)vctx;
    AKV_AES_CIPHER_CTX *dup = NULL;

    Log(LogLevel_Trace, "akv_aes_cipher_dupctx ctx=%p", vctx);

    if (ctx == NULL)
    {
        return NULL;
    }

    dup = (AKV_AES_CIPHER_CTX *)calloc(1, sizeof(AKV_AES_CIPHER_CTX));
    if (dup == NULL)
    {
        return NULL;
    }

    dup->provctx = ctx->provctx;
    dup->key = ctx->key;
    
    if (ctx->algorithm != NULL)
    {
        dup->algorithm = (char *)malloc(strlen(ctx->algorithm) + 1);
        if (dup->algorithm != NULL)
        {
            memcpy(dup->algorithm, ctx->algorithm, strlen(ctx->algorithm) + 1);
        }
    }

    Log(LogLevel_Debug, "akv_aes_cipher_dupctx -> %p", (void *)dup);
    return dup;
}

/* Determine the Azure algorithm based on key size */
static const char *akv_aes_get_algorithm(const AKV_AES_CIPHER_CTX *ctx)
{
    Log(LogLevel_Trace, "akv_aes_get_algorithm ctx=%p", (const void *)ctx);
    
    if (ctx->algorithm != NULL)
    {
        Log(LogLevel_Debug, "akv_aes_get_algorithm -> %s (preset)", ctx->algorithm);
        return ctx->algorithm;
    }
    
    if (ctx->key == NULL)
    {
        Log(LogLevel_Error, "akv_aes_get_algorithm: no key set");
        return NULL;
    }

    /* Map key size to Azure algorithm name */
    switch (ctx->key->key_bits)
    {
    case 128:
        Log(LogLevel_Debug, "akv_aes_get_algorithm -> A128KW");
        return "A128KW";
    case 192:
        Log(LogLevel_Debug, "akv_aes_get_algorithm -> A192KW");
        return "A192KW";
    case 256:
        Log(LogLevel_Debug, "akv_aes_get_algorithm -> A256KW");
        return "A256KW";
    default:
        Log(LogLevel_Error, "akv_aes_get_algorithm: unsupported key size %d", ctx->key->key_bits);
        return NULL;
    }
}

static int akv_aes_cipher_encrypt_init(void *vctx, void *vkey, const OSSL_PARAM params[])
{
    AKV_AES_CIPHER_CTX *ctx = (AKV_AES_CIPHER_CTX *)vctx;
    
    Log(LogLevel_Trace, "akv_aes_cipher_encrypt_init ctx=%p key=%p", vctx, vkey);
    
    if (ctx == NULL || vkey == NULL)
    {
        Log(LogLevel_Error, "akv_aes_cipher_encrypt_init: null context or key");
        return 0;
    }

    ctx->key = (AKV_AES_KEY *)vkey;
    
    /* Process parameters if any */
    (void)params;

    Log(LogLevel_Debug, "akv_aes_cipher_encrypt_init -> 1");
    return 1;
}

static int akv_aes_cipher_decrypt_init(void *vctx, void *vkey, const OSSL_PARAM params[])
{
    AKV_AES_CIPHER_CTX *ctx = (AKV_AES_CIPHER_CTX *)vctx;
    
    Log(LogLevel_Trace, "akv_aes_cipher_decrypt_init ctx=%p key=%p", vctx, vkey);
    
    if (ctx == NULL || vkey == NULL)
    {
        Log(LogLevel_Error, "akv_aes_cipher_decrypt_init: null context or key");
        return 0;
    }

    ctx->key = (AKV_AES_KEY *)vkey;
    
    /* Process parameters if any */
    (void)params;

    Log(LogLevel_Debug, "akv_aes_cipher_decrypt_init -> 1");
    return 1;
}

/* Wrap operation (encrypt) */
static int akv_aes_cipher_encrypt(void *vctx, unsigned char *out, size_t *outlen, 
                                  size_t outsize, const unsigned char *in, size_t inlen)
{
    AKV_AES_CIPHER_CTX *ctx = (AKV_AES_CIPHER_CTX *)vctx;
    MemoryStruct token = {0};
    MemoryStruct wrapped = {0};
    const char *algorithm = NULL;
    int ok = 0;

    Log(LogLevel_Trace, "akv_aes_cipher_encrypt ctx=%p outlen=%zu inlen=%zu", 
        vctx, outlen ? *outlen : 0, inlen);

    if (ctx == NULL || ctx->key == NULL || outlen == NULL)
    {
        Log(LogLevel_Error, "akv_aes_cipher_encrypt: invalid parameters");
        return 0;
    }

    /* Size query */
    if (out == NULL)
    {
        /* Wrapped key is typically input size + 8 bytes for AES-KW */
        *outlen = inlen + 8;
        Log(LogLevel_Debug, "akv_aes_cipher_encrypt size query -> %zu", *outlen);
        return 1;
    }

    algorithm = akv_aes_get_algorithm(ctx);
    if (algorithm == NULL)
    {
        Log(LogLevel_Error, "akv_aes_cipher_encrypt: failed to determine algorithm");
        goto end;
    }

    if (!GetAccessTokenFromEnv(&token))
    {
        Log(LogLevel_Error, "akv_aes_cipher_encrypt: failed to get access token");
        goto end;
    }

    if (!AkvWrap(ctx->key->keyvault_name,
                 ctx->key->key_name,
                 &token,
                 algorithm,
                 in,
                 inlen,
                 &wrapped))
    {
        Log(LogLevel_Error, "akv_aes_cipher_encrypt: AkvWrap failed");
        goto end;
    }

    if (wrapped.size > outsize)
    {
        Log(LogLevel_Error, "akv_aes_cipher_encrypt: output buffer too small (%zu < %zu)", 
            outsize, wrapped.size);
        goto end;
    }

    memcpy(out, wrapped.memory, wrapped.size);
    *outlen = wrapped.size;
    ok = 1;

    Log(LogLevel_Debug, "akv_aes_cipher_encrypt: wrapped %zu bytes -> %zu bytes", 
        inlen, wrapped.size);

end:
    if (token.memory != NULL)
    {
        free(token.memory);
    }
    if (wrapped.memory != NULL)
    {
        free(wrapped.memory);
    }
    return ok;
}

/* Unwrap operation (decrypt) */
static int akv_aes_cipher_decrypt(void *vctx, unsigned char *out, size_t *outlen,
                                  size_t outsize, const unsigned char *in, size_t inlen)
{
    AKV_AES_CIPHER_CTX *ctx = (AKV_AES_CIPHER_CTX *)vctx;
    MemoryStruct token = {0};
    MemoryStruct unwrapped = {0};
    const char *algorithm = NULL;
    int ok = 0;

    Log(LogLevel_Trace, "akv_aes_cipher_decrypt ctx=%p outlen=%zu inlen=%zu",
        vctx, outlen ? *outlen : 0, inlen);

    if (ctx == NULL || ctx->key == NULL || outlen == NULL)
    {
        Log(LogLevel_Error, "akv_aes_cipher_decrypt: invalid parameters");
        return 0;
    }

    /* Size query */
    if (out == NULL)
    {
        /* Unwrapped key is typically wrapped size - 8 bytes */
        *outlen = inlen > 8 ? inlen - 8 : inlen;
        Log(LogLevel_Debug, "akv_aes_cipher_decrypt size query -> %zu", *outlen);
        return 1;
    }

    algorithm = akv_aes_get_algorithm(ctx);
    if (algorithm == NULL)
    {
        Log(LogLevel_Error, "akv_aes_cipher_decrypt: failed to determine algorithm");
        goto end;
    }

    if (!GetAccessTokenFromEnv(&token))
    {
        Log(LogLevel_Error, "akv_aes_cipher_decrypt: failed to get access token");
        goto end;
    }

    if (!AkvUnwrap(ctx->key->keyvault_name,
                   ctx->key->key_name,
                   &token,
                   algorithm,
                   in,
                   inlen,
                   &unwrapped))
    {
        Log(LogLevel_Error, "akv_aes_cipher_decrypt: AkvUnwrap failed");
        goto end;
    }

    if (unwrapped.size > outsize)
    {
        Log(LogLevel_Error, "akv_aes_cipher_decrypt: output buffer too small (%zu < %zu)",
            outsize, unwrapped.size);
        goto end;
    }

    memcpy(out, unwrapped.memory, unwrapped.size);
    *outlen = unwrapped.size;
    ok = 1;

    Log(LogLevel_Debug, "akv_aes_cipher_decrypt: unwrapped %zu bytes -> %zu bytes",
        inlen, unwrapped.size);

end:
    if (token.memory != NULL)
    {
        free(token.memory);
    }
    if (unwrapped.memory != NULL)
    {
        free(unwrapped.memory);
    }
    return ok;
}

static const OSSL_PARAM *akv_aes_cipher_gettable_ctx_params(void *cctx, void *provctx)
{
    static const OSSL_PARAM gettable[] = {
        OSSL_PARAM_utf8_string("algorithm", NULL, 0),
        OSSL_PARAM_END
    };

    (void)cctx;
    (void)provctx;
    return gettable;
}

static const OSSL_PARAM *akv_aes_cipher_settable_ctx_params(void *cctx, void *provctx)
{
    static const OSSL_PARAM settable[] = {
        OSSL_PARAM_utf8_string("algorithm", NULL, 0),
        OSSL_PARAM_END
    };

    (void)cctx;
    (void)provctx;
    return settable;
}

static int akv_aes_cipher_get_ctx_params(void *vctx, OSSL_PARAM params[])
{
    AKV_AES_CIPHER_CTX *ctx = (AKV_AES_CIPHER_CTX *)vctx;
    OSSL_PARAM *p;

    if (ctx == NULL)
    {
        return 0;
    }

    p = OSSL_PARAM_locate(params, "algorithm");
    if (p != NULL)
    {
        const char *alg = akv_aes_get_algorithm(ctx);
        if (alg == NULL || !OSSL_PARAM_set_utf8_string(p, alg))
        {
            return 0;
        }
    }

    return 1;
}

static int akv_aes_cipher_set_ctx_params(void *vctx, const OSSL_PARAM params[])
{
    AKV_AES_CIPHER_CTX *ctx = (AKV_AES_CIPHER_CTX *)vctx;
    const OSSL_PARAM *p;

    if (ctx == NULL)
    {
        return 0;
    }

    p = OSSL_PARAM_locate_const(params, "algorithm");
    if (p != NULL)
    {
        const char *alg = NULL;
        if (!OSSL_PARAM_get_utf8_string_ptr(p, &alg))
        {
            return 0;
        }
        
        free(ctx->algorithm);
        ctx->algorithm = (char *)malloc(strlen(alg) + 1);
        if (ctx->algorithm == NULL)
        {
            return 0;
        }
        memcpy(ctx->algorithm, alg, strlen(alg) + 1);
    }

    return 1;
}

const OSSL_DISPATCH akv_aes_asym_cipher_functions[] = {
    {OSSL_FUNC_ASYM_CIPHER_NEWCTX, (void (*)(void))akv_aes_cipher_newctx},
    {OSSL_FUNC_ASYM_CIPHER_FREECTX, (void (*)(void))akv_aes_cipher_freectx},
    {OSSL_FUNC_ASYM_CIPHER_DUPCTX, (void (*)(void))akv_aes_cipher_dupctx},
    {OSSL_FUNC_ASYM_CIPHER_ENCRYPT_INIT, (void (*)(void))akv_aes_cipher_encrypt_init},
    {OSSL_FUNC_ASYM_CIPHER_DECRYPT_INIT, (void (*)(void))akv_aes_cipher_decrypt_init},
    {OSSL_FUNC_ASYM_CIPHER_ENCRYPT, (void (*)(void))akv_aes_cipher_encrypt},
    {OSSL_FUNC_ASYM_CIPHER_DECRYPT, (void (*)(void))akv_aes_cipher_decrypt},
    {OSSL_FUNC_ASYM_CIPHER_GET_CTX_PARAMS, (void (*)(void))akv_aes_cipher_get_ctx_params},
    {OSSL_FUNC_ASYM_CIPHER_GETTABLE_CTX_PARAMS, (void (*)(void))akv_aes_cipher_gettable_ctx_params},
    {OSSL_FUNC_ASYM_CIPHER_SET_CTX_PARAMS, (void (*)(void))akv_aes_cipher_set_ctx_params},
    {OSSL_FUNC_ASYM_CIPHER_SETTABLE_CTX_PARAMS, (void (*)(void))akv_aes_cipher_settable_ctx_params},
    {0, NULL}
};
