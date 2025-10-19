/* Copyright (c) Microsoft Corporation.
   Licensed under the MIT License. */

#include "akv_provider_internal.h"

#include <openssl/rsa.h>

typedef struct akv_cipher_ctx_st
{
    AKV_PROVIDER_CTX *provctx;
    AKV_KEY *key;
    int padding;
    EVP_MD *oaep_md;
    EVP_MD *mgf1_md;
} AKV_CIPHER_CTX;

static void akv_cipher_reset_digests(AKV_CIPHER_CTX *ctx)
{
    if (ctx->oaep_md != NULL)
    {
        EVP_MD_free(ctx->oaep_md);
        ctx->oaep_md = NULL;
    }
    if (ctx->mgf1_md != NULL)
    {
        EVP_MD_free(ctx->mgf1_md);
        ctx->mgf1_md = NULL;
    }
}

static void *akv_cipher_newctx(void *provctx, const char *propq)
{
    AKV_CIPHER_CTX *ctx = (AKV_CIPHER_CTX *)calloc(1, sizeof(AKV_CIPHER_CTX));
    (void)propq;
    if (ctx == NULL)
    {
        return NULL;
    }

    ctx->provctx = (AKV_PROVIDER_CTX *)provctx;
    ctx->padding = RSA_PKCS1_OAEP_PADDING;
    ctx->oaep_md = EVP_MD_fetch(NULL, OSSL_DIGEST_NAME_SHA2_256, NULL);
    return ctx;
}

static void akv_cipher_freectx(void *vctx)
{
    AKV_CIPHER_CTX *ctx = (AKV_CIPHER_CTX *)vctx;
    if (ctx == NULL)
    {
        return;
    }

    akv_cipher_reset_digests(ctx);
    free(ctx);
}

static void *akv_cipher_dupctx(void *vctx)
{
    AKV_CIPHER_CTX *ctx = (AKV_CIPHER_CTX *)vctx;
    AKV_CIPHER_CTX *dup = NULL;

    if (ctx == NULL)
    {
        return NULL;
    }

    dup = (AKV_CIPHER_CTX *)calloc(1, sizeof(AKV_CIPHER_CTX));
    if (dup == NULL)
    {
        return NULL;
    }

    dup->provctx = ctx->provctx;
    dup->key = ctx->key;
    dup->padding = ctx->padding;

    if (ctx->oaep_md != NULL && EVP_MD_up_ref(ctx->oaep_md) > 0)
    {
        dup->oaep_md = ctx->oaep_md;
    }
    if (ctx->mgf1_md != NULL && EVP_MD_up_ref(ctx->mgf1_md) > 0)
    {
        dup->mgf1_md = ctx->mgf1_md;
    }

    return dup;
}

static int akv_cipher_set_digest(EVP_MD **slot, const char *mdname)
{
    EVP_MD *md = EVP_MD_fetch(NULL, mdname, NULL);
    if (md == NULL)
    {
        return 0;
    }

    if (*slot != NULL)
    {
        EVP_MD_free(*slot);
    }

    *slot = md;
    return 1;
}

static const char *akv_cipher_algorithm(const AKV_CIPHER_CTX *ctx)
{
    int md_nid = NID_undef;

    if (ctx->padding == RSA_PKCS1_PADDING)
    {
        return "RSA1_5";
    }

    if (ctx->padding != RSA_PKCS1_OAEP_PADDING)
    {
        return NULL;
    }

    if (ctx->oaep_md == NULL)
    {
        return NULL;
    }

    md_nid = EVP_MD_type(ctx->oaep_md);

    switch (md_nid)
    {
    case NID_sha1:
        return "RSA-OAEP";
    case NID_sha256:
        return "RSA-OAEP-256";
    case NID_sha384:
        return "RSA-OAEP-384";
    case NID_sha512:
        return "RSA-OAEP-512";
    default:
        return NULL;
    }
}

static int akv_cipher_apply_params(AKV_CIPHER_CTX *ctx, const OSSL_PARAM params[])
{
    const OSSL_PARAM *p = NULL;

    if (params == NULL)
    {
        return 1;
    }

    p = OSSL_PARAM_locate_const(params, OSSL_ASYM_CIPHER_PARAM_PAD_MODE);
    if (p != NULL)
    {
        int pad = 0;
        if (p->data_type == OSSL_PARAM_INTEGER)
        {
            if (!OSSL_PARAM_get_int(p, &pad))
            {
                return 0;
            }
        }
        else if (p->data_type == OSSL_PARAM_UTF8_STRING)
        {
            const char *padname = (const char *)p->data;
            if (strcmp(padname, OSSL_PKEY_RSA_PAD_MODE_PKCSV15) == 0)
            {
                pad = RSA_PKCS1_PADDING;
            }
            else if (strcmp(padname, OSSL_PKEY_RSA_PAD_MODE_OAEP) == 0)
            {
                pad = RSA_PKCS1_OAEP_PADDING;
            }
            else
            {
                return 0;
            }
        }
        else
        {
            return 0;
        }
        ctx->padding = pad;
    }

    p = OSSL_PARAM_locate_const(params, OSSL_ASYM_CIPHER_PARAM_OAEP_DIGEST);
    if (p != NULL)
    {
        const char *mdname = NULL;
        if (!OSSL_PARAM_get_utf8_string_ptr(p, &mdname))
        {
            return 0;
        }
        if (!akv_cipher_set_digest(&ctx->oaep_md, mdname))
        {
            return 0;
        }
    }

    p = OSSL_PARAM_locate_const(params, OSSL_ASYM_CIPHER_PARAM_MGF1_DIGEST);
    if (p != NULL)
    {
        const char *mdname = NULL;
        if (!OSSL_PARAM_get_utf8_string_ptr(p, &mdname))
        {
            return 0;
        }
        if (!akv_cipher_set_digest(&ctx->mgf1_md, mdname))
        {
            return 0;
        }
    }

    p = OSSL_PARAM_locate_const(params, OSSL_ASYM_CIPHER_PARAM_OAEP_LABEL);
    if (p != NULL)
    {
        size_t len = 0;
        if (p->data != NULL)
        {
            len = p->data_size;
        }
        if (len > 0)
        {
            Log(LogLevel_Error, "OAEP labels are not supported by the Azure Key Vault provider");
            return 0;
        }
    }

    return 1;
}

static int akv_cipher_init_common(AKV_CIPHER_CTX *ctx, void *vkey, const OSSL_PARAM params[])
{
    if (ctx == NULL || vkey == NULL)
    {
        return 0;
    }

    ctx->key = (AKV_KEY *)vkey;

    if (!akv_cipher_apply_params(ctx, params))
    {
        return 0;
    }

    if (ctx->padding == RSA_PKCS1_OAEP_PADDING && ctx->mgf1_md != NULL)
    {
        if (EVP_MD_type(ctx->mgf1_md) != EVP_MD_type(ctx->oaep_md))
        {
            Log(LogLevel_Error, "OAEP requires matching MGF1 digest");
            return 0;
        }
    }

    return 1;
}

static int akv_cipher_encrypt_init(void *vctx, void *vkey, const OSSL_PARAM params[])
{
    return akv_cipher_init_common((AKV_CIPHER_CTX *)vctx, vkey, params);
}

static int akv_cipher_decrypt_init(void *vctx, void *vkey, const OSSL_PARAM params[])
{
    return akv_cipher_init_common((AKV_CIPHER_CTX *)vctx, vkey, params);
}

static size_t akv_cipher_expected_size(const AKV_CIPHER_CTX *ctx)
{
    if (ctx->key == NULL || ctx->key->public_key == NULL)
    {
        return 0;
    }

    return (size_t)EVP_PKEY_get_size(ctx->key->public_key);
}

static int akv_cipher_remote_encrypt(AKV_CIPHER_CTX *ctx, unsigned char *out, size_t *outlen, const unsigned char *in, size_t inlen)
{
    MemoryStruct token = {0};
    MemoryStruct encrypted = {0};
    const char *algorithm = NULL;
    int ok = 0;

    algorithm = akv_cipher_algorithm(ctx);
    if (algorithm == NULL)
    {
        Log(LogLevel_Error, "Unsupported RSA padding/digest combination for encryption");
        goto end;
    }

    if (!GetAccessTokenFromEnv(&token))
    {
        Log(LogLevel_Error, "Failed to acquire access token for encryption");
        goto end;
    }

    if (!AkvEncrypt(ctx->key->keyvault_name,
                    ctx->key->key_name,
                    &token,
                    algorithm,
                    in,
                    inlen,
                    &encrypted))
    {
        Log(LogLevel_Error, "Azure Key Vault encryption failed");
        goto end;
    }

    if (encrypted.size > *outlen)
    {
        Log(LogLevel_Error, "Insufficient buffer for ciphertext");
        goto end;
    }

    memcpy(out, encrypted.memory, encrypted.size);
    *outlen = encrypted.size;
    ok = 1;

end:
    if (token.memory != NULL)
    {
        free(token.memory);
    }
    if (encrypted.memory != NULL)
    {
        free(encrypted.memory);
    }
    return ok;
}

static int akv_cipher_remote_decrypt(AKV_CIPHER_CTX *ctx, unsigned char *out, size_t *outlen, const unsigned char *in, size_t inlen)
{
    MemoryStruct token = {0};
    MemoryStruct decrypted = {0};
    const char *algorithm = NULL;
    int ok = 0;

    algorithm = akv_cipher_algorithm(ctx);
    if (algorithm == NULL)
    {
        Log(LogLevel_Error, "Unsupported RSA padding/digest combination for decryption");
        goto end;
    }

    if (!GetAccessTokenFromEnv(&token))
    {
        Log(LogLevel_Error, "Failed to acquire access token for decryption");
        goto end;
    }

    if (!AkvDecrypt(ctx->key->keyvault_name,
                    ctx->key->key_name,
                    &token,
                    algorithm,
                    in,
                    inlen,
                    &decrypted))
    {
        Log(LogLevel_Error, "Azure Key Vault decryption failed");
        goto end;
    }

    if (decrypted.size > *outlen)
    {
        Log(LogLevel_Error, "Insufficient buffer for plaintext");
        goto end;
    }

    memcpy(out, decrypted.memory, decrypted.size);
    *outlen = decrypted.size;
    ok = 1;

end:
    if (token.memory != NULL)
    {
        free(token.memory);
    }
    if (decrypted.memory != NULL)
    {
        free(decrypted.memory);
    }
    return ok;
}

static int akv_cipher_encrypt(void *vctx, unsigned char *out, size_t *outlen, size_t outsize, const unsigned char *in, size_t inlen)
{
    AKV_CIPHER_CTX *ctx = (AKV_CIPHER_CTX *)vctx;
    size_t expected = akv_cipher_expected_size(ctx);

    (void)outsize;

    if (ctx == NULL || ctx->key == NULL || ctx->key->public_key == NULL || outlen == NULL)
    {
        return 0;
    }

    if (out == NULL)
    {
        *outlen = expected;
        return 1;
    }

    if (*outlen < expected)
    {
        return 0;
    }

    *outlen = expected;
    return akv_cipher_remote_encrypt(ctx, out, outlen, in, inlen);
}

static int akv_cipher_decrypt(void *vctx, unsigned char *out, size_t *outlen, size_t outsize, const unsigned char *in, size_t inlen)
{
    AKV_CIPHER_CTX *ctx = (AKV_CIPHER_CTX *)vctx;
    size_t expected = akv_cipher_expected_size(ctx);

    (void)outsize;

    if (ctx == NULL || ctx->key == NULL || ctx->key->public_key == NULL || outlen == NULL)
    {
        return 0;
    }

    if (out == NULL)
    {
        *outlen = expected;
        return 1;
    }

    if (*outlen < expected)
    {
        return 0;
    }

    return akv_cipher_remote_decrypt(ctx, out, outlen, in, inlen);
}

static const OSSL_PARAM *akv_cipher_settable_ctx_params(void *provctx)
{
    static OSSL_PARAM params[] = {
        OSSL_PARAM_utf8_string(OSSL_ASYM_CIPHER_PARAM_PAD_MODE, NULL, 0),
        OSSL_PARAM_utf8_string(OSSL_ASYM_CIPHER_PARAM_OAEP_DIGEST, NULL, 0),
        OSSL_PARAM_utf8_string(OSSL_ASYM_CIPHER_PARAM_MGF1_DIGEST, NULL, 0),
        OSSL_PARAM_octet_string(OSSL_ASYM_CIPHER_PARAM_OAEP_LABEL, NULL, 0),
        OSSL_PARAM_END};
    (void)provctx;
    return params;
}

static const OSSL_PARAM *akv_cipher_gettable_ctx_params(void *provctx)
{
    return akv_cipher_settable_ctx_params(provctx);
}

static int akv_cipher_set_ctx_params(void *vctx, const OSSL_PARAM params[])
{
    return akv_cipher_apply_params((AKV_CIPHER_CTX *)vctx, params);
}

static int akv_cipher_get_ctx_params(void *vctx, OSSL_PARAM params[])
{
    AKV_CIPHER_CTX *ctx = (AKV_CIPHER_CTX *)vctx;
    OSSL_PARAM *p = NULL;

    if (params == NULL)
    {
        return 1;
    }

    p = OSSL_PARAM_locate(params, OSSL_ASYM_CIPHER_PARAM_PAD_MODE);
    if (p != NULL)
    {
        const char *pad = (ctx->padding == RSA_PKCS1_OAEP_PADDING) ? OSSL_PKEY_RSA_PAD_MODE_OAEP : OSSL_PKEY_RSA_PAD_MODE_PKCSV15;
        if (!OSSL_PARAM_set_utf8_string(p, pad))
        {
            return 0;
        }
    }

    p = OSSL_PARAM_locate(params, OSSL_ASYM_CIPHER_PARAM_OAEP_DIGEST);
    if (p != NULL)
    {
        const char *mdname = (ctx->oaep_md != NULL) ? EVP_MD_get0_name(ctx->oaep_md) : "";
        if (!OSSL_PARAM_set_utf8_string(p, mdname))
        {
            return 0;
        }
    }

    return 1;
}

const OSSL_DISPATCH akv_rsa_asym_cipher_functions[] = {
    {OSSL_FUNC_ASYM_CIPHER_NEWCTX, (void (*)(void))akv_cipher_newctx},
    {OSSL_FUNC_ASYM_CIPHER_FREECTX, (void (*)(void))akv_cipher_freectx},
    {OSSL_FUNC_ASYM_CIPHER_DUPCTX, (void (*)(void))akv_cipher_dupctx},
    {OSSL_FUNC_ASYM_CIPHER_ENCRYPT_INIT, (void (*)(void))akv_cipher_encrypt_init},
    {OSSL_FUNC_ASYM_CIPHER_DECRYPT_INIT, (void (*)(void))akv_cipher_decrypt_init},
    {OSSL_FUNC_ASYM_CIPHER_ENCRYPT, (void (*)(void))akv_cipher_encrypt},
    {OSSL_FUNC_ASYM_CIPHER_DECRYPT, (void (*)(void))akv_cipher_decrypt},
    {OSSL_FUNC_ASYM_CIPHER_GET_CTX_PARAMS, (void (*)(void))akv_cipher_get_ctx_params},
    {OSSL_FUNC_ASYM_CIPHER_GETTABLE_CTX_PARAMS, (void (*)(void))akv_cipher_gettable_ctx_params},
    {OSSL_FUNC_ASYM_CIPHER_SET_CTX_PARAMS, (void (*)(void))akv_cipher_set_ctx_params},
    {OSSL_FUNC_ASYM_CIPHER_SETTABLE_CTX_PARAMS, (void (*)(void))akv_cipher_settable_ctx_params},
    {0, NULL}};
