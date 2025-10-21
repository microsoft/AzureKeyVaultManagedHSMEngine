/* Copyright (c) Microsoft Corporation.
   Licensed under the MIT License. */

#include "akv_provider_internal.h"

#include <limits.h>
#include <stdio.h>

#include <openssl/rsa.h>
#include <openssl/ecdsa.h>

/*
 * Signature implementation that bridges OpenSSL requests to Azure Key Vault.
 * Flow overview:
 *   1. OpenSSL CLI (e.g. `openssl dgst -sign ... -provider akv_provider`) fetches
 *      the AKV signature implementation through our dispatch table.
 *   2. OpenSSL passes the selected key URI plus signature parameters into
 *      akv_signature_*_init, which captures the key metadata and desired hash.
 *   3. For signing, OpenSSL streams message data into digest helpers; once the
 *      hash is ready we call AkvSign over REST using the key metadata and hash.
 *   4. The AKV response is normalized (DER/RAW) and returned to OpenSSL so the
 *      CLI writes the signature to disk. For verify, we skip REST and use the
 *      cached public key locally via EVP to confirm signatures.
 */

typedef enum akv_sig_keytype_e
{
    AKV_SIG_KEYTYPE_RSA,
    AKV_SIG_KEYTYPE_EC
} AKV_SIG_KEYTYPE;

/* Tracks per-operation state including hashes, padding, and the bound key. */
typedef struct akv_signature_ctx_st
{
    AKV_PROVIDER_CTX *provctx;
    AKV_SIG_KEYTYPE keytype;
    AKV_KEY *key;
    EVP_MD_CTX *mdctx;
    EVP_MD *md;
    EVP_MD *mgf1_md;
    int operation;
    int padding;
    int pss_saltlen;
} AKV_SIGNATURE_CTX;

/* Reset any cached digest state to keep contexts reusable across calls. */
static void akv_signature_reset_digest(AKV_SIGNATURE_CTX *ctx)
{
    if (ctx->mdctx != NULL)
    {
        EVP_MD_CTX_free(ctx->mdctx);
        ctx->mdctx = NULL;
    }
    if (ctx->md != NULL)
    {
        EVP_MD_free(ctx->md);
        ctx->md = NULL;
    }
    if (ctx->mgf1_md != NULL)
    {
        EVP_MD_free(ctx->mgf1_md);
        ctx->mgf1_md = NULL;
    }
}

static int akv_signature_set_digest(AKV_SIGNATURE_CTX *ctx, const char *mdname)
{
    EVP_MD *md = NULL;

    if (ctx == NULL)
    {
        return 0;
    }

    md = EVP_MD_fetch(NULL, mdname, NULL);
    if (md == NULL)
    {
        return 0;
    }

    if (ctx->md != NULL)
    {
        EVP_MD_free(ctx->md);
    }

    ctx->md = md;

    return 1;
}

static int akv_signature_set_mgf1_digest(AKV_SIGNATURE_CTX *ctx, const char *mdname)
{
    EVP_MD *md = EVP_MD_fetch(NULL, mdname, NULL);
    if (md == NULL)
    {
        return 0;
    }

    if (ctx->mgf1_md != NULL)
    {
        EVP_MD_free(ctx->mgf1_md);
    }

    ctx->mgf1_md = md;
    return 1;
}

/* When callers stream a raw digest we have to infer which hash Azure expects. */
static int akv_signature_ensure_digest_from_size(AKV_SIGNATURE_CTX *ctx, size_t digest_len)
{
    if (ctx->md != NULL)
    {
        return 1;
    }

    switch (digest_len)
    {
    case 20:
        return akv_signature_set_digest(ctx, OSSL_DIGEST_NAME_SHA1);
    case 28:
        return akv_signature_set_digest(ctx, OSSL_DIGEST_NAME_SHA2_224);
    case 32:
        return akv_signature_set_digest(ctx, OSSL_DIGEST_NAME_SHA2_256);
    case 48:
        return akv_signature_set_digest(ctx, OSSL_DIGEST_NAME_SHA2_384);
    case 64:
        return akv_signature_set_digest(ctx, OSSL_DIGEST_NAME_SHA2_512);
    default:
        return 0;
    }
}

/* Azure enforces RSA-PSS salt length rules; reject incompatible requests early. */
static int akv_signature_validate_pss(const AKV_SIGNATURE_CTX *ctx, size_t digest_len)
{
    if (ctx->keytype != AKV_SIG_KEYTYPE_RSA || ctx->padding != RSA_PKCS1_PSS_PADDING)
    {
        return 1;
    }

    if (ctx->pss_saltlen == RSA_PSS_SALTLEN_DIGEST || ctx->pss_saltlen == RSA_PSS_SALTLEN_AUTO || ctx->pss_saltlen == RSA_PSS_SALTLEN_MAX || ctx->pss_saltlen == RSA_PSS_SALTLEN_AUTO_DIGEST_MAX)
    {
        /* Azure Key Vault expects salt length to match digest length for PS algorithms */
        return digest_len == (size_t)EVP_MD_get_size(ctx->md);
    }

    return ctx->pss_saltlen == (int)digest_len;
}

/* Translate local digest + keytype into the Managed HSM signing algorithm name. */
static const char *akv_signature_algorithm(const AKV_SIGNATURE_CTX *ctx)
{
    int md_nid = NID_undef;

    if (ctx->md == NULL)
    {
        return NULL;
    }

    md_nid = EVP_MD_type(ctx->md);

    switch (ctx->keytype)
    {
    case AKV_SIG_KEYTYPE_RSA:
        switch (ctx->padding)
        {
        case RSA_PKCS1_PSS_PADDING:
            if (ctx->mgf1_md != NULL && EVP_MD_type(ctx->mgf1_md) != md_nid)
            {
                return NULL;
            }

            switch (md_nid)
            {
            case NID_sha256:
                return "PS256";
            case NID_sha384:
                return "PS384";
            case NID_sha512:
                return "PS512";
            default:
                return NULL;
            }

        case RSA_PKCS1_PADDING:
            switch (md_nid)
            {
            case NID_sha256:
                return "RS256";
            case NID_sha384:
                return "RS384";
            case NID_sha512:
                return "RS512";
            default:
                return NULL;
            }
        default:
            return NULL;
        }
        break;
    case AKV_SIG_KEYTYPE_EC:
        switch (md_nid)
        {
        case NID_sha256:
            return "ES256";
        case NID_sha384:
            return "ES384";
        case NID_sha512:
            return "ES512";
        default:
            return NULL;
        }
    default:
        break;
    }

    return NULL;
}

/* Shared constructor so RSA and EC flows stay aligned. */
static AKV_SIGNATURE_CTX *akv_signature_newctx_common(void *provctx, AKV_SIG_KEYTYPE keytype)
{
    AKV_SIGNATURE_CTX *ctx = (AKV_SIGNATURE_CTX *)calloc(1, sizeof(AKV_SIGNATURE_CTX));
    if (ctx == NULL)
    {
        return NULL;
    }

    ctx->provctx = (AKV_PROVIDER_CTX *)provctx;
    ctx->keytype = keytype;
    ctx->pss_saltlen = RSA_PSS_SALTLEN_DIGEST;
    ctx->padding = (keytype == AKV_SIG_KEYTYPE_RSA) ? RSA_PKCS1_PADDING : 0;
    return ctx;
}

static void *akv_rsa_signature_newctx(void *provctx, const char *propq)
{
    (void)propq;
    return akv_signature_newctx_common(provctx, AKV_SIG_KEYTYPE_RSA);
}

static void *akv_ecdsa_signature_newctx(void *provctx, const char *propq)
{
    (void)propq;
    return akv_signature_newctx_common(provctx, AKV_SIG_KEYTYPE_EC);
}

static void akv_signature_freectx(void *vctx)
{
    AKV_SIGNATURE_CTX *ctx = (AKV_SIGNATURE_CTX *)vctx;
    if (ctx == NULL)
    {
        return;
    }

    akv_signature_reset_digest(ctx);
    free(ctx);
}

static void *akv_signature_dupctx(void *vctx)
{
    AKV_SIGNATURE_CTX *ctx = (AKV_SIGNATURE_CTX *)vctx;
    AKV_SIGNATURE_CTX *dup = NULL;

    if (ctx == NULL)
    {
        return NULL;
    }

    dup = (AKV_SIGNATURE_CTX *)calloc(1, sizeof(AKV_SIGNATURE_CTX));
    if (dup == NULL)
    {
        return NULL;
    }

    dup->provctx = ctx->provctx;
    dup->keytype = ctx->keytype;
    dup->key = ctx->key;
    dup->padding = ctx->padding;
    dup->pss_saltlen = ctx->pss_saltlen;
    dup->operation = ctx->operation;

    if (ctx->md != NULL)
    {
        if (EVP_MD_up_ref(ctx->md) <= 0)
        {
            akv_signature_freectx(dup);
            return NULL;
        }
        dup->md = ctx->md;
    }

    if (ctx->mgf1_md != NULL)
    {
        if (EVP_MD_up_ref(ctx->mgf1_md) <= 0)
        {
            akv_signature_freectx(dup);
            return NULL;
        }
        dup->mgf1_md = ctx->mgf1_md;
    }

    if (ctx->mdctx != NULL)
    {
        dup->mdctx = EVP_MD_CTX_dup(ctx->mdctx);
        if (dup->mdctx == NULL)
        {
            akv_signature_freectx(dup);
            return NULL;
        }
    }

    return dup;
}

/* Apply digest, padding, and MGF selections that arrive via OSSL params. */
static int akv_signature_apply_common_params(AKV_SIGNATURE_CTX *ctx, const OSSL_PARAM params[])
{
    const OSSL_PARAM *p = NULL;

    if (params == NULL)
    {
        return 1;
    }

    p = OSSL_PARAM_locate_const(params, OSSL_SIGNATURE_PARAM_DIGEST);
    if (p != NULL)
    {
        const char *mdname = NULL;
        if (!OSSL_PARAM_get_utf8_string_ptr(p, &mdname))
        {
            return 0;
        }
        if (!akv_signature_set_digest(ctx, mdname))
        {
            return 0;
        }
    }

    if (ctx->keytype == AKV_SIG_KEYTYPE_RSA)
    {
        p = OSSL_PARAM_locate_const(params, OSSL_SIGNATURE_PARAM_PAD_MODE);
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
                if (strcmp((const char *)p->data, OSSL_PKEY_RSA_PAD_MODE_PKCSV15) == 0)
                {
                    pad = RSA_PKCS1_PADDING;
                }
                else if (strcmp((const char *)p->data, OSSL_PKEY_RSA_PAD_MODE_PSS) == 0)
                {
                    pad = RSA_PKCS1_PSS_PADDING;
                }
                else
                {
                    return 0;
                }
            }
            else
            {
                Log(LogLevel_Error,
                    "Unsupported pad mode parameter type (%d) for RSA signature",
                    p->data_type);
                return 0;
            }
            if (pad != RSA_PKCS1_PSS_PADDING && pad != RSA_PKCS1_PADDING)
            {
                Log(LogLevel_Error, "RSA padding mode not supported (mode=%d)", pad);
                return 0;
            }
            ctx->padding = pad;
        }

        p = OSSL_PARAM_locate_const(params, OSSL_SIGNATURE_PARAM_PSS_SALTLEN);
        if (p != NULL)
        {
            int saltlen = 0;
            if (p->data_type == OSSL_PARAM_INTEGER)
            {
                if (!OSSL_PARAM_get_int(p, &saltlen))
                {
                    return 0;
                }
            }
            else if (p->data_type == OSSL_PARAM_UTF8_STRING)
            {
                const char *salt = (const char *)p->data;
                if (strcasecmp(salt, OSSL_PKEY_RSA_PSS_SALT_LEN_DIGEST) == 0)
                {
                    saltlen = RSA_PSS_SALTLEN_DIGEST;
                }
                else if (strcasecmp(salt, OSSL_PKEY_RSA_PSS_SALT_LEN_AUTO) == 0)
                {
                    saltlen = RSA_PSS_SALTLEN_AUTO;
                }
                else if (strcasecmp(salt, OSSL_PKEY_RSA_PSS_SALT_LEN_MAX) == 0)
                {
                    saltlen = RSA_PSS_SALTLEN_MAX;
                }
                else if (strcasecmp(salt, OSSL_PKEY_RSA_PSS_SALT_LEN_AUTO_DIGEST_MAX) == 0)
                {
                    saltlen = RSA_PSS_SALTLEN_AUTO_DIGEST_MAX;
                }
                else
                {
                    saltlen = atoi(salt);
                }
            }
            else
            {
                Log(LogLevel_Error,
                    "Unsupported PSS salt length parameter type (%d)",
                    p->data_type);
                return 0;
            }
            ctx->pss_saltlen = saltlen;
        }

        p = OSSL_PARAM_locate_const(params, OSSL_SIGNATURE_PARAM_MGF1_DIGEST);
        if (p != NULL)
        {
            const char *mdname = NULL;
            if (!OSSL_PARAM_get_utf8_string_ptr(p, &mdname))
            {
                return 0;
            }
            if (!akv_signature_set_mgf1_digest(ctx, mdname))
            {
                Log(LogLevel_Error,
                    "Failed to fetch MGF1 digest '%s'",
                    mdname != NULL ? mdname : "(null)");
                return 0;
            }
        }
    }

    return 1;
}

/* Capture the key and shared parameters used by both sign and verify inits. */
static int akv_signature_init_common(AKV_SIGNATURE_CTX *ctx, void *vkey, const OSSL_PARAM params[], int operation)
{
    if (ctx == NULL || vkey == NULL)
    {
        return 0;
    }

    ctx->key = (AKV_KEY *)vkey;
    ctx->operation = operation;

    if (!akv_signature_apply_common_params(ctx, params))
    {
        Log(LogLevel_Error, "Failed to apply signature parameters (operation=%d)", operation);
        return 0;
    }

    return 1;
}

static int akv_signature_sign_init(void *vctx, void *vkey, const OSSL_PARAM params[])
{
    return akv_signature_init_common((AKV_SIGNATURE_CTX *)vctx, vkey, params, EVP_PKEY_OP_SIGN);
}

static int akv_signature_verify_init(void *vctx, void *vkey, const OSSL_PARAM params[])
{
    return akv_signature_init_common((AKV_SIGNATURE_CTX *)vctx, vkey, params, EVP_PKEY_OP_VERIFY);
}

static size_t akv_signature_expected_size(const AKV_SIGNATURE_CTX *ctx)
{
    if (ctx->key == NULL || ctx->key->public_key == NULL)
    {
        return 0;
    }

    return (size_t)EVP_PKEY_get_size(ctx->key->public_key);
}

/* Convert Managed HSM ECDSA output (DER or raw) into the format OpenSSL requested. */
static int akv_signature_format_ecdsa_signature(const AKV_SIGNATURE_CTX *ctx, unsigned char *sig, size_t *siglen, const unsigned char *raw, size_t raw_len)
{
    int ok = 0;
    const unsigned char *p = raw;
    ECDSA_SIG *ecsig = NULL;

    if (sig == NULL || siglen == NULL)
    {
        return 0;
    }

    if (raw_len > (size_t)LONG_MAX)
    {
        goto end;
    }

    ecsig = d2i_ECDSA_SIG(NULL, &p, (long)raw_len);
    if (ecsig != NULL && p == raw + raw_len)
    {
        if ((size_t)raw_len > *siglen)
        {
            goto end;
        }
    memcpy(sig, raw, (size_t)raw_len);
    *siglen = (size_t)raw_len;
        ok = 1;
        goto end;
    }

    if (ecsig != NULL)
    {
        ECDSA_SIG_free(ecsig);
        ecsig = NULL;
    }

    if ((raw_len % 2) != 0)
    {
        return 0;
    }

    ecsig = ECDSA_SIG_new();
    if (ecsig == NULL)
    {
        return 0;
    }

    {
        size_t half = raw_len / 2;
        BIGNUM *r = BN_bin2bn(raw, (int)half, NULL);
        BIGNUM *s = BN_bin2bn(raw + half, (int)half, NULL);
        if (r == NULL || s == NULL)
        {
            BN_free(r);
            BN_free(s);
            goto end;
        }
        if (ECDSA_SIG_set0(ecsig, r, s) != 1)
        {
            BN_free(r);
            BN_free(s);
            goto end;
        }
    }

    {
        int der_len = i2d_ECDSA_SIG(ecsig, NULL);
        unsigned char *out = sig;
        if (der_len <= 0 || (size_t)der_len > *siglen)
        {
            goto end;
        }
        i2d_ECDSA_SIG(ecsig, &out);
        *siglen = (size_t)der_len;
        ok = 1;
    }

end:
    if (ecsig != NULL)
    {
        ECDSA_SIG_free(ecsig);
    }
    return ok;
}

/* Normalize the signature blob returned by Azure into OpenSSL expectations. */
static int akv_signature_copy_result(AKV_SIGNATURE_CTX *ctx, unsigned char *sig, size_t *siglen, const MemoryStruct *signature)
{
    if (sig == NULL || siglen == NULL || signature == NULL)
    {
        return 0;
    }

    if (ctx->keytype == AKV_SIG_KEYTYPE_RSA)
    {
        if (signature->size > *siglen)
        {
            return 0;
        }
        memcpy(sig, signature->memory, signature->size);
        *siglen = signature->size;
        return 1;
    }

    return akv_signature_format_ecdsa_signature(ctx, sig, siglen, signature->memory, signature->size);
}

/* Execute the remote sign call against Azure and translate the response. */
static int akv_signature_remote_sign(AKV_SIGNATURE_CTX *ctx, unsigned char *sig, size_t *siglen, const unsigned char *digest, size_t digest_len)
{
    MemoryStruct token = {0};
    MemoryStruct signature = {0};
    const char *algorithm = NULL;
    int ok = 0;

    if (!akv_signature_ensure_digest_from_size(ctx, digest_len))
    {
        Log(LogLevel_Error, "Unable to infer digest for length %zu", digest_len);
        goto end;
    }

    if (!akv_signature_validate_pss(ctx, digest_len))
    {
        Log(LogLevel_Error, "Unsupported PSS salt length for digest length %zu", digest_len);
        goto end;
    }

    algorithm = akv_signature_algorithm(ctx);
    if (algorithm == NULL)
    {
        Log(LogLevel_Error, "Unsupported algorithm selection for signature");
        goto end;
    }

    if (!GetAccessTokenFromEnv(&token))
    {
        Log(LogLevel_Error,
            "Failed to acquire access token for managedhsm://%s/%s",
            ctx->key != NULL && ctx->key->keyvault_name != NULL ? ctx->key->keyvault_name : "(null)",
            ctx->key != NULL && ctx->key->key_name != NULL ? ctx->key->key_name : "(null)");
        goto end;
    }

    if (!AkvSign(ctx->key->keyvault_name,
                 ctx->key->key_name,
                 &token,
                 algorithm,
                 digest,
                 digest_len,
                 &signature))
    {
        Log(LogLevel_Error, "Azure Key Vault sign operation failed for key %s", ctx->key->key_name);
        goto end;
    }

    if (!akv_signature_copy_result(ctx, sig, siglen, &signature))
    {
        Log(LogLevel_Error, "Failed to translate signature result");
        goto end;
    }

    ok = 1;

end:
    if (token.memory != NULL)
    {
        free(token.memory);
    }
    if (signature.memory != NULL)
    {
        free(signature.memory);
    }
    return ok;
}

static int akv_signature_sign(void *vctx, unsigned char *sig, size_t *siglen, size_t sigsize, const unsigned char *tbs, size_t tbslen)
{
    AKV_SIGNATURE_CTX *ctx = (AKV_SIGNATURE_CTX *)vctx;
    size_t expected = 0;

    (void)sigsize;

    if (ctx == NULL || ctx->key == NULL || ctx->key->public_key == NULL || siglen == NULL)
    {
        return 0;
    }

    expected = akv_signature_expected_size(ctx);

    if (sig == NULL)
    {
        *siglen = expected;
        return 1;
    }

    if (*siglen < expected)
    {
        return 0;
    }

    return akv_signature_remote_sign(ctx, sig, siglen, tbs, tbslen);
}

/* Use the cached public key to verify locally and avoid round-trips to Azure. */
static int akv_signature_verify(void *vctx, const unsigned char *sig, size_t siglen, const unsigned char *tbs, size_t tbslen)
{
    AKV_SIGNATURE_CTX *ctx = (AKV_SIGNATURE_CTX *)vctx;
    EVP_PKEY_CTX *verify_ctx = NULL;
    int ok = 0;

    if (ctx == NULL || ctx->key == NULL || ctx->key->public_key == NULL)
    {
        return 0;
    }

    if (!akv_signature_ensure_digest_from_size(ctx, tbslen))
    {
        Log(LogLevel_Error, "Unable to infer digest during verify for length %zu", tbslen);
        return 0;
    }

    verify_ctx = EVP_PKEY_CTX_new_from_pkey(NULL, ctx->key->public_key, NULL);
    if (verify_ctx == NULL)
    {
        return 0;
    }

    if (EVP_PKEY_verify_init(verify_ctx) <= 0)
    {
        goto end;
    }

    if (ctx->md != NULL)
    {
        if (EVP_PKEY_CTX_set_signature_md(verify_ctx, ctx->md) <= 0)
        {
            goto end;
        }
    }

    if (ctx->keytype == AKV_SIG_KEYTYPE_RSA)
    {
        if (EVP_PKEY_CTX_set_rsa_padding(verify_ctx, ctx->padding) <= 0)
        {
            goto end;
        }
        if (ctx->padding == RSA_PKCS1_PSS_PADDING)
        {
            int salt = (ctx->pss_saltlen == RSA_PSS_SALTLEN_DIGEST || ctx->pss_saltlen == RSA_PSS_SALTLEN_AUTO || ctx->pss_saltlen == RSA_PSS_SALTLEN_AUTO_DIGEST_MAX)
                           ? EVP_MD_get_size(ctx->md)
                           : ctx->pss_saltlen;
            if (EVP_PKEY_CTX_set_rsa_pss_saltlen(verify_ctx, salt) <= 0)
            {
                goto end;
            }

            if (ctx->mgf1_md != NULL)
            {
                if (EVP_PKEY_CTX_set_rsa_mgf1_md(verify_ctx, ctx->mgf1_md) <= 0)
                {
                    goto end;
                }
            }
        }
    }

    ok = EVP_PKEY_verify(verify_ctx, sig, siglen, tbs, tbslen);

end:
    if (verify_ctx != NULL)
    {
        EVP_PKEY_CTX_free(verify_ctx);
    }
    return ok;
}

/* Helper for digest-sign and digest-verify entry points so they share setup. */
static int akv_signature_digest_init(AKV_SIGNATURE_CTX *ctx, void *vkey, const OSSL_PARAM params[], int operation, const char *mdname)
{
    if (!akv_signature_init_common(ctx, vkey, params, operation))
    {
        return 0;
    }

    if (mdname == NULL)
    {
        return 0;
    }

    if (!akv_signature_set_digest(ctx, mdname))
    {
        return 0;
    }

    if (ctx->mdctx == NULL)
    {
        ctx->mdctx = EVP_MD_CTX_new();
        if (ctx->mdctx == NULL)
        {
            return 0;
        }
    }

    if (EVP_DigestInit_ex(ctx->mdctx, ctx->md, NULL) <= 0)
    {
        return 0;
    }

    return 1;
}

static int akv_signature_digest_sign_init(void *vctx, const char *mdname, void *vkey, const OSSL_PARAM params[])
{
    return akv_signature_digest_init((AKV_SIGNATURE_CTX *)vctx, vkey, params, EVP_PKEY_OP_SIGN, mdname);
}

static int akv_signature_digest_verify_init(void *vctx, const char *mdname, void *vkey, const OSSL_PARAM params[])
{
    return akv_signature_digest_init((AKV_SIGNATURE_CTX *)vctx, vkey, params, EVP_PKEY_OP_VERIFY, mdname);
}

static int akv_signature_digest_update(void *vctx, const unsigned char *data, size_t datalen)
{
    AKV_SIGNATURE_CTX *ctx = (AKV_SIGNATURE_CTX *)vctx;

    if (ctx == NULL || ctx->mdctx == NULL)
    {
        return 0;
    }

    return EVP_DigestUpdate(ctx->mdctx, data, datalen) > 0;
}

static int akv_signature_digest_sign_final(void *vctx, unsigned char *sig, size_t *siglen, size_t sigsize)
{
    AKV_SIGNATURE_CTX *ctx = (AKV_SIGNATURE_CTX *)vctx;
    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int digest_len = 0;

    (void)sigsize;

    if (ctx == NULL || ctx->mdctx == NULL)
    {
        return 0;
    }

    if (sig == NULL)
    {
        if (siglen == NULL)
        {
            return 0;
        }
        *siglen = akv_signature_expected_size(ctx);
        return 1;
    }

    if (EVP_DigestFinal_ex(ctx->mdctx, digest, &digest_len) <= 0)
    {
        return 0;
    }

    return akv_signature_remote_sign(ctx, sig, siglen, digest, digest_len);
}

static int akv_signature_digest_sign(void *vctx, unsigned char *sig, size_t *siglen, size_t sigsize, const unsigned char *data, size_t datalen)
{
    AKV_SIGNATURE_CTX *ctx = (AKV_SIGNATURE_CTX *)vctx;

    (void)sigsize;

    if (ctx == NULL || ctx->md == NULL)
    {
        return 0;
    }

    if (ctx->mdctx == NULL)
    {
        ctx->mdctx = EVP_MD_CTX_new();
        if (ctx->mdctx == NULL)
        {
            return 0;
        }
    }

    if (sig == NULL)
    {
        if (siglen == NULL)
        {
            return 0;
        }
        *siglen = akv_signature_expected_size(ctx);
        return 1;
    }

    if (EVP_DigestInit_ex(ctx->mdctx, ctx->md, NULL) <= 0)
    {
        return 0;
    }

    if (EVP_DigestUpdate(ctx->mdctx, data, datalen) <= 0)
    {
        return 0;
    }

    return akv_signature_digest_sign_final(ctx, sig, siglen, sigsize);
}

static int akv_signature_digest_verify_final(void *vctx, const unsigned char *sig, size_t siglen)
{
    AKV_SIGNATURE_CTX *ctx = (AKV_SIGNATURE_CTX *)vctx;
    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int digest_len = 0;

    if (ctx == NULL || ctx->mdctx == NULL)
    {
        return 0;
    }

    if (EVP_DigestFinal_ex(ctx->mdctx, digest, &digest_len) <= 0)
    {
        return 0;
    }

    return akv_signature_verify(ctx, sig, siglen, digest, digest_len);
}

static int akv_signature_set_ctx_params(void *vctx, const OSSL_PARAM params[])
{
    return akv_signature_apply_common_params((AKV_SIGNATURE_CTX *)vctx, params);
}

static int akv_signature_get_ctx_params(void *vctx, OSSL_PARAM params[])
{
    AKV_SIGNATURE_CTX *ctx = (AKV_SIGNATURE_CTX *)vctx;
    OSSL_PARAM *p = NULL;

    if (params == NULL)
    {
        return 1;
    }

    p = OSSL_PARAM_locate(params, OSSL_SIGNATURE_PARAM_DIGEST);
    if (p != NULL)
    {
        const char *mdname = (ctx->md != NULL) ? EVP_MD_get0_name(ctx->md) : "";
        if (!OSSL_PARAM_set_utf8_string(p, mdname))
        {
            return 0;
        }
    }

    if (ctx->keytype == AKV_SIG_KEYTYPE_RSA)
    {
        p = OSSL_PARAM_locate(params, OSSL_SIGNATURE_PARAM_PAD_MODE);
        if (p != NULL)
        {
            const char *pad = (ctx->padding == RSA_PKCS1_PSS_PADDING) ? OSSL_PKEY_RSA_PAD_MODE_PSS : OSSL_PKEY_RSA_PAD_MODE_PKCSV15;
            if (!OSSL_PARAM_set_utf8_string(p, pad))
            {
                return 0;
            }
        }

        p = OSSL_PARAM_locate(params, OSSL_SIGNATURE_PARAM_PSS_SALTLEN);
        if (p != NULL)
        {
            const char *salt = NULL;
            char salt_buf[32] = {0};

            switch (ctx->pss_saltlen)
            {
            case RSA_PSS_SALTLEN_DIGEST:
                salt = OSSL_PKEY_RSA_PSS_SALT_LEN_DIGEST;
                break;
            case RSA_PSS_SALTLEN_AUTO:
                salt = OSSL_PKEY_RSA_PSS_SALT_LEN_AUTO;
                break;
            case RSA_PSS_SALTLEN_MAX:
                salt = OSSL_PKEY_RSA_PSS_SALT_LEN_MAX;
                break;
            case RSA_PSS_SALTLEN_AUTO_DIGEST_MAX:
                salt = OSSL_PKEY_RSA_PSS_SALT_LEN_AUTO_DIGEST_MAX;
                break;
            default:
                if (snprintf(salt_buf, sizeof(salt_buf), "%d", ctx->pss_saltlen) < 0)
                {
                    return 0;
                }
                salt = salt_buf;
                break;
            }

            if (!OSSL_PARAM_set_utf8_string(p, salt != NULL ? salt : ""))
            {
                return 0;
            }
        }
    }

    return 1;
}

static const OSSL_PARAM *akv_signature_gettable_ctx_params(void *provctx)
{
    static OSSL_PARAM params[] = {
        OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_DIGEST, NULL, 0),
        OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_PAD_MODE, NULL, 0),
        OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_PSS_SALTLEN, NULL, 0),
        OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_MGF1_DIGEST, NULL, 0),
        OSSL_PARAM_END};
    (void)provctx;
    return params;
}

static const OSSL_PARAM *akv_signature_settable_ctx_params(void *provctx)
{
    return akv_signature_gettable_ctx_params(provctx);
}

static const OSSL_PARAM *akv_signature_gettable_ctx_md_params(void *provctx)
{
    (void)provctx;
    return NULL;
}

static const OSSL_PARAM *akv_signature_settable_ctx_md_params(void *provctx)
{
    (void)provctx;
    return NULL;
}

/* OpenSSL expects MD param hooks in the dispatch table even if we do not expose custom parameters. */
static int akv_signature_get_ctx_md_params(void *vctx, OSSL_PARAM params[])
{
    Log(LogLevel_Trace, "akv_signature_get_ctx_md_params ctx=%p params=%p", vctx, (void *)params);
    (void)vctx;
    (void)params;
    Log(LogLevel_Debug, "akv_signature_get_ctx_md_params -> 1");
    return 1;
}

static int akv_signature_set_ctx_md_params(void *vctx, const OSSL_PARAM params[])
{
    Log(LogLevel_Trace, "akv_signature_set_ctx_md_params ctx=%p params=%p", vctx, (const void *)params);
    (void)vctx;
    (void)params;
    Log(LogLevel_Debug, "akv_signature_set_ctx_md_params -> 1");
    return 1;
}

const OSSL_DISPATCH akv_rsa_signature_functions[] = {
    {OSSL_FUNC_SIGNATURE_NEWCTX, (void (*)(void))akv_rsa_signature_newctx},
    {OSSL_FUNC_SIGNATURE_FREECTX, (void (*)(void))akv_signature_freectx},
    {OSSL_FUNC_SIGNATURE_DUPCTX, (void (*)(void))akv_signature_dupctx},
    {OSSL_FUNC_SIGNATURE_SIGN_INIT, (void (*)(void))akv_signature_sign_init},
    {OSSL_FUNC_SIGNATURE_VERIFY_INIT, (void (*)(void))akv_signature_verify_init},
    {OSSL_FUNC_SIGNATURE_SIGN, (void (*)(void))akv_signature_sign},
    {OSSL_FUNC_SIGNATURE_VERIFY, (void (*)(void))akv_signature_verify},
    {OSSL_FUNC_SIGNATURE_DIGEST_SIGN_INIT, (void (*)(void))akv_signature_digest_sign_init},
    {OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_INIT, (void (*)(void))akv_signature_digest_verify_init},
    {OSSL_FUNC_SIGNATURE_DIGEST_SIGN_UPDATE, (void (*)(void))akv_signature_digest_update},
    {OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_UPDATE, (void (*)(void))akv_signature_digest_update},
    {OSSL_FUNC_SIGNATURE_DIGEST_SIGN_FINAL, (void (*)(void))akv_signature_digest_sign_final},
    {OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_FINAL, (void (*)(void))akv_signature_digest_verify_final},
    {OSSL_FUNC_SIGNATURE_DIGEST_SIGN, (void (*)(void))akv_signature_digest_sign},
    {OSSL_FUNC_SIGNATURE_GET_CTX_PARAMS, (void (*)(void))akv_signature_get_ctx_params},
    {OSSL_FUNC_SIGNATURE_GETTABLE_CTX_PARAMS, (void (*)(void))akv_signature_gettable_ctx_params},
    {OSSL_FUNC_SIGNATURE_SET_CTX_PARAMS, (void (*)(void))akv_signature_set_ctx_params},
    {OSSL_FUNC_SIGNATURE_SETTABLE_CTX_PARAMS, (void (*)(void))akv_signature_settable_ctx_params},
    {OSSL_FUNC_SIGNATURE_GET_CTX_MD_PARAMS, (void (*)(void))akv_signature_get_ctx_md_params},
    {OSSL_FUNC_SIGNATURE_GETTABLE_CTX_MD_PARAMS, (void (*)(void))akv_signature_gettable_ctx_md_params},
    {OSSL_FUNC_SIGNATURE_SET_CTX_MD_PARAMS, (void (*)(void))akv_signature_set_ctx_md_params},
    {OSSL_FUNC_SIGNATURE_SETTABLE_CTX_MD_PARAMS, (void (*)(void))akv_signature_settable_ctx_md_params},
    {0, NULL}};

const OSSL_DISPATCH akv_ecdsa_signature_functions[] = {
    {OSSL_FUNC_SIGNATURE_NEWCTX, (void (*)(void))akv_ecdsa_signature_newctx},
    {OSSL_FUNC_SIGNATURE_FREECTX, (void (*)(void))akv_signature_freectx},
    {OSSL_FUNC_SIGNATURE_DUPCTX, (void (*)(void))akv_signature_dupctx},
    {OSSL_FUNC_SIGNATURE_SIGN_INIT, (void (*)(void))akv_signature_sign_init},
    {OSSL_FUNC_SIGNATURE_VERIFY_INIT, (void (*)(void))akv_signature_verify_init},
    {OSSL_FUNC_SIGNATURE_SIGN, (void (*)(void))akv_signature_sign},
    {OSSL_FUNC_SIGNATURE_VERIFY, (void (*)(void))akv_signature_verify},
    {OSSL_FUNC_SIGNATURE_DIGEST_SIGN_INIT, (void (*)(void))akv_signature_digest_sign_init},
    {OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_INIT, (void (*)(void))akv_signature_digest_verify_init},
    {OSSL_FUNC_SIGNATURE_DIGEST_SIGN_UPDATE, (void (*)(void))akv_signature_digest_update},
    {OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_UPDATE, (void (*)(void))akv_signature_digest_update},
    {OSSL_FUNC_SIGNATURE_DIGEST_SIGN_FINAL, (void (*)(void))akv_signature_digest_sign_final},
    {OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_FINAL, (void (*)(void))akv_signature_digest_verify_final},
    {OSSL_FUNC_SIGNATURE_DIGEST_SIGN, (void (*)(void))akv_signature_digest_sign},
    {OSSL_FUNC_SIGNATURE_GET_CTX_PARAMS, (void (*)(void))akv_signature_get_ctx_params},
    {OSSL_FUNC_SIGNATURE_GETTABLE_CTX_PARAMS, (void (*)(void))akv_signature_gettable_ctx_params},
    {OSSL_FUNC_SIGNATURE_SET_CTX_PARAMS, (void (*)(void))akv_signature_set_ctx_params},
    {OSSL_FUNC_SIGNATURE_SETTABLE_CTX_PARAMS, (void (*)(void))akv_signature_settable_ctx_params},
    {OSSL_FUNC_SIGNATURE_GET_CTX_MD_PARAMS, (void (*)(void))akv_signature_get_ctx_md_params},
    {OSSL_FUNC_SIGNATURE_GETTABLE_CTX_MD_PARAMS, (void (*)(void))akv_signature_gettable_ctx_md_params},
    {OSSL_FUNC_SIGNATURE_SET_CTX_MD_PARAMS, (void (*)(void))akv_signature_set_ctx_md_params},
    {OSSL_FUNC_SIGNATURE_SETTABLE_CTX_MD_PARAMS, (void (*)(void))akv_signature_settable_ctx_md_params},
    {0, NULL}};
