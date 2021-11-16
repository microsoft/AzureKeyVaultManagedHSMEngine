/* Copyright (c) Microsoft Corporation.
   Licensed under the MIT License. */

#include "pch.h"

/**
 * @brief return the algorithm name for key vault or managed HSM for the given public key and hash algorithm
 * @see https://docs.microsoft.com/en-us/rest/api/keyvault/sign/sign
 * 
 * @param ctx Public key context
 * @param sigmd signature hash algorithm
 * @return algorithm name == success, NULL == failure
 */
static char *ctx_to_alg(EVP_PKEY_CTX *ctx, const EVP_MD *sigmd)
{
    int mdType = EVP_MD_type(sigmd);
    Log(LogLevel_Debug, "   sigmd type=%d\n", mdType);

    int pad_mode = RSA_PKCS1_PADDING;
    if (EVP_PKEY_CTX_get_rsa_padding(ctx, &pad_mode) != 1)
    {
        AKVerr(AKV_F_RSA_SIGN, AKV_R_CANT_GET_PADDING);
        return NULL;
    }

    if (pad_mode != RSA_PKCS1_PADDING && pad_mode != RSA_PKCS1_PSS_PADDING)
    {
        AKVerr(AKV_F_RSA_SIGN, AKV_R_INVALID_PADDING);
        return NULL;
    }

    switch (mdType)
    {
    case NID_sha512:
        return pad_mode == RSA_PKCS1_PADDING ? "RS512" : "PS512";
    case NID_sha384:
        return pad_mode == RSA_PKCS1_PADDING ? "RS384" : "PS384";
    case NID_sha256:
        return pad_mode == RSA_PKCS1_PADDING ? "RS256" : "PS256";
    default:
        AKVerr(AKV_F_RSA_SIGN, AKV_R_UNSUPPORTED_KEY_ALGORITHM);
        return NULL;
    }
}

int akv_pkey_rsa_sign(EVP_PKEY_CTX *ctx, unsigned char *sig,
                      size_t *siglen, const unsigned char *tbs,
                      size_t tbslen)
{
    if (siglen == NULL)
    {
        Log(LogLevel_Error, "siglen is NULL\n");
        return 0;
    }

    EVP_PKEY *pkey = EVP_PKEY_CTX_get0_pkey(ctx);
    if (!pkey)
    {
        AKVerr(AKV_F_RSA_SIGN, AKV_R_CANT_GET_KEY);
        return -1;
    }

    RSA *rsa = EVP_PKEY_get0_RSA(pkey);
    if (!rsa)
    {
        AKVerr(AKV_F_RSA_SIGN, AKV_R_INVALID_RSA);
        return -1;
    }

    AKV_KEY *akv_key = RSA_get_ex_data(rsa, rsa_akv_idx);
    if (!akv_key)
    {
        AKVerr(AKV_F_RSA_SIGN, AKV_R_CANT_GET_AKV_KEY);
        return -1;
    }

    const EVP_MD *sigmd = NULL;
    if (EVP_PKEY_CTX_get_signature_md(ctx, &sigmd) != 1)
    {
        AKVerr(AKV_F_RSA_SIGN, AKV_R_INVALID_MD);
        return 0;
    }

    // Don't support no padding.
    if (!sigmd)
    {
        AKVerr(AKV_F_RSA_SIGN, AKV_R_NO_PADDING);
        return 0;
    }

    const char *AKV_ALG = ctx_to_alg(ctx, sigmd);
    Log(LogLevel_Debug, "-->akv_pkey_rsa_sign, tbs size [%zu], AKV_ALG [%s]\n", tbslen, AKV_ALG);

    MemoryStruct accessToken;
    if (!GetAccessTokenFromIMDS(akv_key->keyvault_type, &accessToken))
    {
        return 0;
    }

    MemoryStruct signatureText;
    Log(LogLevel_Debug, "keyvault [%s][%s]\n", akv_key->keyvault_name, akv_key->key_name);
    if (AkvSign(akv_key->keyvault_type, akv_key->keyvault_name, akv_key->key_name, &accessToken, AKV_ALG, tbs, tbslen, &signatureText) == 1)
    {
        Log(LogLevel_Debug, "Signed successfully signature.size=[%zu]\n", signatureText.size);

        if (*siglen == signatureText.size)
        {
            memcpy(sig, signatureText.memory, signatureText.size);
        }
        else
        {
            Log(LogLevel_Debug, "size prob = %zu\n", signatureText.size);
            *siglen = signatureText.size;
        }

        free(signatureText.memory);
        free(accessToken.memory);
        return 1;
    }
    else
    {
        Log(LogLevel_Error, "Failed to Sign\n");
        free(signatureText.memory);
        free(accessToken.memory);
        return 0;
    }
}

/**
 * @brief Return the algorithm name for key vault or managed HSM for the given padding mode
 * @see https://commondatastorage.googleapis.com/chromium-boringssl-docs/rsa.h.html#RSA_PKCS1_OAEP_PADDING
 * @param openssl_padding OpenSSL padding mode
 * @return Algorithm name == success, NULL == failure
 */
static char *padding_to_alg(int openssl_padding)
{
    Log(LogLevel_Debug, "   openssl_padding type=%d\n", openssl_padding);

    switch (openssl_padding)
    {
    case RSA_PKCS1_PADDING:
        return "RSA1_5"; // seems only RSA1_5 is working
    case RSA_PKCS1_OAEP_PADDING:
        return "RSA-OAEP"; //
    default:
        AKVerr(AKV_F_RSA_PRIV_DEC, AKV_R_INVALID_PADDING);
        return NULL;
    }
}

int akv_rsa_priv_dec(int flen, const unsigned char *from,
                     unsigned char *to, RSA *rsa, int padding)
{
    if (padding != RSA_PKCS1_PADDING && padding != RSA_PKCS1_OAEP_PADDING)
    {
        Log(LogLevel_Error, "   unsurported openssl_padding type=%d, only support RSA1_5 or RSA_OAEP \n", padding);
        return -1;
    }

    AKV_KEY *akv_key = NULL;
    const char *alg = padding_to_alg(padding);
    if (alg == NULL)
    {
        Log(LogLevel_Error, "   unsurported openssl_padding type=%d\n, only support RSA1_5 or RSA_OAEP", padding);
        return -1;
    }

    akv_key = RSA_get_ex_data(rsa, rsa_akv_idx);
    if (!akv_key)
    {
        AKVerr(AKV_F_RSA_PRIV_DEC, AKV_R_CANT_GET_AKV_KEY);
        return -1;
    }

    MemoryStruct accessToken;
    if (!GetAccessTokenFromIMDS(akv_key->keyvault_type, &accessToken))
    {
        return -1;
    }

    MemoryStruct clearText;
    if (AkvDecrypt(akv_key->keyvault_type, akv_key->keyvault_name, akv_key->key_name, &accessToken, alg, from, flen, &clearText) == 1)
    {
        Log(LogLevel_Debug, "Decrypt successfully clear text size=[%zu]\n", clearText.size);
        if (to != NULL)
        {
            memcpy(to, clearText.memory, clearText.size);
        }
        else
        {
            Log(LogLevel_Debug, "size probe, return [%zu]\n", clearText.size);
        }

        free(clearText.memory);
        free(accessToken.memory);
        return (int)clearText.size;
    }
    else
    {
        Log(LogLevel_Error, "Failed to decrypt\n");
        free(clearText.memory);
        free(accessToken.memory);
        return -1;
    }
}
