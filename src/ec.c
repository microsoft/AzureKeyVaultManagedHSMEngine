/* Copyright (c) Microsoft Corporation.
   Licensed under the MIT License. */

#include "pch.h"

/**
 * @brief return KeyVault or Managed HSM algorithm name for the given ec key 
 * @see https://docs.microsoft.com/en-us/rest/api/keyvault/sign/sign
 * 
 * @param ecKey EC key
 * @return algorithm name == success, NULL == failure
 */
static char *eckey_to_alg(const EC_KEY *ecKey)
{
  if (ecKey == NULL)
  {
    Log(LogLevel_Error, "ecKey is null\n");
    return NULL;
  }

  const EC_GROUP *ec_group = EC_KEY_get0_group(ecKey);
  if (ec_group == NULL)
  {
    Log(LogLevel_Error, "ec_group is null\n");
    return NULL;
  }

  int nid_crv = EC_GROUP_get_curve_name(ec_group);
  if (nid_crv == NID_X9_62_prime256v1)
  {
    return "ES256";
  }
  else if (nid_crv == NID_secp256k1)
  {
    return "ES256K";
  }
  else if (nid_crv == NID_secp384r1)
  {
    return "ES384";
  }
  else if (nid_crv == NID_secp521r1)
  {
    return "ES512";
  }

  Log(LogLevel_Error, "curve not supported: %d\n", nid_crv);
  return NULL;
}

int akv_eckey_sign(int type, const unsigned char *dgst, int dlen,
                   unsigned char *sig, unsigned int *siglen,
                   const BIGNUM *kinv, const BIGNUM *r, EC_KEY *eckey)
{
  (void)type;
  (void)r;
  (void)kinv;
  int res = -1;

  AKV_KEY *akv_key = EC_KEY_get_ex_data(eckey, eckey_akv_idx);
  if (!akv_key)
  {
    AKVerr(AKV_F_EC_KEY_SIGN, AKV_R_CANT_GET_AKV_KEY);
    return res;
  }

  const char *AKV_ALG = eckey_to_alg(eckey);
  if (AKV_ALG == NULL)
  {
    AKVerr(AKV_F_EC_KEY_SIGN, AKV_R_INVALID_EC_KEY);
    return res;
  }

  Log(LogLevel_Debug, "-->akv_eckey_sign, dgst size [%d], AKV_ALG [%s]\n", dlen, AKV_ALG);

  MemoryStruct accessToken;
  if (!GetAccessTokenFromIMDS(akv_key->keyvault_type, &accessToken))
  {
    return res;
  }

  MemoryStruct signatureText;
  Log(LogLevel_Debug, "keyvault [%s][%s]\n", akv_key->keyvault_name, akv_key->key_name);
  if (AkvSign(akv_key->keyvault_type, akv_key->keyvault_name, akv_key->key_name, &accessToken, AKV_ALG, dgst, dlen, &signatureText) == 1)
  {
    Log(LogLevel_Debug, "Signed successfully signature.size=[%zu]\n", signatureText.size);
    int rSize = (int)signatureText.size / 2;
    int sSize = rSize;

    ECDSA_SIG *ecdsa_sig = ECDSA_SIG_new();
    ECDSA_SIG_set0(ecdsa_sig,
                   BN_bin2bn(signatureText.memory, rSize, NULL),
                   BN_bin2bn(signatureText.memory + rSize, sSize, NULL));

    int derSize = i2d_ECDSA_SIG(ecdsa_sig, NULL);
    unsigned char *derSig = (unsigned char *)malloc(derSize);

    unsigned char *p = derSig; // keep the track of derSig, because i2d_ECDSA_SIG will change the value of p
    i2d_ECDSA_SIG(ecdsa_sig, &p);

    if (siglen)
    {
      *siglen = derSize;
    }

    memcpy(sig, derSig, derSize);
    if (derSig)
      free(derSig);
    if (signatureText.memory)
      free(signatureText.memory);
    if (accessToken.memory)
      free(accessToken.memory);
    if (ecdsa_sig)
      ECDSA_SIG_free(ecdsa_sig);
    Log(LogLevel_Debug, "<--akv_eckey_sign, siglen size [%d], AKV_ALG [%s]\n", derSize, AKV_ALG);
    return 1;
  }
  else
  {
    Log(LogLevel_Error, "Failed to Sign\n");
    if (signatureText.memory)
      free(signatureText.memory);
    if (accessToken.memory)
      free(accessToken.memory);
    return 0;
  }
}

ECDSA_SIG *akv_eckey_sign_sig(const unsigned char *dgst, int dgst_len,
                              const BIGNUM *in_kinv, const BIGNUM *in_r,
                              EC_KEY *eckey)
{
  unsigned char *sig = NULL;
  int siglen = ECDSA_size(eckey);
  ECDSA_SIG *decodedSig = NULL;

  if (siglen > 0)
  {
    sig = (unsigned char *)OPENSSL_zalloc(siglen);
  }

  if (!sig)
  {
    AKVerr(AKV_F_EC_KEY_SIGN_SIG, AKV_R_ALLOC_FAILURE);
    return NULL;
  }

  int ret = akv_eckey_sign(0, dgst, dgst_len, sig, &siglen,
                           NULL, NULL, eckey);

  if (ret == -1)
  {
    goto cleanup;
  }

  const unsigned char *p = sig;
  decodedSig = d2i_ECDSA_SIG(NULL, &p, (long)siglen);

cleanup:
  if (sig)
    OPENSSL_free(sig);
  return decodedSig;
}
