/* Copyright (c) Microsoft Corporation.
   Licensed under the MIT License. */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "pch.h"

#ifndef _WIN32
int strcat_s(char *restrict dest, int destsz, const char *restrict src)
{
  strncat(dest, src, destsz);
  return 0;
}
#endif

char *HexStr(const char *data, size_t len)
{
  if (data == NULL || len == 0)
  {
    return NULL;
  }

  static char hexmap[] =
      {'0', '1', '2', '3', '4', '5', '6', '7',
       '8', '9', 'A', 'B', 'C', 'D', 'E', 'F'};

  char *s = (char *)malloc(len * 2 + 1);
  for (size_t i = 0; i < len; ++i)
  {
    s[2 * i] = hexmap[(data[i] & 0xF0) >> 4];
    s[2 * i + 1] = hexmap[data[i] & 0x0F];
  }

  s[len * 2] = '\0';
  return s;
}

size_t WriteMemoryCallback(void *contents, size_t size, size_t nmemb, void *userp)
{
  size_t realsize = size * nmemb;
  MemoryStruct *mem = (MemoryStruct *)userp;

  mem->memory = realloc(mem->memory, mem->size + realsize + 1);
  if (mem->memory == NULL)
  {
    /* out of memory */
    Log(LogLevel_Error, "not enough memory (realloc returned NULL)\n");
    return 0;
  }

  memcpy(&(mem->memory[mem->size]), contents, realsize);
  mem->size += realsize;
  mem->memory[mem->size] = 0;

  return realsize;
}

int GetAccessTokenFromIMDS(const char *type, MemoryStruct *accessToken)
{
  CURL *curl_handle;
  CURLcode res;

  accessToken->memory = malloc(1);
  accessToken->size = 0;

  char *IDMSEnv = NULL;
  size_t requiredSize;

#ifdef _WIN32
  getenv_s(&requiredSize, NULL, 0, "IDENTITY_ENDPOINT");
  if (requiredSize != 0)
  {
    Log(LogLevel_Error, "IDENTITY_ENDPOINT defined [%zu]\n", requiredSize);
    IDMSEnv = (char *)malloc(requiredSize * sizeof(char));
    if (!IDMSEnv)
    {
      Log(LogLevel_Error, "Failed to allocate memory!\n");
      return 0;
    }

    getenv_s(&requiredSize, IDMSEnv, requiredSize, "IDENTITY_ENDPOINT");
  }
#else
  IDMSEnv = getenv("IDENTITY_ENDPOINT");
#endif

  char idmsUrl[4 * 1024] = {0};
  if (IDMSEnv)
  {
    Log(LogLevel_Info, "Use overrided IDMS url : %s\n", IDMSEnv);
    strcat_s(idmsUrl, sizeof idmsUrl, IDMSEnv);
    strcat_s(idmsUrl, sizeof idmsUrl, "?api-version=2018-02-01");
    free(IDMSEnv);
  }
  else
  {
    strcat_s(idmsUrl, sizeof idmsUrl, "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01");
  }

  if (strcasecmp(type, "vault") == 0)
  {
    strcat_s(idmsUrl, sizeof idmsUrl, "&resource=https://vault.azure.net");
  }
  else if (strcasecmp(type, "managedHsm") == 0)
  {
    strcat_s(idmsUrl, sizeof idmsUrl, "&resource=https://managedhsm.azure.net");
  }
  else
  {
    Log(LogLevel_Error, "AKV type must be either 'managedhsm' or 'vault'!\n");
    return 0;
  }

  curl_handle = curl_easy_init();
  curl_easy_setopt(curl_handle, CURLOPT_URL, idmsUrl);
  struct curl_slist *headers = NULL;
  headers = curl_slist_append(headers, "Content-Type: application/json");
  headers = curl_slist_append(headers, "Metadata: true");
  curl_easy_setopt(curl_handle, CURLOPT_HTTPHEADER, headers);

  curl_easy_setopt(curl_handle, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);
  curl_easy_setopt(curl_handle, CURLOPT_WRITEDATA, (void *)accessToken);
  curl_easy_setopt(curl_handle, CURLOPT_USERAGENT, "libcurl-agent/1.0");

  res = curl_easy_perform(curl_handle);
  curl_easy_cleanup(curl_handle);

  if (res != CURLE_OK)
  {
    Log(LogLevel_Error, "curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
    free(accessToken->memory);
    accessToken->memory = 0;
    accessToken->size = 0;
    return 0;
  }

  struct json_object *parsed_json;
  struct json_object *atoken;
  parsed_json = json_tokener_parse(accessToken->memory);

  if (!json_object_object_get_ex(parsed_json, "access_token", &atoken)) {
    Log(LogLevel_Error, "An access_token field was not found in the IDMS endpoint response. Is a managed identity available?\n");
    free(accessToken->memory);
    accessToken->memory = 0;
    accessToken->size = 0;
    return 0;
  }

  const char *accessTokenStr = json_object_get_string(atoken);
  const size_t accessTokenStrSize = strlen(accessTokenStr);
  char *access = (char *)malloc(accessTokenStrSize + 1);
  memcpy(access, accessTokenStr, accessTokenStrSize);
  access[accessTokenStrSize] = '\0';

  free(accessToken->memory);
  accessToken->memory = access;
  accessToken->size = accessTokenStrSize + 1;
  json_object_put(parsed_json);
  return 1;
}

int AkvSign(const char *type, const char *keyvault, const char *keyname, const MemoryStruct *accessToken, const char *alg, const unsigned char *hashText, size_t hashTextSize, MemoryStruct *signatureText)
{
  CURL *curl_handle;
  CURLcode res;
  json_object *json = NULL;
  int result = 0;
  struct json_object *parsed_json = NULL;
  unsigned char *encodeResult = NULL;

  MemoryStruct signature;
  signature.memory = NULL;
  signature.size = 0;

  size_t outputLen = 0;
  base64urlEncode(hashText, hashTextSize, NULL, &outputLen);
  if (outputLen <= 0)
  {
    Log(LogLevel_Error, "could not encode hash text\n");
    goto cleanup;
  }

  encodeResult = (unsigned char *)malloc(outputLen);
  base64urlEncode(hashText, hashTextSize, encodeResult, &outputLen);

  char keyVaultUrl[4 * 1024] = {0};
  if (strcasecmp(type, "managedHsm") == 0)
  {
    strcat_s(keyVaultUrl, sizeof keyVaultUrl, "https://");
    strcat_s(keyVaultUrl, sizeof keyVaultUrl, keyvault);
    strcat_s(keyVaultUrl, sizeof keyVaultUrl, ".managedhsm.azure.net/keys/");
    strcat_s(keyVaultUrl, sizeof keyVaultUrl, keyname);
    strcat_s(keyVaultUrl, sizeof keyVaultUrl, "/sign");
  }
  else if (strcasecmp(type, "vault") == 0)
  {
    strcat_s(keyVaultUrl, sizeof keyVaultUrl, "https://");
    strcat_s(keyVaultUrl, sizeof keyVaultUrl, keyvault);
    strcat_s(keyVaultUrl, sizeof keyVaultUrl, ".vault.azure.net/keys/");
    strcat_s(keyVaultUrl, sizeof keyVaultUrl, keyname);
    strcat_s(keyVaultUrl, sizeof keyVaultUrl, "/sign");
    strcat_s(keyVaultUrl, sizeof keyVaultUrl, "?");
    strcat_s(keyVaultUrl, sizeof keyVaultUrl, ApiVersion);
  }
  else
  {
    Log(LogLevel_Error, "AKV type must be either 'managedhsm' or 'vault'!\n");
    goto cleanup;
  }

  curl_handle = curl_easy_init();
  curl_easy_setopt(curl_handle, CURLOPT_URL, keyVaultUrl);
  struct curl_slist *headers = NULL;
  headers = curl_slist_append(headers, "Accept: application/json");
  headers = curl_slist_append(headers, "Content-Type: application/json");
  char authHeader[4 * 1024] = {0};
  const char *bearer = "Authorization: Bearer ";
  strcat_s(authHeader, sizeof authHeader, bearer);
  strcat_s(authHeader, sizeof authHeader, accessToken->memory);

  signature.memory = malloc(1);
  signature.size = 0;
  headers = curl_slist_append(headers, authHeader);
  curl_easy_setopt(curl_handle, CURLOPT_HTTPHEADER, headers);
  curl_easy_setopt(curl_handle, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);
  curl_easy_setopt(curl_handle, CURLOPT_WRITEDATA, (void *)(&signature));
  curl_easy_setopt(curl_handle, CURLOPT_USERAGENT, "libcurl-agent/1.0");

  json = json_object_new_object();
  json_object_object_add(json, "alg", json_object_new_string(alg));
  json_object_object_add(json, "value", json_object_new_string(encodeResult));

  curl_easy_setopt(curl_handle, CURLOPT_CUSTOMREQUEST, "POST");
  curl_easy_setopt(curl_handle, CURLOPT_POSTFIELDS, json_object_to_json_string(json));

  res = curl_easy_perform(curl_handle);
  curl_easy_cleanup(curl_handle);

  if (res != CURLE_OK)
  {
    Log(LogLevel_Error, "curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
    goto cleanup;
  }

  parsed_json = json_tokener_parse(signature.memory);

  struct json_object *signedText;

  if (!json_object_object_get_ex(parsed_json, "value", &signedText))
  {
    Log(LogLevel_Error, "no value defined in returned json: \n%s\n", json_object_to_json_string_ext(parsed_json, JSON_C_TO_STRING_SPACED | JSON_C_TO_STRING_PRETTY));
    goto cleanup;
  }
  const char *value = json_object_get_string(signedText);
  const size_t valueSize = strlen(value);
  outputLen = 0;

  int decodeErr = base64urlDecode((const unsigned char *)value, valueSize, NULL, &outputLen);
  if (!decodeErr && outputLen > 0)
  {
    unsigned char *decodeResult = (unsigned char *)malloc(outputLen);
    base64urlDecode((const unsigned char *)value, strlen(value), decodeResult, &outputLen);
    signatureText->memory = decodeResult;
    signatureText->size = outputLen;
    result = 1;
    goto cleanup;
  }
  else
  {
    Log(LogLevel_Error, "decode error %d\n", decodeErr);
    goto cleanup;
  }

cleanup:
  if (encodeResult)
    free(encodeResult);

  if (signature.memory)
    free(signature.memory);

  if (parsed_json)
    json_object_put(parsed_json);

  return result;
}

static EVP_PKEY *getPKey(const unsigned char *n, const size_t nSize, const unsigned char *e, const size_t eSize)
{
  RSA *rsa = RSA_new();
  EVP_PKEY *pk = EVP_PKEY_new();

  if (rsa == NULL || pk == NULL || !EVP_PKEY_assign_RSA(pk, rsa))
  {
    RSA_free(rsa);
    EVP_PKEY_free(pk);
    return NULL;
  }

  if (!RSA_set0_key(rsa, BN_bin2bn(n, (int)nSize, NULL), BN_bin2bn(e, (int)eSize, NULL), NULL))
  {
    EVP_PKEY_free(pk);
    Log(LogLevel_Error, "RSA_set0_key failed\n");
    return NULL;
  }

  return pk;
}

static EVP_PKEY *getECPKey(int nid_curve, const unsigned char *x, const size_t xSize, const unsigned char *y, const size_t ySize)
{
  EC_KEY *ec_key = EC_KEY_new_by_curve_name(nid_curve);
  EC_KEY_set_asn1_flag(ec_key, OPENSSL_EC_NAMED_CURVE);
  EC_KEY_set_conv_form(ec_key, POINT_CONVERSION_COMPRESSED);
  //  EC_KEY_set_conv_form(EVP_PKEY_get1_EC_KEY(peer_key), POINT_CONVERSION_COMPRESSED);
  if (!EC_KEY_set_public_key_affine_coordinates(
          ec_key,
          BN_bin2bn(x, (int)xSize, NULL),
          BN_bin2bn(y, (int)ySize, NULL)))
  {
    Log(LogLevel_Error, "set affine coordinatres failed\n");
    return NULL;
  }

  EVP_PKEY *pk = EVP_PKEY_new();
  if (ec_key == NULL || pk == NULL || !EVP_PKEY_assign_EC_KEY(pk, ec_key))
  {
    EC_KEY_free(ec_key);
    EVP_PKEY_free(pk);
    Log(LogLevel_Error, "EVP_PKEY_assign_EC_KEY failed\n");
    return NULL;
  }

  return pk;
}

EVP_PKEY *AkvGetKey(const char *type, const char *keyvault, const char *keyname, const MemoryStruct *accessToken)
{
  CURL *curl_handle;
  CURLcode res;
  EVP_PKEY *retPKey = NULL;
  /*RSA (N,E)*/
  unsigned char *pkeyN = NULL;
  size_t pkeyNSize = 0;

  unsigned char *pkeyE = NULL;
  size_t pkeyESize = 0;

  /*EC (X,Y)*/
  unsigned char *pkeyX = NULL;
  size_t pkeyXSize = 0;

  unsigned char *pkeyY = NULL;
  size_t pkeyYSize = 0;

  struct json_object *parsed_json = NULL;

  MemoryStruct keyInfo;
  keyInfo.memory = malloc(1); /* will be grown as needed by the realloc above */
  keyInfo.size = 0;           /* no data at this point */

  char keyVaultUrl[4 * 1024] = {0};
  if (strcasecmp(type, "managedHsm") == 0)
  {
    strcat_s(keyVaultUrl, sizeof keyVaultUrl, "https://");
    strcat_s(keyVaultUrl, sizeof keyVaultUrl, keyvault);
    strcat_s(keyVaultUrl, sizeof keyVaultUrl, ".managedhsm.azure.net/keys/");
    strcat_s(keyVaultUrl, sizeof keyVaultUrl, keyname);
  }
  else if (strcasecmp(type, "vault") == 0)
  {
    strcat_s(keyVaultUrl, sizeof keyVaultUrl, "https://");
    strcat_s(keyVaultUrl, sizeof keyVaultUrl, keyvault);
    strcat_s(keyVaultUrl, sizeof keyVaultUrl, ".vault.azure.net/keys/");
    strcat_s(keyVaultUrl, sizeof keyVaultUrl, keyname);
    strcat_s(keyVaultUrl, sizeof keyVaultUrl, "?");
    strcat_s(keyVaultUrl, sizeof keyVaultUrl, ApiVersion);
  }
  else
  {
    Log(LogLevel_Error, "AKV type must be either 'managedhsm' or 'vault'!\n");
    goto cleanup;
  }

  /* init the curl session */
  curl_handle = curl_easy_init();

  /* specify URL to get */
  curl_easy_setopt(curl_handle, CURLOPT_URL, keyVaultUrl);
  // adding the header so service can serialize the request to Bond from Protobuf using Content-Type field
  struct curl_slist *headers = NULL;
  headers = curl_slist_append(headers, "Accept: application/json");
  headers = curl_slist_append(headers, "Content-Type: application/json");
  char authHeader[4 * 1024] = {0};
  const char *bearer = "Authorization: Bearer ";
  strcat_s(authHeader, sizeof authHeader, bearer);
  strcat_s(authHeader, sizeof authHeader, accessToken->memory);

  headers = curl_slist_append(headers, authHeader);
  curl_easy_setopt(curl_handle, CURLOPT_HTTPHEADER, headers);
  curl_easy_setopt(curl_handle, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);
  curl_easy_setopt(curl_handle, CURLOPT_WRITEDATA, (void *)(&keyInfo));
  curl_easy_setopt(curl_handle, CURLOPT_USERAGENT, "libcurl-agent/1.0");

  /* set curl options */
  curl_easy_setopt(curl_handle, CURLOPT_CUSTOMREQUEST, "GET");

  res = curl_easy_perform(curl_handle);
  curl_easy_cleanup(curl_handle);

  if (res != CURLE_OK)
  {
    Log(LogLevel_Error, "curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
    goto cleanup;
  }

  parsed_json = json_tokener_parse(keyInfo.memory);
  Log(LogLevel_Debug, "Key Info in Json \n---\n%s\n---\n", json_object_to_json_string_ext(parsed_json, JSON_C_TO_STRING_SPACED | JSON_C_TO_STRING_PRETTY));

  struct json_object *keyMaterial;
  json_object_object_get_ex(parsed_json, "key", &keyMaterial);

  struct json_object *jKeyType;
  json_object_object_get_ex(keyMaterial, "kty", &jKeyType);
  const char *keyType = json_object_get_string(jKeyType);

  if (keyType == NULL)
  {
    Log(LogLevel_Error, "no kty defined in returned json: \n%s\n", json_object_to_json_string_ext(parsed_json, JSON_C_TO_STRING_SPACED | JSON_C_TO_STRING_PRETTY));
    goto cleanup;
  }

  if (strcasecmp(keyType, "EC-HSM") == 0 || strcasecmp(keyType, "EC") == 0)
  {
    struct json_object *jKeyCrv;
    json_object_object_get_ex(keyMaterial, "crv", &jKeyCrv);
    const char *crv = json_object_get_string(jKeyCrv);
    if (crv == NULL)
    {
      Log(LogLevel_Error, "no crv defined in EC-HSM, returned json: \n%s\n", json_object_to_json_string_ext(parsed_json, JSON_C_TO_STRING_SPACED | JSON_C_TO_STRING_PRETTY));
      goto cleanup;
    }

    int nid_curve;
    /*
    P-256: The NIST P-256 elliptic curve, AKA SECG curve SECP256R1.
    P-384: The NIST P-384 elliptic curve, AKA SECG curve SECP384R1.
    P-521: The NIST P-521 elliptic curve, AKA SECG curve SECP521R1.
    P-256K: The SECG SECP256K1 elliptic curve.
    */
    if (strcasecmp(crv, "P-256") == 0)
    {
      nid_curve = NID_X9_62_prime256v1; // https://stackoverflow.com/questions/41950056/openssl1-1-0-b-is-not-support-secp256r1openssl-ecparam-list-curves
    }
    else if (strcasecmp(crv, "P-256K") == 0)
    {
      nid_curve = NID_secp256k1;
    }
    else if (strcasecmp(crv, "P-384") == 0)
    {
      nid_curve = NID_secp384r1;
    }
    else if (strcasecmp(crv, "P-521") == 0)
    {
      nid_curve = NID_secp521r1;
    }
    else
    {
      Log(LogLevel_Error, "EC-HSM curve not supported: %s\n", crv);
      goto cleanup;
    }

    struct json_object *jKeyX;
    struct json_object *jKeyY;
    json_object_object_get_ex(keyMaterial, "x", &jKeyX);
    json_object_object_get_ex(keyMaterial, "y", &jKeyY);
    const char *xValue = json_object_get_string(jKeyX);
    const char *yValue = json_object_get_string(jKeyY);

    size_t outputLen = 0;

    int decodeErr = base64urlDecode((const unsigned char *)xValue, strlen(xValue), NULL, &outputLen);
    if (!decodeErr && outputLen > 0)
    {
      pkeyX = (unsigned char *)malloc(outputLen);
      pkeyXSize = outputLen;
      base64urlDecode((const unsigned char *)xValue, strlen(xValue), pkeyX, &outputLen);
    }
    else
    {
      Log(LogLevel_Error, "decode X error %d\n", decodeErr);
      goto cleanup;
    }

    outputLen = 0;
    decodeErr = base64urlDecode((const unsigned char *)yValue, strlen(yValue), NULL, &outputLen);
    if (!decodeErr && outputLen > 0)
    {
      pkeyY = (unsigned char *)malloc(outputLen);
      pkeyYSize = outputLen;
      base64urlDecode((const unsigned char *)yValue, strlen(yValue), pkeyY, &outputLen);
    }
    else
    {
      Log(LogLevel_Error, "decode Y error %d\n", decodeErr);
      goto cleanup;
    }

    retPKey = getECPKey(nid_curve, pkeyX, pkeyXSize, pkeyY, pkeyYSize);
  }
  else if (strcasecmp(keyType, "RSA-HSM") == 0 || strcasecmp(keyType, "RSA") == 0)
  {
    struct json_object *jKeyN;
    struct json_object *jKeyE;
    json_object_object_get_ex(keyMaterial, "n", &jKeyN);
    json_object_object_get_ex(keyMaterial, "e", &jKeyE);
    const char *nValue = json_object_get_string(jKeyN);
    const char *eValue = json_object_get_string(jKeyE);
    size_t outputLen = 0;
    int decodeErr = base64urlDecode((const unsigned char *)nValue, strlen(nValue), NULL, &outputLen);

    if (!decodeErr && outputLen > 0)
    {
      pkeyN = (unsigned char *)malloc(outputLen);
      pkeyNSize = outputLen;
      base64urlDecode((const unsigned char *)nValue, strlen(nValue), pkeyN, &outputLen);
    }
    else
    {
      Log(LogLevel_Error, "decode N error %d\n", decodeErr);
      goto cleanup;
    }

    outputLen = 0;
    decodeErr = base64urlDecode((const unsigned char *)eValue, strlen(eValue), NULL, &outputLen);
    if (!decodeErr && outputLen > 0)
    {
      pkeyE = (unsigned char *)malloc(outputLen);
      pkeyESize = outputLen;
      base64urlDecode((const unsigned char *)eValue, strlen(eValue), pkeyE, &outputLen);
    }
    else
    {
      Log(LogLevel_Error, "decode E error %d\n", decodeErr);
      goto cleanup;
    }

    retPKey = getPKey(pkeyN, pkeyNSize, pkeyE, pkeyESize);
  }
  else
  {
    Log(LogLevel_Error, "kty [%s] not supported\n", keyType);
    goto cleanup;
  }

cleanup:
  if (pkeyN)
    free(pkeyN);
  if (pkeyE)
    free(pkeyE);
  if (pkeyX)
    free(pkeyX);
  if (pkeyY)
    free(pkeyY);
  if (keyInfo.memory)
    free(keyInfo.memory);
  if (parsed_json)
    json_object_put(parsed_json);
  return retPKey;
}

int AkvDecrypt(const char *type, const char *keyvault, const char *keyname, const MemoryStruct *accessToken, const char *alg, const unsigned char *ciperText, size_t ciperTextSize, MemoryStruct *decryptedText)
{
  CURL *curl_handle;
  CURLcode res;
  int result = 0;

  struct json_object *parsed_json = NULL;
  json_object *request_json = NULL;

  MemoryStruct decryption;
  decryption.memory = malloc(1); /* will be grown as needed by the realloc above */
  decryption.size = 0;           /* no data at this point */

  char keyVaultUrl[4 * 1024] = {0};
  if (strcasecmp(type, "managedHsm") == 0)
  {
    strcat_s(keyVaultUrl, sizeof keyVaultUrl, "https://");
    strcat_s(keyVaultUrl, sizeof keyVaultUrl, keyvault);
    strcat_s(keyVaultUrl, sizeof keyVaultUrl, ".managedhsm.azure.net/keys/");
    strcat_s(keyVaultUrl, sizeof keyVaultUrl, keyname);
    strcat_s(keyVaultUrl, sizeof keyVaultUrl, "/decrypt");
  }
  else if (strcasecmp(type, "vault") == 0)
  {
    strcat_s(keyVaultUrl, sizeof keyVaultUrl, "https://");
    strcat_s(keyVaultUrl, sizeof keyVaultUrl, keyvault);
    strcat_s(keyVaultUrl, sizeof keyVaultUrl, ".vault.azure.net/keys/");
    strcat_s(keyVaultUrl, sizeof keyVaultUrl, keyname);
    strcat_s(keyVaultUrl, sizeof keyVaultUrl, "/decrypt");
    strcat_s(keyVaultUrl, sizeof keyVaultUrl, "?");
    strcat_s(keyVaultUrl, sizeof keyVaultUrl, ApiVersion);
  }
  else
  {
    Log(LogLevel_Error, "AKV type must be either 'managedhsm' or 'vault'!\n");
    goto cleanup;
  }

  /* init the curl session */
  curl_handle = curl_easy_init();

  /* specify URL to get */
  curl_easy_setopt(curl_handle, CURLOPT_URL, keyVaultUrl);
  // adding the header so service can serialize the request to Bond from Protobuf using Content-Type field
  struct curl_slist *headers = NULL;
  headers = curl_slist_append(headers, "Accept: application/json");
  headers = curl_slist_append(headers, "Content-Type: application/json");
  char authHeader[4 * 1024] = {0};
  const char *bearer = "Authorization: Bearer ";
  strcat_s(authHeader, sizeof authHeader, bearer);
  strcat_s(authHeader, sizeof authHeader, accessToken->memory);

  headers = curl_slist_append(headers, authHeader);
  curl_easy_setopt(curl_handle, CURLOPT_HTTPHEADER, headers);
  curl_easy_setopt(curl_handle, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);
  curl_easy_setopt(curl_handle, CURLOPT_WRITEDATA, (void *)(&decryption));
  curl_easy_setopt(curl_handle, CURLOPT_USERAGENT, "libcurl-agent/1.0");

  /* create json object for post */
  request_json = json_object_new_object();
  /* build post data
    {
        "alg": "RSA1_5",
        "value": "cipher"
    }
  */
  size_t outputLen = 0;
  base64urlEncode(ciperText, ciperTextSize, NULL, &outputLen);
  if (outputLen <= 0)
  {
    Log(LogLevel_Error, "could not encode ciper text\n");
    goto cleanup;
  }

  unsigned char *encodedCiperText = (unsigned char *)malloc(outputLen);
  base64urlEncode(ciperText, ciperTextSize, encodedCiperText, &outputLen);
  json_object_object_add(request_json, "alg", json_object_new_string(alg));
  json_object_object_add(request_json, "value", json_object_new_string(encodedCiperText));
  free(encodedCiperText);

  /* set curl options */
  curl_easy_setopt(curl_handle, CURLOPT_CUSTOMREQUEST, "POST");
  curl_easy_setopt(curl_handle, CURLOPT_POSTFIELDS, json_object_to_json_string(request_json));

  res = curl_easy_perform(curl_handle);
  curl_easy_cleanup(curl_handle);

  if (res != CURLE_OK)
  {
    Log(LogLevel_Error, "curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
    goto cleanup;
  }

  parsed_json = json_tokener_parse(decryption.memory);

  struct json_object *clearText;
  json_object_object_get_ex(parsed_json, "value", &clearText);
  const char *value = json_object_get_string(clearText);
  const size_t valueSize = strlen(value);
  outputLen = 0;

  int decodeErr = base64urlDecode((const unsigned char *)value, valueSize, NULL, &outputLen);
  if (!decodeErr && outputLen > 0)
  {
    unsigned char *result = (unsigned char *)malloc(outputLen);
    base64urlDecode((const unsigned char *)value, strlen(value), result, &outputLen);
    decryptedText->memory = result;
    decryptedText->size = outputLen;
  }
  else
  {
    Log(LogLevel_Error, "decode error %d\n", decodeErr);
    goto cleanup;
  }

  result = 1;
cleanup:
  if (decryption.memory)
    free(decryption.memory);
  if (parsed_json)
    json_object_put(parsed_json);
  if (request_json)
    json_object_put(request_json);
  return result;
}

int AkvEncrypt(const char *type, const char *keyvault, const char *keyname, const MemoryStruct *accessToken, const char *alg, const unsigned char *plainText, size_t plainTextSize, MemoryStruct *encryptedText)
{
  CURL *curl_handle;
  CURLcode res;
  int result = 0;

  struct json_object *parsed_json = NULL;
  json_object *request_json = NULL;

  MemoryStruct encryption;
  encryption.memory = malloc(1); /* will be grown as needed by the realloc above */
  encryption.size = 0;           /* no data at this point */

  char keyVaultUrl[4 * 1024] = {0};
  if (strcasecmp(type, "managedHsm") == 0)
  {
    strcat_s(keyVaultUrl, sizeof keyVaultUrl, "https://");
    strcat_s(keyVaultUrl, sizeof keyVaultUrl, keyvault);
    strcat_s(keyVaultUrl, sizeof keyVaultUrl, ".managedhsm.azure.net/keys/");
    strcat_s(keyVaultUrl, sizeof keyVaultUrl, keyname);
    strcat_s(keyVaultUrl, sizeof keyVaultUrl, "/encrypt");
  }
  else if (strcasecmp(type, "vault") == 0)
  {
    strcat_s(keyVaultUrl, sizeof keyVaultUrl, "https://");
    strcat_s(keyVaultUrl, sizeof keyVaultUrl, keyvault);
    strcat_s(keyVaultUrl, sizeof keyVaultUrl, ".vault.azure.net/keys/");
    strcat_s(keyVaultUrl, sizeof keyVaultUrl, keyname);
    strcat_s(keyVaultUrl, sizeof keyVaultUrl, "/encrypt");
    strcat_s(keyVaultUrl, sizeof keyVaultUrl, "?");
    strcat_s(keyVaultUrl, sizeof keyVaultUrl, ApiVersion);
  }
  else
  {
    Log(LogLevel_Error, "AKV type must be either 'managedhsm' or 'vault'!\n");
    goto cleanup;
  }

  /* init the curl session */
  curl_handle = curl_easy_init();

  /* specify URL to get */
  curl_easy_setopt(curl_handle, CURLOPT_URL, keyVaultUrl);
  // adding the header so service can serialize the request to Bond from Protobuf using Content-Type field
  struct curl_slist *headers = NULL;
  headers = curl_slist_append(headers, "Accept: application/json");
  headers = curl_slist_append(headers, "Content-Type: application/json");
  char authHeader[4 * 1024] = {0};
  const char *bearer = "Authorization: Bearer ";
  strcat_s(authHeader, sizeof authHeader, bearer);
  strcat_s(authHeader, sizeof authHeader, accessToken->memory);

  headers = curl_slist_append(headers, authHeader);
  curl_easy_setopt(curl_handle, CURLOPT_HTTPHEADER, headers);
  curl_easy_setopt(curl_handle, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);
  curl_easy_setopt(curl_handle, CURLOPT_WRITEDATA, (void *)(&encryption));
  curl_easy_setopt(curl_handle, CURLOPT_USERAGENT, "libcurl-agent/1.0");

  /* create json object for post */
  request_json = json_object_new_object();
  /* build post data
    {
        "alg": "RSA1_5",
        "value": "plaintext"
    }
  */
  size_t outputLen = 0;
  base64urlEncode(plainText, plainTextSize, NULL, &outputLen);
  if (outputLen <= 0)
  {
    Log(LogLevel_Error, "could not encode plain text\n");
    goto cleanup;
  }

  unsigned char *encodedPlainText = (unsigned char *)malloc(outputLen);
  base64urlEncode(plainText, plainTextSize, encodedPlainText, &outputLen);
  json_object_object_add(request_json, "alg", json_object_new_string(alg));
  json_object_object_add(request_json, "value", json_object_new_string(encodedPlainText));
  free(encodedPlainText);

  /* set curl options */
  curl_easy_setopt(curl_handle, CURLOPT_CUSTOMREQUEST, "POST");
  curl_easy_setopt(curl_handle, CURLOPT_POSTFIELDS, json_object_to_json_string(request_json));

  res = curl_easy_perform(curl_handle);
  curl_easy_cleanup(curl_handle);

  if (res != CURLE_OK)
  {
    Log(LogLevel_Error, "curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
    goto cleanup;
  }

  parsed_json = json_tokener_parse(encryption.memory);

  struct json_object *cipherText;
  json_object_object_get_ex(parsed_json, "value", &cipherText);
  const char *value = json_object_get_string(cipherText);
  const size_t valueSize = strlen(value);
  outputLen = 0;

  int decodeErr = base64urlDecode((const unsigned char *)value, valueSize, NULL, &outputLen);
  if (!decodeErr && outputLen > 0)
  {
    unsigned char *result = (unsigned char *)malloc(outputLen);
    base64urlDecode((const unsigned char *)value, strlen(value), result, &outputLen);
    encryptedText->memory = result;
    encryptedText->size = outputLen;
  }
  else
  {
    Log(LogLevel_Error, "decode error %d\n", decodeErr);
    goto cleanup;
  }

  result = 1;
cleanup:
  if (encryption.memory)
    free(encryption.memory);
  if (parsed_json)
    json_object_put(parsed_json);
  if (request_json)
    json_object_put(request_json);
  return result;
}