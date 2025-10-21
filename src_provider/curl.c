/* Copyright (c) Microsoft Corporation.
   Licensed under the MIT License. */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/err.h>

#include "akv_provider_shared.h"

#ifndef _WIN32
int strcat_s(char *restrict dest, int destsz, const char *restrict src)
{
  strncat(dest, src, destsz);
  return 0;
}
#endif

static void vaultErrorLog(json_object *parsed_json)
{
    struct json_object *errorText;
    if (json_object_object_get_ex(parsed_json, "error", &errorText))
    {
      struct json_object *code_obj = NULL;
      struct json_object *message_obj = NULL;
      const char *code = NULL;
      const char *message = NULL;

      json_object_object_get_ex(errorText, "code", &code_obj);
      json_object_object_get_ex(errorText, "message", &message_obj);

      if (code_obj != NULL)
      {
        code = json_object_get_string(code_obj);
      }
      if (message_obj != NULL)
      {
        message = json_object_get_string(message_obj);
      }

      const char *error_details = json_object_to_json_string_ext(errorText, JSON_C_TO_STRING_PLAIN);
      Log(LogLevel_Error, "Vault error %s\n", error_details);

  if (code != NULL && strcasecmp(code, "Unauthorized") == 0)
      {
        ERR_raise_data(ERR_LIB_PROV,
                       ERR_R_INTERNAL_ERROR,
                       "Azure Key Vault rejected AZURE_CLI_ACCESS_TOKEN (code=%s, message=%s)",
                       code,
                       message != NULL ? message : "(no message)");
      }
      else
      {
        ERR_raise_data(ERR_LIB_PROV,
                       ERR_R_INTERNAL_ERROR,
                       "Azure Key Vault request failed (code=%s, message=%s)",
                       code != NULL ? code : "unknown",
                       message != NULL ? message : error_details);
      }
    }
    else
    {
      Log(LogLevel_Error, "Vault error - unknown.\n");
      ERR_raise_data(ERR_LIB_PROV,
                     ERR_R_INTERNAL_ERROR,
                     "Azure Key Vault returned an unknown error payload");
    }
}

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
    Log(LogLevel_Error, "not enough memory (realloc returned NULL)\n");
    return 0;
  }

  memcpy(&(mem->memory[mem->size]), contents, realsize);
  mem->size += realsize;
  mem->memory[mem->size] = 0;

  return realsize;
}

#define AZURE_CLI_ACCESS_TOKEN_MAX (8 * 1024)

// Materialize AZURE_CLI_ACCESS_TOKEN into freshly allocated storage.
// getenv returns a pointer backed by the process environment block; copy it immediately so callers
// own a stable buffer (which they must later free) and enforce a predictable size cap.
int GetAccessTokenFromEnv(MemoryStruct *accessToken)
{
  accessToken->memory = NULL;
  accessToken->size = 0;

  const char *azureCliToken = getenv("AZURE_CLI_ACCESS_TOKEN");
  if (!azureCliToken || azureCliToken[0] == '\0')
  {
    Log(LogLevel_Error, "Environment variable AZURE_CLI_ACCESS_TOKEN is not defined or empty.\n");
    ERR_raise_data(ERR_LIB_PROV,
                   ERR_R_PASSED_NULL_PARAMETER,
                   "Set AZURE_CLI_ACCESS_TOKEN before invoking Azure Key Vault operations");
    return 0;
  }

  size_t azureCliAccessTokenSize = strlen(azureCliToken);
  if (azureCliAccessTokenSize + 1 > AZURE_CLI_ACCESS_TOKEN_MAX)
  {
    Log(LogLevel_Error,
        "Environment variable AZURE_CLI_ACCESS_TOKEN exceeds supported size (%zu/%zu bytes).\n",
        azureCliAccessTokenSize + 1,
        (size_t)AZURE_CLI_ACCESS_TOKEN_MAX);
    ERR_raise_data(ERR_LIB_PROV,
                   ERR_R_INTERNAL_ERROR,
                   "AZURE_CLI_ACCESS_TOKEN is too large (%zu bytes)",
                   azureCliAccessTokenSize + 1);
    return 0;
  }

  accessToken->memory = (char *)malloc(azureCliAccessTokenSize + 1);
  if (!accessToken->memory)
  {
    Log(LogLevel_Error, "Failed to allocate memory for the access token.\n");
    accessToken->size = 0;
    ERR_raise_data(ERR_LIB_PROV,
                   ERR_R_MALLOC_FAILURE,
                   "Failed to allocate memory while copying AZURE_CLI_ACCESS_TOKEN");
    return 0;
  }

  memcpy(accessToken->memory, azureCliToken, azureCliAccessTokenSize);
  accessToken->memory[azureCliAccessTokenSize] = '\0';
  accessToken->size = azureCliAccessTokenSize + 1;
  return 1;
}

int AkvSign(const char *keyvault, const char *keyname, const MemoryStruct *accessToken, const char *alg, const unsigned char *hashText, size_t hashTextSize, MemoryStruct *signatureText)
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

  encodeResult = (unsigned char *)malloc(outputLen + 1);
  if (encodeResult == NULL)
  {
    Log(LogLevel_Error, "Failed to allocate %zu bytes for encoded digest\n", outputLen + 1);
    goto cleanup;
  }

  base64urlEncode(hashText, hashTextSize, encodeResult, &outputLen);
  encodeResult[outputLen] = '\0';

  Log(LogLevel_Debug,
      "AkvSign key=%s alg=%s digestLen=%zu digestB64=%s",
      keyname != NULL ? keyname : "(null)",
      alg != NULL ? alg : "(null)",
      hashTextSize,
      (const char *)encodeResult);

  char keyVaultUrl[4 * 1024] = {0};
  strcat_s(keyVaultUrl, sizeof keyVaultUrl, "https://");
  strcat_s(keyVaultUrl, sizeof keyVaultUrl, keyvault);
  strcat_s(keyVaultUrl, sizeof keyVaultUrl, ".managedhsm.azure.net/keys/");
  strcat_s(keyVaultUrl, sizeof keyVaultUrl, keyname);
  strcat_s(keyVaultUrl, sizeof keyVaultUrl, "/sign");

  Log(LogLevel_Debug, "curl.c AkvSign URL: %s", keyVaultUrl);

  curl_handle = curl_easy_init();
  if (curl_handle == NULL)
  {
    Log(LogLevel_Error, "curl_easy_init failed for AkvSign\n");
    goto cleanup;
  }
  curl_easy_setopt(curl_handle, CURLOPT_URL, keyVaultUrl);
  struct curl_slist *headers = NULL;
  headers = curl_slist_append(headers, "Accept: application/json");
  headers = curl_slist_append(headers, "Content-Type: application/json");

  size_t bearer_size = snprintf(NULL, 0, "Authorization: Bearer %s", accessToken->memory) + 1;
  char* bearer = malloc(bearer_size);
  if (!bearer) {
    Log(LogLevel_Error, "Failed to allocate memory for holding the authentication token.\n");
    goto cleanup;
  }
  snprintf(bearer, bearer_size, "Authorization: Bearer %s", accessToken->memory);
  headers = curl_slist_append(headers, bearer);
  free(bearer);

  signature.memory = malloc(1);
  signature.size = 0;
  curl_easy_setopt(curl_handle, CURLOPT_HTTPHEADER, headers);
  curl_easy_setopt(curl_handle, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);
  curl_easy_setopt(curl_handle, CURLOPT_WRITEDATA, (void *)(&signature));
  curl_easy_setopt(curl_handle, CURLOPT_USERAGENT, "libcurl-agent/1.0");

  json = json_object_new_object();
  json_object_object_add(json, "alg", json_object_new_string(alg));
  json_object_object_add(json, "value", json_object_new_string((const char *)encodeResult));

  Log(LogLevel_Trace, "AkvSign request payload: %s", json_object_to_json_string_ext(json, JSON_C_TO_STRING_PLAIN));

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
    vaultErrorLog(parsed_json);
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

  if (json)
    json_object_put(json);

  return result;
}

static EVP_PKEY *getPKey(const unsigned char *n, const size_t nSize, const unsigned char *e, const size_t eSize)
{
  EVP_PKEY *pk = NULL;
  EVP_PKEY_CTX *ctx = NULL;
  unsigned char *n_le = NULL;
  unsigned char *e_le = NULL;

  if (n == NULL || nSize == 0 || e == NULL || eSize == 0)
  {
    Log(LogLevel_Error, "getPKey missing RSA public components\n");
    return NULL;
  }

  ctx = EVP_PKEY_CTX_new_from_name(NULL, "RSA", "provider=default");
  if (ctx == NULL)
  {
    ctx = EVP_PKEY_CTX_new_from_name(NULL, "RSA", "provider=base");
  }
  if (!ctx)
  {
    Log(LogLevel_Error, "Failed to create RSA EVP context\n");
    return NULL;
  }

  if (EVP_PKEY_fromdata_init(ctx) <= 0)
  {
    Log(LogLevel_Error, "EVP_PKEY_fromdata_init failed for RSA\n");
    EVP_PKEY_CTX_free(ctx);
    return NULL;
  }

  n_le = (unsigned char *)malloc(nSize);
  e_le = (unsigned char *)malloc(eSize);
  if (n_le == NULL || e_le == NULL)
  {
    Log(LogLevel_Error, "getPKey failed to allocate buffers for RSA parameters\n");
    goto end;
  }

  /*
   * OSSL_PARAM integer buffers are interpreted in native endianness (see
   * https://www.openssl.org/docs/man3.0/man3/OSSL_PARAM.html#Supported-types),
   * so convert the big-endian JSON payload into little-endian form on hosts
   * where that is required before calling EVP_PKEY_fromdata.
   */
  if (AKV_NATIVE_LITTLE_ENDIAN)
  {
    for (size_t i = 0; i < nSize; ++i)
    {
      n_le[i] = n[nSize - 1 - i];
    }
    for (size_t i = 0; i < eSize; ++i)
    {
      e_le[i] = e[eSize - 1 - i];
    }
  }
  else
  {
    memcpy(n_le, n, nSize);
    memcpy(e_le, e, eSize);
  }

  OSSL_PARAM params[3];
  params[0] = OSSL_PARAM_construct_BN(OSSL_PKEY_PARAM_RSA_N, n_le, nSize);
  params[1] = OSSL_PARAM_construct_BN(OSSL_PKEY_PARAM_RSA_E, e_le, eSize);
  params[2] = OSSL_PARAM_construct_end();

  if (EVP_PKEY_fromdata(ctx, &pk, EVP_PKEY_PUBLIC_KEY, params) <= 0)
  {
    Log(LogLevel_Error, "EVP_PKEY_fromdata failed to materialize RSA key\n");
    pk = NULL;
  }

end:
  if (n_le != NULL)
  {
    free(n_le);
  }
  if (e_le != NULL)
  {
    free(e_le);
  }
  EVP_PKEY_CTX_free(ctx);
  return pk;
}

static EVP_PKEY *getECPKey(const char *group_name, const unsigned char *x, const size_t xSize, const unsigned char *y, const size_t ySize)
{
  EVP_PKEY *pk = NULL;
  EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_name(NULL, "EC", "provider=default");
  if (ctx == NULL)
  {
    ctx = EVP_PKEY_CTX_new_from_name(NULL, "EC", "provider=base");
  }
  if (!ctx)
  {
    Log(LogLevel_Error, "Failed to create EC EVP context\n");
    return NULL;
  }

  if (EVP_PKEY_fromdata_init(ctx) <= 0)
  {
    Log(LogLevel_Error, "EVP_PKEY_fromdata_init failed for EC\n");
    EVP_PKEY_CTX_free(ctx);
    return NULL;
  }

  unsigned char *encoded_point = NULL;
  size_t encoded_len = 0;

  if (x == NULL || y == NULL || xSize == 0 || ySize == 0)
  {
    Log(LogLevel_Error, "getECPKey missing coordinate data for group %s\n", group_name != NULL ? group_name : "(null)");
    goto end;
  }

  if (xSize != ySize)
  {
    Log(LogLevel_Error, "getECPKey coordinate size mismatch for group %s (x=%zu y=%zu)\n", group_name != NULL ? group_name : "(null)", xSize, ySize);
    goto end;
  }

  encoded_len = xSize + ySize + 1;
  encoded_point = (unsigned char *)malloc(encoded_len);
  if (encoded_point == NULL)
  {
    Log(LogLevel_Error, "getECPKey failed to allocate %zu-byte encoded point\n", encoded_len);
    goto end;
  }

  encoded_point[0] = 0x04; /* Uncompressed form */
  memcpy(encoded_point + 1, x, xSize);
  memcpy(encoded_point + 1 + xSize, y, ySize);

  OSSL_PARAM params[5];
  params[0] = OSSL_PARAM_construct_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME, (char *)group_name, 0);
  params[1] = OSSL_PARAM_construct_BN(OSSL_PKEY_PARAM_EC_PUB_X, (unsigned char *)x, xSize);
  params[2] = OSSL_PARAM_construct_BN(OSSL_PKEY_PARAM_EC_PUB_Y, (unsigned char *)y, ySize);
  params[3] = OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_PUB_KEY, encoded_point, encoded_len);
  params[4] = OSSL_PARAM_construct_end();

  if (EVP_PKEY_fromdata(ctx, &pk, EVP_PKEY_PUBLIC_KEY, params) <= 0)
  {
    Log(LogLevel_Error, "EVP_PKEY_fromdata failed to materialize EC key for group %s\n", group_name);
    pk = NULL;
  }

end:
  EVP_PKEY_CTX_free(ctx);
  if (encoded_point != NULL)
  {
    free(encoded_point);
  }
  return pk;
}
EVP_PKEY *AkvGetKey(const char *keyvault, const char *keyname, const MemoryStruct *accessToken)
{
  CURL *curl_handle;
  CURLcode res;
  EVP_PKEY *retPKey = NULL;
  unsigned char *pkeyN = NULL;
  size_t pkeyNSize = 0;

  unsigned char *pkeyE = NULL;
  size_t pkeyESize = 0;

  unsigned char *pkeyX = NULL;
  size_t pkeyXSize = 0;

  unsigned char *pkeyY = NULL;
  size_t pkeyYSize = 0;

  const char *group_name = NULL;

  struct json_object *parsed_json = NULL;

  MemoryStruct keyInfo;
  keyInfo.memory = malloc(1);
  keyInfo.size = 0;

  char keyVaultUrl[4 * 1024] = {0};
  strcat_s(keyVaultUrl, sizeof keyVaultUrl, "https://");
  strcat_s(keyVaultUrl, sizeof keyVaultUrl, keyvault);
  strcat_s(keyVaultUrl, sizeof keyVaultUrl, ".managedhsm.azure.net/keys/");
  strcat_s(keyVaultUrl, sizeof keyVaultUrl, keyname);

  curl_handle = curl_easy_init();

  curl_easy_setopt(curl_handle, CURLOPT_URL, keyVaultUrl);
  struct curl_slist *headers = NULL;
  headers = curl_slist_append(headers, "Accept: application/json");
  headers = curl_slist_append(headers, "Content-Type: application/json");

  size_t bearer_size = snprintf(NULL, 0, "Authorization: Bearer %s", accessToken->memory) + 1;
  char* bearer = malloc(bearer_size);
  if (!bearer) {
    Log(LogLevel_Error, "Failed to allocate memory for holding the authentication token.\n");
    goto cleanup;
  }
  snprintf(bearer, bearer_size, "Authorization: Bearer %s", accessToken->memory);
  headers = curl_slist_append(headers, bearer);
  free(bearer);

  curl_easy_setopt(curl_handle, CURLOPT_HTTPHEADER, headers);
  curl_easy_setopt(curl_handle, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);
  curl_easy_setopt(curl_handle, CURLOPT_WRITEDATA, (void *)(&keyInfo));
  curl_easy_setopt(curl_handle, CURLOPT_USERAGENT, "libcurl-agent/1.0");

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
  if (keyMaterial == NULL)
  {
    vaultErrorLog(parsed_json);
    goto cleanup;
  }

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

  group_name = NULL;
  if (strcasecmp(crv, "P-256") == 0)
    {
      group_name = "prime256v1";
    }
    else if (strcasecmp(crv, "P-256K") == 0)
    {
      group_name = "secp256k1";
    }
    else if (strcasecmp(crv, "P-384") == 0)
    {
      group_name = "secp384r1";
    }
    else if (strcasecmp(crv, "P-521") == 0)
    {
      group_name = "secp521r1";
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
    retPKey = getECPKey(group_name, pkeyX, pkeyXSize, pkeyY, pkeyYSize);
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

int AkvDecrypt(const char *keyvault, const char *keyname, const MemoryStruct *accessToken, const char *alg, const unsigned char *ciperText, size_t ciperTextSize, MemoryStruct *decryptedText)
{
  CURL *curl_handle;
  CURLcode res;
  int result = 0;

  struct json_object *parsed_json = NULL;
  json_object *request_json = NULL;

  MemoryStruct decryption;
  decryption.memory = malloc(1);
  decryption.size = 0;

  char keyVaultUrl[4 * 1024] = {0};
  strcat_s(keyVaultUrl, sizeof keyVaultUrl, "https://");
  strcat_s(keyVaultUrl, sizeof keyVaultUrl, keyvault);
  strcat_s(keyVaultUrl, sizeof keyVaultUrl, ".managedhsm.azure.net/keys/");
  strcat_s(keyVaultUrl, sizeof keyVaultUrl, keyname);
  strcat_s(keyVaultUrl, sizeof keyVaultUrl, "/decrypt");

  curl_handle = curl_easy_init();

  curl_easy_setopt(curl_handle, CURLOPT_URL, keyVaultUrl);
  struct curl_slist *headers = NULL;
  headers = curl_slist_append(headers, "Accept: application/json");
  headers = curl_slist_append(headers, "Content-Type: application/json");

  size_t bearer_size = snprintf(NULL, 0, "Authorization: Bearer %s", accessToken->memory) + 1;
  char* bearer = malloc(bearer_size);
  if (!bearer) {
    Log(LogLevel_Error, "Failed to allocate memory for holding the authentication token.\n");
    goto cleanup;
  }
  snprintf(bearer, bearer_size, "Authorization: Bearer %s", accessToken->memory);
  headers = curl_slist_append(headers, bearer);
  free(bearer);

  curl_easy_setopt(curl_handle, CURLOPT_HTTPHEADER, headers);
  curl_easy_setopt(curl_handle, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);
  curl_easy_setopt(curl_handle, CURLOPT_WRITEDATA, (void *)(&decryption));
  curl_easy_setopt(curl_handle, CURLOPT_USERAGENT, "libcurl-agent/1.0");

  request_json = json_object_new_object();
  size_t outputLen = 0;
  base64urlEncode(ciperText, ciperTextSize, NULL, &outputLen);
  if (outputLen <= 0)
  {
    Log(LogLevel_Error, "could not encode ciper text\n");
    goto cleanup;
  }

  unsigned char *encodedCiperText = (unsigned char *)malloc(outputLen + 1);
  if (encodedCiperText == NULL)
  {
    Log(LogLevel_Error, "Failed to allocate %zu bytes for encoded cipher text\n", outputLen + 1);
    goto cleanup;
  }
  base64urlEncode(ciperText, ciperTextSize, encodedCiperText, &outputLen);
  encodedCiperText[outputLen] = '\0';
  json_object_object_add(request_json, "alg", json_object_new_string(alg));
  json_object_object_add(request_json, "value", json_object_new_string((const char *)encodedCiperText));
  free(encodedCiperText);

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
  if (!json_object_object_get_ex(parsed_json, "value", &clearText)) {
    Log(LogLevel_Error, "no value defined in returned json: \n%s\n", json_object_to_json_string_ext(parsed_json, JSON_C_TO_STRING_SPACED | JSON_C_TO_STRING_PRETTY));
    vaultErrorLog(parsed_json);
    goto cleanup;
  }
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

int AkvEncrypt(const char *keyvault, const char *keyname, const MemoryStruct *accessToken, const char *alg, const unsigned char *clearText, size_t clearTextSize, MemoryStruct *encryptedText)
{
  CURL *curl_handle;
  CURLcode res;
  int result = 0;

  struct json_object *parsed_json = NULL;
  json_object *request_json = NULL;

  MemoryStruct encryption;
  encryption.memory = malloc(1);
  encryption.size = 0;

  char keyVaultUrl[4 * 1024] = {0};
  strcat_s(keyVaultUrl, sizeof keyVaultUrl, "https://");
  strcat_s(keyVaultUrl, sizeof keyVaultUrl, keyvault);
  strcat_s(keyVaultUrl, sizeof keyVaultUrl, ".managedhsm.azure.net/keys/");
  strcat_s(keyVaultUrl, sizeof keyVaultUrl, keyname);
  strcat_s(keyVaultUrl, sizeof keyVaultUrl, "/encrypt");

  curl_handle = curl_easy_init();

  curl_easy_setopt(curl_handle, CURLOPT_URL, keyVaultUrl);
  struct curl_slist *headers = NULL;
  headers = curl_slist_append(headers, "Accept: application/json");
  headers = curl_slist_append(headers, "Content-Type: application/json");

  size_t bearer_size = snprintf(NULL, 0, "Authorization: Bearer %s", accessToken->memory) + 1;
  char* bearer = malloc(bearer_size);
  if (!bearer) {
    Log(LogLevel_Error, "Failed to allocate memory for holding the authentication token.\n");
    goto cleanup;
  }
  snprintf(bearer, bearer_size, "Authorization: Bearer %s", accessToken->memory);
  headers = curl_slist_append(headers, bearer);
  free(bearer);

  curl_easy_setopt(curl_handle, CURLOPT_HTTPHEADER, headers);
  curl_easy_setopt(curl_handle, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);
  curl_easy_setopt(curl_handle, CURLOPT_WRITEDATA, (void *)(&encryption));
  curl_easy_setopt(curl_handle, CURLOPT_USERAGENT, "libcurl-agent/1.0");

  request_json = json_object_new_object();
  size_t outputLen = 0;
  base64urlEncode(clearText, clearTextSize, NULL, &outputLen);
  if (outputLen <= 0)
  {
    Log(LogLevel_Error, "could not encode cleartext\n");
    goto cleanup;
  }

  unsigned char *encodedClearText = (unsigned char *)malloc(outputLen + 1);
  if (encodedClearText == NULL)
  {
    Log(LogLevel_Error, "Failed to allocate %zu bytes for encoded cleartext\n", outputLen + 1);
    goto cleanup;
  }
  base64urlEncode(clearText, clearTextSize, encodedClearText, &outputLen);
  encodedClearText[outputLen] = '\0';
  json_object_object_add(request_json, "alg", json_object_new_string(alg));
  json_object_object_add(request_json, "value", json_object_new_string((const char *)encodedClearText));
  free(encodedClearText);

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
  if (!json_object_object_get_ex(parsed_json, "value", &cipherText)) {
    Log(LogLevel_Error, "no value defined in returned json: \n%s\n", json_object_to_json_string_ext(parsed_json, JSON_C_TO_STRING_SPACED | JSON_C_TO_STRING_PRETTY));
    goto cleanup;
  }
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
