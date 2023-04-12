/* Copyright (c) Microsoft Corporation.
   Licensed under the MIT License. */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "log.h"
#include "pch.h"
//#include <openssl/async.h>
#include "/home/azureuser/repos/roxy/dependencies/include/openssl/async.h"
#include <unistd.h>
#define _GNU_SOURCE             /* See feature_test_macros(7) */
#include <sys/mman.h>
#include <fcntl.h>
//#include <sched.h>


const char *engine_id = "e_akv";
bool do_async_fd = false;
CURL *curl_handle;

static void fd_cleanup(ASYNC_WAIT_CTX *ctx, const void *key,
                           OSSL_ASYNC_FD readfd, void *custom)
{
    if (close(readfd) != 0) {
        log_debug("Failed to close readfd: %d - error: %d\n", readfd, errno);
    }
}

int setup_async_event_notification(volatile ASYNC_JOB *job, char* buf)
{
    ASYNC_WAIT_CTX *waitctx;
    OSSL_ASYNC_FD memfd;
    void *custom = NULL;

    if ((waitctx = ASYNC_get_wait_ctx((ASYNC_JOB *)job)) == NULL) {
        log_debug("Could not obtain wait context for job\n");
        return 0;
    }

    if (ASYNC_WAIT_CTX_get_fd(waitctx, engine_id, &memfd,
                              &custom) == 0) {
        //efd = eventfd(0, EFD_NONBLOCK);
        memfd = memfd_create("test", 0);
        if (memfd == -1) {
            log_debug("Failed to get memfd = %d\n", errno);
            return 0;
        }
        if (write(memfd, buf, strlen(buf)) == -1)
        {
          if (errno != EAGAIN) {
            log_debug("Failed to write to fd: %d - error: %d\n", memfd, errno);
          } 
        }
        else {
          log_debug("memfd is %d\n", memfd);
          void *ptr = mmap(NULL, strlen(buf), PROT_READ | PROT_WRITE, MAP_SHARED, memfd, 0);
          log_debug("Read from memfd %s", (char*)ptr);
        }

        if (ASYNC_WAIT_CTX_set_wait_fd(waitctx, engine_id, memfd,
                                       buf, fd_cleanup) == 0) {
            log_debug("failed to set the fd in the ASYNC_WAIT_CTX\n");
            fd_cleanup(waitctx, engine_id, memfd, NULL);
            return 0;
        }
    }
    return 1;
}

int pause_job(volatile ASYNC_JOB *job, void* userp)
{
    ASYNC_WAIT_CTX *waitctx;
    int ret = 0;
    OSSL_ASYNC_FD readfd;
    void *custom = NULL;
    uint64_t buf = 0;
    char* response;

    if ((waitctx = ASYNC_get_wait_ctx((ASYNC_JOB *)job)) == NULL) {
        log_debug("waitctx == NULL\n");
        return ret;
    }
    log_debug("Pausing job\n");
    if (ASYNC_pause_job() == 0) {
        log_debug("Failed to pause the job\n");
        return ret;
    }
    else {
        log_debug("Paused job\n");
    }
    log_debug("In pause job function, resumed\n");
    if ((ret = ASYNC_WAIT_CTX_get_fd(waitctx, engine_id, &readfd,
                                     &custom)) > 0) {
        /*if (read(readfd, &buf, sizeof(uint64_t)) == -1) {
            if (errno != EAGAIN) {
                log_debug("Failed to read from fd: %d - error: %d\n", readfd, errno);
            } 
            return 0;
        }*/
        log_debug("memfd is %d\n", readfd);
        void *ptr = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_SHARED, readfd, 0);
        response = (char*)ptr;
        log_debug("Read from memfd after resuming job %s\n", response);
    }
    
    // Parsing response from AKV/MHSM
    //char* cl_start = strstr(response, "Content-Length: ") + 16;
    char* cl_start = strstr(response, "content-length: ") + 16;
    if (cl_start == NULL) {
      log_debug("Content Length is not found in response\n");
      return 0;
    }
    int cl = 0;
    while (isdigit(cl_start[0])) {
      cl = 10*cl + (int)cl_start[0] - 48;  // 48 is ASCII code for '0'
      cl_start++;
    }
    log_debug("Content length is %d\n", cl);
    char* response_start = strstr(cl_start, "\r\n\r\n") + 4;
    WriteMemoryCallback(response_start, cl, 1, userp);
    log_debug("Response is %s\n", ((MemoryStruct *)userp)->memory);
    //close(readfd);
    return ret;
}

int wake_job(volatile ASYNC_JOB *job)
{
    ASYNC_WAIT_CTX *waitctx;
    int ret = 0;
    OSSL_ASYNC_FD efd;
    void *custom = NULL;
    // Arbitary value '1' to write down the pipe to trigger event 
    uint64_t buf = 1;

    if ((waitctx = ASYNC_get_wait_ctx((ASYNC_JOB *)job)) == NULL) {
        log_debug("waitctx == NULL\n");
        return ret;
    }

    if ((ret = ASYNC_WAIT_CTX_get_fd(waitctx, engine_id, &efd,
                                     &custom)) > 0) {
        if (write(efd, &buf, sizeof(uint64_t)) == -1) {
            log_debug("Failed to write to fd: %d - error: %d\n", efd, errno);
        }
    }
    return ret;
}

#ifndef _WIN32
int strcat_s(char *restrict dest, int destsz, const char *restrict src)
{
  strncat(dest, src, destsz);
  return 0;
}
#endif

static void vaultErrorLog(json_object *parsed_json)
{
    log_debug("In vaultErrorLog \n");
    struct json_object *errorText;
    if (json_object_object_get_ex(parsed_json, "error", &errorText))
    {
      log_error( "Vault error %s\n", json_object_to_json_string_ext(errorText, JSON_C_TO_STRING_PLAIN));
    }
    else
    {
      log_error( "Vault error - unknown.\n");
    }
}
//hex to ascii helper function
char *HexStr(const char *data, size_t len)
{
  log_debug("In HexStr \n");
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
  log_debug("In WriteMemoryCallback \n");
  size_t realsize = size * nmemb;
  MemoryStruct *mem = (MemoryStruct *)userp;

  mem->memory = realloc(mem->memory, mem->size + realsize + 1);
  if (mem->memory == NULL)
  {
    /* out of memory */
    log_error( "not enough memory (realloc returned NULL)\n");
    return 0;
  }

  memcpy(&(mem->memory[mem->size]), contents, realsize);
  mem->size += realsize;
  mem->memory[mem->size] = 0;

  return realsize;
}

int GetAccessTokenFromIMDS(const char *type, MemoryStruct *accessToken)
{
  log_debug("In GetAccessTokenFromIMDS \n");

	#ifdef _WIN32	
  // Allow AZURE CLI Access token override by environment variable "AZURE_CLI_ACCESS_TOKEN"	
  size_t azureCliAccessTokenSize;	
  getenv_s(&azureCliAccessTokenSize, NULL, 0, "AZURE_CLI_ACCESS_TOKEN");	
  if (azureCliAccessTokenSize != 0)	
  {	
    Log(LogLevel_Info, "Environment variable AZURE_CLI_ACCESS_TOKEN defined [%zu]\n", azureCliAccessTokenSize);	
    accessToken->memory  = (char *)malloc(azureCliAccessTokenSize * sizeof(char));	
    if (!accessToken->memory)	
    {	
      Log(LogLevel_Error, "Environment variable AZURE_CLI_ACCESS_TOKEN defined, but failed to allocate memory for accessToken->memory!\n");	
      return 0;	
    }	
    getenv_s(&azureCliAccessTokenSize, accessToken->memory, azureCliAccessTokenSize, "AZURE_CLI_ACCESS_TOKEN");	
    accessToken->size = azureCliAccessTokenSize;	
    return 1;	
  }	
#else	
  //char *azureCliToken = getenv("AZURE_CLI_ACCESS_TOKEN");
  const char *azureCliToken = "";
  size_t azureCliAccessTokenSize;	
  if (azureCliToken)
  {	
    log_debug("azureCliToken is not null\n");
    azureCliAccessTokenSize = strlen(azureCliToken);	
    Log(LogLevel_Info, "Environment variable AZURE_CLI_ACCESS_TOKEN defined [%zu]\n", azureCliAccessTokenSize);	
    accessToken->memory  = (char *)malloc((azureCliAccessTokenSize+1) * sizeof(char));	
    if (!accessToken->memory)	
    {	
      Log(LogLevel_Error, "Environment variable AZURE_CLI_ACCESS_TOKEN defined, but failed to allocate memory for accessToken->memory!\n");	
      return 0;	
    }	
    memcpy(accessToken->memory, azureCliToken, azureCliAccessTokenSize);	
    accessToken->memory[azureCliAccessTokenSize] = '\0';	
    accessToken->size = azureCliAccessTokenSize;	
    log_debug("Access token fetched from env\n");
    return 1;	
  }	
#endif

  log_debug("Access token not fetched from env\n");
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
    log_error( "IDENTITY_ENDPOINT defined [%zu]\n", requiredSize);
    IDMSEnv = (char *)malloc(requiredSize * sizeof(char));
    if (!IDMSEnv)
    {
      log_error( "Failed to allocate memory!\n");
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
    log_info( "Use overrided IDMS url : %s\n", IDMSEnv);
    strcat_s(idmsUrl, sizeof idmsUrl, IDMSEnv);
    strcat_s(idmsUrl, sizeof idmsUrl, "?api-version=2018-02-01");
#ifdef _WIN32
    free(IDMSEnv);
#endif
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
    log_error( "AKV type must be either 'managedhsm' or 'vault'!\n");
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
    log_error( "curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
    free(accessToken->memory);
    accessToken->memory = NULL;
    accessToken->size = 0;
    return 0;
  }

  struct json_object *parsed_json;
  struct json_object *atoken;
  parsed_json = json_tokener_parse(accessToken->memory);

  if (!json_object_object_get_ex(parsed_json, "access_token", &atoken)) {
    log_error( "An access_token field was not found in the IDMS endpoint response. Is a managed identity available?\n");
    vaultErrorLog(parsed_json);
    free(accessToken->memory);
    accessToken->memory = NULL;
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
  log_debug("In AkvSign \n");
  //CURL *curl_handle;
  CURLcode res;
  json_object *json = NULL;
  int result = 0;
  struct json_object *parsed_json = NULL;
  char *encodeResult = NULL;

  MemoryStruct signature;
  signature.memory = NULL;
  signature.size = 0;

  size_t outputLen = 0;

  //to find the output length
  outputLen = base64_encode_len(hashTextSize);
  // encode the hashtext
  encodeResult = malloc(outputLen+1);
  for(int i = 0; i < outputLen+1; i++){
    encodeResult[i] = '\0';
  }
  base64_encode(encodeResult, hashText, hashTextSize);

  //prints to check the results/passed values
  log_info("Hashtext size (from parameters): %d", hashTextSize);
  log_info("Hashtext: %s", HexStr(hashText, hashTextSize));
  log_info("Given Encoded result: %s", encodeResult);
  log_info("output length: %d", outputLen);
  log_info("keyvault: %s", keyvault);
  log_info("keyname: %s", keyname);
  log_info("accesstoken: %s", accessToken->memory);
  log_info("alg: %s", alg);
  log_info("type %s", type);

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
    log_error( "AKV type must be either 'managedhsm' or 'vault'!\n");
    goto cleanup;
  }

  char authHeader[4 * 1024] = {0};
  const char *bearer = "Authorization: Bearer ";
  strcat_s(authHeader, sizeof authHeader, bearer);
  strcat_s(authHeader, sizeof authHeader, accessToken->memory);
  log_info("auth header bearer: %s", bearer);
  log_info("auth header accesstoken: %s", accessToken->memory); 

  signature.memory = malloc(1);
  signature.size = 0;

  json = json_object_new_object();
  json_object_object_add(json, "alg", json_object_new_string(alg));
  json_object_object_add(json, "value", json_object_new_string(encodeResult));
  const char *post_body = json_object_to_json_string(json);
  log_info( "json: \n%s", json_object_to_json_string_ext(json, JSON_C_TO_STRING_SPACED));

  ASYNC_JOB *currjob;
  currjob = ASYNC_get_current_job();
  if (currjob && do_async_fd) 
  {
    log_debug("Executing within a job\n");
    const char *post_request_format = "POST /keys/%s/sign HTTP/1.1\r\nHost: afd-keyless-test-wus.managedhsm.azure.net\r\nAccept: application/json\r\nConnection: keep-alive, Keep-Alive\r\nKeep-Alive: timeout=5, max=100\r\nContent-Type: application/json\r\nContent-Length: %d\r\nAuthorization: Bearer %s\r\n\r\n%s\r\n\r\n\r\n";
    //const char *post_request_format = "POST /keys/%s/sign?api-version=7.2 HTTP/1.1\r\nHost: t-cbrugal-kv.vault.azure.net\r\nAccept: application/json\r\nConnection: keep-alive, Keep-Alive\r\nKeep-Alive: timeout=5, max=100\r\nContent-Type: application/json\r\nContent-Length: %d\r\nAuthorization: Bearer %s\r\n\r\n%s\r\n\r\n\r\n";
    int buf_size = strlen(post_request_format)+strlen(keyname)+strlen(accessToken->memory)+strlen(post_body);
    char *buf = malloc(buf_size);
    sprintf(buf, post_request_format, keyname, strlen(post_body), accessToken->memory, post_body);
    log_debug("%s\n", buf);
    setup_async_event_notification(currjob, buf);
    pause_job(currjob, &signature);
  }
  else if (currjob) {
    log_debug("Executing within a job, in nginx threadpool flow\n");
    KEYLESS_CTX *keyless_ctx = malloc(sizeof(KEYLESS_CTX));
    keyless_ctx->type = type;
    keyless_ctx->keyvault = &keyVaultUrl;
    keyless_ctx->keyname = keyname;
    keyless_ctx->access_token = &authHeader;
    keyless_ctx->alg = alg;
    keyless_ctx->input_buffer = hashText;
    keyless_ctx->input_buffer_size = hashTextSize;
    ASYNC_WAIT_CTX_set_keyless_ctx(ASYNC_get_wait_ctx(currjob), keyless_ctx);
    ASYNC_pause_job();
    log_debug("Job woken up in nginx threadpool flow\n");
    signature.memory = keyless_ctx->output_buffer;
    signature.size = keyless_ctx->output_buffer_size;
  }
  else {
    log_debug("Not executing within a job\n");
    //building up the curl_handle call (url, headers, tokens, values (POST))
    if (curl_handle == NULL) {
      curl_handle = curl_easy_init();
    }
    curl_easy_setopt(curl_handle, CURLOPT_URL, keyVaultUrl);
    struct curl_slist *headers = NULL;
    headers = curl_slist_append(headers, "Accept: application/json");
    headers = curl_slist_append(headers, "Content-Type: application/json");
    headers = curl_slist_append(headers, authHeader);
    curl_easy_setopt(curl_handle, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl_handle, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);
    curl_easy_setopt(curl_handle, CURLOPT_WRITEDATA, (void *)(&signature));
    curl_easy_setopt(curl_handle, CURLOPT_USERAGENT, "libcurl-agent/1.0");
    curl_easy_setopt(curl_handle, CURLOPT_CUSTOMREQUEST, "POST");
    curl_easy_setopt(curl_handle, CURLOPT_POSTFIELDS, post_body);

    res = curl_easy_perform(curl_handle);
    //curl_easy_cleanup(curl_handle);

    if (res != CURLE_OK)
    {
      log_error( "curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
      goto cleanup;
    }
  }
  parsed_json = json_tokener_parse(signature.memory);

  struct json_object *signedText;

  log_info( "parsed json: \n%s", json_object_to_json_string_ext(parsed_json, JSON_C_TO_STRING_SPACED));
  if (!json_object_object_get_ex(parsed_json, "value", &signedText))
  {
    log_error( "no value defined in returned json: \n%s\n", json_object_to_json_string_ext(parsed_json, JSON_C_TO_STRING_SPACED));
    vaultErrorLog(parsed_json);
    goto cleanup;
  }
  const char *value = json_object_get_string(signedText);
  const size_t valueSize = strlen(value);
  outputLen = 0;
  int decodeErr = base64urlDecode((const unsigned char *)value, valueSize, NULL, &outputLen);

  log_info("Value size: %d", valueSize);
  log_info("Output length: %d", outputLen);

  unsigned char * decodeResult = malloc(outputLen+1);

  if ( !decodeErr && outputLen > 0)
  {
    base64urlDecode((const unsigned char *)value, strlen(value), decodeResult, &outputLen);
    log_info("Given Decoded result: %s",  HexStr(decodeResult, outputLen));
    log_info("signature text size: %d", signatureText->size);
    signatureText->memory = decodeResult;
    signatureText->size = outputLen;
    result = 1;
    goto cleanup;
  }
  else
  {
    log_error( "decode error: did not decode properly\n");
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
  log_debug("In getPKey \n");
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
    log_error( "RSA_set0_key failed\n");
    return NULL;
  }

  return pk;
}

static EVP_PKEY *getECPKey(int nid_curve, const unsigned char *x, const size_t xSize, const unsigned char *y, const size_t ySize)
{
  log_debug("In getECPKey \n");
  EC_KEY *ec_key = EC_KEY_new_by_curve_name(nid_curve);
  EC_KEY_set_asn1_flag(ec_key, OPENSSL_EC_NAMED_CURVE);
  EC_KEY_set_conv_form(ec_key, POINT_CONVERSION_COMPRESSED);
  //  EC_KEY_set_conv_form(EVP_PKEY_get1_EC_KEY(peer_key), POINT_CONVERSION_COMPRESSED);
  if (!EC_KEY_set_public_key_affine_coordinates(
          ec_key,
          BN_bin2bn(x, (int)xSize, NULL),
          BN_bin2bn(y, (int)ySize, NULL)))
  {
    log_error( "set affine coordinatres failed\n");
    return NULL;
  }

  EVP_PKEY *pk = EVP_PKEY_new();
  if (ec_key == NULL || pk == NULL || !EVP_PKEY_assign_EC_KEY(pk, ec_key))
  {
    EC_KEY_free(ec_key);
    EVP_PKEY_free(pk);
    log_error( "EVP_PKEY_assign_EC_KEY failed\n");
    return NULL;
  }

  return pk;
}

EVP_PKEY *AkvGetKey(const char *type, const char *keyvault, const char *keyname, const MemoryStruct *accessToken)
{
  log_debug("In AkvGetKey \n");
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
    log_error( "AKV type must be either 'managedhsm' or 'vault'!\n");
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
    log_error( "curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
    goto cleanup;
  }

  parsed_json = json_tokener_parse(keyInfo.memory);
  log_debug( "Key Info in Json \n---\n%s\n---\n", json_object_to_json_string_ext(parsed_json, JSON_C_TO_STRING_SPACED | JSON_C_TO_STRING_PRETTY));

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
    log_error( "no kty defined in returned json: \n%s\n", json_object_to_json_string_ext(parsed_json, JSON_C_TO_STRING_SPACED | JSON_C_TO_STRING_PRETTY));
    goto cleanup;
  }

  if (strcasecmp(keyType, "EC-HSM") == 0 || strcasecmp(keyType, "EC") == 0)
  {
    struct json_object *jKeyCrv;
    json_object_object_get_ex(keyMaterial, "crv", &jKeyCrv);
    const char *crv = json_object_get_string(jKeyCrv);
    if (crv == NULL)
    {
      log_error( "no crv defined in EC-HSM, returned json: \n%s\n", json_object_to_json_string_ext(parsed_json, JSON_C_TO_STRING_SPACED | JSON_C_TO_STRING_PRETTY));
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
      log_error( "EC-HSM curve not supported: %s\n", crv);
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
      log_error( "decode X error %d\n", decodeErr);
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
      log_error( "decode Y error %d\n", decodeErr);
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
      log_error( "decode N error %d\n", decodeErr);
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
      log_error( "decode E error %d\n", decodeErr);
      goto cleanup;
    }

    retPKey = getPKey(pkeyN, pkeyNSize, pkeyE, pkeyESize);
  }
  else
  {
    log_error( "kty [%s] not supported\n", keyType);
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
  log_debug("In AkvDecrypt \n");
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
    log_error( "AKV type must be either 'managedhsm' or 'vault'!\n");
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
    log_error( "could not encode ciper text\n");
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
    log_error( "curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
    goto cleanup;
  }

  parsed_json = json_tokener_parse(decryption.memory);

  struct json_object *clearText;
  if (!json_object_object_get_ex(parsed_json, "value", &clearText)) {
    log_error( "no value defined in returned json: \n%s\n", json_object_to_json_string_ext(parsed_json, JSON_C_TO_STRING_SPACED | JSON_C_TO_STRING_PRETTY));
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
    log_error( "decode error %d\n", decodeErr);
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

int AkvEncrypt(const char *type, const char *keyvault, const char *keyname, const MemoryStruct *accessToken, const char *alg, const unsigned char *clearText, size_t clearTextSize, MemoryStruct *encryptedText)
{
  log_debug("In AkvEncrypt \n");
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
    log_error( "AKV type must be either 'managedhsm' or 'vault'!\n");
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
        "value": "cleartext"
    }
  */
  size_t outputLen = 0;
  base64urlEncode(clearText, clearTextSize, NULL, &outputLen);
  if (outputLen <= 0)
  {
    log_error( "could not encode cleartext\n");
    goto cleanup;
  }

  unsigned char *encodedClearText = (unsigned char *)malloc(outputLen);
  base64urlEncode(clearText, clearTextSize, encodedClearText, &outputLen);
  json_object_object_add(request_json, "alg", json_object_new_string(alg));
  json_object_object_add(request_json, "value", json_object_new_string(encodedClearText));
  free(encodedClearText);

  /* set curl options */
  curl_easy_setopt(curl_handle, CURLOPT_CUSTOMREQUEST, "POST");
  curl_easy_setopt(curl_handle, CURLOPT_POSTFIELDS, json_object_to_json_string(request_json));

  res = curl_easy_perform(curl_handle);
  curl_easy_cleanup(curl_handle);

  if (res != CURLE_OK)
  {
    log_error( "curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
    goto cleanup;
  }

  parsed_json = json_tokener_parse(encryption.memory);

  struct json_object *cipherText;
  if (!json_object_object_get_ex(parsed_json, "value", &cipherText)) {
    log_error( "no value defined in returned json: \n%s\n", json_object_to_json_string_ext(parsed_json, JSON_C_TO_STRING_SPACED | JSON_C_TO_STRING_PRETTY));
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
    log_error( "decode error %d\n", decodeErr);
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