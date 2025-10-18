/* Copyright (c) Microsoft Corporation.
   Licensed under the MIT License. */

#ifndef AKV_PROVIDER_SHARED_H
#define AKV_PROVIDER_SHARED_H

#define __STDC_WANT_LIB_EXT1__ 1

#include <assert.h>
#include <ctype.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/bn.h>
#include <openssl/core.h>
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/decoder.h>
#include <openssl/encoder.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/params.h>
#include <openssl/ecdsa.h>

#include <curl/curl.h>
#include <json-c/json.h>

#ifdef _WIN32
#define strcasecmp _stricmp
#define AKV_PROVIDER_EXPORT __declspec(dllexport)
#else
#define AKV_PROVIDER_EXPORT
#endif

#define LogLevel_Error 0
#define LogLevel_Info 1
#define LogLevel_Debug 2
#define LogLevel_Trace 3

extern int LOG_LEVEL;

#define Log(level, fmt, ...)                                                   \
    do                                                                         \
    {                                                                          \
        WriteLog(level, __LINE__, __FILE__, __FUNCTION__, fmt, ##__VA_ARGS__); \
    } while (0)

void WriteLog(
    int level,
    int line,
    const char *file,
    const char *function,
    const char *fmt,
    ...);

#define KEY_ID_MAX_SIZE 255
#define ApiVersion "api-version=7.2"

struct MemoryStruct_st
{
    unsigned char *memory;
    size_t size;
};

typedef struct MemoryStruct_st MemoryStruct;

char *HexStr(const char *data, size_t len);
size_t WriteMemoryCallback(void *contents, size_t size, size_t nmemb, void *userp);
int GetAccessTokenFromIMDS(const char *type, MemoryStruct *accessToken);
int AkvSign(const char *type, const char *keyvault, const char *keyname, const MemoryStruct *accessToken, const char *alg, const unsigned char *hashText, size_t hashTextSize, MemoryStruct *signatureText);
int AkvDecrypt(const char *type, const char *keyvault, const char *keyname, const MemoryStruct *accessToken, const char *alg, const unsigned char *ciperText, size_t ciperTextSize, MemoryStruct *decryptedText);
int AkvEncrypt(const char *type, const char *keyvault, const char *keyname, const MemoryStruct *accessToken, const char *alg, const unsigned char *clearText, size_t clearTextSize, MemoryStruct *encryptedText);
EVP_PKEY *AkvGetKey(const char *type, const char *keyvault, const char *keyname, const MemoryStruct *accessToken);
void base64urlEncode(const unsigned char *input, size_t inputLen, unsigned char *output, size_t *outputLen);
int base64urlDecode(const unsigned char *input, size_t inputLen, unsigned char *output, size_t *outputLen);

void akv_provider_set_log_level(int level);

#endif /* AKV_PROVIDER_SHARED_H */
