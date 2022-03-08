/* Copyright (c) Microsoft Corporation.
   Licensed under the MIT License. */

#ifndef PCH_H
#define PCH_H
#define __STDC_WANT_LIB_EXT1__ 1

// add headers that you want to pre-compile here

#include <openssl/crypto.h>
#include <openssl/buffer.h>
#include <openssl/bn.h>
#include <openssl/rsa.h>
#include <openssl/dsa.h>
#include <openssl/engine.h>
#include <assert.h>
#include <ctype.h>

#include <curl/curl.h>
#include <json-c/json.h>
#include <string.h>

#include "e_akv_err.h"
#include "base64.h"

#ifdef _WIN32
#define strcasecmp _stricmp
#endif

#define LogLevel_Error 0
#define LogLevel_Info 1
#define LogLevel_Debug 2

extern int LOG_LEVEL;

#define Log(level, fmt, ...)                                                   \
    do                                                                         \
    {                                                                          \
        WriteLog(level, __LINE__, __FILE__, __FUNCTION__, fmt, ##__VA_ARGS__); \
    } while (0)

/**
Write log information to stdout
@param[in] level Log level
@param[in] line Code line number
@param[in] file File name
@param[in] function Function name
@param[in] fmt Format string for the output
*/
void WriteLog(
    int level,
    int line,
    const char *file,
    const char *function,
    const char *fmt,
    ...);

#define KEY_ID_MAX_SIZE 255

extern const ENGINE_CMD_DEFN akv_cmd_defns[];

/**
Engine control function
@param[in] e Input engine
@param[in] cmd Command code, only one command is supported right now to turn on debug
@param[in] i Debug level, 0 == OFF, other == ON
@param[in] p Not Used
@param[in] f Not Used
*/
int akv_ctrl(ENGINE *e, int cmd, long i, void *p, void (*f)(void));

#define ApiVersion "api-version=7.2"
struct MemoryStruct_st
{
    unsigned char *memory;
    size_t size;
};

typedef struct MemoryStruct_st MemoryStruct;

/**
 * @brief Output the hex printable string for the input data array
 *
 * @param data Input binary data array
 * @param len Length of input binary data array
 * @return Hex printable string
 */
char *HexStr(const char *data, size_t len);

/**
 * @brief Callback function in lib Curl to store the response data
 *
 * @param contents Reponse data
 * @param size Size of memory block
 * @param nmemb Number of memory block
 * @param userp The MemoryStruct to store the repsonse data
 * @return The total size of response data = memory block size * number of memory block
 */
size_t WriteMemoryCallback(void *contents, size_t size, size_t nmemb, void *userp);

/**
 * @brief Get the Access Token From IMDS service
 *
 * @param type The type of the key vault, e.g. "vault" or "managedHsm"
 * @param accessToken The returned access token
 * @return 1 == success, 0 == failure
 */
int GetAccessTokenFromIMDS(const char *type, MemoryStruct *accessToken);

/**
 * @brief Sign with RSA or EC private key stored in key vault or managed HSM
 *
 * @param type The type of the key vault, e.g. "vault" or "managedHsm"
 * @param keyvault The key vault or managed HSM name
 * @param keyname  The key name
 * @param accessToken The access token
 * @param alg Algorithm, e.g. "RS256"
 * @param hashText The hash text to be signed
 * @param hashTextSize The size of the hash text
 * @param signatureText The returned signature text
 * @return 1 == success, 0 == failure
 */
int AkvSign(const char *type, const char *keyvault, const char *keyname, const MemoryStruct *accessToken, const char *alg, const unsigned char *hashText, size_t hashTextSize, MemoryStruct *signatureText);

/**
 * @brief Decrypt with RSA or EC private key stored in key vault or managed HSM
 *
 * @param type The type of the key vault, e.g. "vault" or "managedHsm"
 * @param keyvault The key vault or managed HSM name
 * @param keyname The key name
 * @param accessToken The access token
 * @param alg Algorithm, e.g. "RS256"
 * @param ciperText The cipher text to be decrypted
 * @param ciperTextSize The size of the cipher text
 * @param decryptedText The returned decrypted text
 * @return 1 == success, 0 == failure
 */
int AkvDecrypt(const char *type, const char *keyvault, const char *keyname, const MemoryStruct *accessToken, const char *alg, const unsigned char *ciperText, size_t ciperTextSize, MemoryStruct *decryptedText);

/**
 * @brief Encrypt with RSA or EC private key stored in key vault or managed HSM
 *
 * @param type The type of the key vault, e.g. "vault" or "managedHsm"
 * @param keyvault The key vault or managed HSM name
 * @param keyname The key name
 * @param accessToken The access token
 * @param alg Algorithm, e.g. "RS256"
 * @param plainText The plain text to be decrypted
 * @param plainTextSize The size of the plain text
 * @param encryptedText The returned encrypted text
 * @return 1 == success, 0 == failure
 */
int AkvEncrypt(const char *type, const char *keyvault, const char *keyname, const MemoryStruct *accessToken, const char *alg, const unsigned char *plainText, size_t plainTextSize, MemoryStruct *encryptedText);

/**
 * @brief Get the Openssl public key from key vault or managed HSM
 *
 * @param type The type of the key vault, e.g. "vault" or "managedHsm"
 * @param keyvault The key vault or managed HSM name
 * @param keyname The key name
 * @param accessToken The access token
 * @return EVP_PKEY == success, NULL == failure
 */
EVP_PKEY *AkvGetKey(const char *type, const char *keyvault, const char *keyname, const MemoryStruct *accessToken);

struct AKV_KEY_st
{
    char *keyvault_type; // managedHsm or vault
    char *keyvault_name;
    char *key_name;
};

typedef struct AKV_KEY_st AKV_KEY;

extern int akv_idx;
extern int rsa_akv_idx;
extern int eckey_akv_idx;

/**
 * @brief Create AKV_KEY structure to store key vault type, key vault name, and key name.
 *
 * @param keyvault_type The type of the key vault, e.g. "vault" or "managedHsm"
 * @param keyvault_name The key vault or Managed HSM name
 * @param key_name The key name
 * @return AKV_KEY == success, NULL == failure
 */
AKV_KEY *acquire_akv_key(
    const char *keyvault_type, // managedHsm or vault
    const char *keyvault_name,
    const char *key_name);

/**
 * @brief Release AKV_KEY structure
 *
 * @param key The AKV_KEY structure to be released
 */
void destroy_akv_key(AKV_KEY *key);

/**
 * @brief Engine function for RSA private key signing
 *
 * @param ctx EVP_PKEY context
 * @param sig Signature text
 * @param siglen Signature text length
 * @param tbs To be signed text
 * @param tbslen To be signed text length
 * @return 1 == success, 0 == failure
 */
int akv_pkey_rsa_sign(EVP_PKEY_CTX *ctx, unsigned char *sig,
                      size_t *siglen, const unsigned char *tbs,
                      size_t tbslen);

static EVP_PKEY *akv_load_privkey(ENGINE *eng, const char *key_id,
                           UI_METHOD *ui_method, void *callback_data);

/**
 * @brief Engine function for RSA private key decrypt
 *
 * @param flen cipher text length
 * @param from cipher text
 * @param to decrypted text
 * @param rsa RSA key context
 * @param padding Padding type
 * @return 1 == success, 0 == failure
 */
int akv_rsa_priv_dec(int flen, const unsigned char *from,
                     unsigned char *to, RSA *rsa, int padding);


/**
 * @brief Engine function for RSA private key encrypt
 *
 * @param flen cipher text length
 * @param from plain text
 * @param to cipher text
 * @param rsa RSA key context
 * @param padding Padding type
 * @return 1 == success, 0 == failure
 */
int akv_rsa_priv_enc(int flen, const unsigned char *from,
                     unsigned char *to, RSA *rsa, int padding);

/**
 * @brief Engine function for EC private key signing
 *
 * @param type Not Used
 * @param dgst digest text
 * @param dlen digest text length
 * @param sig signature text
 * @param siglen signature text length
 * @param kinv Not Used
 * @param r Not Used
 * @param eckey EC key context
 * @return 1 == success, 0 == failure
 */
int akv_eckey_sign(int type, const unsigned char *dgst, int dlen,
                   unsigned char *sig, unsigned int *siglen,
                   const BIGNUM *kinv, const BIGNUM *r, EC_KEY *eckey);

/**
 * @brief Engine function for EC private key signing
 *
 * @param dgst digest text
 * @param dgst_len digest text length
 * @param in_kinv Not Used
 * @param in_r Not Used
 * @param eckey EC key context
 * @return ECDSA_SIG == success, NULL == failure
 */
ECDSA_SIG *akv_eckey_sign_sig(const unsigned char *dgst, int dgst_len,
                              const BIGNUM *in_kinv, const BIGNUM *in_r,
                              EC_KEY *eckey);

#endif //PCH_H
