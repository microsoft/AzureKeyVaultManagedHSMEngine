/* Copyright (c) Microsoft Corporation.
   Licensed under the MIT License. */

#include "pch.h"
#include <openssl/err.h>
#include "e_akv_err.h"

#ifndef OPENSSL_NO_ERR

static ERR_STRING_DATA AKV_str_functs[] = {
    {ERR_PACK(0, AKV_F_CTRL, 0), "akv_ctrl"},
    {ERR_PACK(0, AKV_F_CTX_NEW, 0), "akv_ctx_new"},
    {ERR_PACK(0, AKV_F_INIT, 0), "akv_init"},
    {ERR_PACK(0, AKV_F_LOAD, 0), "akv_load"},
    {ERR_PACK(0, AKV_F_RSA_PRIV_DEC, 0), "akv_rsa_priv_dec"},
    {ERR_PACK(0, AKV_F_RSA_PRIV_ENC, 0), "akv_rsa_priv_enc"},
    {ERR_PACK(0, AKV_F_GET_PRIVATE_RSA, 0), "akv_get_private_rsa"},
    {ERR_PACK(0, AKV_F_GET_PRIVATE_EC_KEY, 0), "akv_get_private_eckey"},
    {ERR_PACK(0, AKV_F_EC_KEY_SIGN, 0), "akv_eckey_sign"},
    {ERR_PACK(0, AKV_F_EC_KEY_SIGN_SETUP, 0), "akv_eckey_sign_setup"},
    {ERR_PACK(0, AKV_F_EC_KEY_SIGN_SIG, 0), "akv_eckey_sign_sig"},
    {ERR_PACK(0, AKV_F_LOAD_PRIVKEY, 0), "akv_load_privkey"},
    {ERR_PACK(0, AKV_F_ACQUIRE_AKV, 0), "acquire_akv_key"},
    {ERR_PACK(0, AKV_F_RSA_SIGN, 0), "akv_pkey_rsa_sign"},
    {ERR_PACK(0, AKV_F_LOAD_KEY_CERT, 0), "akv_load_key_cert"},
    {0, NULL}};

static ERR_STRING_DATA AKV_str_reasons[] = {
    {ERR_PACK(0, 0, AKV_R_ALLOC_FAILURE), "allocation failure"},
    {ERR_PACK(0, 0, AKV_R_CANT_FIND_AKV_CONTEXT), "cant find akv context"},
    {ERR_PACK(0, 0, AKV_R_PARSE_KEY_ID_ERROR), "parse key id error"},
    {ERR_PACK(0, 0, AKV_R_LOAD_PUBKEY_ERROR), "load public key error"},
    {ERR_PACK(0, 0, AKV_R_OPEN_ERROR), "pfx open error"},
    {ERR_PACK(0, 0, AKV_R_UNSUPPORTED_SSL_CLIENT_CERT), "unsupported ssl client cert"},
    {ERR_PACK(0, 0, AKV_R_CANT_GET_KEY), "can't get key"},
    {ERR_PACK(0, 0, AKV_R_CANT_GET_METHOD), "cant get methid"},
    {ERR_PACK(0, 0, AKV_R_ENGINE_NOT_INITIALIZED), "engine not initialized"},
    {ERR_PACK(0, 0, AKV_R_FILE_OPEN_ERROR), "file open error"},
    {ERR_PACK(0, 0, AKV_R_INVALID_RSA), "invalid RSA"},
    {ERR_PACK(0, 0, AKV_R_INVALID_EC_KEY), "invalid EC_KEY"},
    {ERR_PACK(0, 0, AKV_R_UNSUPPORTED_KEY_ALGORITHM), "unsupported key algorithm"},
    {ERR_PACK(0, 0, AKV_R_UNKNOWN_COMMAND), "unknown command"},
    {ERR_PACK(0, 0, AKV_R_CANT_CREATE_X509), "can't create X509 object from cert context"},
    {ERR_PACK(0, 0, AKV_R_INVALID_STORE_LOCATION), "invalid store location"},
    {ERR_PACK(0, 0, AKV_R_CANT_OPEN_STORE), "can't open store"},
    {ERR_PACK(0, 0, AKV_R_INVALID_KEY_SPEC), "invalid key spec"},
    {ERR_PACK(0, 0, AKV_R_INVALID_CERT), "invalid cert"},
    {ERR_PACK(0, 0, AKV_R_CANT_FIND_CERT), "can't find cert"},
    {ERR_PACK(0, 0, AKV_R_INVALID_THUMBPRINT), "invalid thumbprint"},
    {ERR_PACK(0, 0, AKV_R_INVALID_MD), "invalid MD"},
    {ERR_PACK(0, 0, AKV_R_NO_PADDING), "no padding not supported"},
    {ERR_PACK(0, 0, AKV_R_CANT_GET_PADDING), "can't get padding"},
    {ERR_PACK(0, 0, AKV_R_CANT_GET_AKV_KEY), "can't get akv key"},
    {ERR_PACK(0, 0, AKV_R_INVALID_SALT), "invalid salt"},
    {ERR_PACK(0, 0, AKV_R_INVALID_PADDING), "invalid padding"},
    {ERR_PACK(0, 0, AKV_R_AKV_SIGN_HASH_FAIL), "sign hash fail"},
    {ERR_PACK(0, 0, AKV_R_AKV_DECRYPT_FAIL_1), "first decrypt fail"},
    {ERR_PACK(0, 0, AKV_R_AKV_DECRYPT_FAIL_2), "second decrypt fail"},
    {ERR_PACK(0, 0, AKV_R_ENCODE_FAIL), "encode fail"},
    {0, NULL}};
#endif

static int lib_code = 0;
static int error_loaded = 0;

int ERR_load_AKV_strings(void)
{
    if (lib_code == 0)
        lib_code = ERR_get_next_error_library();

    if (!error_loaded)
    {
#ifndef OPENSSL_NO_ERR
        ERR_load_strings(lib_code, AKV_str_functs);
        ERR_load_strings(lib_code, AKV_str_reasons);
#endif
        error_loaded = 1;
    }
    return 1;
}

void ERR_unload_AKV_strings(void)
{
    if (error_loaded)
    {
#ifndef OPENSSL_NO_ERR
        ERR_unload_strings(lib_code, AKV_str_functs);
        ERR_unload_strings(lib_code, AKV_str_reasons);
#endif
        error_loaded = 0;
    }
}

void ERR_AKV_error(int function, int reason, char *file, int line)
{
    if (lib_code == 0)
        lib_code = ERR_get_next_error_library();
    ERR_PUT_error(lib_code, function, reason, file, line);
}