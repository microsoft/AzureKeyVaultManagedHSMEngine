/* Copyright (c) Microsoft Corporation.
   Licensed under the MIT License. */

#include "log.h"
#include "pch.h"

/*
#include <openssl/async.h>
#include <unistd.h>
#include <sys/eventfd.h>
#define _GNU_SOURCE           
#include <sched.h>

const char *engine_id = "e_akv";

static void fd_cleanup(ASYNC_WAIT_CTX *ctx, const void *key,
                           OSSL_ASYNC_FD readfd, void *custom)
{
    if (close(readfd) != 0) {
        log_debug("Failed to close readfd: %d - error: %d\n", readfd, errno);
    }
}

int setup_async_event_notification(volatile ASYNC_JOB *job)
{
    ASYNC_WAIT_CTX *waitctx;
    OSSL_ASYNC_FD efd;
    void *custom = NULL;

    if ((waitctx = ASYNC_get_wait_ctx((ASYNC_JOB *)job)) == NULL) {
        log_debug("Could not obtain wait context for job\n");
        return 0;
    }

    if (ASYNC_WAIT_CTX_get_fd(waitctx, engine_id, &efd,
                              &custom) == 0) {
        efd = eventfd(0, EFD_NONBLOCK);
        if (efd == -1) {
            log_debug("Failed to get eventfd = %d\n", errno);
            return 0;
        }

        if (ASYNC_WAIT_CTX_set_wait_fd(waitctx, engine_id, efd,
                                       custom, fd_cleanup) == 0) {
            log_debug("failed to set the fd in the ASYNC_WAIT_CTX\n");
            fd_cleanup(waitctx, engine_id, efd, NULL);
            return 0;
        }
    }
    return 1;
}

int pause_job(volatile ASYNC_JOB *job)
{
    ASYNC_WAIT_CTX *waitctx;
    int ret = 0;
    OSSL_ASYNC_FD readfd;
    void *custom = NULL;
    uint64_t buf = 0;

    if ((waitctx = ASYNC_get_wait_ctx((ASYNC_JOB *)job)) == NULL) {
        log_debug("waitctx == NULL\n");
        return ret;
    }
    log_debug("Pauing job\n");
    if (ASYNC_pause_job() == 0) {
        log_debug("Failed to pause the job\n");
        return ret;
    }
    else {
        log_debug("Paused job\n");
    }

    if ((ret = ASYNC_WAIT_CTX_get_fd(waitctx, engine_id, &readfd,
                                     &custom)) > 0) {
        if (read(readfd, &buf, sizeof(uint64_t)) == -1) {
            if (errno != EAGAIN) {
                log_debug("Failed to read from fd: %d - error: %d\n", readfd, errno);
            } 
            return 0;
        }
    }
    log_debug("In pause job function, resumed\n");
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

void *async_crypto_op(void *vargp)
{
    crypto_op_data* op_data = (crypto_op_data*)vargp;
    op_data->x = 100;
    unsigned cpu, node;
    getcpu(&cpu, &node);
    log_debug("Async thread cpu %u node %u\n", cpu, node);
    AkvSign(op_data->type, op_data->keyvault, op_data->keyname, op_data->accessToken, op_data->alg, op_data->hashText, op_data->hashTextSize, op_data->signatureText);
    wake_job(op_data->async_job);
}
*/

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
    log_debug( "   sigmd type=%d", mdType);

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
    log_debug("In akv_pkey_rsa_sign \n");
    
    if (siglen == NULL)
    {
        log_error( "siglen is NULL\n");
        return 0;
    }

    EVP_PKEY *pkey = EVP_PKEY_CTX_get0_pkey(ctx);
    if (!pkey)
    {
        log_debug("EVP_PKEY_CTX_get0_pkey failed \n");
        AKVerr(AKV_F_RSA_SIGN, AKV_R_CANT_GET_KEY);
        return -1;
    }

    RSA *rsa = EVP_PKEY_get0_RSA(pkey);
    if (!rsa)
    {
        log_debug("EVP_PKEY_get0_RSA failed \n");
        AKVerr(AKV_F_RSA_SIGN, AKV_R_INVALID_RSA);
        return -1;
    }

    if (!sig) {
        // OpenSSL may call this method without a sig array to
        // obtain the expected siglen value. This should be
        // treated as a successful call.
        *siglen = RSA_size(rsa);
        log_debug( "sig is null, setting siglen to [%zu]\n", *siglen);
        return 1;
    }

    AKV_KEY *akv_key = RSA_get_ex_data(rsa, rsa_akv_idx);
    if (!akv_key)
    {
        log_debug("Fallback to openssl method \n");
        int (*psign)(EVP_PKEY_CTX *ctx, unsigned char *sig, size_t *siglen,
                 const unsigned char *tbs, size_t tbslen);
        const EVP_PKEY_METHOD *orig_pmeth = EVP_PKEY_meth_find(EVP_PKEY_id(pkey));
        if (!psign) {
            log_debug("psign NULL before get sign method\n");
        }
        log_debug("psign before get sign method %d\n", psign);
        EVP_PKEY_meth_get_sign(orig_pmeth, 0, &psign);

        if (!psign) {
            log_debug("Coudn't find openssl fallback\n");
            return -1;
        }
        log_debug("psign after get sign method %d\n", psign);
        log_debug("akv_pkey_rsa_sign method fn pointer %d\n", &akv_pkey_rsa_sign);
        return psign(ctx, sig, siglen, tbs, tbslen);
        /*AKVerr(AKV_F_RSA_SIGN, AKV_R_CANT_GET_AKV_KEY);
        return -1;*/
    }

    const EVP_MD *sigmd = NULL;
    if (EVP_PKEY_CTX_get_signature_md(ctx, &sigmd) != 1)
    {
        log_debug("EVP_PKEY_CTX_get_signature_md failed \n");
        AKVerr(AKV_F_RSA_SIGN, AKV_R_INVALID_MD);
        return 0;
    }

    // Don't support no padding.
    if (!sigmd)
    {
        log_debug("sigmd is false  \n");
        AKVerr(AKV_F_RSA_SIGN, AKV_R_NO_PADDING);
        return 0;
    }

    const char *AKV_ALG = ctx_to_alg(ctx, sigmd);
    log_debug( "-->akv_pkey_rsa_sign, tbs size [%zu], AKV_ALG [%s]", tbslen, AKV_ALG);

    MemoryStruct accessToken;
    if (!GetAccessTokenFromIMDS(akv_key->keyvault_type, &accessToken))
    {
        return 0;
    }

    MemoryStruct signatureText;
    log_debug( "keyvault [%s][%s]", akv_key->keyvault_name, akv_key->key_name);
    /*int ret;
    ASYNC_JOB *currjob;
    currjob = ASYNC_get_current_job();
    if (currjob != NULL) {
        unsigned cpu, node;
        getcpu(&cpu, &node);
        log_debug("Executing within a job cpu %u node %u\n", cpu, node);
        crypto_op_data *op_data = malloc(sizeof(crypto_op_data));
        pthread_t async_tid;
        op_data->accessToken = &accessToken;
        op_data->alg = AKV_ALG;
        op_data->async_job = currjob;
        op_data->hashText = tbs;
        op_data->hashTextSize = tbslen;
        op_data->keyname = akv_key->key_name;
        op_data->keyvault = akv_key->keyvault_name;
        op_data->signatureText = &signatureText;
        op_data->type = akv_key->keyvault_type;
        op_data->x = 1;
        /*pthread_mutex_lock(&txt_mutex);
        log_debug("before setting txt in rsa, txt %d txt ptr %p\n", *txt, txt);
        *txt = 7;
        pthread_mutex_unlock(&txt_mutex);
        crypto_op_enqueue(async_crypto_op_queue, op_data);
        int c = 0;
        unsigned cpu, node;
        //crypto_op_data* d = crypto_op_dequeue(async_crypto_op_queue);
        //log_debug("Dequeued %p\n", d);
        //crypto_op_enqueue(async_crypto_op_queue, op_data);*/
        /*setup_async_event_notification(currjob);
        pthread_create(&async_tid, NULL, async_crypto_op, op_data);
        //wake_job(currjob);
        pause_job(currjob);
        log_debug("In akv_pkey_rsa_sign function, resumed\n");
        log_debug("In akv_pkey_rsa_sign op_data x %d\n", op_data->x);
        ret = 1;
        //free(op_data);
    } else {
        log_debug("Not executing within a job\n");
        ret = AkvSign(akv_key->keyvault_type, akv_key->keyvault_name, akv_key->key_name, &accessToken, AKV_ALG, tbs, tbslen, &signatureText);
    }*/
     
    int ret = AkvSign(akv_key->keyvault_type, akv_key->keyvault_name, akv_key->key_name, &accessToken, AKV_ALG, tbs, tbslen, &signatureText);

    if (ret == 1)
    {
        log_debug("Signed successfully signature.size=[%zu]\n", signatureText.size);

        if (*siglen == signatureText.size)
        {
            memcpy(sig, signatureText.memory, signatureText.size);
        }
        else
        {
            log_debug( "size prob = %zu\n", signatureText.size);
            *siglen = signatureText.size;
        }

        free(signatureText.memory);
        free(accessToken.memory);
        return 1;
    }
    else
    {
        log_error( "Failed to Sign\n");
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
    log_debug( "   openssl_padding type=%d\n", openssl_padding);

    switch (openssl_padding)
    {
    case RSA_PKCS1_PADDING:
    case RSA_NO_PADDING:
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
    log_debug("In akv_rsa_priv_dec \n");
    if (padding != RSA_PKCS1_PADDING && padding != RSA_PKCS1_OAEP_PADDING && padding != RSA_NO_PADDING)
    {
        log_error( "   unsurported openssl_padding type=%d, only support RSA1_5 or RSA_OAEP \n", padding);
        return -1;
    }

    AKV_KEY *akv_key = NULL;
    const char *alg = padding_to_alg(padding);
    if (alg == NULL)
    {
        log_error( "   unsurported openssl_padding type=%d\n, only support RSA1_5 or RSA_OAEP", padding);
        return -1;
    }

    akv_key = RSA_get_ex_data(rsa, rsa_akv_idx);
    if (!akv_key)
    {
        typedef int (*PFN_RSA_meth_priv_dec)(int flen, const unsigned char *from, unsigned char *to, RSA *rsa, int padding);
        const RSA_METHOD *ossl_rsa_meth = RSA_PKCS1_OpenSSL();
        PFN_RSA_meth_priv_dec pfn_rsa_meth_priv_dec = RSA_meth_get_priv_dec(ossl_rsa_meth);

        if (!pfn_rsa_meth_priv_dec) {
            log_debug("Coudn't find openssl fallback\n");
            return -1;
        }

        return pfn_rsa_meth_priv_dec(flen, from, to, rsa, padding);
        /*AKVerr(AKV_F_RSA_PRIV_DEC, AKV_R_CANT_GET_AKV_KEY);
        return -1;*/
    }

    MemoryStruct accessToken;
    if (!GetAccessTokenFromIMDS(akv_key->keyvault_type, &accessToken))
    {
        return -1;
    }

    MemoryStruct clearText;
    if (AkvDecrypt(akv_key->keyvault_type, akv_key->keyvault_name, akv_key->key_name, &accessToken, alg, from, flen, &clearText) == 1)
    {
        log_debug( "Decrypt successfully clear text size=[%zu]\n", clearText.size);
        if (to != NULL)
        {
            memcpy(to, clearText.memory, clearText.size);
        }
        else
        {
            log_debug( "size probe, return [%zu]\n", clearText.size);
        }

        free(clearText.memory);
        free(accessToken.memory);
        return (int)clearText.size;
    }
    else
    {
        log_error( "Failed to decrypt\n");
        free(clearText.memory);
        free(accessToken.memory);
        return -1;
    }
}


int akv_rsa_priv_enc(int flen, const unsigned char *from,
                     unsigned char *to, RSA *rsa, int padding)
{
    log_debug("In akv_rsa_priv_enc \n");
    if (padding != RSA_PKCS1_PADDING && padding != RSA_PKCS1_OAEP_PADDING && padding != RSA_NO_PADDING)
    {
        log_error( "   unsurported openssl_padding type=%d, only support RSA1_5 or RSA_OAEP \n", padding);
        return -1;
    }

    AKV_KEY *akv_key = NULL;
    const char *alg = padding_to_alg(padding);
    if (alg == NULL)
    {
        log_error( "   unsurported openssl_padding type=%d\n, only support RSA1_5 or RSA_OAEP", padding);
        return -1;
    }

    akv_key = RSA_get_ex_data(rsa, rsa_akv_idx);
    if (!akv_key)
    {
        typedef int (*PFN_RSA_meth_priv_enc)(int flen, const unsigned char *from, unsigned char *to, RSA *rsa, int padding);
        const RSA_METHOD *ossl_rsa_meth = RSA_PKCS1_OpenSSL();
        PFN_RSA_meth_priv_enc pfn_rsa_meth_priv_enc = RSA_meth_get_priv_enc(ossl_rsa_meth);

        if (!pfn_rsa_meth_priv_enc) {
            log_debug("Coudn't find openssl fallback\n");
            return -1;
        }

        return pfn_rsa_meth_priv_enc(flen, from, to, rsa, padding);
        /*AKVerr(AKV_F_RSA_PRIV_DEC, AKV_R_CANT_GET_AKV_KEY);
        return -1;*/
    }

    MemoryStruct accessToken;
    if (!GetAccessTokenFromIMDS(akv_key->keyvault_type, &accessToken))
    {
        return -1;
    }

    MemoryStruct clearText;
    if (AkvEncrypt(akv_key->keyvault_type, akv_key->keyvault_name, akv_key->key_name, &accessToken, alg, from, flen, &clearText) == 1)
    {
        log_debug( "Decrypt successfully clear text size=[%zu]\n", clearText.size);
        if (to != NULL)
        {
            memcpy(to, clearText.memory, clearText.size);
        }
        else
        {
            log_debug( "size probe, return [%zu]\n", clearText.size);
        }

        free(clearText.memory);
        free(accessToken.memory);
        return (int)clearText.size;
    }
    else
    {
        log_error( "Failed to decrypt\n");
        free(clearText.memory);
        free(accessToken.memory);
        return -1;
    }
}
