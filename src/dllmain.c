/* Copyright (c) Microsoft Corporation.
   Licensed under the MIT License. */

#include "log.h"
#include "pch.h"
#include <signal.h>
#include <openssl/async.h>
#include <unistd.h>
#include <sys/eventfd.h>

static const char *engine_akv_id = "e_akv";
static const char *engine_akv_name = "AKV/HSM engine";

static RSA_METHOD *akv_rsa_method = NULL;
static EC_KEY_METHOD *akv_eckey_method = NULL;

int akv_idx = -1;
int rsa_akv_idx = -1;
int eckey_akv_idx = -1;

volatile crypto_op_queue* async_crypto_op_queue = NULL;
volatile int* volatile txt = NULL;
pthread_mutex_t txt_mutex;
pthread_t thread_id, thread_id2;

/*int wake_job(volatile ASYNC_JOB *job)
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

    if ((ret = ASYNC_WAIT_CTX_get_fd(waitctx, "e_akv", &efd,
                                     &custom)) > 0) {
        if (write(efd, &buf, sizeof(uint64_t)) == -1) {
            log_debug("Failed to write to fd: %d - error: %d\n", efd, errno);
        }
    }
    return ret;
}

void *async_thread2(void *vargp)
{
    log_debug("In async thread 2\n");
    unsigned cpu, node;

    while (true)
    {
        sleep(1);
        getcpu(&cpu, &node);
        pthread_mutex_lock(&txt_mutex);
        *txt = 100;
        log_debug("Thread2: op_data queue size is %d txt %d txt ptr %p cpu %u node %u\n", crypto_op_queue_get_size(async_crypto_op_queue),*txt, txt, cpu, node);
        pthread_mutex_unlock(&txt_mutex);
    }
}

void *async_thread_task(void *vargp)
{
    log_debug("In async thread\n");
    unsigned cpu, node;
    while (true)
    {
        sleep(1);
        getcpu(&cpu, &node);
        pthread_mutex_lock(&txt_mutex);
        log_debug("op_data queue size is %d txt %d txt ptr %p cpu %u node %u\n", crypto_op_queue_get_size(async_crypto_op_queue),*txt, txt, cpu, node);
        pthread_mutex_unlock(&txt_mutex);
        crypto_op_data* op_data = crypto_op_dequeue(async_crypto_op_queue);
        log_debug("op_data dequeued is %p\n", op_data);

        if (op_data) 
        {
            log_debug("Dequeued item\n");
            AkvSign(op_data->type, op_data->keyvault, op_data->keyname, op_data->accessToken, op_data->alg, op_data->hashText, op_data->hashTextSize, op_data->signatureText);
            log_debug("Waking async job\n");
            wake_job(op_data->async_job);
        }
    }
}*/

/**
 * @brief Free RSA context, paired with RSA_set_ex_data in akv_load_privkey.
 *
 * @param rsa RSA context
 * @return 0 == success, 1 == failure
 */
int akv_rsa_free(RSA *rsa)
{
    AKV_KEY *akv_key = NULL;
    typedef int (*PFN_RSA_meth_finish)(RSA * rsa);
    const RSA_METHOD *ossl_rsa_meth = RSA_PKCS1_OpenSSL();
    PFN_RSA_meth_finish pfn_rsa_meth_finish = RSA_meth_get_finish(ossl_rsa_meth);
    if (pfn_rsa_meth_finish)
    {
        pfn_rsa_meth_finish(rsa);
    }

    akv_key = RSA_get_ex_data(rsa, rsa_akv_idx);

    if (!akv_key)
    {
        return 1;
    }

    destroy_akv_key(akv_key);
    RSA_set_ex_data(rsa, rsa_akv_idx, NULL);
    return 1;
}

/**
 * @brief Free EC_KEY context, paired with EC_KEY_set_ex_data in akv_load_privkey.
 *
 * @param eckey EC_KEY context
 */
void akv_eckey_free(EC_KEY *eckey)
{
    AKV_KEY *akv_key;
    akv_key = EC_KEY_get_ex_data(eckey, eckey_akv_idx);
    // Not our key. First time we do EC_KEY_set_method
    // actually goes through here.
    if (!akv_key)
    {
        return;
    }

    destroy_akv_key(akv_key);
    EC_KEY_set_ex_data(eckey, eckey_akv_idx, NULL);
}

/**
 * @brief Set up engine for AKV/HSM.
 *
 * @param e Engine
 * @return 1 == success, 0 == failure
 */
static int akv_init(ENGINE *e)
{
    if (akv_idx < 0)
    {
        akv_idx = ENGINE_get_ex_new_index(0, NULL, NULL, NULL, 0);
        if (akv_idx < 0)
            goto err;

        /* Setup RSA_METHOD */
        rsa_akv_idx = RSA_get_ex_new_index(0, NULL, NULL, NULL, 0);
        if (rsa_akv_idx < 0)
            goto err;
        RSA_meth_set_priv_dec(akv_rsa_method, akv_rsa_priv_dec);
        RSA_meth_set_priv_enc(akv_rsa_method, akv_rsa_priv_enc);
        RSA_meth_set_finish(akv_rsa_method, akv_rsa_free);

        /* Setup EC_METHOD */
        int (*old_eckey_sign_setup)(EC_KEY *, BN_CTX *, BIGNUM **, BIGNUM **) = NULL;
        EC_KEY_METHOD_get_sign(EC_KEY_OpenSSL(), NULL, &old_eckey_sign_setup, NULL);
        if (!old_eckey_sign_setup)
        {
            goto err;
        }

        eckey_akv_idx = EC_KEY_get_ex_new_index(0, NULL, NULL, NULL, 0);
        if (eckey_akv_idx < 0)
            goto err;

        EC_KEY_METHOD_set_init(akv_eckey_method, NULL, akv_eckey_free, NULL, NULL, NULL, NULL);
        EC_KEY_METHOD_set_sign(akv_eckey_method, akv_eckey_sign, old_eckey_sign_setup,
                               akv_eckey_sign_sig);


        // create a log file pointer
        FILE* fp = fopen("/var/log/nginx/akv_error.log", "aw+");
        
        // add log file to the logger
        log_add_fp(fp, LOG_DEBUG);
        pthread_mutex_init(&txt_mutex, NULL);
        pthread_mutex_lock(&txt_mutex);
        txt = malloc(sizeof(int));
        *txt = 0;
        pthread_mutex_unlock(&txt_mutex);
        async_crypto_op_queue = crypto_op_queue_create();
       /* pthread_create(&thread_id, NULL, async_thread_task, NULL);
        pthread_create(&thread_id2, NULL, async_thread2, NULL);*/
    }

    return 1;

err:
    AKVerr(AKV_F_INIT, AKV_R_ALLOC_FAILURE);
    return 0;
}

/**
 * @brief Free any resouces associated with AKV/HSM.
 *
 * @param e Engine
 * @return 1 == success, 0 == failure
 */
static int akv_finish(ENGINE *e)
{
    log_debug("In akv_finish\n");
    free(async_crypto_op_queue);
   /* pthread_kill(thread_id, SIGKILL);
    pthread_join(thread_id, NULL); 
    pthread_kill(thread_id2, SIGKILL);
    pthread_join(thread_id2, NULL); */
    return 1;
}

/**
 * @brief Free engine methods
 *
 * @param e Engine
 * @return 1 == success, 0 == failure
 */
static int akv_destroy(ENGINE *e)
{
    if (akv_rsa_method)
    {
        RSA_meth_free(akv_rsa_method);
        akv_rsa_method = NULL;
    }

    if (akv_eckey_method)
    {
        EC_KEY_METHOD_free(akv_eckey_method);
        akv_eckey_method = NULL;
    }

    ERR_unload_AKV_strings();
    return 1;
}

/**
 * @brief Load public key from AKV/HSM.
 *
 * @param key_id Key ID to load, e.g. "<vault type>:<keyvault name>:<key name>"
 * @param pevpkey Public key
 * @return 1 == success, 0 == failure
 */
static int load_key(const char *key_id, EVP_PKEY **pevpkey)
{
    *pevpkey = NULL;

    AKV_KEY *key = NULL;
    EVP_PKEY *pkey = NULL;

    char keyvault_type[KEY_ID_MAX_SIZE + 1];
    char keyvault_name[KEY_ID_MAX_SIZE + 1];
    char key_name[KEY_ID_MAX_SIZE + 1];
#ifdef _WIN32
    int scanned = sscanf_s(key_id,
                           "%[^:]:%[^:]:%[^:]",
                           keyvault_type, KEY_ID_MAX_SIZE,
                           keyvault_name, KEY_ID_MAX_SIZE,
                           key_name, KEY_ID_MAX_SIZE);
#else
    int scanned = sscanf(key_id,
                         "%[^:]:%[^:]:%[^:]",
                         keyvault_type,
                         keyvault_name,
                         key_name);
#endif
    if (scanned != 3)
    {
        AKVerr(AKV_F_LOAD_KEY_CERT, AKV_R_PARSE_KEY_ID_ERROR);
        goto err;
    }

    if (strcasecmp(keyvault_type, "managedHsm") != 0 && strcasecmp(keyvault_type, "vault") != 0)
    {
        AKVerr(AKV_F_LOAD_KEY_CERT, AKV_R_PARSE_KEY_ID_ERROR);
        goto err;
    }

    key = acquire_akv_key(keyvault_type, keyvault_name, key_name);
    if (!key)
    {
        AKVerr(AKV_F_LOAD_KEY_CERT, AKV_R_CANT_GET_KEY);
        goto err;
    }

    MemoryStruct accessToken;
    if (!GetAccessTokenFromIMDS(keyvault_type, &accessToken))
    {
        goto err;
    }

    pkey = AkvGetKey(keyvault_type, keyvault_name, key_name, &accessToken);
    if (!pkey)
    {
        AKVerr(AKV_F_LOAD_KEY_CERT, AKV_R_LOAD_PUBKEY_ERROR);
        goto err;
    }

    if (EVP_PKEY_id(pkey) == EVP_PKEY_RSA)
    {
        RSA *rsa = EVP_PKEY_get0_RSA(pkey);
        if (!rsa)
        {
            AKVerr(AKV_F_LOAD_KEY_CERT, AKV_R_INVALID_RSA);
            goto err;
        }

        RSA_set_method(rsa, akv_rsa_method);
        RSA_set_ex_data(rsa, rsa_akv_idx, key);
    }
    else if (EVP_PKEY_id(pkey) == EVP_PKEY_EC)
    {
        EC_KEY *ec = EVP_PKEY_get0_EC_KEY(pkey);
        if (!ec)
        {
            AKVerr(AKV_F_LOAD_KEY_CERT, AKV_R_INVALID_EC_KEY);
            goto err;
        }

        EC_KEY_set_method(ec, akv_eckey_method);
        EC_KEY_set_ex_data(ec, eckey_akv_idx, key);
    }
    else
    {
        AKVerr(AKV_F_LOAD_KEY_CERT, AKV_R_UNSUPPORTED_KEY_ALGORITHM);
        goto err;
    }

    *pevpkey = pkey;
    free(accessToken.memory);
    return 1;
err:
    // Unref key if we're not keeping it.
    if (pkey)
        EVP_PKEY_free(pkey);
    if (key)
        destroy_akv_key(key);
    if (accessToken.memory)
        free(accessToken.memory);
    return 0;
}

/**
 * @brief Load public key from AKV/HSM.
 *
 * @param eng Engine
 * @param key_id Key ID to load, e.g. "<vault type>:<keyvault name>:<key name>"
 * @param ui_method Not used
 * @param callback_data  Not used
 * @return Public key == success, NULL == failure
 */
static EVP_PKEY *akv_load_pubkey(ENGINE *eng, const char *key_id,
                                 UI_METHOD *ui_method, void *callback_data)
{
    EVP_PKEY *pkey = NULL;

    load_key(key_id, &pkey);
    return pkey;
}

// This function returns either nids table or methods table.

/**
 * @brief Setup engine methods
 *
 * @param e Engine
 * @param pmeth methods table
 * @param nids nids table
 * @param nid RSA or EC
 * @return 1 ==
 */
static int akv_pkey_meths(ENGINE *e, EVP_PKEY_METHOD **pmeth,
                          const int **nids, int nid)
{
    if (!pmeth)
    {
        static int akv_pkey_nids[] = {
            EVP_PKEY_RSA,
            EVP_PKEY_RSA_PSS,
            EVP_PKEY_EC,
        };

        *nids = akv_pkey_nids;
        return sizeof(akv_pkey_nids) / sizeof(akv_pkey_nids[0]);
    }

    if (nid == EVP_PKEY_RSA)
    {
        static EVP_PKEY_METHOD *akv_rsa_pkey_meth = NULL;

        if (!akv_rsa_pkey_meth)
        {
            akv_rsa_pkey_meth = EVP_PKEY_meth_new(EVP_PKEY_RSA, 0);
            EVP_PKEY_meth_copy(akv_rsa_pkey_meth,
                               EVP_PKEY_meth_find(EVP_PKEY_RSA));
            EVP_PKEY_meth_set_sign(akv_rsa_pkey_meth, 0,
                                   akv_pkey_rsa_sign);
        }

        *pmeth = akv_rsa_pkey_meth;
        return 1;
    }
    else if (nid == EVP_PKEY_RSA_PSS)
    {
        static EVP_PKEY_METHOD *akv_rsa_pss_pkey_meth = NULL;

        if (!akv_rsa_pss_pkey_meth)
        {
            akv_rsa_pss_pkey_meth = EVP_PKEY_meth_new(EVP_PKEY_RSA, 0);
            EVP_PKEY_meth_copy(akv_rsa_pss_pkey_meth,
                               EVP_PKEY_meth_find(EVP_PKEY_RSA_PSS));

            int (*old_sign_init)(EVP_PKEY_CTX *) = NULL;
            EVP_PKEY_meth_get_sign(akv_rsa_pss_pkey_meth,
                                   &old_sign_init, NULL);
            EVP_PKEY_meth_set_sign(akv_rsa_pss_pkey_meth,
                                   old_sign_init, akv_pkey_rsa_sign);
        }

        *pmeth = akv_rsa_pss_pkey_meth;
        return 1;
    }
    else if (nid == EVP_PKEY_EC)
    {
        // Unchanged.
        *pmeth = (EVP_PKEY_METHOD *)EVP_PKEY_meth_find(nid);
        return 1;
    }

    *pmeth = NULL;
    return 0;
}

/**
 * @brief Bind engine to OpenSSL
 *
 * @param e Engine
 * @return 1 == success, 0 == failure
 */
static int bind_akv(ENGINE *e)
{
    akv_rsa_method = RSA_meth_dup(RSA_PKCS1_OpenSSL());
    if (!akv_rsa_method)
        goto memerr;
    RSA_meth_set1_name(akv_rsa_method, "AKV RSA method");

    akv_eckey_method = EC_KEY_METHOD_new(EC_KEY_OpenSSL());
    if (!akv_eckey_method)
        goto memerr;

    if (!ENGINE_set_id(e, engine_akv_id) || !ENGINE_set_name(e, engine_akv_name) || !ENGINE_set_flags(e, ENGINE_FLAGS_NO_REGISTER_ALL) || !ENGINE_set_init_function(e, akv_init) || !ENGINE_set_finish_function(e, akv_finish) || !ENGINE_set_destroy_function(e, akv_destroy) || !ENGINE_set_RSA(e, akv_rsa_method) || !ENGINE_set_EC(e, akv_eckey_method) || !ENGINE_set_load_privkey_function(e, akv_load_pubkey) || !ENGINE_set_load_pubkey_function(e, akv_load_pubkey)|| !ENGINE_set_pkey_meths(e, akv_pkey_meths) || !ENGINE_set_cmd_defns(e, akv_cmd_defns) || !ENGINE_set_ctrl_function(e, akv_ctrl))
        goto memerr;

    ERR_load_AKV_strings();
    return 1;
memerr:
    if (akv_rsa_method)
    {
        RSA_meth_free(akv_rsa_method);
        akv_rsa_method = NULL;
    }

    return 0;
}

/**
 * @brief Helper function to load engine
 *
 * @param e Engine
 * @param id Engine ID
 * @return 1 == success, 0 == failure
 */
static int bind_helper(ENGINE *e, const char *id)
{
    if (id && (strcmp(id, engine_akv_id) != 0))
        return 0;
    if (!bind_akv(e))
        return 0;
    return 1;
}

IMPLEMENT_DYNAMIC_CHECK_FN()
IMPLEMENT_DYNAMIC_BIND_FN(bind_helper)

#ifdef _WIN32
/**
 * @brief DLL entry point
 *
 * @param hModule Module handle
 * @param ul_reason_for_call unused
 * @param lpReserved unused
 * @return TRUE == success, FALSE == failure
 */
BOOL APIENTRY DllMain(HMODULE hModule,
                      DWORD ul_reason_for_call,
                      LPVOID lpReserved)
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}
#endif
