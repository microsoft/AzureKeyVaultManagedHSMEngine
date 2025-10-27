// OpenSSL dispatch tables and algorithm definitions
// Corresponds to OSSL_DISPATCH and OSSL_ALGORITHM structures in akv_provider.c

use std::os::raw::{c_char, c_int, c_void};
use std::ptr;

// OpenSSL operation IDs (from openssl/core_dispatch.h)
pub const OSSL_OP_STORE: c_int = 22;
pub const OSSL_OP_KEYMGMT: c_int = 10;
pub const OSSL_OP_SIGNATURE: c_int = 12;
pub const OSSL_OP_ASYM_CIPHER: c_int = 13;

// OpenSSL function IDs for provider core
pub const OSSL_FUNC_PROVIDER_GETTABLE_PARAMS: c_int = 1024;
pub const OSSL_FUNC_PROVIDER_GET_PARAMS: c_int = 1025;
pub const OSSL_FUNC_PROVIDER_QUERY_OPERATION: c_int = 1027;
pub const OSSL_FUNC_PROVIDER_TEARDOWN: c_int = 1030;

// OpenSSL function IDs for store loader
pub const OSSL_FUNC_STORE_OPEN: c_int = 1;
pub const OSSL_FUNC_STORE_ATTACH: c_int = 2;
pub const OSSL_FUNC_STORE_SETTABLE_CTX_PARAMS: c_int = 3;
pub const OSSL_FUNC_STORE_SET_CTX_PARAMS: c_int = 4;
pub const OSSL_FUNC_STORE_LOAD: c_int = 5;
pub const OSSL_FUNC_STORE_EOF: c_int = 6;
pub const OSSL_FUNC_STORE_CLOSE: c_int = 7;

// OpenSSL function IDs for key management
pub const OSSL_FUNC_KEYMGMT_NEW: c_int = 1;
pub const OSSL_FUNC_KEYMGMT_LOAD: c_int = 8;
pub const OSSL_FUNC_KEYMGMT_FREE: c_int = 10;
pub const OSSL_FUNC_KEYMGMT_GET_PARAMS: c_int = 11;
pub const OSSL_FUNC_KEYMGMT_GETTABLE_PARAMS: c_int = 12;
pub const OSSL_FUNC_KEYMGMT_SET_PARAMS: c_int = 13;
pub const OSSL_FUNC_KEYMGMT_SETTABLE_PARAMS: c_int = 14;
pub const OSSL_FUNC_KEYMGMT_QUERY_OPERATION_NAME: c_int = 20;
pub const OSSL_FUNC_KEYMGMT_HAS: c_int = 21;
pub const OSSL_FUNC_KEYMGMT_MATCH: c_int = 23;
pub const OSSL_FUNC_KEYMGMT_IMPORT: c_int = 40;
pub const OSSL_FUNC_KEYMGMT_IMPORT_TYPES: c_int = 41;
pub const OSSL_FUNC_KEYMGMT_EXPORT: c_int = 42;
pub const OSSL_FUNC_KEYMGMT_EXPORT_TYPES: c_int = 43;

// OpenSSL function IDs for signature
pub const OSSL_FUNC_SIGNATURE_NEWCTX: c_int = 1;
pub const OSSL_FUNC_SIGNATURE_FREECTX: c_int = 3;
pub const OSSL_FUNC_SIGNATURE_DUPCTX: c_int = 4;
pub const OSSL_FUNC_SIGNATURE_SIGN_INIT: c_int = 10;
pub const OSSL_FUNC_SIGNATURE_SIGN: c_int = 11;
pub const OSSL_FUNC_SIGNATURE_VERIFY_INIT: c_int = 12;
pub const OSSL_FUNC_SIGNATURE_VERIFY: c_int = 13;
pub const OSSL_FUNC_SIGNATURE_DIGEST_SIGN_INIT: c_int = 20;
pub const OSSL_FUNC_SIGNATURE_DIGEST_SIGN_UPDATE: c_int = 21;
pub const OSSL_FUNC_SIGNATURE_DIGEST_SIGN_FINAL: c_int = 22;
pub const OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_INIT: c_int = 24;
pub const OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_UPDATE: c_int = 25;
pub const OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_FINAL: c_int = 26;
pub const OSSL_FUNC_SIGNATURE_GET_CTX_PARAMS: c_int = 50;
pub const OSSL_FUNC_SIGNATURE_GETTABLE_CTX_PARAMS: c_int = 51;
pub const OSSL_FUNC_SIGNATURE_SET_CTX_PARAMS: c_int = 52;
pub const OSSL_FUNC_SIGNATURE_SETTABLE_CTX_PARAMS: c_int = 53;

// OpenSSL function IDs for asymmetric cipher
pub const OSSL_FUNC_ASYM_CIPHER_NEWCTX: c_int = 1;
pub const OSSL_FUNC_ASYM_CIPHER_FREECTX: c_int = 3;
pub const OSSL_FUNC_ASYM_CIPHER_DUPCTX: c_int = 4;
pub const OSSL_FUNC_ASYM_CIPHER_ENCRYPT_INIT: c_int = 10;
pub const OSSL_FUNC_ASYM_CIPHER_ENCRYPT: c_int = 11;
pub const OSSL_FUNC_ASYM_CIPHER_DECRYPT_INIT: c_int = 12;
pub const OSSL_FUNC_ASYM_CIPHER_DECRYPT: c_int = 13;
pub const OSSL_FUNC_ASYM_CIPHER_GET_CTX_PARAMS: c_int = 50;
pub const OSSL_FUNC_ASYM_CIPHER_GETTABLE_CTX_PARAMS: c_int = 51;
pub const OSSL_FUNC_ASYM_CIPHER_SET_CTX_PARAMS: c_int = 52;
pub const OSSL_FUNC_ASYM_CIPHER_SETTABLE_CTX_PARAMS: c_int = 53;

/// OSSL_DISPATCH structure (matches OpenSSL's definition)
/// C definition: struct { int function_id; void (*function)(void); }
#[repr(C)]
pub struct OsslDispatch {
    pub function_id: c_int,
    pub function: *mut ::std::os::raw::c_void,
}

impl OsslDispatch {
    pub const fn new(function_id: c_int, function: *mut ::std::os::raw::c_void) -> Self {
        Self { function_id, function }
    }
    
    pub const fn end() -> Self {
        Self { function_id: 0, function: ptr::null_mut() }
    }
}

// Mark raw pointers in OsslDispatch as safe to share between threads
// This is safe because the function pointers point to static functions defined in the provider
unsafe impl Sync for OsslDispatch {}

/// OSSL_ALGORITHM structure (matches OpenSSL's definition)
#[repr(C)]
pub struct OsslAlgorithm {
    pub algorithm_names: *const c_char,
    pub property_definition: *const c_char,
    pub implementation: *const OsslDispatch,
    pub algorithm_description: *const c_char,
}

// Mark raw pointers in OsslAlgorithm as safe to share between threads
// This is safe because the pointers point to static string literals and static dispatch tables
unsafe impl Sync for OsslAlgorithm {}

impl OsslAlgorithm {
    pub const fn end() -> Self {
        Self {
            algorithm_names: ptr::null(),
            property_definition: ptr::null(),
            implementation: ptr::null(),
            algorithm_description: ptr::null(),
        }
    }
}

// Helper macro to create null-terminated strings for C
macro_rules! c_str {
    ($s:expr) => {
        concat!($s, "\0").as_ptr() as *const c_char
    };
}

// Store loader dispatch table
pub static AKV_STORE_FUNCTIONS: [OsslDispatch; 8] = [
    OsslDispatch::new(
        OSSL_FUNC_STORE_OPEN,
        crate::akv_store_open as *mut c_void,
    ),
    OsslDispatch::new(
        OSSL_FUNC_STORE_ATTACH,
        crate::akv_store_attach as *mut c_void,
    ),
    OsslDispatch::new(
        OSSL_FUNC_STORE_SETTABLE_CTX_PARAMS,
        crate::akv_store_settable_ctx_params as *mut c_void,
    ),
    OsslDispatch::new(
        OSSL_FUNC_STORE_SET_CTX_PARAMS,
        crate::akv_store_set_ctx_params as *mut c_void,
    ),
    OsslDispatch::new(
        OSSL_FUNC_STORE_LOAD,
        crate::akv_store_load as *mut c_void,
    ),
    OsslDispatch::new(
        OSSL_FUNC_STORE_EOF,
        crate::akv_store_eof as *mut c_void,
    ),
    OsslDispatch::new(
        OSSL_FUNC_STORE_CLOSE,
        crate::akv_store_close as *mut c_void,
    ),
    OsslDispatch::end(),
];

// Store algorithm table
pub static AKV_STORE_ALGS: [OsslAlgorithm; 2] = [
    OsslAlgorithm {
        algorithm_names: c_str!("managedhsm"),
        property_definition: c_str!("provider=akv_provider"),
        implementation: AKV_STORE_FUNCTIONS.as_ptr(),
        algorithm_description: c_str!("Azure Managed HSM store"),
    },
    OsslAlgorithm::end(),
];

// Key management dispatch tables

/// RSA key management functions
pub static AKV_RSA_KEYMGMT_FUNCTIONS: [OsslDispatch; 15] = [
    OsslDispatch::new(OSSL_FUNC_KEYMGMT_NEW, crate::keymgmt::akv_keymgmt_new as *mut c_void),
    OsslDispatch::new(OSSL_FUNC_KEYMGMT_FREE, crate::keymgmt::akv_keymgmt_free as *mut c_void),
    OsslDispatch::new(OSSL_FUNC_KEYMGMT_LOAD, crate::keymgmt::akv_keymgmt_load as *mut c_void),
    OsslDispatch::new(OSSL_FUNC_KEYMGMT_HAS, crate::keymgmt::akv_keymgmt_has as *mut c_void),
    OsslDispatch::new(OSSL_FUNC_KEYMGMT_MATCH, crate::keymgmt::akv_keymgmt_match as *mut c_void),
    OsslDispatch::new(OSSL_FUNC_KEYMGMT_GET_PARAMS, crate::keymgmt::akv_keymgmt_get_params as *mut c_void),
    OsslDispatch::new(OSSL_FUNC_KEYMGMT_GETTABLE_PARAMS, crate::keymgmt::akv_rsa_keymgmt_gettable_params as *mut c_void),
    OsslDispatch::new(OSSL_FUNC_KEYMGMT_SET_PARAMS, crate::keymgmt::akv_keymgmt_set_params as *mut c_void),
    OsslDispatch::new(OSSL_FUNC_KEYMGMT_SETTABLE_PARAMS, crate::keymgmt::akv_rsa_keymgmt_settable_params as *mut c_void),
    OsslDispatch::new(OSSL_FUNC_KEYMGMT_IMPORT, crate::keymgmt::akv_rsa_keymgmt_import as *mut c_void),
    OsslDispatch::new(OSSL_FUNC_KEYMGMT_IMPORT_TYPES, crate::keymgmt::akv_rsa_keymgmt_eximport_types as *mut c_void),
    OsslDispatch::new(OSSL_FUNC_KEYMGMT_EXPORT, crate::keymgmt::akv_keymgmt_export as *mut c_void),
    OsslDispatch::new(OSSL_FUNC_KEYMGMT_EXPORT_TYPES, crate::keymgmt::akv_rsa_keymgmt_eximport_types as *mut c_void),
    OsslDispatch::new(OSSL_FUNC_KEYMGMT_QUERY_OPERATION_NAME, crate::keymgmt::akv_rsa_keymgmt_query as *mut c_void),
    OsslDispatch::end(),
];

/// EC key management functions
pub static AKV_EC_KEYMGMT_FUNCTIONS: [OsslDispatch; 15] = [
    OsslDispatch::new(OSSL_FUNC_KEYMGMT_NEW, crate::keymgmt::akv_keymgmt_new as *mut c_void),
    OsslDispatch::new(OSSL_FUNC_KEYMGMT_FREE, crate::keymgmt::akv_keymgmt_free as *mut c_void),
    OsslDispatch::new(OSSL_FUNC_KEYMGMT_LOAD, crate::keymgmt::akv_keymgmt_load as *mut c_void),
    OsslDispatch::new(OSSL_FUNC_KEYMGMT_HAS, crate::keymgmt::akv_keymgmt_has as *mut c_void),
    OsslDispatch::new(OSSL_FUNC_KEYMGMT_MATCH, crate::keymgmt::akv_keymgmt_match as *mut c_void),
    OsslDispatch::new(OSSL_FUNC_KEYMGMT_GET_PARAMS, crate::keymgmt::akv_keymgmt_get_params as *mut c_void),
    OsslDispatch::new(OSSL_FUNC_KEYMGMT_GETTABLE_PARAMS, crate::keymgmt::akv_ec_keymgmt_gettable_params as *mut c_void),
    OsslDispatch::new(OSSL_FUNC_KEYMGMT_SET_PARAMS, crate::keymgmt::akv_keymgmt_set_params as *mut c_void),
    OsslDispatch::new(OSSL_FUNC_KEYMGMT_SETTABLE_PARAMS, crate::keymgmt::akv_ec_keymgmt_settable_params as *mut c_void),
    OsslDispatch::new(OSSL_FUNC_KEYMGMT_IMPORT, crate::keymgmt::akv_ec_keymgmt_import as *mut c_void),
    OsslDispatch::new(OSSL_FUNC_KEYMGMT_IMPORT_TYPES, crate::keymgmt::akv_ec_keymgmt_eximport_types as *mut c_void),
    OsslDispatch::new(OSSL_FUNC_KEYMGMT_EXPORT, crate::keymgmt::akv_keymgmt_export as *mut c_void),
    OsslDispatch::new(OSSL_FUNC_KEYMGMT_EXPORT_TYPES, crate::keymgmt::akv_ec_keymgmt_eximport_types as *mut c_void),
    OsslDispatch::new(OSSL_FUNC_KEYMGMT_QUERY_OPERATION_NAME, crate::keymgmt::akv_ec_keymgmt_query as *mut c_void),
    OsslDispatch::end(),
];

/// AES key management functions
pub static AKV_AES_KEYMGMT_FUNCTIONS: [OsslDispatch; 8] = [
    OsslDispatch::new(OSSL_FUNC_KEYMGMT_NEW, crate::keymgmt::akv_aes_keymgmt_new as *mut c_void),
    OsslDispatch::new(OSSL_FUNC_KEYMGMT_FREE, crate::keymgmt::akv_aes_keymgmt_free as *mut c_void),
    OsslDispatch::new(OSSL_FUNC_KEYMGMT_LOAD, crate::keymgmt::akv_aes_keymgmt_load as *mut c_void),
    OsslDispatch::new(OSSL_FUNC_KEYMGMT_HAS, crate::keymgmt::akv_aes_keymgmt_has as *mut c_void),
    OsslDispatch::new(OSSL_FUNC_KEYMGMT_GETTABLE_PARAMS, crate::keymgmt::akv_aes_keymgmt_gettable_params as *mut c_void),
    OsslDispatch::new(OSSL_FUNC_KEYMGMT_SETTABLE_PARAMS, crate::keymgmt::akv_aes_keymgmt_settable_params as *mut c_void),
    OsslDispatch::new(OSSL_FUNC_KEYMGMT_QUERY_OPERATION_NAME, crate::keymgmt::akv_aes_keymgmt_query as *mut c_void),
    OsslDispatch::end(),
];

/// Key management algorithm table
/// Key management algorithm table - MINIMAL: RSA only for smoke test
pub static AKV_KEYMGMT_ALGS: [OsslAlgorithm; 2] = [
    OsslAlgorithm {
        algorithm_names: c_str!("RSA:rsaEncryption"),
        property_definition: c_str!("provider=akv_provider"),
        implementation: AKV_RSA_KEYMGMT_FUNCTIONS.as_ptr(),
        algorithm_description: c_str!("Azure Key Vault RSA key management"),
    },
    /* Temporarily disabled for minimal smoke test
    OsslAlgorithm {
        algorithm_names: c_str!("EC:id-ecPublicKey"),
        property_definition: c_str!("provider=akv_provider"),
        implementation: AKV_EC_KEYMGMT_FUNCTIONS.as_ptr(),
        algorithm_description: c_str!("Azure Key Vault EC key management"),
    },
    OsslAlgorithm {
        algorithm_names: c_str!("AES-128-KW:id-aes128-wrap:AES-128-WRAP:2.16.840.1.101.3.4.1.5"),
        property_definition: c_str!("provider=akv_provider"),
        implementation: AKV_AES_KEYMGMT_FUNCTIONS.as_ptr(),
        algorithm_description: c_str!("Azure Key Vault AES-128 key management"),
    },
    OsslAlgorithm {
        algorithm_names: c_str!("AES-192-KW:id-aes192-wrap:AES-192-WRAP:2.16.840.1.101.3.4.1.25"),
        property_definition: c_str!("provider=akv_provider"),
        implementation: AKV_AES_KEYMGMT_FUNCTIONS.as_ptr(),
        algorithm_description: c_str!("Azure Key Vault AES-192 key management"),
    },
    OsslAlgorithm {
        algorithm_names: c_str!("AES-256-KW:id-aes256-wrap:AES-256-WRAP:2.16.840.1.101.3.4.1.45"),
        property_definition: c_str!("provider=akv_provider"),
        implementation: AKV_AES_KEYMGMT_FUNCTIONS.as_ptr(),
        algorithm_description: c_str!("Azure Key Vault AES-256 key management"),
    },
    */
    OsslAlgorithm::end(),
];

/// RSA signature dispatch functions
pub static AKV_RSA_SIGNATURE_FUNCTIONS: [OsslDispatch; 15] = [
    OsslDispatch::new(OSSL_FUNC_SIGNATURE_NEWCTX, crate::signature::akv_rsa_signature_newctx as *mut c_void),
    OsslDispatch::new(OSSL_FUNC_SIGNATURE_FREECTX, crate::signature::akv_signature_freectx as *mut c_void),
    OsslDispatch::new(OSSL_FUNC_SIGNATURE_SIGN_INIT, crate::signature::akv_signature_sign_init as *mut c_void),
    OsslDispatch::new(OSSL_FUNC_SIGNATURE_SIGN, crate::signature::akv_signature_sign as *mut c_void),
    OsslDispatch::new(OSSL_FUNC_SIGNATURE_VERIFY_INIT, crate::signature::akv_signature_verify_init as *mut c_void),
    OsslDispatch::new(OSSL_FUNC_SIGNATURE_VERIFY, crate::signature::akv_signature_verify as *mut c_void),
    OsslDispatch::new(OSSL_FUNC_SIGNATURE_DIGEST_SIGN_INIT, crate::signature::akv_signature_digest_sign_init as *mut c_void),
    OsslDispatch::new(OSSL_FUNC_SIGNATURE_DIGEST_SIGN_UPDATE, crate::signature::akv_signature_digest_update as *mut c_void),
    OsslDispatch::new(OSSL_FUNC_SIGNATURE_DIGEST_SIGN_FINAL, crate::signature::akv_signature_digest_sign_final as *mut c_void),
    OsslDispatch::new(OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_INIT, crate::signature::akv_signature_digest_verify_init as *mut c_void),
    OsslDispatch::new(OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_UPDATE, crate::signature::akv_signature_digest_update as *mut c_void),
    OsslDispatch::new(OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_FINAL, crate::signature::akv_signature_digest_verify_final as *mut c_void),
    OsslDispatch::new(OSSL_FUNC_SIGNATURE_GET_CTX_PARAMS, crate::signature::akv_signature_get_ctx_params as *mut c_void),
    OsslDispatch::new(OSSL_FUNC_SIGNATURE_SETTABLE_CTX_PARAMS, crate::signature::akv_signature_settable_ctx_params as *mut c_void),
    OsslDispatch::end(),
];

/// EC/ECDSA signature dispatch functions
pub static AKV_ECDSA_SIGNATURE_FUNCTIONS: [OsslDispatch; 15] = [
    OsslDispatch::new(OSSL_FUNC_SIGNATURE_NEWCTX, crate::signature::akv_ecdsa_signature_newctx as *mut c_void),
    OsslDispatch::new(OSSL_FUNC_SIGNATURE_FREECTX, crate::signature::akv_signature_freectx as *mut c_void),
    OsslDispatch::new(OSSL_FUNC_SIGNATURE_SIGN_INIT, crate::signature::akv_signature_sign_init as *mut c_void),
    OsslDispatch::new(OSSL_FUNC_SIGNATURE_SIGN, crate::signature::akv_signature_sign as *mut c_void),
    OsslDispatch::new(OSSL_FUNC_SIGNATURE_VERIFY_INIT, crate::signature::akv_signature_verify_init as *mut c_void),
    OsslDispatch::new(OSSL_FUNC_SIGNATURE_VERIFY, crate::signature::akv_signature_verify as *mut c_void),
    OsslDispatch::new(OSSL_FUNC_SIGNATURE_DIGEST_SIGN_INIT, crate::signature::akv_signature_digest_sign_init as *mut c_void),
    OsslDispatch::new(OSSL_FUNC_SIGNATURE_DIGEST_SIGN_UPDATE, crate::signature::akv_signature_digest_update as *mut c_void),
    OsslDispatch::new(OSSL_FUNC_SIGNATURE_DIGEST_SIGN_FINAL, crate::signature::akv_signature_digest_sign_final as *mut c_void),
    OsslDispatch::new(OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_INIT, crate::signature::akv_signature_digest_verify_init as *mut c_void),
    OsslDispatch::new(OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_UPDATE, crate::signature::akv_signature_digest_update as *mut c_void),
    OsslDispatch::new(OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_FINAL, crate::signature::akv_signature_digest_verify_final as *mut c_void),
    OsslDispatch::new(OSSL_FUNC_SIGNATURE_GET_CTX_PARAMS, crate::signature::akv_signature_get_ctx_params as *mut c_void),
    OsslDispatch::new(OSSL_FUNC_SIGNATURE_SETTABLE_CTX_PARAMS, crate::signature::akv_signature_settable_ctx_params as *mut c_void),
    OsslDispatch::end(),
];

/// Signature algorithm table
pub static AKV_SIGNATURE_ALGS: [OsslAlgorithm; 3] = [
    OsslAlgorithm {
        algorithm_names: c_str!("RSA:rsaEncryption"),
        property_definition: c_str!("provider=akv_provider"),
        implementation: AKV_RSA_SIGNATURE_FUNCTIONS.as_ptr(),
        algorithm_description: c_str!("Azure Key Vault RSA signature"),
    },
    OsslAlgorithm {
        algorithm_names: c_str!("ECDSA:EC:id-ecPublicKey"),
        property_definition: c_str!("provider=akv_provider"),
        implementation: AKV_ECDSA_SIGNATURE_FUNCTIONS.as_ptr(),
        algorithm_description: c_str!("Azure Key Vault ECDSA signature"),
    },
    OsslAlgorithm::end(),
];

/// RSA asymmetric cipher dispatch functions
pub static AKV_RSA_ASYM_CIPHER_FUNCTIONS: [OsslDispatch; 11] = [
    OsslDispatch::new(OSSL_FUNC_ASYM_CIPHER_NEWCTX, crate::cipher::akv_rsa_cipher_newctx as *mut c_void),
    OsslDispatch::new(OSSL_FUNC_ASYM_CIPHER_FREECTX, crate::cipher::akv_rsa_cipher_freectx as *mut c_void),
    OsslDispatch::new(OSSL_FUNC_ASYM_CIPHER_ENCRYPT_INIT, crate::cipher::akv_rsa_cipher_encrypt_init as *mut c_void),
    OsslDispatch::new(OSSL_FUNC_ASYM_CIPHER_ENCRYPT, crate::cipher::akv_rsa_cipher_encrypt as *mut c_void),
    OsslDispatch::new(OSSL_FUNC_ASYM_CIPHER_DECRYPT_INIT, crate::cipher::akv_rsa_cipher_decrypt_init as *mut c_void),
    OsslDispatch::new(OSSL_FUNC_ASYM_CIPHER_DECRYPT, crate::cipher::akv_rsa_cipher_decrypt as *mut c_void),
    OsslDispatch::new(OSSL_FUNC_ASYM_CIPHER_GET_CTX_PARAMS, crate::cipher::akv_rsa_cipher_get_ctx_params as *mut c_void),
    OsslDispatch::new(OSSL_FUNC_ASYM_CIPHER_GETTABLE_CTX_PARAMS, crate::cipher::akv_rsa_cipher_gettable_ctx_params as *mut c_void),
    OsslDispatch::new(OSSL_FUNC_ASYM_CIPHER_SET_CTX_PARAMS, crate::cipher::akv_rsa_cipher_set_ctx_params as *mut c_void),
    OsslDispatch::new(OSSL_FUNC_ASYM_CIPHER_SETTABLE_CTX_PARAMS, crate::cipher::akv_rsa_cipher_settable_ctx_params as *mut c_void),
    OsslDispatch::end(),
];

/// AES asymmetric cipher dispatch functions (key wrap/unwrap)
pub static AKV_AES_ASYM_CIPHER_FUNCTIONS: [OsslDispatch; 11] = [
    OsslDispatch::new(OSSL_FUNC_ASYM_CIPHER_NEWCTX, crate::cipher::akv_aes_cipher_newctx as *mut c_void),
    OsslDispatch::new(OSSL_FUNC_ASYM_CIPHER_FREECTX, crate::cipher::akv_aes_cipher_freectx as *mut c_void),
    OsslDispatch::new(OSSL_FUNC_ASYM_CIPHER_ENCRYPT_INIT, crate::cipher::akv_aes_cipher_encrypt_init as *mut c_void),
    OsslDispatch::new(OSSL_FUNC_ASYM_CIPHER_ENCRYPT, crate::cipher::akv_aes_cipher_encrypt as *mut c_void),
    OsslDispatch::new(OSSL_FUNC_ASYM_CIPHER_DECRYPT_INIT, crate::cipher::akv_aes_cipher_decrypt_init as *mut c_void),
    OsslDispatch::new(OSSL_FUNC_ASYM_CIPHER_DECRYPT, crate::cipher::akv_aes_cipher_decrypt as *mut c_void),
    OsslDispatch::new(OSSL_FUNC_ASYM_CIPHER_GET_CTX_PARAMS, crate::cipher::akv_aes_cipher_get_ctx_params as *mut c_void),
    OsslDispatch::new(OSSL_FUNC_ASYM_CIPHER_GETTABLE_CTX_PARAMS, crate::cipher::akv_aes_cipher_gettable_ctx_params as *mut c_void),
    OsslDispatch::new(OSSL_FUNC_ASYM_CIPHER_SET_CTX_PARAMS, crate::cipher::akv_aes_cipher_set_ctx_params as *mut c_void),
    OsslDispatch::new(OSSL_FUNC_ASYM_CIPHER_SETTABLE_CTX_PARAMS, crate::cipher::akv_aes_cipher_settable_ctx_params as *mut c_void),
    OsslDispatch::end(),
];

/// Asymmetric cipher algorithm table
pub static AKV_ASYM_CIPHER_ALGS: [OsslAlgorithm; 5] = [
    OsslAlgorithm {
        algorithm_names: c_str!("RSA:rsaEncryption"),
        property_definition: c_str!("provider=akv_provider"),
        implementation: AKV_RSA_ASYM_CIPHER_FUNCTIONS.as_ptr(),
        algorithm_description: c_str!("Azure Key Vault RSA cipher"),
    },
    OsslAlgorithm {
        algorithm_names: c_str!("AES-128-KW:id-aes128-wrap:AES-128-WRAP:2.16.840.1.101.3.4.1.5"),
        property_definition: c_str!("provider=akv_provider"),
        implementation: AKV_AES_ASYM_CIPHER_FUNCTIONS.as_ptr(),
        algorithm_description: c_str!("Azure Key Vault AES-128 key wrap"),
    },
    OsslAlgorithm {
        algorithm_names: c_str!("AES-192-KW:id-aes192-wrap:AES-192-WRAP:2.16.840.1.101.3.4.1.25"),
        property_definition: c_str!("provider=akv_provider"),
        implementation: AKV_AES_ASYM_CIPHER_FUNCTIONS.as_ptr(),
        algorithm_description: c_str!("Azure Key Vault AES-192 key wrap"),
    },
    OsslAlgorithm {
        algorithm_names: c_str!("AES-256-KW:id-aes256-wrap:AES-256-WRAP:2.16.840.1.101.3.4.1.45"),
        property_definition: c_str!("provider=akv_provider"),
        implementation: AKV_AES_ASYM_CIPHER_FUNCTIONS.as_ptr(),
        algorithm_description: c_str!("Azure Key Vault AES-256 key wrap"),
    },
    OsslAlgorithm::end(),
];

// TODO: Signature algorithm tables
// pub static AKV_SIGNATURE_ALGS: [OsslAlgorithm; N] = [...];

// TODO: Asymmetric cipher algorithm tables
// pub static AKV_ASYM_CIPHER_ALGS: [OsslAlgorithm; N] = [...];

// Main provider dispatch table
pub static AKV_DISPATCH_TABLE: [OsslDispatch; 5] = [
    OsslDispatch::new(
        OSSL_FUNC_PROVIDER_GETTABLE_PARAMS,
        crate::akv_gettable_params as *mut c_void,
    ),
    OsslDispatch::new(
        OSSL_FUNC_PROVIDER_GET_PARAMS,
        crate::akv_get_params as *mut c_void,
    ),
    OsslDispatch::new(
        OSSL_FUNC_PROVIDER_QUERY_OPERATION,
        crate::akv_query_operation as *mut c_void,
    ),
    OsslDispatch::new(
        OSSL_FUNC_PROVIDER_TEARDOWN,
        crate::akv_teardown as *mut c_void,
    ),
    OsslDispatch::end(),
];

/// Query operation and return appropriate algorithm table
pub unsafe fn query_operation_impl(operation_id: c_int) -> *const OsslAlgorithm {
    log::trace!("query_operation_impl operation_id={}", operation_id);
    
    let (result, op_name) = match operation_id {
        OSSL_OP_STORE => (AKV_STORE_ALGS.as_ptr(), "STORE"),
        OSSL_OP_KEYMGMT => {
            log::debug!("Returning KEYMGMT algorithms: RSA dispatch table at {:p}", AKV_RSA_KEYMGMT_FUNCTIONS.as_ptr());
            log::debug!("  RSA KEYMGMT functions:");
            for (i, dispatch) in AKV_RSA_KEYMGMT_FUNCTIONS.iter().enumerate() {
                log::debug!("    [{}] function_id={}, function={:p}", i, dispatch.function_id, dispatch.function);
            }
            (AKV_KEYMGMT_ALGS.as_ptr(), "KEYMGMT")
        },
        // Temporarily disable signature and cipher for minimal smoke test
        // OSSL_OP_SIGNATURE => AKV_SIGNATURE_ALGS.as_ptr(),
        // OSSL_OP_ASYM_CIPHER => AKV_ASYM_CIPHER_ALGS.as_ptr(),
        _ => (ptr::null(), "UNKNOWN"),
    };
    
    log::debug!("query_operation_impl({}) -> {:p}", op_name, result);
    result
}



