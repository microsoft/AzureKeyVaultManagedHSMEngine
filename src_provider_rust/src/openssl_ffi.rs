// FFI bindings for OpenSSL functions not available in openssl-rs crate
// These are needed for provider implementation

use std::os::raw::{c_char, c_int, c_void};
use crate::ossl_param::OsslParam;

// Opaque types from OpenSSL
#[repr(C)]
pub struct EVP_PKEY_CTX {
    _private: [u8; 0],
}

#[repr(C)]
pub struct EVP_PKEY {
    _private: [u8; 0],
}

extern "C" {
    /// Create a new EVP_PKEY_CTX from algorithm name and properties
    /// libname can be NULL to use default library
    pub fn EVP_PKEY_CTX_new_from_name(
        libctx: *mut c_void,
        name: *const c_char,
        propquery: *const c_char,
    ) -> *mut EVP_PKEY_CTX;

    /// Free an EVP_PKEY_CTX
    pub fn EVP_PKEY_CTX_free(ctx: *mut EVP_PKEY_CTX);

    /// Initialize context for fromdata operation
    pub fn EVP_PKEY_fromdata_init(ctx: *mut EVP_PKEY_CTX) -> c_int;

    /// Create EVP_PKEY from OSSL_PARAM array
    pub fn EVP_PKEY_fromdata(
        ctx: *mut EVP_PKEY_CTX,
        ppkey: *mut *mut EVP_PKEY,
        selection: c_int,
        params: *mut OsslParam,
    ) -> c_int;

    /// Convert EVP_PKEY to OSSL_PARAM array
    pub fn EVP_PKEY_todata(
        pkey: *const EVP_PKEY,
        selection: c_int,
        params: *mut *mut OsslParam,
    ) -> c_int;

    /// Free OSSL_PARAM array allocated by OpenSSL
    pub fn OSSL_PARAM_free(params: *mut OsslParam);

    /// Get parameters from EVP_PKEY
    pub fn EVP_PKEY_get_params(pkey: *const EVP_PKEY, params: *mut OsslParam) -> c_int;

    /// Set parameters on EVP_PKEY
    pub fn EVP_PKEY_set_params(pkey: *mut EVP_PKEY, params: *const OsslParam) -> c_int;

    /// Compare two EVP_PKEY objects
    pub fn EVP_PKEY_eq(a: *const EVP_PKEY, b: *const EVP_PKEY) -> c_int;

    /// Free an EVP_PKEY
    pub fn EVP_PKEY_free(pkey: *mut EVP_PKEY);
}
