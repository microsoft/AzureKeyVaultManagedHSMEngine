// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

// FFI bindings for OpenSSL functions not available in openssl-rs crate
// These are needed for provider implementation

use crate::ossl_param::OsslParam;
use openssl_sys::EVP_MD;
use std::os::raw::{c_char, c_int, c_uchar, c_void};

// Opaque types from OpenSSL
#[allow(non_camel_case_types)]
#[repr(C)]
pub struct EVP_PKEY_CTX {
    _private: [u8; 0],
}

#[allow(non_camel_case_types)]
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
    #[allow(dead_code)]
    pub fn EVP_PKEY_get_params(pkey: *const EVP_PKEY, params: *mut OsslParam) -> c_int;

    /// Set parameters on EVP_PKEY
    pub fn EVP_PKEY_set_params(pkey: *mut EVP_PKEY, params: *const OsslParam) -> c_int;

    /// Compare two EVP_PKEY objects
    pub fn EVP_PKEY_eq(a: *const EVP_PKEY, b: *const EVP_PKEY) -> c_int;

    // OSSL_PARAM functions
    pub fn EVP_PKEY_CTX_new_from_pkey(
        libctx: *mut c_void,
        pkey: *mut EVP_PKEY,
        propquery: *const c_char,
    ) -> *mut EVP_PKEY_CTX;

    /// Initialize context for verification
    pub fn EVP_PKEY_verify_init(ctx: *mut EVP_PKEY_CTX) -> c_int;

    /// Perform a verification using raw digest input
    pub fn EVP_PKEY_verify(
        ctx: *mut EVP_PKEY_CTX,
        sig: *const c_uchar,
        siglen: usize,
        tbs: *const c_uchar,
        tbslen: usize,
    ) -> c_int;

    /// Set the expected signature digest algorithm
    pub fn EVP_PKEY_CTX_set_signature_md(ctx: *mut EVP_PKEY_CTX, md: *const EVP_MD) -> c_int;

    /// Configure RSA padding mode
    pub fn EVP_PKEY_CTX_set_rsa_padding(ctx: *mut EVP_PKEY_CTX, pad_mode: c_int) -> c_int;

    /// Configure RSA-PSS salt length
    pub fn EVP_PKEY_CTX_set_rsa_pss_saltlen(ctx: *mut EVP_PKEY_CTX, saltlen: c_int) -> c_int;

    /// Configure RSA-PSS MGF1 digest
    pub fn EVP_PKEY_CTX_set_rsa_mgf1_md(ctx: *mut EVP_PKEY_CTX, md: *const EVP_MD) -> c_int;

    /// Get the last error from the OpenSSL error queue
    pub fn ERR_get_error() -> c_ulong;

    /// Get error string for an error code
    pub fn ERR_error_string(e: c_ulong, buf: *mut c_char) -> *const c_char;
}

use std::os::raw::c_ulong;

/// Helper function to print OpenSSL errors to log
pub fn log_openssl_errors(prefix: &str) {
    loop {
        let err = unsafe { ERR_get_error() };
        if err == 0 {
            break;
        }

        let mut buf = [0i8; 256];
        let err_str = unsafe {
            let ptr = ERR_error_string(err, buf.as_mut_ptr());
            if ptr.is_null() {
                break;
            }
            std::ffi::CStr::from_ptr(ptr).to_string_lossy().into_owned()
        };

        log::error!("{}: OpenSSL error 0x{:x}: {}", prefix, err, err_str);
    }
}
