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
            std::ffi::CStr::from_ptr(ptr)
                .to_string_lossy()
                .into_owned()
        };
        
        log::error!("{}: OpenSSL error 0x{:x}: {}", prefix, err, err_str);
    }
}
