// Azure Key Vault Managed HSM OpenSSL Provider - Rust Implementation
// Copyright (c) Microsoft Corporation.

//! OpenSSL Provider for Azure Managed HSM
//! 
//! This provider enables OpenSSL to use Azure Managed HSM for cryptographic operations
//! including signing, encryption, and key management.

mod provider;
mod store;
mod dispatch;
mod ossl_param;
mod auth;
mod keymgmt;
mod signature;
mod cipher;
mod logging;
mod base64;
mod http_client;
mod openssl_helpers;
mod openssl_ffi;

pub use provider::*;
pub use store::*;
pub use dispatch::*;
pub use ossl_param::*;
pub use auth::*;
pub use logging::*;
pub use openssl_helpers::*;

use std::os::raw::{c_char, c_int, c_void};

// Provider name and version constants
const PROVIDER_NAME: &str = "Azure Managed HSM Provider";
// C string constants for parameters
static PROVIDER_NAME_CSTR: &[u8] = b"Azure Managed HSM Provider\0";
static PROVIDER_VERSION_CSTR: &[u8] = b"0.1.0\0";
static PROVIDER_BUILDINFO_CSTR: &[u8] = b"Azure Managed HSM Provider (Rust)\0";
/// This is the entry point called by OpenSSL when loading the provider
/// Corresponds to OSSL_provider_init in akv_provider.c
#[no_mangle]
pub unsafe extern "C" fn OSSL_provider_init(
    handle: *const c_void,
    _in_: *const c_void,
    out: *mut *const c_void,
    provctx: *mut *mut c_void,
) -> c_int {
    log::trace!(
        "OSSL_provider_init handle={:p} out={:p} provctx={:p}",
        handle, out, provctx
    );
    
    // Initialize logging first
    if let Err(e) = init_logging() {
        eprintln!("Failed to initialize logging: {}", e);
    }
    
    // Check environment variables for log configuration
    if let Ok(log_level_str) = std::env::var("AKV_LOG_LEVEL") {
        if let Ok(level) = log_level_str.parse::<i32>() {
            log::debug!("AKV log level set to {} via environment", level);
        }
    }
    
    if let Ok(log_file) = std::env::var("AKV_LOG_FILE") {
        if !log_file.is_empty() {
            log::debug!("AKV log file set to {} via environment", log_file);
            // TODO: Implement file logging
        }
    }
    
    if out.is_null() || provctx.is_null() {
        log::error!("OSSL_provider_init received null output pointers");
        log::debug!("OSSL_provider_init -> 0 (bad arguments)");
        return 0;
    }
    
    // Allocate provider context
    let ctx = Box::new(ProviderContext::new(handle));
    let ctx_ptr = Box::into_raw(ctx);
    
    *provctx = ctx_ptr as *mut c_void;
    
    // Set dispatch table
    *out = AKV_DISPATCH_TABLE.as_ptr() as *const c_void;
    
    log::debug!("OSSL_provider_init -> 1 (ctx={:p})", ctx_ptr);
    log::info!("{} initialized", PROVIDER_NAME);
    
    1 // Success
}

/// Provider teardown function
/// Corresponds to akv_teardown in akv_provider.c
#[no_mangle]
pub unsafe extern "C" fn akv_teardown(provctx: *mut c_void) {
    log::trace!("akv_teardown provctx={:p}", provctx);
    
    if !provctx.is_null() {
        let _ = Box::from_raw(provctx as *mut ProviderContext);
    }
    
    log::debug!("akv_teardown complete");
}

/// Get provider parameters (name, version, etc.)
/// Corresponds to akv_get_params in akv_provider.c
#[no_mangle]
pub unsafe extern "C" fn akv_get_params(
    _provctx: *mut c_void,
    params: *mut OsslParam,
) -> c_int {
    log::trace!("akv_get_params params={:p}", params);
    
    if params.is_null() {
        log::debug!("akv_get_params -> 0 (null params)");
        return 0;
    }
    
    // Provider name
    let name_key = OSSL_PROV_PARAM_NAME.as_ptr() as *const c_char;
    let p = OsslParam::locate(params, name_key);
    if !p.is_null() {
        let name = PROVIDER_NAME_CSTR.as_ptr() as *const c_char;
        if !(*p).set_utf8_ptr(name) {
            log::debug!("akv_get_params failed to set provider name");
            return 0;
        }
    }
    
    // Provider version
    let version_key = OSSL_PROV_PARAM_VERSION.as_ptr() as *const c_char;
    let p = OsslParam::locate(params, version_key);
    if !p.is_null() {
        let version = PROVIDER_VERSION_CSTR.as_ptr() as *const c_char;
        if !(*p).set_utf8_ptr(version) {
            log::debug!("akv_get_params failed to set provider version");
            return 0;
        }
    }
    
    // Build info
    let buildinfo_key = OSSL_PROV_PARAM_BUILDINFO.as_ptr() as *const c_char;
    let p = OsslParam::locate(params, buildinfo_key);
    if !p.is_null() {
        let buildinfo = PROVIDER_BUILDINFO_CSTR.as_ptr() as *const c_char;
        if !(*p).set_utf8_ptr(buildinfo) {
            log::debug!("akv_get_params failed to set build info");
            return 0;
        }
    }
    
    // Status (is provider running)
    let status_key = OSSL_PROV_PARAM_STATUS.as_ptr() as *const c_char;
    let p = OsslParam::locate(params, status_key);
    if !p.is_null() {
        if !(*p).set_int(1) {
            log::debug!("akv_get_params failed to set status");
            return 0;
        }
    }
    
    log::debug!("akv_get_params -> 1");
    1
}

/// Get gettable parameters
/// Corresponds to akv_gettable_params in akv_provider.c
#[no_mangle]
pub unsafe extern "C" fn akv_gettable_params(_provctx: *mut c_void) -> *const OsslParam {
    log::trace!("akv_gettable_params");
    let result = PROVIDER_GETTABLE_PARAMS.as_ptr();
    log::debug!("akv_gettable_params -> {:p}", result);
    result
}

/// Query provider operations
/// Corresponds to akv_query_operation in akv_provider.c
#[no_mangle]
pub unsafe extern "C" fn akv_query_operation(
    _provctx: *mut c_void,
    operation_id: c_int,
    no_cache: *mut c_int,
) -> *const c_void {
    log::trace!("akv_query_operation operation_id={}", operation_id);
    
    if !no_cache.is_null() {
        *no_cache = 0;
    }
    
    let result = query_operation_impl(operation_id);
    
    log::debug!("akv_query_operation -> {:p}", result);
    result as *const c_void
}

/// Check if provider is running
#[no_mangle]
pub unsafe extern "C" fn akv_prov_is_running() -> c_int {
    log::trace!("akv_prov_is_running");
    log::debug!("akv_prov_is_running -> 1");
    1
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_provider_constants() {
        assert_eq!(PROVIDER_NAME, "Azure Managed HSM Provider");
        assert_eq!(PROVIDER_VERSION, "0.1.0");
    }
}
