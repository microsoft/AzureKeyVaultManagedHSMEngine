// Store loader functionality
// Corresponds to akv_store_* functions in akv_provider.c

use crate::auth::AccessToken;
use crate::http_client::{AkvHttpClient, KeyType, PublicKeyMaterial};
use crate::openssl_helpers::{build_ec_public_key, build_rsa_public_key};
use crate::ossl_param::{
    OsslParam, OSSL_OBJECT_PARAM_DATA_TYPE, OSSL_OBJECT_PARAM_REFERENCE, OSSL_OBJECT_PARAM_TYPE,
    OSSL_OBJECT_PKEY,
};
use crate::provider::{parse_uri, AkvAesKey, AkvKey, ProviderContext};
use std::ffi::{CStr, CString};
use std::os::raw::{c_char, c_int, c_void};
use std::ptr;

/// Store context for loading keys from Azure Managed HSM
/// Corresponds to AKV_STORE_CTX
pub struct StoreContext {
    pub provctx: *mut ProviderContext,
    pub keyvault_name: Option<String>,
    pub key_name: Option<String>,
    pub key_version: Option<String>,
    pub exhausted: bool,
}

impl StoreContext {
    pub fn new(provctx: *mut ProviderContext) -> Self {
        log::trace!("StoreContext::new provctx={:p}", provctx);
        Self {
            provctx,
            keyvault_name: None,
            key_name: None,
            key_version: None,
            exhausted: false,
        }
    }

    /// Parse and set URI metadata
    pub fn parse_uri(&mut self, uri: &str) -> bool {
        log::trace!("StoreContext::parse_uri uri={}", uri);

        match parse_uri(uri) {
            Ok(parsed) => {
                self.keyvault_name = Some(parsed.vault_name);
                self.key_name = Some(parsed.key_name);
                self.key_version = parsed.key_version;
                log::debug!(
                    "StoreContext::parse_uri -> true (vault={:?} name={:?} version={:?})",
                    self.keyvault_name,
                    self.key_name,
                    self.key_version
                );
                true
            }
            Err(e) => {
                log::debug!("StoreContext::parse_uri -> false ({})", e);
                false
            }
        }
    }

    /// Log the URL that would be used for curl GET key operation
    pub fn log_curl_get_key_url(&self) {
        log::trace!("log_curl_get_key_url");

        if let (Some(vault), Some(name)) = (&self.keyvault_name, &self.key_name) {
            let url = if let Some(version) = &self.key_version {
                format!(
                    "https://{}.managedhsm.azure.net/keys/{}/{}",
                    vault, name, version
                )
            } else {
                format!("https://{}.managedhsm.azure.net/keys/{}", vault, name)
            };
            log::debug!("curl.c AkvGetKey URL: {}", url);
        } else {
            log::debug!("log_curl_get_key_url skipped (incomplete metadata)");
        }
    }
}

impl Drop for StoreContext {
    fn drop(&mut self) {
        log::trace!("StoreContext::drop");
        log::debug!("StoreContext::drop complete");
    }
}

// OpenSSL C FFI functions for store loader
// These will be exposed via OSSL_DISPATCH table

/// Open a store context from a URI
/// Corresponds to akv_store_open
#[no_mangle]
pub unsafe extern "C" fn akv_store_open(provctx: *mut c_void, uri: *const c_char) -> *mut c_void {
    log::trace!("akv_store_open provctx={:p} uri={:p}", provctx, uri);

    if uri.is_null() {
        log::debug!("akv_store_open -> NULL (null uri)");
        return ptr::null_mut();
    }

    let uri_str = match CStr::from_ptr(uri).to_str() {
        Ok(s) => s,
        Err(_) => {
            log::debug!("akv_store_open -> NULL (invalid utf8)");
            return ptr::null_mut();
        }
    };

    let mut ctx = Box::new(StoreContext::new(provctx as *mut ProviderContext));

    if !ctx.parse_uri(uri_str) {
        log::debug!("akv_store_open -> NULL (parsing failed)");
        return ptr::null_mut();
    }

    let ctx_ptr = Box::into_raw(ctx);
    log::debug!("akv_store_open -> {:p}", ctx_ptr);
    ctx_ptr as *mut c_void
}

/// Attach to an existing BIO (not supported)
/// Corresponds to akv_store_attach
#[no_mangle]
pub unsafe extern "C" fn akv_store_attach(_provctx: *mut c_void, _bio: *mut c_void) -> *mut c_void {
    log::trace!("akv_store_attach (not supported)");
    log::debug!("akv_store_attach -> NULL (not supported)");
    ptr::null_mut()
}

/// Get settable context parameters (empty list)
/// Corresponds to akv_store_settable_ctx_params
#[no_mangle]
pub unsafe extern "C" fn akv_store_settable_ctx_params(_provctx: *mut c_void) -> *const c_void {
    log::trace!("akv_store_settable_ctx_params");
    // Return pointer to empty OSSL_PARAM array (to be implemented)
    log::debug!("akv_store_settable_ctx_params -> NULL");
    ptr::null()
}

/// Set context parameters (no-op)
/// Corresponds to akv_store_set_ctx_params
#[no_mangle]
pub unsafe extern "C" fn akv_store_set_ctx_params(
    _loaderctx: *mut c_void,
    _params: *const c_void,
) -> c_int {
    log::trace!("akv_store_set_ctx_params (no-op)");
    log::debug!("akv_store_set_ctx_params -> 1");
    1
}

/// Load a key from Azure Managed HSM
/// Corresponds to akv_store_load
#[no_mangle]
pub unsafe extern "C" fn akv_store_load(
    loaderctx: *mut c_void,
    object_cb: *mut c_void,
    object_cbarg: *mut c_void,
    _pw_cb: *mut c_void,
    _pw_cbarg: *mut c_void,
) -> c_int {
    log::trace!("akv_store_load loaderctx={:p}", loaderctx);

    if loaderctx.is_null() {
        log::debug!("akv_store_load -> 0 (null context)");
        return 0;
    }

    let ctx = &mut *(loaderctx as *mut StoreContext);

    if ctx.exhausted {
        log::debug!("akv_store_load -> 0 (exhausted)");
        return 0;
    }

    // Get access token from environment
    let access_token = match AccessToken::from_env() {
        Ok(token) => token,
        Err(e) => {
            log::error!("Failed to get access token: {}", e);
            ctx.exhausted = true;
            log::debug!("akv_store_load -> 0 (no access token)");
            return 0;
        }
    };

    // Extract key information
    let vault_name = match ctx.keyvault_name.clone() {
        Some(v) => v,
        None => {
            log::error!("Missing vault name");
            ctx.exhausted = true;
            return 0;
        }
    };

    let key_name = match ctx.key_name.clone() {
        Some(k) => k,
        None => {
            log::error!("Missing key name");
            ctx.exhausted = true;
            return 0;
        }
    };

    // Create HTTP client
    let client = match AkvHttpClient::new(vault_name, access_token) {
        Ok(c) => c,
        Err(e) => {
            log::error!("Failed to create HTTP client: {}", e);
            ctx.exhausted = true;
            return 0;
        }
    };

    // Get key type first
    let (key_type, key_size) = match client.get_key_type(&key_name) {
        Ok(t) => t,
        Err(e) => {
            log::error!("Failed to get key type for {}: {}", key_name, e);
            ctx.exhausted = true;
            return 0;
        }
    };

    log::info!("Loading key {} (type: {:?})", key_name, key_type);

    // Handle symmetric keys (AES)
    if key_type == KeyType::Oct || key_type == KeyType::OctHsm {
        let key_bits = key_size.unwrap_or(256);

        log::debug!("Creating AkvAesKey for {} ({} bits)", key_name, key_bits);

        let mut akv_key = Box::new(AkvAesKey::new(ctx.provctx));
        akv_key.keyvault_name = Some(ctx.keyvault_name.clone().unwrap());
        akv_key.key_name = Some(key_name.clone());
        akv_key.key_version = ctx.key_version.clone();
        akv_key.key_bits = key_bits;

        // Prepare to pass key reference to OpenSSL
        let mut key_ptr = Box::into_raw(akv_key) as *mut c_void;
        let mut object_type = OSSL_OBJECT_PKEY;

        let data_type_ptr = match key_bits {
            128 => b"AES-128-KW\0".as_ptr() as *mut c_char,
            192 => b"AES-192-KW\0".as_ptr() as *mut c_char,
            256 => b"AES-256-KW\0".as_ptr() as *mut c_char,
            other => {
                log::warn!(
                    "Unsupported AES key size {} bits, defaulting to AES-256-KW descriptor",
                    other
                );
                b"AES-256-KW\0".as_ptr() as *mut c_char
            }
        };

        // Build OSSL_PARAM array
        let params: [OsslParam; 4] = [
            OsslParam::construct_int(
                OSSL_OBJECT_PARAM_TYPE.as_ptr() as *const c_char,
                &mut object_type as *mut c_int,
            ),
            OsslParam::construct_utf8_string(
                OSSL_OBJECT_PARAM_DATA_TYPE.as_ptr() as *const c_char,
                data_type_ptr,
                0,
            ),
            OsslParam::construct_octet_string(
                OSSL_OBJECT_PARAM_REFERENCE.as_ptr() as *const c_char,
                &mut key_ptr as *mut *mut c_void as *mut c_void,
                std::mem::size_of::<*mut AkvAesKey>(),
            ),
            OsslParam::end(),
        ];

        // Call the object callback
        type ObjectCallback = unsafe extern "C" fn(*const OsslParam, *mut c_void) -> c_int;
        let callback: ObjectCallback = std::mem::transmute(object_cb);

        let cb_result = callback(params.as_ptr(), object_cbarg);

        if cb_result == 0 {
            log::error!("AES object callback failed");
            crate::openssl_ffi::log_openssl_errors("AES object callback");
            // Free the key since callback failed
            let _ = unsafe { Box::from_raw(key_ptr as *mut AkvAesKey) };
            ctx.exhausted = true;
            return 0;
        }

        log::info!("Delivered AES key reference for {}", key_name);
        ctx.exhausted = true;
        return 1;
    }

    // Handle asymmetric keys (RSA/EC)
    let key_material = match client.get_key(&key_name, ctx.key_version.as_deref()) {
        Ok(m) => m,
        Err(e) => {
            log::error!("Failed to get key material for {}: {}", key_name, e);
            ctx.exhausted = true;
            return 0;
        }
    };

    match key_material {
        PublicKeyMaterial::Rsa(rsa_key) => {
            log::debug!("Creating AkvKey for RSA key {}", key_name);

            let mut akv_key = Box::new(AkvKey::new(ctx.provctx));
            akv_key.set_metadata(
                &ctx.keyvault_name.clone().unwrap(),
                &key_name,
                ctx.key_version.as_deref(),
            );

            // Build OpenSSL RSA public key from modulus and exponent
            match build_rsa_public_key(&rsa_key.n, &rsa_key.e) {
                Ok(pkey) => akv_key.set_public(pkey),
                Err(e) => {
                    log::error!("Failed to build RSA public key: {}", e);
                    ctx.exhausted = true;
                    return 0;
                }
            }

            // Prepare to pass key reference to OpenSSL
            let mut key_ptr = Box::into_raw(akv_key) as *mut c_void;
            let mut object_type = OSSL_OBJECT_PKEY;

            let data_type = CString::new("RSA").unwrap();
            let data_type_ptr = data_type.as_ptr() as *mut c_char;

            log::trace!(
                "Building OSSL_PARAM array: type={}, data_type='RSA', reference={:p}, ref_size={}",
                object_type,
                key_ptr,
                std::mem::size_of::<*mut c_void>()
            );

            // Build OSSL_PARAM array
            let params: [OsslParam; 4] = [
                OsslParam::construct_int(
                    OSSL_OBJECT_PARAM_TYPE.as_ptr() as *const c_char,
                    &mut object_type as *mut c_int,
                ),
                OsslParam::construct_utf8_string(
                    OSSL_OBJECT_PARAM_DATA_TYPE.as_ptr() as *const c_char,
                    data_type_ptr,
                    0,
                ),
                OsslParam::construct_octet_string(
                    OSSL_OBJECT_PARAM_REFERENCE.as_ptr() as *const c_char,
                    &mut key_ptr as *mut *mut c_void as *mut c_void,
                    std::mem::size_of::<*mut c_void>(),
                ),
                OsslParam::end(),
            ];

            log::debug!(
                "Calling object callback: callback={:p}, cbarg={:p}, params={:p}",
                object_cb,
                object_cbarg,
                params.as_ptr()
            );

            // Call the object callback
            type ObjectCallback = unsafe extern "C" fn(*const OsslParam, *mut c_void) -> c_int;
            let callback: ObjectCallback = std::mem::transmute(object_cb);

            let cb_result = callback(params.as_ptr(), object_cbarg);

            log::debug!("Object callback returned: {}", cb_result);

            if cb_result == 0 {
                log::error!("RSA object callback failed (returned 0)");
                crate::openssl_ffi::log_openssl_errors("Object callback");
                log::debug!("Freeing rejected key at {:p}", key_ptr);
                let _ = unsafe { Box::from_raw(key_ptr as *mut AkvKey) };
                ctx.exhausted = true;
                return 0;
            }

            log::info!("Delivered RSA key reference for {}", key_name);
            ctx.exhausted = true;
            return 1;
        }
        PublicKeyMaterial::Ec(ec_key) => {
            log::debug!(
                "Creating AkvKey for EC key {} (curve: {})",
                key_name,
                ec_key.curve
            );

            let mut akv_key = Box::new(AkvKey::new(ctx.provctx));
            akv_key.set_metadata(
                &ctx.keyvault_name.clone().unwrap(),
                &key_name,
                ctx.key_version.as_deref(),
            );

            // Build OpenSSL EC public key from x, y, curve
            match build_ec_public_key(&ec_key.x, &ec_key.y, &ec_key.curve) {
                Ok(pkey) => akv_key.set_public(pkey),
                Err(e) => {
                    log::error!("Failed to build EC public key: {}", e);
                    ctx.exhausted = true;
                    return 0;
                }
            }

            // Prepare to pass key reference to OpenSSL
            let mut key_ptr = Box::into_raw(akv_key) as *mut c_void;
            let mut object_type = OSSL_OBJECT_PKEY;

            let data_type = CString::new("EC").unwrap();
            let data_type_ptr = data_type.as_ptr() as *mut c_char;

            // Build OSSL_PARAM array
            let params: [OsslParam; 4] = [
                OsslParam::construct_int(
                    OSSL_OBJECT_PARAM_TYPE.as_ptr() as *const c_char,
                    &mut object_type as *mut c_int,
                ),
                OsslParam::construct_utf8_string(
                    OSSL_OBJECT_PARAM_DATA_TYPE.as_ptr() as *const c_char,
                    data_type_ptr,
                    0,
                ),
                OsslParam::construct_octet_string(
                    OSSL_OBJECT_PARAM_REFERENCE.as_ptr() as *const c_char,
                    &mut key_ptr as *mut *mut c_void as *mut c_void,
                    std::mem::size_of::<*mut c_void>(),
                ),
                OsslParam::end(),
            ];

            // Call the object callback
            type ObjectCallback = unsafe extern "C" fn(*const OsslParam, *mut c_void) -> c_int;
            let callback: ObjectCallback = std::mem::transmute(object_cb);

            let cb_result = callback(params.as_ptr(), object_cbarg);

            if cb_result == 0 {
                log::error!("EC object callback failed");
                let _ = unsafe { Box::from_raw(key_ptr as *mut AkvKey) };
                ctx.exhausted = true;
                return 0;
            }

            log::info!("Delivered EC key reference for {}", key_name);
            ctx.exhausted = true;
            return 1;
        }
        PublicKeyMaterial::Symmetric { .. } => {
            // Should have been handled above
            log::error!("Unexpected symmetric key material");
            ctx.exhausted = true;
            return 0;
        }
    }
}

/// Check if store is exhausted (EOF)
/// Corresponds to akv_store_eof
#[no_mangle]
pub unsafe extern "C" fn akv_store_eof(loaderctx: *mut c_void) -> c_int {
    log::trace!("akv_store_eof loaderctx={:p}", loaderctx);

    if loaderctx.is_null() {
        log::debug!("akv_store_eof -> 1 (null context)");
        return 1;
    }

    let ctx = &*(loaderctx as *mut StoreContext);
    let eof = if ctx.exhausted { 1 } else { 0 };

    log::debug!("akv_store_eof -> {}", eof);
    eof
}

/// Close and free store context
/// Corresponds to akv_store_close
#[no_mangle]
pub unsafe extern "C" fn akv_store_close(loaderctx: *mut c_void) -> c_int {
    log::trace!("akv_store_close loaderctx={:p}", loaderctx);

    if !loaderctx.is_null() {
        let _ = Box::from_raw(loaderctx as *mut StoreContext);
    }

    log::debug!("akv_store_close -> 1");
    1
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_store_context_parse_uri() {
        let mut ctx = StoreContext::new(ptr::null_mut());
        assert!(ctx.parse_uri("akv:vault=myvault,name=mykey"));
        assert_eq!(ctx.keyvault_name, Some("myvault".to_string()));
        assert_eq!(ctx.key_name, Some("mykey".to_string()));
    }
}
