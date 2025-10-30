/* Copyright (c) Microsoft Corporation.
Licensed under the MIT License. */

use crate::auth::AccessToken;
use crate::http_client::AkvHttpClient;
use crate::ossl_param::OsslParam;
use crate::provider::{AkvAesKey, AkvKey, ProviderContext};
use std::ffi::CStr;
use std::os::raw::{c_char, c_int, c_uchar, c_void};
use std::ptr;

/// RSA padding modes
const RSA_PKCS1_PADDING: c_int = 1;
const RSA_PKCS1_OAEP_PADDING: c_int = 4;

fn normalize_aes_algorithm_name(name: &str) -> Option<&'static str> {
    let primary = name.split(':').next().unwrap_or(name).trim();
    let upper = primary.to_ascii_uppercase();

    match upper.as_str() {
        "A128KW" | "AES-128-KW" | "ID-AES128-WRAP" | "AES-128-WRAP" | "2.16.840.1.101.3.4.1.5" => {
            Some("A128KW")
        }
        "A192KW" | "AES-192-KW" | "ID-AES192-WRAP" | "AES-192-WRAP" | "2.16.840.1.101.3.4.1.25" => {
            Some("A192KW")
        }
        "A256KW" | "AES-256-KW" | "ID-AES256-WRAP" | "AES-256-WRAP" | "2.16.840.1.101.3.4.1.45" => {
            Some("A256KW")
        }
        _ => None,
    }
}

/// RSA Cipher context for asymmetric encryption/decryption
pub struct RsaCipherContext {
    provctx: *mut ProviderContext,
    key: Option<Box<AkvKey>>,
    padding: c_int,
    oaep_md_name: Option<String>,
    mgf1_md_name: Option<String>,
}

impl RsaCipherContext {
    fn new(provctx: *mut ProviderContext) -> Box<Self> {
        Box::new(RsaCipherContext {
            provctx,
            key: None,
            padding: RSA_PKCS1_OAEP_PADDING,
            oaep_md_name: Some("SHA1".to_string()), // Azure defaults to SHA-1
            mgf1_md_name: None,
        })
    }

    /// Get the Azure algorithm name based on padding and digest
    fn get_algorithm(&self) -> Option<&'static str> {
        match self.padding {
            RSA_PKCS1_PADDING => Some("RSA1_5"),
            RSA_PKCS1_OAEP_PADDING => {
                let md_name = self.oaep_md_name.as_deref()?;
                match md_name {
                    "SHA1" => Some("RSA-OAEP"),
                    "SHA256" | "SHA2-256" => Some("RSA-OAEP-256"),
                    "SHA384" | "SHA2-384" => Some("RSA-OAEP-384"),
                    "SHA512" | "SHA2-512" => Some("RSA-OAEP-512"),
                    _ => None,
                }
            }
            _ => None,
        }
    }

    /// Decrypt using Azure Managed HSM
    fn decrypt_remote(&self, ciphertext: &[u8]) -> Result<Vec<u8>, String> {
        let key = self.key.as_ref().ok_or("No key set")?;
        let algorithm = self.get_algorithm().ok_or("Unsupported padding/digest")?;

        let vault_name = key.keyvault_name.as_ref().ok_or("No vault name")?;
        let key_name = key.key_name.as_ref().ok_or("No key name")?;

        let token =
            AccessToken::acquire().map_err(|e| format!("Failed to get access token: {}", e))?;
        let client = AkvHttpClient::new(vault_name.clone(), token)
            .map_err(|e| format!("Failed to create HTTP client: {}", e))?;

        client
            .decrypt(key_name, algorithm, ciphertext)
            .map_err(|e| format!("Azure decrypt failed: {}", e))
    }

    /// Get expected size for output
    fn expected_size(&self) -> usize {
        match &self.key {
            Some(key) => key.public_key.as_ref().map(|pk| pk.size()).unwrap_or(0),
            None => 0,
        }
    }
}

/// AES Cipher context for key wrap/unwrap
pub struct AesCipherContext {
    provctx: *mut ProviderContext,
    key: Option<Box<AkvAesKey>>,
    algorithm: Option<String>,
}

impl AesCipherContext {
    fn new(provctx: *mut ProviderContext) -> Box<Self> {
        Box::new(AesCipherContext {
            provctx,
            key: None,
            algorithm: None,
        })
    }

    /// Get the Azure algorithm based on configured value or key size
    fn get_algorithm(&self) -> Result<&'static str, String> {
        if let Some(ref alg) = self.algorithm {
            return normalize_aes_algorithm_name(alg)
                .ok_or_else(|| format!("Unsupported AES algorithm '{}'", alg));
        }

        let key = self
            .key
            .as_ref()
            .ok_or_else(|| "No key set for AES context".to_string())?;

        match key.key_bits {
            128 => Ok("A128KW"),
            192 => Ok("A192KW"),
            256 => Ok("A256KW"),
            other => Err(format!("Unsupported AES key size {}", other)),
        }
    }

    /// Wrap a key using Azure Managed HSM
    fn wrap_key_remote(&self, plaintext: &[u8]) -> Result<Vec<u8>, String> {
        let key = self.key.as_ref().ok_or_else(|| "No key set".to_string())?;
        let algorithm = self.get_algorithm()?;

        let vault_name = key.keyvault_name.as_ref().ok_or("No vault name")?;
        let key_name = key.key_name.as_ref().ok_or("No key name")?;

        let token =
            AccessToken::acquire().map_err(|e| format!("Failed to get access token: {}", e))?;
        let client = AkvHttpClient::new(vault_name.clone(), token)
            .map_err(|e| format!("Failed to create HTTP client: {}", e))?;

        client
            .wrap_key(key_name, algorithm, plaintext)
            .map_err(|e| format!("Azure wrap_key failed: {}", e))
    }

    /// Unwrap a key using Azure Managed HSM
    fn unwrap_key_remote(&self, ciphertext: &[u8]) -> Result<Vec<u8>, String> {
        let key = self.key.as_ref().ok_or_else(|| "No key set".to_string())?;
        let algorithm = self.get_algorithm()?;

        let vault_name = key.keyvault_name.as_ref().ok_or("No vault name")?;
        let key_name = key.key_name.as_ref().ok_or("No key name")?;

        let token =
            AccessToken::acquire().map_err(|e| format!("Failed to get access token: {}", e))?;
        let client = AkvHttpClient::new(vault_name.clone(), token)
            .map_err(|e| format!("Failed to create HTTP client: {}", e))?;

        client
            .unwrap_key(key_name, algorithm, ciphertext)
            .map_err(|e| format!("Azure unwrap_key failed: {}", e))
    }
}

//
// OpenSSL RSA ASYM_CIPHER dispatch functions
//

/// Create new RSA cipher context
#[no_mangle]
pub unsafe extern "C" fn akv_rsa_cipher_newctx(
    provctx: *mut c_void,
    _propq: *const c_char,
) -> *mut c_void {
    let ctx = RsaCipherContext::new(provctx as *mut ProviderContext);
    Box::into_raw(ctx) as *mut c_void
}

/// Free RSA cipher context
#[no_mangle]
pub unsafe extern "C" fn akv_rsa_cipher_freectx(vctx: *mut c_void) {
    if !vctx.is_null() {
        let _ctx = Box::from_raw(vctx as *mut RsaCipherContext);
    }
}

/// Initialize for decryption
#[no_mangle]
pub unsafe extern "C" fn akv_rsa_cipher_decrypt_init(
    vctx: *mut c_void,
    vkey: *mut c_void,
    _params: *const OsslParam,
) -> c_int {
    if vctx.is_null() || vkey.is_null() {
        return 0;
    }

    let ctx = &mut *(vctx as *mut RsaCipherContext);
    let key_ref = &*(vkey as *const AkvKey);

    // Clone the key into the context
    ctx.key = Some(Box::new(AkvKey {
        provctx: ctx.provctx,
        keyvault_name: key_ref.keyvault_name.clone(),
        key_name: key_ref.key_name.clone(),
        key_version: key_ref.key_version.clone(),
        public_key: key_ref.public_key.clone(),
    }));

    1
}

/// Initialize for encryption (not typically used - encryption happens locally)
#[no_mangle]
pub unsafe extern "C" fn akv_rsa_cipher_encrypt_init(
    vctx: *mut c_void,
    vkey: *mut c_void,
    _params: *const OsslParam,
) -> c_int {
    // Same as decrypt_init for key setup
    akv_rsa_cipher_decrypt_init(vctx, vkey, _params)
}

/// Decrypt operation
#[no_mangle]
pub unsafe extern "C" fn akv_rsa_cipher_decrypt(
    vctx: *mut c_void,
    out: *mut c_uchar,
    outlen: *mut usize,
    outsize: usize,
    input: *const c_uchar,
    inlen: usize,
) -> c_int {
    if vctx.is_null() || outlen.is_null() {
        return 0;
    }

    let ctx = &*(vctx as *const RsaCipherContext);
    let expected = ctx.expected_size();

    // If out is null, return expected size
    if out.is_null() {
        *outlen = expected;
        return 1;
    }

    if outsize < expected {
        *outlen = expected;
        return 0;
    }

    if input.is_null() {
        return 0;
    }

    let ciphertext = std::slice::from_raw_parts(input, inlen);

    match ctx.decrypt_remote(ciphertext) {
        Ok(plaintext) => {
            if plaintext.len() > outsize {
                return 0;
            }
            ptr::copy_nonoverlapping(plaintext.as_ptr(), out, plaintext.len());
            *outlen = plaintext.len();
            1
        }
        Err(e) => {
            log::error!("Decrypt failed: {}", e);
            0
        }
    }
}

/// Encrypt operation (typically done locally with public key)
#[no_mangle]
pub unsafe extern "C" fn akv_rsa_cipher_encrypt(
    vctx: *mut c_void,
    out: *mut c_uchar,
    outlen: *mut usize,
    _outsize: usize,
    _input: *const c_uchar,
    _inlen: usize,
) -> c_int {
    if vctx.is_null() || outlen.is_null() {
        return 0;
    }

    let ctx = &*(vctx as *const RsaCipherContext);
    let expected = ctx.expected_size();

    // If out is null, return expected size
    if out.is_null() {
        *outlen = expected;
        return 1;
    }

    // Encryption is not implemented - should be done locally with public key
    log::error!("RSA encryption not supported in Azure provider - use local encryption");
    0
}

/// Set context parameters
#[no_mangle]
pub unsafe extern "C" fn akv_rsa_cipher_set_ctx_params(
    vctx: *mut c_void,
    params: *const OsslParam,
) -> c_int {
    if vctx.is_null() || params.is_null() {
        return 1;
    }

    let ctx = &mut *(vctx as *mut RsaCipherContext);
    let mut current = params;

    while !(*current).key.is_null() {
        let key_cstr = CStr::from_ptr((*current).key);
        if let Ok(key_str) = key_cstr.to_str() {
            match key_str {
                "pad-mode" => {
                    if let Some(value_ptr) = OsslParam::get_utf8_string_ptr(current) {
                        if let Ok(pad_str) = CStr::from_ptr(value_ptr).to_str() {
                            ctx.padding = match pad_str {
                                "oaep" => RSA_PKCS1_OAEP_PADDING,
                                "pkcs1" => RSA_PKCS1_PADDING,
                                _ => ctx.padding,
                            };
                        }
                    }
                }
                "oaep-digest" => {
                    if let Some(value_ptr) = OsslParam::get_utf8_string_ptr(current) {
                        if let Ok(md_name) = CStr::from_ptr(value_ptr).to_str() {
                            ctx.oaep_md_name = Some(md_name.to_string());
                        }
                    }
                }
                "mgf1-digest" => {
                    if let Some(value_ptr) = OsslParam::get_utf8_string_ptr(current) {
                        if let Ok(md_name) = CStr::from_ptr(value_ptr).to_str() {
                            ctx.mgf1_md_name = Some(md_name.to_string());
                        }
                    }
                }
                _ => {}
            }
        }
        current = current.offset(1);
    }

    1
}

/// Get context parameters
#[no_mangle]
pub unsafe extern "C" fn akv_rsa_cipher_get_ctx_params(
    _vctx: *mut c_void,
    _params: *mut OsslParam,
) -> c_int {
    // No parameters to get currently
    1
}

/// Get settable context parameters
#[no_mangle]
pub unsafe extern "C" fn akv_rsa_cipher_settable_ctx_params(
    _vctx: *mut c_void,
    _provctx: *mut c_void,
) -> *const OsslParam {
    static EMPTY: OsslParam = OsslParam {
        key: ptr::null(),
        data_type: 0,
        data: ptr::null_mut(),
        data_size: 0,
        return_size: 0,
    };
    &EMPTY as *const OsslParam
}

/// Get gettable context parameters
#[no_mangle]
pub unsafe extern "C" fn akv_rsa_cipher_gettable_ctx_params(
    _vctx: *mut c_void,
    _provctx: *mut c_void,
) -> *const OsslParam {
    akv_rsa_cipher_settable_ctx_params(_vctx, _provctx)
}

//
// OpenSSL AES ASYM_CIPHER dispatch functions
//

/// Create new AES cipher context
#[no_mangle]
pub unsafe extern "C" fn akv_aes_cipher_newctx(
    provctx: *mut c_void,
    _propq: *const c_char,
) -> *mut c_void {
    let ctx = AesCipherContext::new(provctx as *mut ProviderContext);
    Box::into_raw(ctx) as *mut c_void
}

/// Free AES cipher context
#[no_mangle]
pub unsafe extern "C" fn akv_aes_cipher_freectx(vctx: *mut c_void) {
    if !vctx.is_null() {
        let _ctx = Box::from_raw(vctx as *mut AesCipherContext);
    }
}

/// Initialize for encryption (wrap)
#[no_mangle]
pub unsafe extern "C" fn akv_aes_cipher_encrypt_init(
    vctx: *mut c_void,
    vkey: *mut c_void,
    _params: *const OsslParam,
) -> c_int {
    if vctx.is_null() || vkey.is_null() {
        return 0;
    }

    let ctx = &mut *(vctx as *mut AesCipherContext);
    let key_ref = &*(vkey as *const AkvAesKey);

    // Clone the key into the context
    ctx.key = Some(Box::new(AkvAesKey {
        provctx: ctx.provctx,
        keyvault_name: key_ref.keyvault_name.clone(),
        key_name: key_ref.key_name.clone(),
        key_version: key_ref.key_version.clone(),
        key_bits: key_ref.key_bits,
    }));

    1
}

/// Initialize for decryption (unwrap)
#[no_mangle]
pub unsafe extern "C" fn akv_aes_cipher_decrypt_init(
    vctx: *mut c_void,
    vkey: *mut c_void,
    _params: *const OsslParam,
) -> c_int {
    // Same as encrypt_init for key setup
    akv_aes_cipher_encrypt_init(vctx, vkey, _params)
}

/// Encrypt operation (wrap key)
#[no_mangle]
pub unsafe extern "C" fn akv_aes_cipher_encrypt(
    vctx: *mut c_void,
    out: *mut c_uchar,
    outlen: *mut usize,
    outsize: usize,
    input: *const c_uchar,
    inlen: usize,
) -> c_int {
    if vctx.is_null() || outlen.is_null() || input.is_null() {
        return 0;
    }

    let ctx = &*(vctx as *const AesCipherContext);

    // If out is null, estimate output size (input + overhead)
    if out.is_null() {
        *outlen = inlen + 8;
        return 1;
    }

    let plaintext = std::slice::from_raw_parts(input, inlen);

    match ctx.wrap_key_remote(plaintext) {
        Ok(wrapped) => {
            if wrapped.len() > outsize {
                *outlen = wrapped.len();
                return 0;
            }
            ptr::copy_nonoverlapping(wrapped.as_ptr(), out, wrapped.len());
            *outlen = wrapped.len();
            1
        }
        Err(e) => {
            log::error!("Wrap key failed: {}", e);
            0
        }
    }
}

/// Decrypt operation (unwrap key)
#[no_mangle]
pub unsafe extern "C" fn akv_aes_cipher_decrypt(
    vctx: *mut c_void,
    out: *mut c_uchar,
    outlen: *mut usize,
    outsize: usize,
    input: *const c_uchar,
    inlen: usize,
) -> c_int {
    if vctx.is_null() || outlen.is_null() || input.is_null() {
        return 0;
    }

    let ctx = &*(vctx as *const AesCipherContext);

    // If out is null, estimate output size
    if out.is_null() {
        *outlen = inlen.saturating_sub(8);
        return 1;
    }

    let ciphertext = std::slice::from_raw_parts(input, inlen);

    match ctx.unwrap_key_remote(ciphertext) {
        Ok(unwrapped) => {
            if unwrapped.len() > outsize {
                *outlen = unwrapped.len();
                return 0;
            }
            ptr::copy_nonoverlapping(unwrapped.as_ptr(), out, unwrapped.len());
            *outlen = unwrapped.len();
            1
        }
        Err(e) => {
            log::error!("Unwrap key failed: {}", e);
            0
        }
    }
}

/// Set AES context parameters
#[no_mangle]
pub unsafe extern "C" fn akv_aes_cipher_set_ctx_params(
    vctx: *mut c_void,
    params: *const OsslParam,
) -> c_int {
    if vctx.is_null() || params.is_null() {
        return 1;
    }

    let ctx = &mut *(vctx as *mut AesCipherContext);
    let mut current = params;

    while !(*current).key.is_null() {
        let key_cstr = CStr::from_ptr((*current).key);
        if let Ok(key_str) = key_cstr.to_str() {
            if key_str == "algorithm" {
                if let Some(value_ptr) = OsslParam::get_utf8_string_ptr(current) {
                    if let Ok(alg_str) = CStr::from_ptr(value_ptr).to_str() {
                        if let Some(normalized) = normalize_aes_algorithm_name(alg_str) {
                            ctx.algorithm = Some(normalized.to_string());
                            log::debug!(
                                "akv_aes_cipher_set_ctx_params -> algorithm set to {}",
                                normalized
                            );
                        } else {
                            log::warn!(
                                "akv_aes_cipher_set_ctx_params ignoring unsupported algorithm '{}'",
                                alg_str
                            );
                        }
                    }
                }
            }
        }
        current = current.offset(1);
    }

    1
}

/// Get AES context parameters
#[no_mangle]
pub unsafe extern "C" fn akv_aes_cipher_get_ctx_params(
    _vctx: *mut c_void,
    _params: *mut OsslParam,
) -> c_int {
    1
}

/// Get settable AES context parameters
#[no_mangle]
pub unsafe extern "C" fn akv_aes_cipher_settable_ctx_params(
    _vctx: *mut c_void,
    _provctx: *mut c_void,
) -> *const OsslParam {
    static EMPTY: OsslParam = OsslParam {
        key: ptr::null(),
        data_type: 0,
        data: ptr::null_mut(),
        data_size: 0,
        return_size: 0,
    };
    &EMPTY as *const OsslParam
}

/// Get gettable AES context parameters
#[no_mangle]
pub unsafe extern "C" fn akv_aes_cipher_gettable_ctx_params(
    _vctx: *mut c_void,
    _provctx: *mut c_void,
) -> *const OsslParam {
    akv_aes_cipher_settable_ctx_params(_vctx, _provctx)
}
