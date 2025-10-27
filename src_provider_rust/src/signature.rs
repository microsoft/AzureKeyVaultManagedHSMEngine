/* Copyright (c) Microsoft Corporation.
   Licensed under the MIT License. */

use crate::auth::AccessToken;
use crate::http_client::AkvHttpClient;
use crate::ossl_param::{OsslParam, OSSL_PARAM_UTF8_STRING, OSSL_PARAM_OCTET_STRING};
use crate::provider::{AkvKey, ProviderContext};
use openssl::bn::BigNum;
use openssl::ecdsa::EcdsaSig;
use openssl::hash::MessageDigest;
use openssl::md_ctx::MdCtx;
use openssl::rsa::Padding;
use openssl::sign::Verifier;
use std::ffi::CStr;
use std::os::raw::{c_char, c_int, c_uchar, c_void};
use std::ptr;

/// RSA padding modes
const RSA_PKCS1_PADDING: c_int = 1;
const RSA_PSS_PADDING: c_int = 6;

/// PSS salt length
const RSA_PSS_SALTLEN_DIGEST: c_int = -1;

/// Signature operations
const EVP_PKEY_OP_SIGN: c_int = 1;
const EVP_PKEY_OP_VERIFY: c_int = 2;

/// Key types for signature
#[derive(Debug, Clone, Copy)]
enum KeyType {
    Rsa,
    Ec,
}

/// Signature context for RSA and EC operations
pub struct SignatureContext {
    provctx: *mut ProviderContext,
    keytype: KeyType,
    key: Option<Box<AkvKey>>,
    mdctx: Option<MdCtx>,
    md_name: Option<String>,
    mgf1_md_name: Option<String>,
    operation: c_int,
    padding: c_int,
    pss_saltlen: c_int,
}

impl SignatureContext {
    fn new_rsa(provctx: *mut ProviderContext) -> Box<Self> {
        log::trace!("SignatureContext::new_rsa");
        Box::new(SignatureContext {
            provctx,
            keytype: KeyType::Rsa,
            key: None,
            mdctx: None,
            md_name: None,
            mgf1_md_name: None,
            operation: 0,
            padding: RSA_PKCS1_PADDING,
            pss_saltlen: RSA_PSS_SALTLEN_DIGEST,
        })
    }

    fn new_ec(provctx: *mut ProviderContext) -> Box<Self> {
        log::trace!("SignatureContext::new_ec");
        Box::new(SignatureContext {
            provctx,
            keytype: KeyType::Ec,
            key: None,
            mdctx: None,
            md_name: None,
            mgf1_md_name: None,
            operation: 0,
            padding: 0,
            pss_saltlen: 0,
        })
    }

    /// Get the Azure algorithm name based on context
    fn get_algorithm(&self) -> Option<&'static str> {
        let md_name = self.md_name.as_deref()?;

        match self.keytype {
            KeyType::Rsa => {
                if self.padding == RSA_PSS_PADDING {
                    // RSA-PSS
                    match md_name {
                        "SHA256" | "SHA2-256" => Some("PS256"),
                        "SHA384" | "SHA2-384" => Some("PS384"),
                        "SHA512" | "SHA2-512" => Some("PS512"),
                        _ => None,
                    }
                } else {
                    // RSA PKCS#1 v1.5
                    match md_name {
                        "SHA256" | "SHA2-256" => Some("RS256"),
                        "SHA384" | "SHA2-384" => Some("RS384"),
                        "SHA512" | "SHA2-512" => Some("RS512"),
                        _ => None,
                    }
                }
            }
            KeyType::Ec => {
                // ECDSA
                match md_name {
                    "SHA256" | "SHA2-256" => Some("ES256"),
                    "SHA384" | "SHA2-384" => Some("ES384"),
                    "SHA512" | "SHA2-512" => Some("ES512"),
                    "SHA256K" => Some("ES256K"),
                    _ => None,
                }
            }
        }
    }

    /// Sign using Azure Managed HSM
    fn sign_remote(&self, digest: &[u8]) -> Result<Vec<u8>, String> {
        let key = self.key.as_ref().ok_or("No key set")?;
        let algorithm = self.get_algorithm().ok_or("Unsupported algorithm")?;

        let vault_name = key.keyvault_name.as_ref().ok_or("No vault name")?;
        let key_name = key.key_name.as_ref().ok_or("No key name")?;

        log::trace!(
            "sign_remote key={} algorithm={} digest_len={}",
            key_name, algorithm, digest.len()
        );

        let token = AccessToken::from_env().map_err(|e| format!("Failed to get access token: {}", e))?;
        let client = AkvHttpClient::new(vault_name.clone(), token)
            .map_err(|e| format!("Failed to create HTTP client: {}", e))?;

        let signature = client
            .sign(key_name, algorithm, digest)
            .map_err(|e| format!("Azure sign failed: {}", e))?;

        // For EC signatures, convert from raw format to DER
        if matches!(self.keytype, KeyType::Ec) {
            self.format_ecdsa_signature(&signature)
        } else {
            Ok(signature)
        }
    }

    /// Convert raw ECDSA signature to DER format
    fn format_ecdsa_signature(&self, raw_sig: &[u8]) -> Result<Vec<u8>, String> {
        if raw_sig.len() % 2 != 0 {
            return Err("Invalid EC signature length".to_string());
        }

        let half = raw_sig.len() / 2;
        let r = BigNum::from_slice(&raw_sig[..half])
            .map_err(|e| format!("Failed to parse R: {}", e))?;
        let s = BigNum::from_slice(&raw_sig[half..])
            .map_err(|e| format!("Failed to parse S: {}", e))?;

        let sig = EcdsaSig::from_private_components(r, s)
            .map_err(|e| format!("Failed to create ECDSA signature: {}", e))?;

        sig.to_der()
            .map_err(|e| format!("Failed to encode DER: {}", e))
    }

    /// Verify signature using cached public key
    fn verify_local(&self, sig: &[u8], tbs: &[u8]) -> Result<bool, String> {
        let key = self.key.as_ref().ok_or("No key set")?;
        let pkey = key.public_key.as_ref().ok_or("No public key")?;

        let md_name = self.md_name.as_ref().ok_or("No message digest set")?;
        
        // Map digest name to MessageDigest
        let md = match md_name.as_str() {
            "SHA256" | "SHA2-256" => MessageDigest::sha256(),
            "SHA384" | "SHA2-384" => MessageDigest::sha384(),
            "SHA512" | "SHA2-512" => MessageDigest::sha512(),
            _ => return Err(format!("Unsupported digest: {}", md_name)),
        };

        let mut verifier = Verifier::new(md, pkey)
            .map_err(|e| format!("Failed to create verifier: {}", e))?;

        if matches!(self.keytype, KeyType::Rsa) && self.padding == RSA_PSS_PADDING {
            verifier
                .set_rsa_padding(Padding::PKCS1_PSS)
                .map_err(|e| format!("Failed to set PSS padding: {}", e))?;
            verifier
                .set_rsa_pss_saltlen(openssl::sign::RsaPssSaltlen::DIGEST_LENGTH)
                .map_err(|e| format!("Failed to set PSS salt length: {}", e))?;

            if let Some(mgf1_name) = &self.mgf1_md_name {
                let mgf1_md = match mgf1_name.as_str() {
                    "SHA256" | "SHA2-256" => MessageDigest::sha256(),
                    "SHA384" | "SHA2-384" => MessageDigest::sha384(),
                    "SHA512" | "SHA2-512" => MessageDigest::sha512(),
                    _ => return Err(format!("Unsupported MGF1 digest: {}", mgf1_name)),
                };
                verifier
                    .set_rsa_mgf1_md(mgf1_md)
                    .map_err(|e| format!("Failed to set MGF1 digest: {}", e))?;
            }
        }

        verifier
            .verify_oneshot(sig, tbs)
            .map_err(|e| format!("Verification failed: {}", e))
    }

    /// Get expected signature size
    fn expected_size(&self) -> usize {
        match &self.key {
            Some(key) => key.public_key.as_ref().map(|pk| pk.size()).unwrap_or(0),
            None => 0,
        }
    }
}

//
// OpenSSL SIGNATURE dispatch functions
//

/// Create new RSA signature context
#[no_mangle]
pub unsafe extern "C" fn akv_rsa_signature_newctx(
    provctx: *mut c_void,
    _propq: *const c_char,
) -> *mut c_void {
    log::trace!("akv_rsa_signature_newctx");
    let ctx = SignatureContext::new_rsa(provctx as *mut ProviderContext);
    Box::into_raw(ctx) as *mut c_void
}

/// Create new EC signature context
#[no_mangle]
pub unsafe extern "C" fn akv_ecdsa_signature_newctx(
    provctx: *mut c_void,
    _propq: *const c_char,
) -> *mut c_void {
    log::trace!("akv_ecdsa_signature_newctx");
    let ctx = SignatureContext::new_ec(provctx as *mut ProviderContext);
    Box::into_raw(ctx) as *mut c_void
}

/// Free signature context
#[no_mangle]
pub unsafe extern "C" fn akv_signature_freectx(vctx: *mut c_void) {
    log::trace!("akv_signature_freectx");
    if !vctx.is_null() {
        let _ctx = Box::from_raw(vctx as *mut SignatureContext);
        // Drop happens automatically
    }
}

/// Initialize for signing
#[no_mangle]
pub unsafe extern "C" fn akv_signature_sign_init(
    vctx: *mut c_void,
    vkey: *mut c_void,
    _params: *const OsslParam,
) -> c_int {
    log::trace!("akv_signature_sign_init");
    if vctx.is_null() || vkey.is_null() {
        return 0;
    }

    let ctx = &mut *(vctx as *mut SignatureContext);
    let key_ref = &*(vkey as *const AkvKey);
    
    // Clone the key into the context
    ctx.key = Some(Box::new(AkvKey {
        provctx: ctx.provctx,
        keyvault_name: key_ref.keyvault_name.clone(),
        key_name: key_ref.key_name.clone(),
        key_version: key_ref.key_version.clone(),
        public_key: key_ref.public_key.clone(),
    }));
    ctx.operation = EVP_PKEY_OP_SIGN;
    
    1
}

/// Initialize for verification
#[no_mangle]
pub unsafe extern "C" fn akv_signature_verify_init(
    vctx: *mut c_void,
    vkey: *mut c_void,
    _params: *const OsslParam,
) -> c_int {
    log::trace!("akv_signature_verify_init");
    if vctx.is_null() || vkey.is_null() {
        return 0;
    }

    let ctx = &mut *(vctx as *mut SignatureContext);
    let key_ref = &*(vkey as *const AkvKey);
    
    // Clone the key into the context
    ctx.key = Some(Box::new(AkvKey {
        provctx: ctx.provctx,
        keyvault_name: key_ref.keyvault_name.clone(),
        key_name: key_ref.key_name.clone(),
        key_version: key_ref.key_version.clone(),
        public_key: key_ref.public_key.clone(),
    }));
    ctx.operation = EVP_PKEY_OP_VERIFY;
    
    1
}

/// Sign operation (called with pre-computed digest)
#[no_mangle]
pub unsafe extern "C" fn akv_signature_sign(
    vctx: *mut c_void,
    sig: *mut c_uchar,
    siglen: *mut usize,
    sigsize: usize,
    tbs: *const c_uchar,
    tbslen: usize,
) -> c_int {
    log::trace!("akv_signature_sign sigsize={} tbslen={}", sigsize, tbslen);
    
    if vctx.is_null() || siglen.is_null() {
        return 0;
    }

    let ctx = &*(vctx as *const SignatureContext);
    let expected = ctx.expected_size();

    // If sig is null, return expected size
    if sig.is_null() {
        *siglen = expected;
        return 1;
    }

    if sigsize < expected {
        *siglen = expected;
        return 0;
    }

    if tbs.is_null() {
        return 0;
    }

    let digest = std::slice::from_raw_parts(tbs, tbslen);
    
    match ctx.sign_remote(digest) {
        Ok(signature) => {
            if signature.len() > sigsize {
                return 0;
            }
            ptr::copy_nonoverlapping(signature.as_ptr(), sig, signature.len());
            *siglen = signature.len();
            1
        }
        Err(e) => {
            log::error!("Sign failed: {}", e);
            0
        }
    }
}

/// Verify operation
#[no_mangle]
pub unsafe extern "C" fn akv_signature_verify(
    vctx: *mut c_void,
    sig: *const c_uchar,
    siglen: usize,
    tbs: *const c_uchar,
    tbslen: usize,
) -> c_int {
    log::trace!("akv_signature_verify siglen={} tbslen={}", siglen, tbslen);
    
    if vctx.is_null() || sig.is_null() || tbs.is_null() {
        return 0;
    }

    let ctx = &*(vctx as *const SignatureContext);
    let sig_slice = std::slice::from_raw_parts(sig, siglen);
    let tbs_slice = std::slice::from_raw_parts(tbs, tbslen);
    
    match ctx.verify_local(sig_slice, tbs_slice) {
        Ok(true) => 1,
        Ok(false) => 0,
        Err(e) => {
            log::error!("Verify failed: {}", e);
            0
        }
    }
}

/// Initialize digest-sign operation
#[no_mangle]
pub unsafe extern "C" fn akv_signature_digest_sign_init(
    vctx: *mut c_void,
    mdname: *const c_char,
    vkey: *mut c_void,
    _params: *const OsslParam,
) -> c_int {
    log::trace!("akv_signature_digest_sign_init");
    
    if vctx.is_null() || vkey.is_null() {
        return 0;
    }

    let ctx = &mut *(vctx as *mut SignatureContext);
    let key_ref = &*(vkey as *const AkvKey);
    
    // Clone the key
    ctx.key = Some(Box::new(AkvKey {
        provctx: ctx.provctx,
        keyvault_name: key_ref.keyvault_name.clone(),
        key_name: key_ref.key_name.clone(),
        key_version: key_ref.key_version.clone(),
        public_key: key_ref.public_key.clone(),
    }));
    ctx.operation = EVP_PKEY_OP_SIGN;

    // Set digest if provided
    if !mdname.is_null() {
        if let Ok(name) = CStr::from_ptr(mdname).to_str() {
            ctx.md_name = Some(name.to_string());
            
            // Create MD context
            match MdCtx::new() {
                Ok(mdctx) => {
                    ctx.mdctx = Some(mdctx);
                }
                Err(e) => {
                    log::error!("Failed to create MD context: {}", e);
                    return 0;
                }
            }
        }
    }

    1
}

/// Initialize digest-verify operation
#[no_mangle]
pub unsafe extern "C" fn akv_signature_digest_verify_init(
    vctx: *mut c_void,
    mdname: *const c_char,
    vkey: *mut c_void,
    _params: *const OsslParam,
) -> c_int {
    log::trace!("akv_signature_digest_verify_init");
    
    if vctx.is_null() || vkey.is_null() {
        return 0;
    }

    let ctx = &mut *(vctx as *mut SignatureContext);
    let key_ref = &*(vkey as *const AkvKey);
    
    // Clone the key
    ctx.key = Some(Box::new(AkvKey {
        provctx: ctx.provctx,
        keyvault_name: key_ref.keyvault_name.clone(),
        key_name: key_ref.key_name.clone(),
        key_version: key_ref.key_version.clone(),
        public_key: key_ref.public_key.clone(),
    }));
    ctx.operation = EVP_PKEY_OP_VERIFY;

    // Set digest if provided
    if !mdname.is_null() {
        if let Ok(name) = CStr::from_ptr(mdname).to_str() {
            ctx.md_name = Some(name.to_string());
            
            // Create MD context
            match MdCtx::new() {
                Ok(mdctx) => {
                    ctx.mdctx = Some(mdctx);
                }
                Err(e) => {
                    log::error!("Failed to create MD context: {}", e);
                    return 0;
                }
            }
        }
    }

    1
}

/// Update digest with more data
#[no_mangle]
pub unsafe extern "C" fn akv_signature_digest_update(
    vctx: *mut c_void,
    data: *const c_uchar,
    datalen: usize,
) -> c_int {
    if vctx.is_null() || data.is_null() {
        return 0;
    }

    let ctx = &mut *(vctx as *mut SignatureContext);
    
    if let Some(ref mut mdctx) = ctx.mdctx {
        let data_slice = std::slice::from_raw_parts(data, datalen);
        match mdctx.digest_update(data_slice) {
            Ok(_) => 1,
            Err(e) => {
                log::error!("Digest update failed: {}", e);
                0
            }
        }
    } else {
        log::error!("MD context not initialized");
        0
    }
}

/// Finalize digest-sign
#[no_mangle]
pub unsafe extern "C" fn akv_signature_digest_sign_final(
    vctx: *mut c_void,
    sig: *mut c_uchar,
    siglen: *mut usize,
    sigsize: usize,
) -> c_int {
    log::trace!("akv_signature_digest_sign_final sigsize={}", sigsize);
    
    if vctx.is_null() || siglen.is_null() {
        return 0;
    }

    let ctx = &mut *(vctx as *mut SignatureContext);
    let expected = ctx.expected_size();

    // If sig is null, return expected size
    if sig.is_null() {
        *siglen = expected;
        return 1;
    }

    if sigsize < expected {
        *siglen = expected;
        return 0;
    }

    // Finalize digest
    if let Some(ref mut mdctx) = ctx.mdctx {
        let mut digest = vec![0u8; 64]; // Max digest size
        match mdctx.digest_final(&mut digest) {
            Ok(len) => {
                digest.truncate(len);
                
                // Sign the digest
                match ctx.sign_remote(&digest) {
                    Ok(signature) => {
                        if signature.len() > sigsize {
                            return 0;
                        }
                        ptr::copy_nonoverlapping(signature.as_ptr(), sig, signature.len());
                        *siglen = signature.len();
                        1
                    }
                    Err(e) => {
                        log::error!("Sign failed: {}", e);
                        0
                    }
                }
            }
            Err(e) => {
                log::error!("Digest final failed: {}", e);
                0
            }
        }
    } else {
        log::error!("MD context not initialized");
        0
    }
}

/// Finalize digest-verify
#[no_mangle]
pub unsafe extern "C" fn akv_signature_digest_verify_final(
    vctx: *mut c_void,
    sig: *const c_uchar,
    siglen: usize,
) -> c_int {
    log::trace!("akv_signature_digest_verify_final siglen={}", siglen);
    
    if vctx.is_null() || sig.is_null() {
        return 0;
    }

    let ctx = &mut *(vctx as *mut SignatureContext);
    
    // Finalize digest
    if let Some(ref mut mdctx) = ctx.mdctx {
        let mut digest = vec![0u8; 64]; // Max digest size
        match mdctx.digest_final(&mut digest) {
            Ok(len) => {
                digest.truncate(len);
                
                // Verify the signature
                let sig_slice = std::slice::from_raw_parts(sig, siglen);
                match ctx.verify_local(sig_slice, &digest) {
                    Ok(true) => 1,
                    Ok(false) => 0,
                    Err(e) => {
                        log::error!("Verify failed: {}", e);
                        0
                    }
                }
            }
            Err(e) => {
                log::error!("Digest final failed: {}", e);
                0
            }
        }
    } else {
        log::error!("MD context not initialized");
        0
    }
}

/// Get context parameters
#[no_mangle]
pub unsafe extern "C" fn akv_signature_get_ctx_params(
    _vctx: *mut c_void,
    _params: *mut OsslParam,
) -> c_int {
    // No parameters to get currently
    1
}

/// Get gettable context parameters
#[no_mangle]
pub unsafe extern "C" fn akv_signature_gettable_ctx_params(
    _vctx: *mut c_void,
    _provctx: *mut c_void,
) -> *const OsslParam {
    // List of parameters that can be retrieved from signature context
    static PARAMS: [OsslParam; 6] = [
        OsslParam {
            key: b"algorithm-id\0".as_ptr() as *const c_char,
            data_type: OSSL_PARAM_OCTET_STRING,
            data: ptr::null_mut(),
            data_size: 0,
            return_size: 0,
        },
        OsslParam {
            key: b"digest\0".as_ptr() as *const c_char,
            data_type: OSSL_PARAM_UTF8_STRING,
            data: ptr::null_mut(),
            data_size: 0,
            return_size: 0,
        },
        OsslParam {
            key: b"pad-mode\0".as_ptr() as *const c_char,
            data_type: OSSL_PARAM_UTF8_STRING,
            data: ptr::null_mut(),
            data_size: 0,
            return_size: 0,
        },
        OsslParam {
            key: b"saltlen\0".as_ptr() as *const c_char,
            data_type: OSSL_PARAM_UTF8_STRING,
            data: ptr::null_mut(),
            data_size: 0,
            return_size: 0,
        },
        OsslParam {
            key: b"mgf1-digest\0".as_ptr() as *const c_char,
            data_type: OSSL_PARAM_UTF8_STRING,
            data: ptr::null_mut(),
            data_size: 0,
            return_size: 0,
        },
        OsslParam {
            key: ptr::null(),
            data_type: 0,
            data: ptr::null_mut(),
            data_size: 0,
            return_size: 0,
        },
    ];
    PARAMS.as_ptr()
}

/// Set context parameters
#[no_mangle]
pub unsafe extern "C" fn akv_signature_set_ctx_params(
    vctx: *mut c_void,
    params: *const OsslParam,
) -> c_int {
    if vctx.is_null() || params.is_null() {
        return 1;
    }

    let ctx = &mut *(vctx as *mut SignatureContext);
    let mut current = params;

    while !(*current).key.is_null() {
        let key_cstr = CStr::from_ptr((*current).key);
        if let Ok(key_str) = key_cstr.to_str() {
            match key_str {
                "digest" => {
                    if let Some(value_ptr) = OsslParam::get_utf8_string_ptr(current) {
                        if let Ok(md_name) = CStr::from_ptr(value_ptr).to_str() {
                            ctx.md_name = Some(md_name.to_string());
                        }
                    }
                }
                "pad-mode" => {
                    if let Some(padding) = OsslParam::get_int(current) {
                        ctx.padding = padding;
                    }
                }
                "mgf1-digest" => {
                    if let Some(value_ptr) = OsslParam::get_utf8_string_ptr(current) {
                        if let Ok(md_name) = CStr::from_ptr(value_ptr).to_str() {
                            ctx.mgf1_md_name = Some(md_name.to_string());
                        }
                    }
                }
                "saltlen" => {
                    if let Some(saltlen) = OsslParam::get_int(current) {
                        ctx.pss_saltlen = saltlen;
                    }
                }
                _ => {}
            }
        }
        current = current.offset(1);
    }

    1
}

/// Get settable context parameters
#[no_mangle]
pub unsafe extern "C" fn akv_signature_settable_ctx_params(
    _vctx: *mut c_void,
    _provctx: *mut c_void,
) -> *const OsslParam {
    // Same parameters can be set as can be retrieved
    akv_signature_gettable_ctx_params(_vctx, _provctx)
}

/// Duplicate signature context (DUPCTX)
#[no_mangle]
pub unsafe extern "C" fn akv_signature_dupctx(vctx: *mut c_void) -> *mut c_void {
    log::trace!("akv_signature_dupctx: vctx={:p}", vctx);
    
    if vctx.is_null() {
        log::debug!("akv_signature_dupctx -> NULL (src null)");
        return ptr::null_mut();
    }
    
    let src_ctx = &*(vctx as *const SignatureContext);
    
    // Clone the key by creating a new Box with the same contents
    // Note: This creates a shallow copy - both contexts share the same key data
    let key_clone = if let Some(ref key) = src_ctx.key {
        Some(Box::new(AkvKey {
            provctx: key.provctx,
            keyvault_name: key.keyvault_name.clone(),
            key_name: key.key_name.clone(),
            key_version: key.key_version.clone(),
            public_key: key.public_key.as_ref().map(|pk| pk.clone()),
        }))
    } else {
        None
    };
    
    let dup_ctx = Box::new(SignatureContext {
        provctx: src_ctx.provctx,
        keytype: src_ctx.keytype,
        key: key_clone,
        mdctx: None, // MD context is not duplicated
        md_name: src_ctx.md_name.clone(),
        mgf1_md_name: src_ctx.mgf1_md_name.clone(),
        padding: src_ctx.padding,
        pss_saltlen: src_ctx.pss_saltlen,
        operation: src_ctx.operation,
    });
    
    let dup_ptr = Box::into_raw(dup_ctx) as *mut c_void;
    log::debug!("akv_signature_dupctx -> {:p} from {:p}", dup_ptr, vctx);
    dup_ptr
}

/// Single-call digest and sign (DIGEST_SIGN)
#[no_mangle]
pub unsafe extern "C" fn akv_signature_digest_sign(
    vctx: *mut c_void,
    sig: *mut u8,
    siglen: *mut usize,
    sigsize: usize,
    tbs: *const u8,
    tbslen: usize,
) -> c_int {
    log::trace!(
        "akv_signature_digest_sign: vctx={:p} sig={:p} siglen={:p} sigsize={} tbslen={}",
        vctx, sig, siglen, sigsize, tbslen
    );
    
    // This is a convenience function that combines digest_init, update, and final
    // For now, we'll use the existing digest_sign_final after hashing
    if vctx.is_null() {
        return 0;
    }
    
    // Initialize digest if not already done
    if akv_signature_digest_sign_init(vctx, ptr::null(), ptr::null_mut(), ptr::null()) == 0 {
        log::error!("akv_signature_digest_sign: init failed");
        return 0;
    }
    
    // Update with data
    if akv_signature_digest_update(vctx, tbs, tbslen) == 0 {
        log::error!("akv_signature_digest_sign: update failed");
        return 0;
    }
    
    // Finalize
    akv_signature_digest_sign_final(vctx, sig, siglen, sigsize)
}

/// Get list of gettable MD context parameters (GETTABLE_CTX_MD_PARAMS)
#[no_mangle]
pub unsafe extern "C" fn akv_signature_gettable_ctx_md_params(
    _vctx: *mut c_void,
    _provctx: *mut c_void,
) -> *const OsslParam {
    log::trace!("akv_signature_gettable_ctx_md_params");
    // Return empty list - MD params are handled internally
    static EMPTY: OsslParam = OsslParam {
        key: ptr::null(),
        data_type: 0,
        data: ptr::null_mut(),
        data_size: 0,
        return_size: 0,
    };
    &EMPTY as *const OsslParam
}

/// Get list of settable MD context parameters (SETTABLE_CTX_MD_PARAMS)
#[no_mangle]
pub unsafe extern "C" fn akv_signature_settable_ctx_md_params(
    _vctx: *mut c_void,
    _provctx: *mut c_void,
) -> *const OsslParam {
    log::trace!("akv_signature_settable_ctx_md_params");
    // Return empty list - MD params are handled internally
    static EMPTY: OsslParam = OsslParam {
        key: ptr::null(),
        data_type: 0,
        data: ptr::null_mut(),
        data_size: 0,
        return_size: 0,
    };
    &EMPTY as *const OsslParam
}

/// Get MD context parameters (GET_CTX_MD_PARAMS)
#[no_mangle]
pub unsafe extern "C" fn akv_signature_get_ctx_md_params(
    _vctx: *mut c_void,
    _params: *mut OsslParam,
) -> c_int {
    log::trace!("akv_signature_get_ctx_md_params");
    // Nothing to get currently
    1
}

/// Set MD context parameters (SET_CTX_MD_PARAMS)
#[no_mangle]
pub unsafe extern "C" fn akv_signature_set_ctx_md_params(
    _vctx: *mut c_void,
    _params: *const OsslParam,
) -> c_int {
    log::trace!("akv_signature_set_ctx_md_params");
    // Nothing to set currently
    1
}
