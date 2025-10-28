/* Copyright (c) Microsoft Corporation.
   Licensed under the MIT License. */

use crate::auth::AccessToken;
use crate::http_client::AkvHttpClient;
use crate::openssl_ffi;
use crate::ossl_param::{OsslParam, OSSL_PARAM_UTF8_STRING, OSSL_PARAM_OCTET_STRING};
use crate::provider::{AkvKey, ProviderContext};
use openssl::bn::BigNum;
use openssl::ecdsa::EcdsaSig;
use openssl::hash::{MessageDigest, Hasher};
use foreign_types::ForeignTypeRef;
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

/// ASN.1 types
const V_ASN1_NULL: c_int = 5;

// OpenSSL FFI declarations for X509_ALGOR
#[allow(non_camel_case_types)]
#[repr(C)]
struct X509_ALGOR {
    _opaque: [u8; 0],
}

#[allow(non_camel_case_types)]
#[repr(C)]
struct ASN1_OBJECT {
    _opaque: [u8; 0],
}

extern "C" {
    fn X509_ALGOR_new() -> *mut X509_ALGOR;
    fn X509_ALGOR_free(algor: *mut X509_ALGOR);
    fn X509_ALGOR_set0(
        algor: *mut X509_ALGOR,
        aobj: *mut ASN1_OBJECT,
        ptype: c_int,
        pval: *mut c_void,
    ) -> c_int;
    fn i2d_X509_ALGOR(algor: *const X509_ALGOR, pp: *mut *mut c_uchar) -> c_int;
    fn OBJ_nid2obj(n: c_int) -> *mut ASN1_OBJECT;
    fn OSSL_PARAM_set_octet_string(p: *mut OsslParam, val: *const c_void, len: usize) -> c_int;
}

/// NIDs for signature algorithms
#[allow(non_upper_case_globals)]
const NID_sha256WithRSAEncryption: c_int = 668;
#[allow(non_upper_case_globals)]
const NID_sha384WithRSAEncryption: c_int = 669;
#[allow(non_upper_case_globals)]
const NID_sha512WithRSAEncryption: c_int = 670;
#[allow(non_upper_case_globals)]
const NID_ecdsa_with_SHA256: c_int = 794;
#[allow(non_upper_case_globals)]
const NID_ecdsa_with_SHA384: c_int = 795;
#[allow(non_upper_case_globals)]
const NID_ecdsa_with_SHA512: c_int = 796;
#[allow(non_upper_case_globals)]
const NID_rsassaPss: c_int = 912;

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
    hasher: Option<Hasher>,
    md_name: Option<String>,
    mgf1_md_name: Option<String>,
    operation: c_int,
    padding: c_int,
    pss_saltlen: c_int,
    aid: Option<Vec<u8>>,  // DER-encoded algorithm identifier for X.509 operations
}

impl SignatureContext {
    fn new_rsa(provctx: *mut ProviderContext) -> Box<Self> {
        log::trace!("SignatureContext::new_rsa");
        Box::new(SignatureContext {
            provctx,
            keytype: KeyType::Rsa,
            key: None,
            hasher: None,
            md_name: None,
            mgf1_md_name: None,
            operation: 0,
            padding: RSA_PKCS1_PADDING,
            pss_saltlen: RSA_PSS_SALTLEN_DIGEST,
            aid: None,
        })
    }

    fn new_ec(provctx: *mut ProviderContext) -> Box<Self> {
        log::trace!("SignatureContext::new_ec");
        Box::new(SignatureContext {
            provctx,
            keytype: KeyType::Ec,
            key: None,
            hasher: None,
            md_name: None,
            mgf1_md_name: None,
            operation: 0,
            padding: 0,
            pss_saltlen: 0,
            aid: None,
        })
    }

    /// Compute DER-encoded algorithm identifier for X.509 operations
    /// Based on key type, digest, and padding mode
    fn compute_algorithm_id(&mut self) -> bool {
        let md_name = match &self.md_name {
            Some(name) => name.as_str(),
            None => {
                log::debug!("compute_algorithm_id: no digest set");
                return false;
            }
        };

        // Determine the signature algorithm NID
        let sig_nid = match self.keytype {
            KeyType::Rsa => {
                if self.padding == RSA_PSS_PADDING {
                    // For RSA-PSS, use rsassaPss NID (TODO: encode PSS parameters properly)
                    log::debug!("compute_algorithm_id: RSA-PSS not fully implemented, using basic NID");
                    NID_rsassaPss
                } else {
                    // For PKCS#1 v1.5, combine digest + RSA encryption
                    match md_name {
                        "sha256" | "SHA256" | "SHA2-256" => NID_sha256WithRSAEncryption,
                        "sha384" | "SHA384" | "SHA2-384" => NID_sha384WithRSAEncryption,
                        "sha512" | "SHA512" | "SHA2-512" => NID_sha512WithRSAEncryption,
                        _ => {
                            log::error!("compute_algorithm_id: unsupported RSA digest {}", md_name);
                            return false;
                        }
                    }
                }
            }
            KeyType::Ec => {
                // For ECDSA, combine digest + ECDSA
                match md_name {
                    "sha256" | "SHA256" | "SHA2-256" => NID_ecdsa_with_SHA256,
                    "sha384" | "SHA384" | "SHA2-384" => NID_ecdsa_with_SHA384,
                    "sha512" | "SHA512" | "SHA2-512" => NID_ecdsa_with_SHA512,
                    _ => {
                        log::error!("compute_algorithm_id: unsupported ECDSA digest {}", md_name);
                        return false;
                    }
                }
            }
        };

        unsafe {
            // Create X509_ALGOR structure
            let algor = X509_ALGOR_new();
            if algor.is_null() {
                log::error!("compute_algorithm_id: X509_ALGOR_new failed");
                return false;
            }

            // Set algorithm OID
            if X509_ALGOR_set0(algor, OBJ_nid2obj(sig_nid), V_ASN1_NULL, ptr::null_mut()) != 1 {
                log::error!("compute_algorithm_id: X509_ALGOR_set0 failed");
                X509_ALGOR_free(algor);
                return false;
            }

            // Get DER encoding size
            let der_len = i2d_X509_ALGOR(algor, ptr::null_mut());
            if der_len <= 0 {
                log::error!("compute_algorithm_id: i2d_X509_ALGOR size failed");
                X509_ALGOR_free(algor);
                return false;
            }

            // Allocate Vec for DER encoding
            let mut der_vec: Vec<u8> = vec![0u8; der_len as usize];
            let mut der_ptr = der_vec.as_mut_ptr();
            
            // Encode to DER
            let actual_len = i2d_X509_ALGOR(algor, &mut der_ptr);
            if actual_len != der_len {
                log::error!("compute_algorithm_id: i2d_X509_ALGOR encode failed");
                X509_ALGOR_free(algor);
                return false;
            }

            // Free OpenSSL structure
            X509_ALGOR_free(algor);

            // Store in context
            self.aid = Some(der_vec);

            log::debug!(
                "compute_algorithm_id: generated {} bytes for sig_nid={} (md={}, keytype={:?}, padding={})",
                der_len, sig_nid, md_name, self.keytype, self.padding
            );

            true
        }
    }

    /// Get the Azure algorithm name based on context
    fn get_algorithm(&self) -> Option<&'static str> {
        let md_name = self.md_name.as_deref()?;

        match self.keytype {
            KeyType::Rsa => {
                if self.padding == RSA_PSS_PADDING {
                    // RSA-PSS
                    match md_name {
                        "sha256" | "SHA256" | "SHA2-256" => Some("PS256"),
                        "sha384" | "SHA384" | "SHA2-384" => Some("PS384"),
                        "sha512" | "SHA512" | "SHA2-512" => Some("PS512"),
                        _ => None,
                    }
                } else {
                    // RSA PKCS#1 v1.5
                    match md_name {
                        "sha256" | "SHA256" | "SHA2-256" => Some("RS256"),
                        "sha384" | "SHA384" | "SHA2-384" => Some("RS384"),
                        "sha512" | "SHA512" | "SHA2-512" => Some("RS512"),
                        _ => None,
                    }
                }
            }
            KeyType::Ec => {
                // ECDSA
                match md_name {
                    "sha256" | "SHA256" | "SHA2-256" => Some("ES256"),
                    "sha384" | "SHA384" | "SHA2-384" => Some("ES384"),
                    "sha512" | "SHA512" | "SHA2-512" => Some("ES512"),
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

        let md = match &self.md_name {
            Some(md_name) => MessageDigest::from_name(md_name)
                .or_else(|| MessageDigest::from_name(&md_name.to_lowercase()))
                .ok_or_else(|| format!("Unsupported digest: {}", md_name))?,
            None => match tbs.len() {
                32 => MessageDigest::sha256(),
                48 => MessageDigest::sha384(),
                64 => MessageDigest::sha512(),
                _ => {
                    return Err(format!(
                        "Unable to infer digest algorithm for length {}",
                        tbs.len()
                    ))
                }
            },
        };

        let md_label = self
            .md_name
            .as_deref()
            .unwrap_or(match tbs.len() {
                32 => "sha256",
                48 => "sha384",
                64 => "sha512",
                _ => "<unknown>",
            });

        log::debug!(
            "verify_local: keytype={:?} padding={} sig_len={} digest_len={} md={}",
            self.keytype,
            self.padding,
            sig.len(),
            tbs.len(),
            md_label
        );

    let pkey_ptr = pkey.as_ref().as_ptr() as *mut openssl_ffi::EVP_PKEY;
    let verify_ctx = unsafe {
            openssl_ffi::EVP_PKEY_CTX_new_from_pkey(ptr::null_mut(), pkey_ptr, ptr::null())
        };

        if verify_ctx.is_null() {
            return Err("EVP_PKEY_CTX_new_from_pkey failed".to_string());
        }

        let mut result = unsafe { openssl_ffi::EVP_PKEY_verify_init(verify_ctx) };
        if result <= 0 {
            unsafe { openssl_ffi::EVP_PKEY_CTX_free(verify_ctx) };
            openssl_ffi::log_openssl_errors("EVP_PKEY_verify_init");
            return Err("EVP_PKEY_verify_init failed".to_string());
        }

        result = unsafe { openssl_ffi::EVP_PKEY_CTX_set_signature_md(verify_ctx, md.as_ptr()) };
        if result <= 0 {
            unsafe { openssl_ffi::EVP_PKEY_CTX_free(verify_ctx) };
            openssl_ffi::log_openssl_errors("EVP_PKEY_CTX_set_signature_md");
            return Err("Failed to set signature digest".to_string());
        }

        if matches!(self.keytype, KeyType::Rsa) {
            result = unsafe { openssl_ffi::EVP_PKEY_CTX_set_rsa_padding(verify_ctx, self.padding) };
            if result <= 0 {
                unsafe { openssl_ffi::EVP_PKEY_CTX_free(verify_ctx) };
                openssl_ffi::log_openssl_errors("EVP_PKEY_CTX_set_rsa_padding");
                return Err("Failed to set RSA padding".to_string());
            }

            if self.padding == RSA_PSS_PADDING {
                let saltlen = if self.pss_saltlen >= 0 {
                    self.pss_saltlen
                } else {
                    md.size() as c_int
                };

                result = unsafe { openssl_ffi::EVP_PKEY_CTX_set_rsa_pss_saltlen(verify_ctx, saltlen) };
                if result <= 0 {
                    unsafe { openssl_ffi::EVP_PKEY_CTX_free(verify_ctx) };
                    openssl_ffi::log_openssl_errors("EVP_PKEY_CTX_set_rsa_pss_saltlen");
                    return Err("Failed to set RSA-PSS salt length".to_string());
                }

                if let Some(mgf1_name) = &self.mgf1_md_name {
                    let mgf1_md = MessageDigest::from_name(mgf1_name)
                        .or_else(|| MessageDigest::from_name(&mgf1_name.to_lowercase()))
                        .ok_or_else(|| format!("Unsupported MGF1 digest: {}", mgf1_name))?;

                    result = unsafe {
                        openssl_ffi::EVP_PKEY_CTX_set_rsa_mgf1_md(verify_ctx, mgf1_md.as_ptr())
                    };
                    if result <= 0 {
                        unsafe { openssl_ffi::EVP_PKEY_CTX_free(verify_ctx) };
                        openssl_ffi::log_openssl_errors("EVP_PKEY_CTX_set_rsa_mgf1_md");
                        return Err("Failed to set RSA-PSS MGF1 digest".to_string());
                    }
                }
            }
        }

        result = unsafe {
            openssl_ffi::EVP_PKEY_verify(
                verify_ctx,
                sig.as_ptr(),
                sig.len(),
                tbs.as_ptr(),
                tbs.len(),
            )
        };

        unsafe { openssl_ffi::EVP_PKEY_CTX_free(verify_ctx) };

        if result < 0 {
            openssl_ffi::log_openssl_errors("EVP_PKEY_verify");
            return Err("Verification failed".to_string());
        }

        log::debug!("verify_local: EVP_PKEY_verify -> {}", result);

        Ok(result == 1)
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
    log::trace!("akv_signature_digest_sign_init vctx={:p} mdname={:p} vkey={:p}", vctx, mdname, vkey);
    
    if vctx.is_null() {
        log::error!("akv_signature_digest_sign_init: vctx is null");
        return 0;
    }
    
    if vkey.is_null() {
        log::error!("akv_signature_digest_sign_init: vkey is null");
        return 0;
    }

    log::debug!("akv_signature_digest_sign_init: casting pointers");
    let ctx = &mut *(vctx as *mut SignatureContext);
    let key_ref = &*(vkey as *const AkvKey);
    
    log::debug!("akv_signature_digest_sign_init: cloning key (vault={}, name={})", 
        key_ref.keyvault_name.as_deref().unwrap_or("<none>"),
        key_ref.key_name.as_deref().unwrap_or("<none>"));
    
    // Clone the key
    ctx.key = Some(Box::new(AkvKey {
        provctx: ctx.provctx,
        keyvault_name: key_ref.keyvault_name.clone(),
        key_name: key_ref.key_name.clone(),
        key_version: key_ref.key_version.clone(),
        public_key: key_ref.public_key.clone(),
    }));
    
    log::debug!("akv_signature_digest_sign_init: key cloned successfully");
    ctx.operation = EVP_PKEY_OP_SIGN;

    // Set digest if provided
    if !mdname.is_null() {
        if let Ok(name) = CStr::from_ptr(mdname).to_str() {
            log::debug!("akv_signature_digest_sign_init: digest name={}", name);
            ctx.md_name = Some(name.to_string());
            
            // Compute algorithm identifier for X.509 operations
            ctx.compute_algorithm_id();
            
            // Create and initialize hasher with the digest algorithm
            log::debug!("akv_signature_digest_sign_init: creating hasher for {}", name);
            let md = match MessageDigest::from_name(name) {
                Some(md) => md,
                None => {
                    log::error!("Unknown digest algorithm: {}", name);
                    return 0;
                }
            };
            
            match Hasher::new(md) {
                Ok(hasher) => {
                    ctx.hasher = Some(hasher);
                    log::debug!("akv_signature_digest_sign_init: hasher created and initialized");
                }
                Err(e) => {
                    log::error!("Failed to create hasher: {}", e);
                    return 0;
                }
            }
        }
    } else {
        log::debug!("akv_signature_digest_sign_init: no digest name provided");
    }

    log::info!("akv_signature_digest_sign_init -> 1 (success)");
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
            
            // Compute algorithm identifier for X.509 operations
            ctx.compute_algorithm_id();
            
            // Create and initialize hasher with the digest algorithm
            let md = match MessageDigest::from_name(name) {
                Some(md) => md,
                None => {
                    log::error!("Unknown digest algorithm: {}", name);
                    return 0;
                }
            };
            
            match Hasher::new(md) {
                Ok(hasher) => {
                    ctx.hasher = Some(hasher);
                }
                Err(e) => {
                    log::error!("Failed to create hasher: {}", e);
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
    log::trace!("akv_signature_digest_update vctx={:p} datalen={}", vctx, datalen);
    
    if vctx.is_null() || data.is_null() {
        log::error!("akv_signature_digest_update: null pointer");
        return 0;
    }

    let ctx = &mut *(vctx as *mut SignatureContext);
    
    if let Some(ref mut hasher) = ctx.hasher {
        let data_slice = std::slice::from_raw_parts(data, datalen);
        match hasher.update(data_slice) {
            Ok(_) => {
                log::debug!("akv_signature_digest_update -> 1 (success, {} bytes)", datalen);
                1
            }
            Err(e) => {
                log::error!("Digest update failed: {}", e);
                0
            }
        }
    } else {
        log::error!("Hasher not initialized");
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
    if let Some(ref mut hasher) = ctx.hasher {
        match hasher.finish() {
            Ok(digest) => {
                log::debug!("Digest finalized: {} bytes", digest.len());
                
                // Sign the digest
                match ctx.sign_remote(&digest) {
                    Ok(signature) => {
                        if signature.len() > sigsize {
                            return 0;
                        }
                        ptr::copy_nonoverlapping(signature.as_ptr(), sig, signature.len());
                        *siglen = signature.len();
                        log::info!("akv_signature_digest_sign_final -> 1 (signature {} bytes)", signature.len());
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
        log::error!("Hasher not initialized");
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
    if let Some(ref mut hasher) = ctx.hasher {
        match hasher.finish() {
            Ok(digest) => {
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
        log::error!("Hasher not initialized");
        0
    }
}

/// Get context parameters
#[no_mangle]
pub unsafe extern "C" fn akv_signature_get_ctx_params(
    vctx: *mut c_void,
    params: *mut OsslParam,
) -> c_int {
    if vctx.is_null() || params.is_null() {
        return 1; // Nothing to get
    }

    let ctx = &*(vctx as *const SignatureContext);

    // Log all requested parameters
    let mut current = params;
    while !(*current).key.is_null() {
        if let Ok(key) = CStr::from_ptr((*current).key).to_str() {
            log::trace!("akv_signature_get_ctx_params requested: {}", key);
        }
        current = current.add(1);
    }

    // Find and handle ALGORITHM_ID parameter
    let aid_key = b"algorithm-id\0".as_ptr() as *const c_char;
    let aid_param = OsslParam::locate(params, aid_key);
    if !aid_param.is_null() {
        if let Some(ref aid_vec) = ctx.aid {
            log::debug!("akv_signature_get_ctx_params returning ALGORITHM_ID ({} bytes)", aid_vec.len());
            if OSSL_PARAM_set_octet_string(aid_param, aid_vec.as_ptr() as *const c_void, aid_vec.len()) != 1 {
                log::error!("akv_signature_get_ctx_params failed to set ALGORITHM_ID");
                return 0;
            }
        } else {
            log::debug!("akv_signature_get_ctx_params ALGORITHM_ID requested but not available");
            // Don't fail - just skip setting it
        }
    }

    // Find and handle DIGEST parameter
    let digest_key = b"digest\0".as_ptr() as *const c_char;
    let digest_param = OsslParam::locate(params, digest_key);
    if !digest_param.is_null() {
        let mdname = ctx.md_name.as_deref().unwrap_or("");
        let mdname_cstr = std::ffi::CString::new(mdname).unwrap();
        if !(*digest_param).set_utf8_ptr(mdname_cstr.as_ptr()) {
            log::error!("akv_signature_get_ctx_params failed to set digest");
            return 0;
        }
        // Keep the CString alive by leaking it (OpenSSL expects the pointer to remain valid)
        std::mem::forget(mdname_cstr);
    }

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
    log::trace!("akv_signature_set_ctx_params vctx={:p} params={:p}", vctx, params);
    
    if vctx.is_null() || params.is_null() {
        log::debug!("akv_signature_set_ctx_params -> 1 (null params, no-op)");
        return 1;
    }

    let ctx = &mut *(vctx as *mut SignatureContext);
    let mut current = params;
    let mut param_count = 0;

    while !(*current).key.is_null() {
        let key_cstr = CStr::from_ptr((*current).key);
        if let Ok(key_str) = key_cstr.to_str() {
            log::debug!("akv_signature_set_ctx_params: processing param '{}' (data_type={})", key_str, (*current).data_type);
            match key_str {
                "digest" => {
                    if let Some(value_ptr) = OsslParam::get_utf8_string_ptr(current) {
                        if let Ok(md_name) = CStr::from_ptr(value_ptr).to_str() {
                            log::debug!("  Setting digest={}", md_name);
                            ctx.md_name = Some(md_name.to_string());
                            // Compute algorithm identifier when digest changes
                            ctx.compute_algorithm_id();
                            param_count += 1;
                        }
                    }
                }
                "pad-mode" => {
                    // Try as integer first, then as string
                    if let Some(padding) = OsslParam::get_int(current) {
                        log::debug!("  Setting pad-mode={} (from int)", padding);
                        ctx.padding = padding;
                        param_count += 1;
                    } else if let Some(value_ptr) = OsslParam::get_utf8_string_ptr(current) {
                        if let Ok(value_str) = CStr::from_ptr(value_ptr).to_str() {
                            // Parse string padding mode (e.g., "pss", "pkcs1")
                            let padding = match value_str.to_lowercase().as_str() {
                                "pss" => RSA_PSS_PADDING,
                                "pkcs1" | "pkcs1_padding" => RSA_PKCS1_PADDING,
                                _ => {
                                    // Try to parse as number
                                    value_str.parse::<c_int>().unwrap_or(RSA_PKCS1_PADDING)
                                }
                            };
                            log::debug!("  Setting pad-mode={} (from string '{}')", padding, value_str);
                            ctx.padding = padding;
                            param_count += 1;
                        }
                    }
                }
                "mgf1-digest" => {
                    if let Some(value_ptr) = OsslParam::get_utf8_string_ptr(current) {
                        if let Ok(md_name) = CStr::from_ptr(value_ptr).to_str() {
                            log::debug!("  Setting mgf1-digest={}", md_name);
                            ctx.mgf1_md_name = Some(md_name.to_string());
                            param_count += 1;
                        }
                    }
                }
                "saltlen" => {
                    // Try as integer first, then as string
                    if let Some(saltlen) = OsslParam::get_int(current) {
                        log::debug!("  Setting saltlen={} (from int)", saltlen);
                        ctx.pss_saltlen = saltlen;
                        param_count += 1;
                    } else if let Some(value_ptr) = OsslParam::get_utf8_string_ptr(current) {
                        if let Ok(value_str) = CStr::from_ptr(value_ptr).to_str() {
                            // Parse string saltlen (e.g., "digest", "auto", "32")
                            let saltlen = match value_str.to_lowercase().as_str() {
                                "digest" => RSA_PSS_SALTLEN_DIGEST,
                                "auto" | "max" => -2, // RSA_PSS_SALTLEN_AUTO
                                _ => {
                                    // Try to parse as number
                                    value_str.parse::<c_int>().unwrap_or(RSA_PSS_SALTLEN_DIGEST)
                                }
                            };
                            log::debug!("  Setting saltlen={} (from string '{}')", saltlen, value_str);
                            ctx.pss_saltlen = saltlen;
                            param_count += 1;
                        }
                    }
                }
                _ => {
                    log::debug!("  Ignoring unknown param '{}'", key_str);
                }
            }
        }
        current = current.offset(1);
    }

    log::info!("akv_signature_set_ctx_params -> 1 (processed {} params)", param_count);
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
    
    // Try to duplicate the hasher
    let hasher_clone = if let Some(ref md_name) = src_ctx.md_name {
        if let Some(md) = MessageDigest::from_name(md_name) {
            match Hasher::new(md) {
                Ok(hasher) => {
                    log::debug!("Created new hasher for duplicated context");
                    Some(hasher)
                }
                Err(e) => {
                    log::warn!("Failed to create hasher in dupctx: {}", e);
                    None
                }
            }
        } else {
            log::warn!("Unknown digest {} in dupctx", md_name);
            None
        }
    } else {
        None
    };
    
    let dup_ctx = Box::new(SignatureContext {
        provctx: src_ctx.provctx,
        keytype: src_ctx.keytype,
        key: key_clone,
        hasher: hasher_clone,
        md_name: src_ctx.md_name.clone(),
        mgf1_md_name: src_ctx.mgf1_md_name.clone(),
        padding: src_ctx.padding,
        pss_saltlen: src_ctx.pss_saltlen,
        operation: src_ctx.operation,
        aid: src_ctx.aid.clone(),
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
    
    if vctx.is_null() {
        return 0;
    }
    
    let ctx = &mut *(vctx as *mut SignatureContext);
    
    // Check if digest_sign_init was already called (for X.509 operations)
    if ctx.hasher.is_some() && ctx.md_name.is_some() {
        log::trace!("akv_signature_digest_sign: using pre-initialized digest context");
        
        // For size query, just return expected size
        if sig.is_null() {
            let expected = ctx.expected_size();
            if !siglen.is_null() {
                *siglen = expected;
            }
            return 1;
        }
        
        // For actual signing, create a FRESH hasher to avoid any state issues
        let md_name = ctx.md_name.as_ref().unwrap();
        let md = match MessageDigest::from_name(md_name) {
            Some(md) => md,
            None => {
                log::error!("Unknown digest algorithm: {}", md_name);
                return 0;
            }
        };
        
        let mut fresh_hasher = match Hasher::new(md) {
            Ok(h) => h,
            Err(e) => {
                log::error!("Failed to create fresh hasher: {}", e);
                return 0;
            }
        };
        
        // Hash the TBS data
        if fresh_hasher.update(std::slice::from_raw_parts(tbs, tbslen)).is_err() {
            log::error!("akv_signature_digest_sign: hasher update failed");
            return 0;
        }
        
        // Finalize and sign
        let digest = match fresh_hasher.finish() {
            Ok(d) => d,
            Err(e) => {
                log::error!("Digest final failed: {}", e);
                return 0;
            }
        };
        
        log::debug!("Digest finalized: {} bytes", digest.len());
        
        // Sign the digest
        match ctx.sign_remote(&digest) {
            Ok(signature) => {
                let expected = ctx.expected_size();
                if sigsize < expected {
                    *siglen = expected;
                    return 0;
                }
                if signature.len() > sigsize {
                    return 0;
                }
                ptr::copy_nonoverlapping(signature.as_ptr(), sig, signature.len());
                *siglen = signature.len();
                log::info!("akv_signature_digest_sign -> 1 (signature {} bytes)", signature.len());
                return 1;
            }
            Err(e) => {
                log::error!("Sign failed: {}", e);
                return 0;
            }
        }
    }
    
    // Otherwise, this is a standalone digest_sign call - do the full operation
    log::trace!("akv_signature_digest_sign: standalone operation (no pre-init)");
    
    // Initialize digest if not already done
    if akv_signature_digest_sign_init(vctx, ptr::null(), ptr::null_mut(), ptr::null()) == 0 {
        log::error!("akv_signature_digest_sign: init failed");
        return 0;
    }
    
    // Update with data (if not a size query)
    if !sig.is_null() {
        if akv_signature_digest_update(vctx, tbs, tbslen) == 0 {
            log::error!("akv_signature_digest_sign: update failed");
            return 0;
        }
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
