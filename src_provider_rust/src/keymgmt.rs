// Key management functionality
// Corresponds to akv_keymgmt.c

use crate::openssl_ffi;
use crate::ossl_param::OsslParam;
use crate::provider::{AkvAesKey, AkvKey, ProviderContext};
use openssl::pkey::PKey;
use std::ffi::{CStr, CString};
use std::os::raw::{c_char, c_int, c_void};
use std::ptr;

// OpenSSL key selection flags
pub const OSSL_KEYMGMT_SELECT_PRIVATE_KEY: c_int = 0x01;
pub const OSSL_KEYMGMT_SELECT_PUBLIC_KEY: c_int = 0x02;
pub const OSSL_KEYMGMT_SELECT_OTHER_PARAMETERS: c_int = 0x80;

// OpenSSL operation IDs (must match dispatch.rs)
pub const OSSL_OP_SIGNATURE: c_int = 12;
pub const OSSL_OP_ASYM_CIPHER: c_int = 13;

// Common OSSL parameter names used during export
const OSSL_PKEY_PARAM_BITS: &[u8] = b"bits\0";
const OSSL_PKEY_PARAM_SECURITY_BITS: &[u8] = b"security-bits\0";
const OSSL_PKEY_PARAM_MAX_SIZE: &[u8] = b"max-size\0";
const OSSL_PKEY_PARAM_DEFAULT_DIGEST: &[u8] = b"default-digest\0";
const OSSL_PKEY_PARAM_MANDATORY_DIGEST: &[u8] = b"mandatory-digest\0";
const OSSL_PKEY_PARAM_RSA_N: &[u8] = b"n\0";
const OSSL_PKEY_PARAM_RSA_E: &[u8] = b"e\0";
const OSSL_PKEY_PARAM_GROUP_NAME: &[u8] = b"group\0";
const OSSL_PKEY_PARAM_PUB_KEY: &[u8] = b"pub\0";
const OSSL_PKEY_PARAM_EC_PUB_X: &[u8] = b"qx\0";
const OSSL_PKEY_PARAM_EC_PUB_Y: &[u8] = b"qy\0";
const OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY: &[u8] = b"encoded-pub-key\0";

// Static gettable parameter descriptors for RSA
static RSA_GETTABLE_PARAMS: [OsslParam; 8] = [
    OsslParam {
        key: OSSL_PKEY_PARAM_BITS.as_ptr() as *const c_char,
        data_type: crate::ossl_param::OSSL_PARAM_INTEGER,
        data: ptr::null_mut(),
        data_size: 0,
        return_size: 0,
    },
    OsslParam {
        key: OSSL_PKEY_PARAM_SECURITY_BITS.as_ptr() as *const c_char,
        data_type: crate::ossl_param::OSSL_PARAM_INTEGER,
        data: ptr::null_mut(),
        data_size: 0,
        return_size: 0,
    },
    OsslParam {
        key: OSSL_PKEY_PARAM_MAX_SIZE.as_ptr() as *const c_char,
        data_type: crate::ossl_param::OSSL_PARAM_INTEGER,
        data: ptr::null_mut(),
        data_size: 0,
        return_size: 0,
    },
    OsslParam {
        key: OSSL_PKEY_PARAM_DEFAULT_DIGEST.as_ptr() as *const c_char,
        data_type: crate::ossl_param::OSSL_PARAM_UTF8_STRING,
        data: ptr::null_mut(),
        data_size: 0,
        return_size: 0,
    },
    OsslParam {
        key: OSSL_PKEY_PARAM_MANDATORY_DIGEST.as_ptr() as *const c_char,
        data_type: crate::ossl_param::OSSL_PARAM_UTF8_STRING,
        data: ptr::null_mut(),
        data_size: 0,
        return_size: 0,
    },
    OsslParam {
        key: OSSL_PKEY_PARAM_RSA_N.as_ptr() as *const c_char,
        data_type: crate::ossl_param::OSSL_PARAM_UNSIGNED_INTEGER,
        data: ptr::null_mut(),
        data_size: 0,
        return_size: 0,
    },
    OsslParam {
        key: OSSL_PKEY_PARAM_RSA_E.as_ptr() as *const c_char,
        data_type: crate::ossl_param::OSSL_PARAM_UNSIGNED_INTEGER,
        data: ptr::null_mut(),
        data_size: 0,
        return_size: 0,
    },
    OsslParam::end(),
];

// Static gettable parameter descriptors for EC
static EC_GETTABLE_PARAMS: [OsslParam; 10] = [
    OsslParam {
        key: OSSL_PKEY_PARAM_GROUP_NAME.as_ptr() as *const c_char,
        data_type: crate::ossl_param::OSSL_PARAM_UTF8_STRING,
        data: ptr::null_mut(),
        data_size: 0,
        return_size: 0,
    },
    OsslParam {
        key: OSSL_PKEY_PARAM_BITS.as_ptr() as *const c_char,
        data_type: crate::ossl_param::OSSL_PARAM_INTEGER,
        data: ptr::null_mut(),
        data_size: 0,
        return_size: 0,
    },
    OsslParam {
        key: OSSL_PKEY_PARAM_SECURITY_BITS.as_ptr() as *const c_char,
        data_type: crate::ossl_param::OSSL_PARAM_INTEGER,
        data: ptr::null_mut(),
        data_size: 0,
        return_size: 0,
    },
    OsslParam {
        key: OSSL_PKEY_PARAM_MAX_SIZE.as_ptr() as *const c_char,
        data_type: crate::ossl_param::OSSL_PARAM_INTEGER,
        data: ptr::null_mut(),
        data_size: 0,
        return_size: 0,
    },
    OsslParam {
        key: OSSL_PKEY_PARAM_MANDATORY_DIGEST.as_ptr() as *const c_char,
        data_type: crate::ossl_param::OSSL_PARAM_UTF8_STRING,
        data: ptr::null_mut(),
        data_size: 0,
        return_size: 0,
    },
    OsslParam {
        key: OSSL_PKEY_PARAM_PUB_KEY.as_ptr() as *const c_char,
        data_type: crate::ossl_param::OSSL_PARAM_OCTET_STRING,
        data: ptr::null_mut(),
        data_size: 0,
        return_size: 0,
    },
    OsslParam {
        key: OSSL_PKEY_PARAM_EC_PUB_X.as_ptr() as *const c_char,
        data_type: crate::ossl_param::OSSL_PARAM_UNSIGNED_INTEGER,
        data: ptr::null_mut(),
        data_size: 0,
        return_size: 0,
    },
    OsslParam {
        key: OSSL_PKEY_PARAM_EC_PUB_Y.as_ptr() as *const c_char,
        data_type: crate::ossl_param::OSSL_PARAM_UNSIGNED_INTEGER,
        data: ptr::null_mut(),
        data_size: 0,
        return_size: 0,
    },
    OsslParam {
        key: OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY.as_ptr() as *const c_char,
        data_type: crate::ossl_param::OSSL_PARAM_OCTET_STRING,
        data: ptr::null_mut(),
        data_size: 0,
        return_size: 0,
    },
    OsslParam::end(),
];

// Static export type descriptors for RSA (advertised via export_types callbacks)
static RSA_EXPORT_TYPES: [OsslParam; 3] = [
    OsslParam {
        key: OSSL_PKEY_PARAM_RSA_N.as_ptr() as *const c_char,
        data_type: crate::ossl_param::OSSL_PARAM_UNSIGNED_INTEGER,
        data: ptr::null_mut(),
        data_size: 0,
        return_size: 0,
    },
    OsslParam {
        key: OSSL_PKEY_PARAM_RSA_E.as_ptr() as *const c_char,
        data_type: crate::ossl_param::OSSL_PARAM_UNSIGNED_INTEGER,
        data: ptr::null_mut(),
        data_size: 0,
        return_size: 0,
    },
    OsslParam::end(),
];

// Static export type descriptors for EC
static EC_EXPORT_TYPES: [OsslParam; 4] = [
    OsslParam {
        key: OSSL_PKEY_PARAM_EC_PUB_X.as_ptr() as *const c_char,
        data_type: crate::ossl_param::OSSL_PARAM_UNSIGNED_INTEGER,
        data: ptr::null_mut(),
        data_size: 0,
        return_size: 0,
    },
    OsslParam {
        key: OSSL_PKEY_PARAM_EC_PUB_Y.as_ptr() as *const c_char,
        data_type: crate::ossl_param::OSSL_PARAM_UNSIGNED_INTEGER,
        data: ptr::null_mut(),
        data_size: 0,
        return_size: 0,
    },
    OsslParam {
        key: OSSL_PKEY_PARAM_GROUP_NAME.as_ptr() as *const c_char,
        data_type: crate::ossl_param::OSSL_PARAM_UTF8_STRING,
        data: ptr::null_mut(),
        data_size: 0,
        return_size: 0,
    },
    OsslParam::end(),
];

// Static gettable parameter descriptors for AES
static AES_GETTABLE_PARAMS: [OsslParam; 4] = [
    OsslParam {
        key: OSSL_PKEY_PARAM_BITS.as_ptr() as *const c_char,
        data_type: crate::ossl_param::OSSL_PARAM_INTEGER,
        data: ptr::null_mut(),
        data_size: 0,
        return_size: 0,
    },
    OsslParam {
        key: OSSL_PKEY_PARAM_SECURITY_BITS.as_ptr() as *const c_char,
        data_type: crate::ossl_param::OSSL_PARAM_INTEGER,
        data: ptr::null_mut(),
        data_size: 0,
        return_size: 0,
    },
    OsslParam {
        key: OSSL_PKEY_PARAM_MAX_SIZE.as_ptr() as *const c_char,
        data_type: crate::ossl_param::OSSL_PARAM_INTEGER,
        data: ptr::null_mut(),
        data_size: 0,
        return_size: 0,
    },
    OsslParam::end(),
];

// Static import type descriptors for AES
static AES_IMPORT_TYPES: [OsslParam; 5] = [
    OsslParam {
        key: b"vault\0".as_ptr() as *const c_char,
        data_type: crate::ossl_param::OSSL_PARAM_UTF8_STRING,
        data: ptr::null_mut(),
        data_size: 0,
        return_size: 0,
    },
    OsslParam {
        key: b"key\0".as_ptr() as *const c_char,
        data_type: crate::ossl_param::OSSL_PARAM_UTF8_STRING,
        data: ptr::null_mut(),
        data_size: 0,
        return_size: 0,
    },
    OsslParam {
        key: b"version\0".as_ptr() as *const c_char,
        data_type: crate::ossl_param::OSSL_PARAM_UTF8_STRING,
        data: ptr::null_mut(),
        data_size: 0,
        return_size: 0,
    },
    OsslParam {
        key: OSSL_PKEY_PARAM_BITS.as_ptr() as *const c_char,
        data_type: crate::ossl_param::OSSL_PARAM_INTEGER,
        data: ptr::null_mut(),
        data_size: 0,
        return_size: 0,
    },
    OsslParam::end(),
];

/// Check if an AKV_KEY has private key metadata (keyvault and key names)
fn akv_key_has_private(key: &AkvKey) -> bool {
    log::trace!("akv_key_has_private key={:p}", key);
    let result = key.keyvault_name.is_some() && key.key_name.is_some();
    log::debug!("akv_key_has_private -> {}", result);
    result
}

/// Check if an AES key has private key metadata
fn akv_aes_key_has_private(key: &AkvAesKey) -> bool {
    log::trace!("akv_aes_key_has_private key={:p}", key);
    let result = key.keyvault_name.is_some() && key.key_name.is_some();
    log::debug!("akv_aes_key_has_private -> {}", result);
    result
}

// ============================================================================
// Common KEYMGMT Functions (used by RSA, EC, and AES)
// ============================================================================

/// Create a new key management context
/// Corresponds to akv_keymgmt_new
/// Create a new key management context
/// Corresponds to akv_keymgmt_new in C
#[no_mangle]
pub unsafe extern "C" fn akv_keymgmt_new(provctx: *mut c_void) -> *mut c_void {
    log::trace!("akv_keymgmt_new provctx={:p}", provctx);
    log::info!("========== akv_keymgmt_new CALLED ==========");

    let key = Box::new(AkvKey::new(provctx as *mut ProviderContext));
    let key_ptr = Box::into_raw(key) as *mut c_void;

    log::debug!("akv_keymgmt_new -> {:p}", key_ptr);
    key_ptr
}

/// Free a key management context
/// Corresponds to akv_keymgmt_free
#[no_mangle]
pub unsafe extern "C" fn akv_keymgmt_free(vkey: *mut c_void) {
    log::trace!("akv_keymgmt_free key={:p}", vkey);

    if !vkey.is_null() {
        let _ = Box::from_raw(vkey as *mut AkvKey);
    }

    log::debug!("akv_keymgmt_free complete for {:p}", vkey);
}

/// Load a key from a reference (from store loader)
/// Load a key from a reference
/// Corresponds to akv_keymgmt_load in C
#[no_mangle]
pub unsafe extern "C" fn akv_keymgmt_load(
    reference: *const c_void,
    reference_sz: usize,
) -> *mut c_void {
    log::trace!(
        "akv_keymgmt_load reference={:p} size={}",
        reference,
        reference_sz
    );
    log::info!("========== akv_keymgmt_load CALLED ==========");
    log::debug!(
        "akv_keymgmt_load called: reference={:p}, size={}, expected_size={}",
        reference,
        reference_sz,
        std::mem::size_of::<*mut AkvKey>()
    );

    if reference.is_null() {
        log::error!("akv_keymgmt_load -> NULL (null reference)");
        return ptr::null_mut();
    }

    if reference_sz != std::mem::size_of::<*mut AkvKey>() {
        log::error!(
            "akv_keymgmt_load -> NULL (invalid reference size: {} != {})",
            reference_sz,
            std::mem::size_of::<*mut AkvKey>()
        );
        return ptr::null_mut();
    }

    // Extract the key pointer from the reference and take ownership
    let key_ptr_ref = reference as *mut *mut AkvKey;
    let key_ptr = *key_ptr_ref;

    log::debug!("akv_keymgmt_load extracted key pointer: {:p}", key_ptr);

    if key_ptr.is_null() {
        log::error!("akv_keymgmt_load -> NULL (extracted null key pointer)");
        return ptr::null_mut();
    }

    *key_ptr_ref = ptr::null_mut(); // Clear the reference

    log::info!("akv_keymgmt_load -> {:p} (success)", key_ptr as *mut c_void);
    key_ptr as *mut c_void
}

/// Check if a key has the specified components
/// Corresponds to akv_keymgmt_has
#[no_mangle]
pub unsafe extern "C" fn akv_keymgmt_has(vkey: *const c_void, selection: c_int) -> c_int {
    log::trace!("akv_keymgmt_has key={:p} selection=0x{:x}", vkey, selection);
    log::info!(
        "========== akv_keymgmt_has CALLED (selection=0x{:x}) ==========",
        selection
    );

    if vkey.is_null() {
        log::error!("akv_keymgmt_has -> 0 (null key)");
        return 0;
    }

    let key = &*(vkey as *const AkvKey);

    // Check if public key is required and present
    if (selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0 && key.public_key.is_none() {
        log::error!("akv_keymgmt_has -> 0 (missing public key)");
        return 0;
    }

    // Check if private key metadata is required and present
    if (selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0 && !akv_key_has_private(key) {
        log::error!("akv_keymgmt_has -> 0 (missing private metadata)");
        return 0;
    }

    log::debug!("akv_keymgmt_has -> 1");
    1
}

/// Check if two keys match
/// Corresponds to akv_keymgmt_match
#[no_mangle]
pub unsafe extern "C" fn akv_keymgmt_match(
    vkey1: *const c_void,
    vkey2: *const c_void,
    selection: c_int,
) -> c_int {
    log::trace!(
        "akv_keymgmt_match key1={:p} key2={:p} selection=0x{:x}",
        vkey1,
        vkey2,
        selection
    );

    if vkey1.is_null() || vkey2.is_null() {
        log::debug!("akv_keymgmt_match -> 0 (null keys)");
        return 0;
    }

    let key1 = &*(vkey1 as *const AkvKey);
    let key2 = &*(vkey2 as *const AkvKey);

    // Check if public keys match using EVP_PKEY_eq
    if (selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0 {
        if key1.public_key.is_none() || key2.public_key.is_none() {
            log::debug!(
                "akv_keymgmt_match -> 0 (missing public key, sel=0x{:x})",
                selection
            );
            return 0;
        }

        // Use OpenSSL's EVP_PKEY_eq to compare public keys
        // Transmute the PKey reference to get the underlying EVP_PKEY pointer
        let pkey1_ptr =
            key1.public_key.as_ref().unwrap() as *const _ as *const openssl_ffi::EVP_PKEY;
        let pkey2_ptr =
            key2.public_key.as_ref().unwrap() as *const _ as *const openssl_ffi::EVP_PKEY;

        if openssl_ffi::EVP_PKEY_eq(pkey1_ptr, pkey2_ptr) <= 0 {
            log::debug!(
                "akv_keymgmt_match -> 0 (public key mismatch, sel=0x{:x})",
                selection
            );
            return 0;
        }
    }
    // Check if private keys match (same vault and key name)
    if (selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0 {
        if !akv_key_has_private(key1) || !akv_key_has_private(key2) {
            log::debug!(
                "akv_keymgmt_match -> 0 (private metadata missing, sel=0x{:x})",
                selection
            );
            return 0;
        }

        // Compare vault names (case-insensitive)
        let vault1 = key1.keyvault_name.as_ref().unwrap();
        let vault2 = key2.keyvault_name.as_ref().unwrap();
        if !vault1.eq_ignore_ascii_case(vault2) {
            log::debug!(
                "akv_keymgmt_match -> 0 (vault identity mismatch, sel=0x{:x})",
                selection
            );
            return 0;
        }

        // Compare key names (case-insensitive)
        let name1 = key1.key_name.as_ref().unwrap();
        let name2 = key2.key_name.as_ref().unwrap();
        if !name1.eq_ignore_ascii_case(name2) {
            log::debug!(
                "akv_keymgmt_match -> 0 (key name mismatch, sel=0x{:x})",
                selection
            );
            return 0;
        }

        // Compare versions if present
        match (&key1.key_version, &key2.key_version) {
            (Some(v1), Some(v2)) => {
                if !v1.eq_ignore_ascii_case(v2) {
                    log::debug!(
                        "akv_keymgmt_match -> 0 (version mismatch, sel=0x{:x})",
                        selection
                    );
                    return 0;
                }
            }
            (Some(_), None) | (None, Some(_)) => {
                log::debug!(
                    "akv_keymgmt_match -> 0 (version presence mismatch, sel=0x{:x})",
                    selection
                );
                return 0;
            }
            (None, None) => {
                // Both have no version - OK
            }
        }
    }

    log::debug!("akv_keymgmt_match -> 1");
    1
}

/// Get key parameters (stub for now)
/// Corresponds to akv_keymgmt_get_params
#[no_mangle]
pub unsafe extern "C" fn akv_keymgmt_get_params(
    vkey: *const c_void,
    params: *mut OsslParam,
) -> c_int {
    log::trace!("akv_keymgmt_get_params key={:p} params={:p}", vkey, params);
    log::info!("========== akv_keymgmt_get_params CALLED ==========");

    if vkey.is_null() {
        log::error!("akv_keymgmt_get_params -> 0 (null key)");
        return 0;
    }

    let key = &*(vkey as *const AkvKey);

    if key.public_key.is_none() {
        log::error!("akv_keymgmt_get_params -> 0 (missing public key)");
        return 0;
    }

    if params.is_null() {
        log::debug!("akv_keymgmt_get_params -> 1 (no params requested)");
        return 1;
    }

    // Log requested parameters
    let mut param_idx = 0;
    let mut current_param = params;
    while !(*current_param).key.is_null() {
        let key_cstr = std::ffi::CStr::from_ptr((*current_param).key);
        let key_str = key_cstr.to_string_lossy();
        log::debug!(
            "  Param[{}]: key='{}', data_type={}",
            param_idx,
            key_str,
            (*current_param).data_type
        );
        param_idx += 1;
        current_param = current_param.add(1);
    }

    // Get key parameters
    // For now, manually handle the common parameters OpenSSL requests
    // TODO: Properly delegate to EVP_PKEY_get_params once we figure out pointer extraction

    let mut param_idx = 0;
    let mut current_param = params;
    while !(*current_param).key.is_null() {
        let key_cstr = std::ffi::CStr::from_ptr((*current_param).key);
        let key_str = key_cstr.to_string_lossy();

        match key_str.as_ref() {
            "bits" => {
                // For RSA 3072-bit key
                if (*current_param).data_type == 1 && !(*current_param).data.is_null() {
                    let bits_ptr = (*current_param).data as *mut c_int;
                    *bits_ptr = 3072; // Azure Managed HSM uses 3072-bit RSA keys
                    log::debug!("  Set bits=3072");
                }
            }
            "security-bits" => {
                if (*current_param).data_type == 1 && !(*current_param).data.is_null() {
                    let sec_bits_ptr = (*current_param).data as *mut c_int;
                    *sec_bits_ptr = 128; // Security level for 3072-bit RSA
                    log::debug!("  Set security-bits=128");
                }
            }
            "max-size" => {
                if (*current_param).data_type == 1 && !(*current_param).data.is_null() {
                    let max_size_ptr = (*current_param).data as *mut c_int;
                    *max_size_ptr = 384; // 3072 bits = 384 bytes
                    log::debug!("  Set max-size=384");
                }
            }
            _ => {
                log::debug!("  Skipping unknown parameter '{}'", key_str);
            }
        }

        param_idx += 1;
        current_param = current_param.add(1);
    }

    log::info!(
        "akv_keymgmt_get_params -> 1 (success, set {} params)",
        param_idx
    );
    1
}

/// Set key parameters (stub for now)
/// Corresponds to akv_keymgmt_set_params
#[no_mangle]
pub unsafe extern "C" fn akv_keymgmt_set_params(
    vkey: *mut c_void,
    params: *const OsslParam,
) -> c_int {
    log::trace!("akv_keymgmt_set_params key={:p} params={:p}", vkey, params);

    if vkey.is_null() {
        log::debug!("akv_keymgmt_set_params -> 0 (null key)");
        return 0;
    }

    let key = &mut *(vkey as *mut AkvKey);

    if key.public_key.is_none() {
        log::debug!("akv_keymgmt_set_params -> 0 (missing public key)");
        return 0;
    }

    if params.is_null() {
        log::debug!("akv_keymgmt_set_params -> 1 (no params to set)");
        return 1;
    }

    // Delegate to OpenSSL's EVP_PKEY_set_params
    let pkey_ptr = key.public_key.as_ref().unwrap() as *const _ as *mut openssl_ffi::EVP_PKEY;
    let result = openssl_ffi::EVP_PKEY_set_params(pkey_ptr, params);

    if result <= 0 {
        log::debug!("akv_keymgmt_set_params -> 0 (EVP_PKEY_set_params failed)");
        return 0;
    }

    log::debug!("akv_keymgmt_set_params -> 1");
    1
}

/// Export key data via callback
/// Corresponds to akv_keymgmt_export
#[no_mangle]
pub unsafe extern "C" fn akv_keymgmt_export(
    vkey: *const c_void,
    selection: c_int,
    callback: *mut c_void,
    cbarg: *mut c_void,
) -> c_int {
    log::trace!(
        "akv_keymgmt_export key={:p} selection=0x{:x} callback={:p} cbarg={:p}",
        vkey,
        selection,
        callback,
        cbarg
    );
    log::info!("========== akv_keymgmt_export CALLED ==========");
    log::debug!("akv_keymgmt_export: selection=0x{:x}", selection);

    if vkey.is_null() || callback.is_null() {
        log::error!("akv_keymgmt_export -> 0 (invalid arguments)");
        return 0;
    }

    let key = &*(vkey as *const AkvKey);

    if key.public_key.is_none() {
        log::debug!("akv_keymgmt_export -> 0 (no cached public key)");
        return 0;
    }

    // We can only export public key material
    // If private key is requested (even along with public), refuse the export
    // This forces OpenSSL to use our provider's operations instead of trying to
    // create a standalone EVP_PKEY and use default provider operations
    if (selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0 {
        log::debug!(
            "akv_keymgmt_export -> 0 (private material requested but not exportable: sel=0x{:x})",
            selection
        );
        return 0;
    }

    // Manual export: Extract key components and build OSSL_PARAM
    // Note: We reverse bytes only when importing from Azure, not when exporting
    log::debug!("akv_keymgmt_export: extracting key components");

    let pkey = key.public_key.as_ref().unwrap();

    // Try to get RSA key
    if let Ok(rsa_key) = pkey.rsa() {
        let n_bn = rsa_key.n();
        let e_bn = rsa_key.e();

        // Convert BIGNUMs to byte arrays
        let mut n_vec = n_bn.to_vec();
        let mut e_vec = e_bn.to_vec();

        // BigNum::to_vec() returns big-endian. OSSL_PARAM expects native endianness.
        // Since we're on little-endian Windows, we need to reverse.
        if cfg!(target_endian = "little") {
            n_vec.reverse();
            e_vec.reverse();
            log::debug!("akv_keymgmt_export: reversed to native endianness for OSSL_PARAM");
        }

        log::debug!(
            "akv_keymgmt_export: RSA n_len={}, e_len={}",
            n_vec.len(),
            e_vec.len()
        );

        // Build OSSL_PARAM array
        let params_vec = vec![
            OsslParam::construct_big_number(
                c"n".as_ptr() as *const i8,
                n_vec.as_ptr() as *mut u8,
                n_vec.len(),
            ),
            OsslParam::construct_big_number(
                c"e".as_ptr() as *const i8,
                e_vec.as_ptr() as *mut u8,
                e_vec.len(),
            ),
            OsslParam::end(),
        ];

        // Call the callback
        type ExportCallback = unsafe extern "C" fn(*const OsslParam, *mut c_void) -> c_int;
        let cb: ExportCallback = std::mem::transmute(callback);

        let result = cb(params_vec.as_ptr(), cbarg);
        log::debug!("akv_keymgmt_export -> {} (manual RSA export)", result);
        return result;
    }

    // Try to get EC key
    if let Ok(ec_key) = pkey.ec_key() {
        let group = ec_key.group();
        let pub_key_point = ec_key.public_key();

        // Convert point to uncompressed form (0x04 || x || y)
        use openssl::ec::PointConversionForm;
        let pub_key_bytes = pub_key_point
            .to_bytes(
                group,
                PointConversionForm::UNCOMPRESSED,
                &mut openssl::bn::BigNumContext::new().unwrap(),
            )
            .unwrap();

        log::debug!(
            "akv_keymgmt_export: EC pub_key_bytes_len={}",
            pub_key_bytes.len()
        );

        // Get curve NID and name
        let nid = group.curve_name().unwrap();
        let curve_name = nid.long_name().unwrap();
        log::debug!("akv_keymgmt_export: EC curve={}", curve_name);

        // Build OSSL_PARAM array for EC key
        let params_vec = vec![
            OsslParam::construct_octet_string(
                c"pub".as_ptr() as *const i8,
                pub_key_bytes.as_ptr() as *mut c_void,
                pub_key_bytes.len(),
            ),
            OsslParam::construct_utf8_string(
                c"group".as_ptr() as *const i8,
                curve_name.as_ptr() as *mut i8,
                curve_name.len(),
            ),
            OsslParam::end(),
        ];

        // Call the callback
        type ExportCallback = unsafe extern "C" fn(*const OsslParam, *mut c_void) -> c_int;
        let cb: ExportCallback = std::mem::transmute(callback);

        let result = cb(params_vec.as_ptr(), cbarg);
        log::debug!("akv_keymgmt_export -> {} (manual EC export)", result);
        return result;
    }

    log::error!("akv_keymgmt_export: unknown key type");
    0
}

// ============================================================================
// RSA-specific KEYMGMT Functions
// ============================================================================

/// Get gettable parameters for RSA keys
#[no_mangle]
pub unsafe extern "C" fn akv_rsa_keymgmt_gettable_params(
    _provctx: *mut c_void,
) -> *const OsslParam {
    log::trace!("akv_rsa_keymgmt_gettable_params");
    let ptr = RSA_GETTABLE_PARAMS.as_ptr();
    log::debug!("akv_rsa_keymgmt_gettable_params -> {:p}", ptr);
    ptr
}

/// Get settable parameters for RSA keys
#[no_mangle]
pub unsafe extern "C" fn akv_rsa_keymgmt_settable_params(
    _provctx: *mut c_void,
) -> *const OsslParam {
    log::trace!("akv_rsa_keymgmt_settable_params");
    static END_PARAM: OsslParam = OsslParam::end();
    log::debug!(
        "akv_rsa_keymgmt_settable_params -> {:p}",
        &END_PARAM as *const OsslParam
    );
    &END_PARAM as *const OsslParam
}

/// Import types for RSA keys
#[no_mangle]
pub unsafe extern "C" fn akv_rsa_keymgmt_eximport_types(_selection: c_int) -> *const OsslParam {
    log::trace!(
        "akv_rsa_keymgmt_eximport_types selection=0x{:x}",
        _selection
    );

    if (_selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0 || _selection == 0 {
        let ptr = RSA_EXPORT_TYPES.as_ptr();
        log::debug!("akv_rsa_keymgmt_eximport_types -> {:p}", ptr);
        ptr
    } else {
        log::debug!("akv_rsa_keymgmt_eximport_types -> NULL");
        ptr::null()
    }
}

/// Common import logic for RSA and EC keys
/// Corresponds to akv_keymgmt_import_common in C
unsafe fn akv_keymgmt_import_common(
    key: &mut AkvKey,
    algorithm: &str,
    selection: c_int,
    params: *const OsslParam,
) -> c_int {
    log::trace!(
        "akv_keymgmt_import_common key={:p} algorithm={} selection=0x{:x} params={:p}",
        key as *const AkvKey,
        algorithm,
        selection,
        params
    );

    // Reject unmanaged public-only imports (let default provider handle them)
    if (selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0
        && (selection & !OSSL_KEYMGMT_SELECT_PUBLIC_KEY) == 0
        && !akv_key_has_private(key)
    {
        log::debug!("akv_keymgmt_import_common -> 0 (public import without metadata)");
        return 0;
    }

    // Create EVP_PKEY_CTX using default or base provider to avoid recursion
    let algo_cstr = match CString::new(algorithm) {
        Ok(s) => s,
        Err(e) => {
            log::error!(
                "Failed to create CString for algorithm {}: {}",
                algorithm,
                e
            );
            return 0;
        }
    };

    let provider_default = CString::new("provider=default").unwrap();
    let provider_base = CString::new("provider=base").unwrap();

    let mut ctx = openssl_ffi::EVP_PKEY_CTX_new_from_name(
        ptr::null_mut(),
        algo_cstr.as_ptr(),
        provider_default.as_ptr(),
    );

    if ctx.is_null() {
        ctx = openssl_ffi::EVP_PKEY_CTX_new_from_name(
            ptr::null_mut(),
            algo_cstr.as_ptr(),
            provider_base.as_ptr(),
        );
    }

    if ctx.is_null() {
        log::error!(
            "akv_keymgmt_import_common failed to create ctx for {}",
            algorithm
        );
        return 0;
    }

    // Initialize context for fromdata operation
    if openssl_ffi::EVP_PKEY_fromdata_init(ctx) <= 0 {
        log::error!(
            "akv_keymgmt_import_common fromdata_init failed for {}",
            algorithm
        );
        openssl_ffi::EVP_PKEY_CTX_free(ctx);
        return 0;
    }

    // Create EVP_PKEY from params
    let mut tmp: *mut openssl_ffi::EVP_PKEY = ptr::null_mut();
    if openssl_ffi::EVP_PKEY_fromdata(ctx, &mut tmp, selection, params as *mut OsslParam) <= 0 {
        log::error!(
            "akv_keymgmt_import_common fromdata failed for {} (sel=0x{:x})",
            algorithm,
            selection
        );
        openssl_ffi::EVP_PKEY_CTX_free(ctx);
        return 0;
    }

    // Wrap the EVP_PKEY in an openssl-rs PKey
    // We need to transfer ownership from the raw pointer to Rust
    let pkey = std::mem::transmute::<*mut openssl_ffi::EVP_PKEY, PKey<openssl::pkey::Public>>(tmp);
    key.set_public(pkey);

    openssl_ffi::EVP_PKEY_CTX_free(ctx);

    log::debug!(
        "akv_keymgmt_import_common imported {} key into {:p}",
        algorithm,
        key as *const AkvKey
    );
    1
}

/// Import an RSA key (stub for now)
#[no_mangle]
pub unsafe extern "C" fn akv_rsa_keymgmt_import(
    vkey: *mut c_void,
    selection: c_int,
    params: *const OsslParam,
) -> c_int {
    log::trace!(
        "akv_rsa_keymgmt_import key={:p} selection=0x{:x} params={:p}",
        vkey,
        selection,
        params
    );

    if vkey.is_null() {
        log::debug!("akv_rsa_keymgmt_import -> 0 (null key)");
        return 0;
    }

    let key = &mut *(vkey as *mut AkvKey);
    let result = akv_keymgmt_import_common(key, "RSA", selection, params);

    log::debug!("akv_rsa_keymgmt_import -> {}", result);
    result
}

/// Query which operations are supported for RSA keys
#[no_mangle]
pub unsafe extern "C" fn akv_rsa_keymgmt_query(operation_id: c_int) -> *const c_char {
    log::trace!("akv_rsa_keymgmt_query operation_id={}", operation_id);

    if operation_id == OSSL_OP_SIGNATURE {
        log::debug!("akv_rsa_keymgmt_query -> RSA (signature)");
        return b"RSA\0".as_ptr() as *const c_char;
    }

    if operation_id == OSSL_OP_ASYM_CIPHER {
        log::debug!("akv_rsa_keymgmt_query -> RSA (asym_cipher)");
        return b"RSA\0".as_ptr() as *const c_char;
    }

    log::debug!("akv_rsa_keymgmt_query -> NULL");
    ptr::null()
}

// ============================================================================
// EC-specific KEYMGMT Functions
// ============================================================================

/// Get gettable parameters for EC keys
#[no_mangle]
pub unsafe extern "C" fn akv_ec_keymgmt_gettable_params(_provctx: *mut c_void) -> *const OsslParam {
    log::trace!("akv_ec_keymgmt_gettable_params");
    let ptr = EC_GETTABLE_PARAMS.as_ptr();
    log::debug!("akv_ec_keymgmt_gettable_params -> {:p}", ptr);
    ptr
}

/// Get settable parameters for EC keys
#[no_mangle]
pub unsafe extern "C" fn akv_ec_keymgmt_settable_params(_provctx: *mut c_void) -> *const OsslParam {
    log::trace!("akv_ec_keymgmt_settable_params");
    static END_PARAM: OsslParam = OsslParam::end();
    log::debug!(
        "akv_ec_keymgmt_settable_params -> {:p}",
        &END_PARAM as *const OsslParam
    );
    &END_PARAM as *const OsslParam
}

/// Import/export types for EC keys
#[no_mangle]
pub unsafe extern "C" fn akv_ec_keymgmt_eximport_types(_selection: c_int) -> *const OsslParam {
    log::trace!("akv_ec_keymgmt_eximport_types selection=0x{:x}", _selection);

    if (_selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0 || _selection == 0 {
        let ptr = EC_EXPORT_TYPES.as_ptr();
        log::debug!("akv_ec_keymgmt_eximport_types -> {:p}", ptr);
        ptr
    } else {
        log::debug!("akv_ec_keymgmt_eximport_types -> NULL");
        ptr::null()
    }
}

/// Import an EC key (stub for now)
#[no_mangle]
pub unsafe extern "C" fn akv_ec_keymgmt_import(
    vkey: *mut c_void,
    selection: c_int,
    params: *const OsslParam,
) -> c_int {
    log::trace!(
        "akv_ec_keymgmt_import key={:p} selection=0x{:x} params={:p}",
        vkey,
        selection,
        params
    );

    if vkey.is_null() {
        log::debug!("akv_ec_keymgmt_import -> 0 (null key)");
        return 0;
    }

    let key = &mut *(vkey as *mut AkvKey);
    let result = akv_keymgmt_import_common(key, "EC", selection, params);

    log::debug!("akv_ec_keymgmt_import -> {}", result);
    result
}

/// Query which operations are supported for EC keys
#[no_mangle]
pub unsafe extern "C" fn akv_ec_keymgmt_query(operation_id: c_int) -> *const c_char {
    log::trace!("akv_ec_keymgmt_query operation_id={}", operation_id);

    if operation_id == OSSL_OP_SIGNATURE {
        log::debug!("akv_ec_keymgmt_query -> ECDSA (signature)");
        return b"ECDSA\0".as_ptr() as *const c_char;
    }

    log::debug!("akv_ec_keymgmt_query -> NULL");
    ptr::null()
}

// ============================================================================
// AES-specific KEYMGMT Functions
// ============================================================================

/// Create a new AES key management context
#[no_mangle]
pub unsafe extern "C" fn akv_aes_keymgmt_new(provctx: *mut c_void) -> *mut c_void {
    log::trace!("akv_aes_keymgmt_new provctx={:p}", provctx);

    let key = Box::new(AkvAesKey::new(provctx as *mut ProviderContext));
    let key_ptr = Box::into_raw(key) as *mut c_void;

    log::debug!("akv_aes_keymgmt_new -> {:p}", key_ptr);
    key_ptr
}

/// Free an AES key management context
#[no_mangle]
pub unsafe extern "C" fn akv_aes_keymgmt_free(vkey: *mut c_void) {
    log::trace!("akv_aes_keymgmt_free key={:p}", vkey);

    if !vkey.is_null() {
        let _ = Box::from_raw(vkey as *mut AkvAesKey);
    }

    log::debug!("akv_aes_keymgmt_free complete for {:p}", vkey);
}

/// Load an AES key from a reference
#[no_mangle]
pub unsafe extern "C" fn akv_aes_keymgmt_load(
    reference: *const c_void,
    reference_sz: usize,
) -> *mut c_void {
    log::trace!(
        "akv_aes_keymgmt_load reference={:p} size={}",
        reference,
        reference_sz
    );

    if reference.is_null() || reference_sz != std::mem::size_of::<*mut AkvAesKey>() {
        log::debug!("akv_aes_keymgmt_load -> NULL (invalid reference)");
        return ptr::null_mut();
    }

    let key_ptr_ref = reference as *mut *mut AkvAesKey;
    let key_ptr = *key_ptr_ref;
    *key_ptr_ref = ptr::null_mut();

    log::debug!("akv_aes_keymgmt_load -> {:p}", key_ptr as *mut c_void);
    key_ptr as *mut c_void
}

/// Check if an AES key has the specified components
#[no_mangle]
pub unsafe extern "C" fn akv_aes_keymgmt_has(vkey: *const c_void, selection: c_int) -> c_int {
    log::trace!(
        "akv_aes_keymgmt_has key={:p} selection=0x{:x}",
        vkey,
        selection
    );

    if vkey.is_null() {
        log::debug!("akv_aes_keymgmt_has -> 0 (null key)");
        return 0;
    }

    let key = &*(vkey as *const AkvAesKey);

    if (selection & (OSSL_KEYMGMT_SELECT_PRIVATE_KEY | OSSL_KEYMGMT_SELECT_OTHER_PARAMETERS)) != 0 {
        let result = if akv_aes_key_has_private(key) { 1 } else { 0 };
        log::debug!(
            "akv_aes_keymgmt_has selection=0x{:x} -> {}",
            selection,
            result
        );
        return result;
    }

    log::debug!(
        "akv_aes_keymgmt_has -> 0 (unsupported selection 0x{:x})",
        selection
    );
    0
}

/// Check if two AES keys match (same Key Vault metadata)
#[no_mangle]
pub unsafe extern "C" fn akv_aes_keymgmt_match(
    vkey1: *const c_void,
    vkey2: *const c_void,
    selection: c_int,
) -> c_int {
    log::trace!(
        "akv_aes_keymgmt_match key1={:p} key2={:p} selection=0x{:x}",
        vkey1,
        vkey2,
        selection
    );

    if vkey1.is_null() || vkey2.is_null() {
        log::debug!("akv_aes_keymgmt_match -> 0 (null key)");
        return 0;
    }

    let key1 = &*(vkey1 as *const AkvAesKey);
    let key2 = &*(vkey2 as *const AkvAesKey);

    if !akv_aes_key_has_private(key1) || !akv_aes_key_has_private(key2) {
        log::debug!("akv_aes_keymgmt_match -> 0 (missing metadata)");
        return 0;
    }

    let vault_match = key1
        .keyvault_name
        .as_ref()
        .zip(key2.keyvault_name.as_ref())
        .map(|(a, b)| a.eq_ignore_ascii_case(b))
        .unwrap_or(false);

    if !vault_match {
        log::debug!("akv_aes_keymgmt_match -> 0 (vault mismatch)");
        return 0;
    }

    let name_match = key1
        .key_name
        .as_ref()
        .zip(key2.key_name.as_ref())
        .map(|(a, b)| a.eq_ignore_ascii_case(b))
        .unwrap_or(false);

    if !name_match {
        log::debug!("akv_aes_keymgmt_match -> 0 (name mismatch)");
        return 0;
    }

    let version_match = match (&key1.key_version, &key2.key_version) {
        (Some(v1), Some(v2)) => v1.eq_ignore_ascii_case(v2),
        (None, None) => true,
        _ => false,
    };

    if !version_match {
        log::debug!("akv_aes_keymgmt_match -> 0 (version mismatch)");
        return 0;
    }

    if selection != 0 {
        log::debug!("akv_aes_keymgmt_match selection=0x{:x} -> 1", selection);
    }

    1
}

/// Get gettable parameters for AES keys
#[no_mangle]
pub unsafe extern "C" fn akv_aes_keymgmt_gettable_params(
    _provctx: *mut c_void,
) -> *const OsslParam {
    log::trace!("akv_aes_keymgmt_gettable_params");
    log::debug!(
        "akv_aes_keymgmt_gettable_params -> {:p}",
        AES_GETTABLE_PARAMS.as_ptr()
    );
    AES_GETTABLE_PARAMS.as_ptr()
}

/// Get settable parameters for AES keys
#[no_mangle]
pub unsafe extern "C" fn akv_aes_keymgmt_settable_params(
    _provctx: *mut c_void,
) -> *const OsslParam {
    log::trace!("akv_aes_keymgmt_settable_params");
    static END_PARAM: OsslParam = OsslParam::end();
    log::debug!(
        "akv_aes_keymgmt_settable_params -> {:p}",
        &END_PARAM as *const OsslParam
    );
    &END_PARAM as *const OsslParam
}

/// Query which operations are supported for AES keys
#[no_mangle]
pub unsafe extern "C" fn akv_aes_keymgmt_query(operation_id: c_int) -> *const c_char {
    log::trace!("akv_aes_keymgmt_query operation_id={}", operation_id);

    if operation_id == OSSL_OP_ASYM_CIPHER {
        log::debug!("akv_aes_keymgmt_query -> AES-256-KW (asym_cipher)");
        return b"AES-256-KW\0".as_ptr() as *const c_char;
    }

    log::debug!("akv_aes_keymgmt_query -> NULL");
    ptr::null()
}

/// Import parameters for AES keys (used to configure remote metadata)
#[no_mangle]
pub unsafe extern "C" fn akv_aes_keymgmt_import(
    vkey: *mut c_void,
    _selection: c_int,
    params: *const OsslParam,
) -> c_int {
    log::trace!("akv_aes_keymgmt_import key={:p}", vkey);

    if vkey.is_null() || params.is_null() {
        log::error!("akv_aes_keymgmt_import -> 0 (invalid arguments)");
        return 0;
    }

    let key = &mut *(vkey as *mut AkvAesKey);

    let mut vault: Option<String> = None;
    let mut name: Option<String> = None;
    let mut version: Option<String> = None;
    let mut bits: Option<usize> = None;

    let mut current = params;
    while !(*current).key.is_null() {
        let key_cstr = CStr::from_ptr((*current).key);
        if let Ok(key_str) = key_cstr.to_str() {
            let key_lower = key_str.to_ascii_lowercase();
            match key_lower.as_str() {
                "vault" => {
                    if let Some(ptr) = OsslParam::get_utf8_string_ptr(current) {
                        if let Ok(value) = CStr::from_ptr(ptr).to_str() {
                            vault = Some(value.to_string());
                        }
                    }
                }
                "key" => {
                    if let Some(ptr) = OsslParam::get_utf8_string_ptr(current) {
                        if let Ok(value) = CStr::from_ptr(ptr).to_str() {
                            name = Some(value.to_string());
                        }
                    }
                }
                "version" => {
                    if let Some(ptr) = OsslParam::get_utf8_string_ptr(current) {
                        if let Ok(value) = CStr::from_ptr(ptr).to_str() {
                            version = Some(value.to_string());
                        }
                    }
                }
                "bits" => {
                    if let Some(value) = OsslParam::get_int(current) {
                        if value > 0 {
                            bits = Some(value as usize);
                        }
                    }
                }
                _ => {}
            }
        }

        current = current.add(1);
    }

    let bits_value = bits.unwrap_or(key.key_bits);

    if let (Some(ref vault_val), Some(ref name_val)) = (&vault, &name) {
        key.set_metadata(vault_val, name_val, version.as_deref(), bits_value);
    } else {
        key.key_bits = bits_value;

        if let Some(v) = vault {
            key.keyvault_name = Some(v);
        }
        if let Some(n) = name {
            key.key_name = Some(n);
        }
        if let Some(ver) = version {
            key.key_version = Some(ver);
        }
    }

    log::debug!(
        "akv_aes_keymgmt_import -> vault={:?} key={:?} version={:?} bits={}",
        key.keyvault_name,
        key.key_name,
        key.key_version,
        key.key_bits
    );

    1
}

/// Return import parameter descriptors for AES
#[no_mangle]
pub unsafe extern "C" fn akv_aes_keymgmt_import_types(_selection: c_int) -> *const OsslParam {
    log::trace!("akv_aes_keymgmt_import_types");
    AES_IMPORT_TYPES.as_ptr()
}

/// Populate requested AES parameters
#[no_mangle]
pub unsafe extern "C" fn akv_aes_keymgmt_get_params(
    vkey: *mut c_void,
    params: *mut OsslParam,
) -> c_int {
    log::trace!("akv_aes_keymgmt_get_params key={:p}", vkey);

    if vkey.is_null() || params.is_null() {
        log::debug!("akv_aes_keymgmt_get_params -> 0 (invalid arguments)");
        return 0;
    }

    let key = &*(vkey as *mut AkvAesKey);
    let bits = key.key_bits as c_int;
    let bytes = (key.key_bits / 8) as c_int;

    let bits_param = OsslParam::locate(params, OSSL_PKEY_PARAM_BITS.as_ptr() as *const c_char);
    if !bits_param.is_null() && (*bits_param).set_int(bits) == false {
        log::debug!("akv_aes_keymgmt_get_params -> 0 (failed to set bits)");
        return 0;
    }

    let sec_param = OsslParam::locate(
        params,
        OSSL_PKEY_PARAM_SECURITY_BITS.as_ptr() as *const c_char,
    );
    if !sec_param.is_null() && (*sec_param).set_int(bits) == false {
        log::debug!("akv_aes_keymgmt_get_params -> 0 (failed to set security bits)");
        return 0;
    }

    let max_param = OsslParam::locate(params, OSSL_PKEY_PARAM_MAX_SIZE.as_ptr() as *const c_char);
    if !max_param.is_null() && (*max_param).set_int(bytes) == false {
        log::debug!("akv_aes_keymgmt_get_params -> 0 (failed to set max size)");
        return 0;
    }

    log::debug!(
        "akv_aes_keymgmt_get_params -> bits={} security={} max_bytes={}",
        bits,
        bits,
        bytes
    );

    1
}
