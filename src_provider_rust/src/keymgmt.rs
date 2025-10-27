// Key management functionality
// Corresponds to akv_keymgmt.c

use crate::provider::{ProviderContext, AkvKey, AkvAesKey};
use crate::ossl_param::OsslParam;
use openssl::bn::BigNumContext;
use openssl::ec::PointConversionForm;
use openssl::pkey::Id;
use std::ffi::CString;
use std::os::raw::{c_char, c_int, c_void};
use std::ptr;

// OpenSSL key selection flags
pub const OSSL_KEYMGMT_SELECT_PRIVATE_KEY: c_int = 0x01;
pub const OSSL_KEYMGMT_SELECT_PUBLIC_KEY: c_int = 0x02;
pub const OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS: c_int = 0x04;
pub const OSSL_KEYMGMT_SELECT_OTHER_PARAMETERS: c_int = 0x80;
pub const OSSL_KEYMGMT_SELECT_ALL: c_int = 0xFF;

// OpenSSL operation IDs
pub const OSSL_OP_SIGNATURE: c_int = 10;
pub const OSSL_OP_ASYM_CIPHER: c_int = 11;

// Common OSSL parameter names used during export
const OSSL_PKEY_PARAM_ID: &[u8] = b"id\0";
const OSSL_PKEY_PARAM_TYPE: &[u8] = b"type\0";
const OSSL_PKEY_PARAM_BITS: &[u8] = b"bits\0";
const OSSL_PKEY_PARAM_SECURITY_BITS: &[u8] = b"security-bits\0";
const OSSL_PKEY_PARAM_MAX_SIZE: &[u8] = b"max-size\0";
const OSSL_PKEY_PARAM_FRIENDLY_NAME: &[u8] = b"friendly-name\0";
const OSSL_PKEY_PARAM_PUB_KEY: &[u8] = b"pub\0";
const OSSL_PKEY_PARAM_RSA_N: &[u8] = b"n\0";
const OSSL_PKEY_PARAM_RSA_E: &[u8] = b"e\0";
const OSSL_PKEY_PARAM_EC_GROUP_NAME: &[u8] = b"group\0";
const OSSL_PKEY_PARAM_EC_ENCODING: &[u8] = b"encoding\0";
const OSSL_PKEY_PARAM_EC_POINT_CONVERSION_FORMAT: &[u8] = b"format\0";

// Static export type descriptors advertised via export_types callbacks
static RSA_EXPORT_TYPES: [OsslParam; 10] = [
    OsslParam {
        key: OSSL_PKEY_PARAM_TYPE.as_ptr() as *const c_char,
        data_type: crate::ossl_param::OSSL_PARAM_UTF8_STRING,
        data: ptr::null_mut(),
        data_size: 0,
        return_size: 0,
    },
    OsslParam {
        key: OSSL_PKEY_PARAM_FRIENDLY_NAME.as_ptr() as *const c_char,
        data_type: crate::ossl_param::OSSL_PARAM_UTF8_STRING,
        data: ptr::null_mut(),
        data_size: 0,
        return_size: 0,
    },
    OsslParam {
        key: OSSL_PKEY_PARAM_ID.as_ptr() as *const c_char,
        data_type: crate::ossl_param::OSSL_PARAM_UTF8_STRING,
        data: ptr::null_mut(),
        data_size: 0,
        return_size: 0,
    },
    OsslParam {
        key: OSSL_PKEY_PARAM_BITS.as_ptr() as *const c_char,
        data_type: crate::ossl_param::OSSL_PARAM_UNSIGNED_INTEGER,
        data: ptr::null_mut(),
        data_size: std::mem::size_of::<usize>(),
        return_size: 0,
    },
    OsslParam {
        key: OSSL_PKEY_PARAM_SECURITY_BITS.as_ptr() as *const c_char,
        data_type: crate::ossl_param::OSSL_PARAM_INTEGER,
        data: ptr::null_mut(),
        data_size: std::mem::size_of::<c_int>(),
        return_size: 0,
    },
    OsslParam {
        key: OSSL_PKEY_PARAM_MAX_SIZE.as_ptr() as *const c_char,
        data_type: crate::ossl_param::OSSL_PARAM_UNSIGNED_INTEGER,
        data: ptr::null_mut(),
        data_size: std::mem::size_of::<usize>(),
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

static EC_EXPORT_TYPES: [OsslParam; 11] = [
    OsslParam {
        key: OSSL_PKEY_PARAM_TYPE.as_ptr() as *const c_char,
        data_type: crate::ossl_param::OSSL_PARAM_UTF8_STRING,
        data: ptr::null_mut(),
        data_size: 0,
        return_size: 0,
    },
    OsslParam {
        key: OSSL_PKEY_PARAM_FRIENDLY_NAME.as_ptr() as *const c_char,
        data_type: crate::ossl_param::OSSL_PARAM_UTF8_STRING,
        data: ptr::null_mut(),
        data_size: 0,
        return_size: 0,
    },
    OsslParam {
        key: OSSL_PKEY_PARAM_ID.as_ptr() as *const c_char,
        data_type: crate::ossl_param::OSSL_PARAM_UTF8_STRING,
        data: ptr::null_mut(),
        data_size: 0,
        return_size: 0,
    },
    OsslParam {
        key: OSSL_PKEY_PARAM_BITS.as_ptr() as *const c_char,
        data_type: crate::ossl_param::OSSL_PARAM_UNSIGNED_INTEGER,
        data: ptr::null_mut(),
        data_size: std::mem::size_of::<usize>(),
        return_size: 0,
    },
    OsslParam {
        key: OSSL_PKEY_PARAM_SECURITY_BITS.as_ptr() as *const c_char,
        data_type: crate::ossl_param::OSSL_PARAM_INTEGER,
        data: ptr::null_mut(),
        data_size: std::mem::size_of::<c_int>(),
        return_size: 0,
    },
    OsslParam {
        key: OSSL_PKEY_PARAM_MAX_SIZE.as_ptr() as *const c_char,
        data_type: crate::ossl_param::OSSL_PARAM_UNSIGNED_INTEGER,
        data: ptr::null_mut(),
        data_size: std::mem::size_of::<usize>(),
        return_size: 0,
    },
    OsslParam {
        key: OSSL_PKEY_PARAM_EC_GROUP_NAME.as_ptr() as *const c_char,
        data_type: crate::ossl_param::OSSL_PARAM_UTF8_STRING,
        data: ptr::null_mut(),
        data_size: 0,
        return_size: 0,
    },
    OsslParam {
        key: OSSL_PKEY_PARAM_EC_ENCODING.as_ptr() as *const c_char,
        data_type: crate::ossl_param::OSSL_PARAM_UTF8_STRING,
        data: ptr::null_mut(),
        data_size: 0,
        return_size: 0,
    },
    OsslParam {
        key: OSSL_PKEY_PARAM_EC_POINT_CONVERSION_FORMAT.as_ptr() as *const c_char,
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
#[no_mangle]
pub unsafe extern "C" fn akv_keymgmt_new(provctx: *mut c_void) -> *mut c_void {
    log::trace!("akv_keymgmt_new provctx={:p}", provctx);
    
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
/// Corresponds to akv_keymgmt_load
#[no_mangle]
pub unsafe extern "C" fn akv_keymgmt_load(
    reference: *const c_void,
    reference_sz: usize,
) -> *mut c_void {
    log::trace!("akv_keymgmt_load reference={:p} size={}", reference, reference_sz);
    log::debug!(
        "akv_keymgmt_load called: reference={:p}, size={}, expected_size={}",
        reference, reference_sz, std::mem::size_of::<*mut AkvKey>()
    );
    
    if reference.is_null() {
        log::error!("akv_keymgmt_load -> NULL (null reference)");
        return ptr::null_mut();
    }
    
    if reference_sz != std::mem::size_of::<*mut AkvKey>() {
        log::error!(
            "akv_keymgmt_load -> NULL (invalid reference size: {} != {})",
            reference_sz, std::mem::size_of::<*mut AkvKey>()
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
    
    if vkey.is_null() {
        log::debug!("akv_keymgmt_has -> 0 (null key)");
        return 0;
    }
    
    let key = &*(vkey as *const AkvKey);
    
    // Check if public key is required and present
    if (selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0 && key.public_key.is_none() {
        log::debug!("akv_keymgmt_has -> 0 (missing public key)");
        return 0;
    }
    
    // Check if private key metadata is required and present
    if (selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0 && !akv_key_has_private(key) {
        log::debug!("akv_keymgmt_has -> 0 (missing private metadata)");
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
    log::trace!("akv_keymgmt_match key1={:p} key2={:p} selection=0x{:x}", vkey1, vkey2, selection);
    
    if vkey1.is_null() || vkey2.is_null() {
        log::debug!("akv_keymgmt_match -> 0 (null keys)");
        return 0;
    }
    
    let key1 = &*(vkey1 as *const AkvKey);
    let key2 = &*(vkey2 as *const AkvKey);
    
    // Check if private keys match (same vault and key name)
    if (selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0 {
        if key1.keyvault_name != key2.keyvault_name || key1.key_name != key2.key_name {
            log::debug!("akv_keymgmt_match -> 0 (private keys differ)");
            return 0;
        }
    }
    
    // For public keys, we could compare the actual public key material
    // For now, we assume match if we get here
    log::debug!("akv_keymgmt_match -> 1");
    1
}

/// Get key parameters (stub for now)
/// Corresponds to akv_keymgmt_get_params
#[no_mangle]
pub unsafe extern "C" fn akv_keymgmt_get_params(
    _vkey: *const c_void,
    _params: *mut OsslParam,
) -> c_int {
    log::trace!("akv_keymgmt_get_params (stub)");
    log::debug!("akv_keymgmt_get_params -> 1");
    1
}

/// Set key parameters (stub for now)
/// Corresponds to akv_keymgmt_set_params
#[no_mangle]
pub unsafe extern "C" fn akv_keymgmt_set_params(
    _vkey: *mut c_void,
    _params: *const OsslParam,
) -> c_int {
    log::trace!("akv_keymgmt_set_params (stub)");
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
        "akv_keymgmt_export key={:p} selection=0x{:x} callback={:p}",
        vkey, selection, callback
    );

    if vkey.is_null() || callback.is_null() {
        log::debug!("akv_keymgmt_export -> 0 (invalid arguments)");
        return 0;
    }

    let key = &*(vkey as *const AkvKey);

    let pkey = match key.public_key.as_ref() {
        Some(p) => p,
        None => {
            log::debug!("akv_keymgmt_export -> 0 (no cached public key)");
            return 0;
        }
    };

    let key_type = match pkey.id() {
        Id::RSA => "RSA",
        Id::EC => "EC",
        other => {
            log::error!("Unsupported key type for export: {:?}", other);
            return 0;
        }
    };

    if (selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0 {
        log::debug!("akv_keymgmt_export requested private key (not supported)");
    }

    let mut params: Vec<OsslParam> = Vec::new();
    let mut owned_strings: Vec<CString> = Vec::new();

    // Key type string
    owned_strings.push(CString::new(key_type).expect("static string"));
    let type_ptr = owned_strings.last().unwrap().as_ptr() as *mut c_char;
    params.push(OsslParam::construct_utf8_string(
        OSSL_PKEY_PARAM_TYPE.as_ptr() as *const c_char,
        type_ptr,
        0,
    ));

    // Friendly name (key name)
    if let Some(name) = &key.key_name {
        match CString::new(name.as_str()) {
            Ok(cstr) => {
                owned_strings.push(cstr);
                let ptr = owned_strings.last().unwrap().as_ptr() as *mut c_char;
                params.push(OsslParam::construct_utf8_string(
                    OSSL_PKEY_PARAM_FRIENDLY_NAME.as_ptr() as *const c_char,
                    ptr,
                    0,
                ));
            }
            Err(e) => {
                log::error!("Failed to build friendly name string: {}", e);
                return 0;
            }
        }
    }

    // Key identifier (managedhsm URI)
    if let (Some(vault), Some(name)) = (&key.keyvault_name, &key.key_name) {
        let mut identifier = format!("managedhsm:{}:{}", vault, name);
        if let Some(version) = &key.key_version {
            identifier.push(':');
            identifier.push_str(version);
        }

        match CString::new(identifier) {
            Ok(cstr) => {
                owned_strings.push(cstr);
                let ptr = owned_strings.last().unwrap().as_ptr() as *mut c_char;
                params.push(OsslParam::construct_utf8_string(
                    OSSL_PKEY_PARAM_ID.as_ptr() as *const c_char,
                    ptr,
                    0,
                ));
            }
            Err(e) => {
                log::error!("Failed to build key identifier string: {}", e);
                return 0;
            }
        }
    }

    // Key size metadata
    let mut bits_value: c_int = pkey.bits() as c_int;
    params.push(OsslParam::construct_int(
        OSSL_PKEY_PARAM_BITS.as_ptr() as *const c_char,
        &mut bits_value,
    ));

    let mut security_bits_value: c_int = pkey.security_bits() as c_int;
    params.push(OsslParam::construct_int(
        OSSL_PKEY_PARAM_SECURITY_BITS.as_ptr() as *const c_char,
        &mut security_bits_value,
    ));

    let mut max_size_value: usize = pkey.size();
    params.push(OsslParam::construct_size_t(
        OSSL_PKEY_PARAM_MAX_SIZE.as_ptr() as *const c_char,
        &mut max_size_value,
    ));

    // Buffers that must outlive the callback
    let mut rsa_n_bytes: Vec<u8> = Vec::new();
    let mut rsa_e_bytes: Vec<u8> = Vec::new();
    let mut rsa_pub_bytes: Vec<u8> = Vec::new();
    let mut ec_point_bytes: Vec<u8> = Vec::new();

    match pkey.id() {
        Id::RSA => {
            let rsa = match pkey.rsa() {
                Ok(r) => r,
                Err(e) => {
                    log::error!("Failed to access RSA key components: {}", e);
                    return 0;
                }
            };

            rsa_n_bytes = rsa.n().to_vec();
            rsa_e_bytes = rsa.e().to_vec();

            match rsa.public_key_to_der() {
                Ok(der) => rsa_pub_bytes = der,
                Err(e) => {
                    log::error!("Failed to DER encode RSA public key: {}", e);
                    return 0;
                }
            }

            if rsa_n_bytes.is_empty() || rsa_e_bytes.is_empty() || rsa_pub_bytes.is_empty() {
                log::error!("RSA key export encountered empty component");
                return 0;
            }

            params.push(OsslParam::construct_big_number(
                OSSL_PKEY_PARAM_RSA_N.as_ptr() as *const c_char,
                rsa_n_bytes.as_mut_ptr(),
                rsa_n_bytes.len(),
            ));
            params.push(OsslParam::construct_big_number(
                OSSL_PKEY_PARAM_RSA_E.as_ptr() as *const c_char,
                rsa_e_bytes.as_mut_ptr(),
                rsa_e_bytes.len(),
            ));
            params.push(OsslParam::construct_octet_string(
                OSSL_PKEY_PARAM_PUB_KEY.as_ptr() as *const c_char,
                rsa_pub_bytes.as_mut_ptr() as *mut c_void,
                rsa_pub_bytes.len(),
            ));
        }
        Id::EC => {
            let ec = match pkey.ec_key() {
                Ok(ec) => ec,
                Err(e) => {
                    log::error!("Failed to access EC key components: {}", e);
                    return 0;
                }
            };

            if let Some(nid) = ec.group().curve_name() {
                match nid.short_name() {
                    Ok(name) => match CString::new(name) {
                        Ok(cstr) => {
                            owned_strings.push(cstr);
                            let ptr = owned_strings.last().unwrap().as_ptr() as *mut c_char;
                            params.push(OsslParam::construct_utf8_string(
                                OSSL_PKEY_PARAM_EC_GROUP_NAME.as_ptr() as *const c_char,
                                ptr,
                                0,
                            ));
                        }
                        Err(e) => {
                            log::error!("Failed to build EC group string: {}", e);
                            return 0;
                        }
                    },
                    Err(e) => {
                        log::error!("Failed to resolve EC group short name: {}", e);
                        return 0;
                    }
                }
            }

            // Provide encoding metadata expected by OpenSSL
            owned_strings.push(CString::new("encoded-point").expect("static string"));
            let encoding_ptr = owned_strings.last().unwrap().as_ptr() as *mut c_char;
            params.push(OsslParam::construct_utf8_string(
                OSSL_PKEY_PARAM_EC_ENCODING.as_ptr() as *const c_char,
                encoding_ptr,
                0,
            ));

            owned_strings.push(CString::new("uncompressed").expect("static string"));
            let format_ptr = owned_strings.last().unwrap().as_ptr() as *mut c_char;
            params.push(OsslParam::construct_utf8_string(
                OSSL_PKEY_PARAM_EC_POINT_CONVERSION_FORMAT.as_ptr() as *const c_char,
                format_ptr,
                0,
            ));

            let mut ctx = match BigNumContext::new() {
                Ok(ctx) => ctx,
                Err(e) => {
                    log::error!("Failed to allocate BigNumContext: {}", e);
                    return 0;
                }
            };

            match ec.public_key().to_bytes(
                ec.group(),
                PointConversionForm::UNCOMPRESSED,
                &mut ctx,
            ) {
                Ok(bytes) => ec_point_bytes = bytes,
                Err(e) => {
                    log::error!("Failed to encode EC public point: {}", e);
                    return 0;
                }
            }

            if ec_point_bytes.is_empty() {
                log::error!("EC key export encountered empty public point");
                return 0;
            }

            params.push(OsslParam::construct_octet_string(
                OSSL_PKEY_PARAM_PUB_KEY.as_ptr() as *const c_char,
                ec_point_bytes.as_mut_ptr() as *mut c_void,
                ec_point_bytes.len(),
            ));
        }
        _ => unreachable!(),
    }

    params.push(OsslParam::end());

    type ExportCallback = unsafe extern "C" fn(*const OsslParam, *mut c_void) -> c_int;
    let cb: ExportCallback = std::mem::transmute(callback);

    let result = cb(params.as_ptr(), cbarg);

    if result == 0 {
        log::error!("Key export callback reported failure");
    } else {
        log::debug!("akv_keymgmt_export -> 1");
    }

    result
}

// ============================================================================
// RSA-specific KEYMGMT Functions
// ============================================================================

/// Get gettable parameters for RSA keys
#[no_mangle]
pub unsafe extern "C" fn akv_rsa_keymgmt_gettable_params(_provctx: *mut c_void) -> *const OsslParam {
    log::trace!("akv_rsa_keymgmt_gettable_params");
    // Return empty list for now
        static END_PARAM: OsslParam = OsslParam::end();
        log::debug!("akv_rsa_keymgmt_gettable_params -> {:p}", &END_PARAM as *const OsslParam);
        &END_PARAM as *const OsslParam
}

/// Get settable parameters for RSA keys
#[no_mangle]
pub unsafe extern "C" fn akv_rsa_keymgmt_settable_params(_provctx: *mut c_void) -> *const OsslParam {
    log::trace!("akv_rsa_keymgmt_settable_params");
    static END_PARAM: OsslParam = OsslParam::end();
    log::debug!("akv_rsa_keymgmt_settable_params -> {:p}", &END_PARAM as *const OsslParam);
    &END_PARAM as *const OsslParam
}

/// Import types for RSA keys
#[no_mangle]
pub unsafe extern "C" fn akv_rsa_keymgmt_eximport_types(_selection: c_int) -> *const OsslParam {
    log::trace!("akv_rsa_keymgmt_eximport_types selection=0x{:x}", _selection);

    if (_selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0 || _selection == 0 {
        let ptr = RSA_EXPORT_TYPES.as_ptr();
        log::debug!("akv_rsa_keymgmt_eximport_types -> {:p}", ptr);
        ptr
    } else {
        log::debug!("akv_rsa_keymgmt_eximport_types -> NULL");
        ptr::null()
    }
}

/// Import an RSA key (stub for now)
#[no_mangle]
pub unsafe extern "C" fn akv_rsa_keymgmt_import(
    _vkey: *mut c_void,
    _selection: c_int,
    _params: *const OsslParam,
) -> c_int {
    log::trace!("akv_rsa_keymgmt_import (stub)");
    log::debug!("akv_rsa_keymgmt_import -> 0 (not implemented)");
    0
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
    static END_PARAM: OsslParam = OsslParam::end();
    log::debug!("akv_ec_keymgmt_gettable_params -> {:p}", &END_PARAM as *const OsslParam);
    &END_PARAM as *const OsslParam
}

/// Get settable parameters for EC keys
#[no_mangle]
pub unsafe extern "C" fn akv_ec_keymgmt_settable_params(_provctx: *mut c_void) -> *const OsslParam {
    log::trace!("akv_ec_keymgmt_settable_params");
    static END_PARAM: OsslParam = OsslParam::end();
    log::debug!("akv_ec_keymgmt_settable_params -> {:p}", &END_PARAM as *const OsslParam);
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
    _vkey: *mut c_void,
    _selection: c_int,
    _params: *const OsslParam,
) -> c_int {
    log::trace!("akv_ec_keymgmt_import (stub)");
    log::debug!("akv_ec_keymgmt_import -> 0 (not implemented)");
    0
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
    log::trace!("akv_aes_keymgmt_load reference={:p} size={}", reference, reference_sz);
    
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
    log::trace!("akv_aes_keymgmt_has key={:p} selection=0x{:x}", vkey, selection);
    
    if vkey.is_null() {
        log::debug!("akv_aes_keymgmt_has -> 0 (null key)");
        return 0;
    }
    
    let key = &*(vkey as *const AkvAesKey);
    
    // AES keys are symmetric, so private == public
    if (selection & (OSSL_KEYMGMT_SELECT_PRIVATE_KEY | OSSL_KEYMGMT_SELECT_PUBLIC_KEY)) != 0 
        && !akv_aes_key_has_private(key) {
        log::debug!("akv_aes_keymgmt_has -> 0 (missing key metadata)");
        return 0;
    }
    
    log::debug!("akv_aes_keymgmt_has -> 1");
    1
}

/// Get gettable parameters for AES keys
#[no_mangle]
pub unsafe extern "C" fn akv_aes_keymgmt_gettable_params(_provctx: *mut c_void) -> *const OsslParam {
    log::trace!("akv_aes_keymgmt_gettable_params");
    static END_PARAM: OsslParam = OsslParam::end();
    log::debug!("akv_aes_keymgmt_gettable_params -> {:p}", &END_PARAM as *const OsslParam);
    &END_PARAM as *const OsslParam
}

/// Get settable parameters for AES keys
#[no_mangle]
pub unsafe extern "C" fn akv_aes_keymgmt_settable_params(_provctx: *mut c_void) -> *const OsslParam {
    log::trace!("akv_aes_keymgmt_settable_params");
    static END_PARAM: OsslParam = OsslParam::end();
    log::debug!("akv_aes_keymgmt_settable_params -> {:p}", &END_PARAM as *const OsslParam);
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

