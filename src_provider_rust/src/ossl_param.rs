// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

// OpenSSL OSSL_PARAM handling
// Provides Rust-friendly wrappers for OpenSSL parameter structures

use std::os::raw::{c_char, c_int, c_uint, c_void};
use std::ptr;

/// OSSL_PARAM structure (matches OpenSSL's definition)
/// Used to pass parameters between OpenSSL and provider
#[repr(C)]
#[derive(Copy, Clone)]
pub struct OsslParam {
    pub key: *const c_char,
    pub data_type: c_uint,
    pub data: *mut c_void,
    pub data_size: usize,
    pub return_size: usize,
}

// Mark OsslParam as safe to share between threads
// This is safe because it's only used in FFI contexts with static data
unsafe impl Sync for OsslParam {}

// OpenSSL parameter data types
pub const OSSL_PARAM_INTEGER: c_uint = 1;
pub const OSSL_PARAM_UNSIGNED_INTEGER: c_uint = 2;
pub const OSSL_PARAM_REAL: c_uint = 3;
pub const OSSL_PARAM_UTF8_STRING: c_uint = 4;
pub const OSSL_PARAM_OCTET_STRING: c_uint = 5;
pub const OSSL_PARAM_UTF8_PTR: c_uint = 6;
pub const OSSL_PARAM_OCTET_PTR: c_uint = 7;

// OpenSSL parameter names (from core_names.h)
pub const OSSL_PROV_PARAM_NAME: &[u8] = b"name\0";
pub const OSSL_PROV_PARAM_VERSION: &[u8] = b"version\0";
pub const OSSL_PROV_PARAM_BUILDINFO: &[u8] = b"buildinfo\0";
pub const OSSL_PROV_PARAM_STATUS: &[u8] = b"status\0";

pub const OSSL_OBJECT_PARAM_TYPE: &[u8] = b"type\0";
pub const OSSL_OBJECT_PARAM_DATA_TYPE: &[u8] = b"data-type\0";
pub const OSSL_OBJECT_PARAM_REFERENCE: &[u8] = b"reference\0";

// Object types
pub const OSSL_OBJECT_PKEY: c_int = 2; // From OpenSSL core_object.h

impl OsslParam {
    /// Create an end-of-array marker
    pub const fn end() -> Self {
        Self {
            key: ptr::null(),
            data_type: 0,
            data: ptr::null_mut(),
            data_size: 0,
            return_size: 0,
        }
    }

    /// Create a UTF8 string pointer parameter
    pub const fn construct_utf8_ptr(key: *const c_char, value: *mut *const c_char) -> Self {
        Self {
            key,
            data_type: OSSL_PARAM_UTF8_PTR,
            data: value as *mut c_void,
            data_size: 0,
            return_size: 0,
        }
    }

    /// Create an integer parameter
    pub fn construct_int(key: *const c_char, value: *mut c_int) -> Self {
        Self {
            key,
            data_type: OSSL_PARAM_INTEGER,
            data: value as *mut c_void,
            data_size: std::mem::size_of::<c_int>(),
            return_size: 0,
        }
    }

    /// Create an octet string parameter
    pub fn construct_octet_string(key: *const c_char, value: *mut c_void, size: usize) -> Self {
        Self {
            key,
            data_type: OSSL_PARAM_OCTET_STRING,
            data: value,
            data_size: size,
            return_size: 0,
        }
    }

    /// Create an unsigned big number parameter (binary big-endian data)
    pub fn construct_big_number(key: *const c_char, value: *mut u8, size: usize) -> Self {
        Self {
            key,
            data_type: OSSL_PARAM_UNSIGNED_INTEGER,
            data: value as *mut c_void,
            data_size: size,
            return_size: 0,
        }
    }

    /// Create a size_t parameter (uses unsigned integer representation)
    pub fn construct_size_t(key: *const c_char, value: *mut usize) -> Self {
        Self {
            key,
            data_type: OSSL_PARAM_UNSIGNED_INTEGER,
            data: value as *mut c_void,
            data_size: std::mem::size_of::<usize>(),
            return_size: 0,
        }
    }

    /// Create a UTF8 string parameter
    pub fn construct_utf8_string(key: *const c_char, value: *mut c_char, value_len: usize) -> Self {
        Self {
            key,
            data_type: OSSL_PARAM_UTF8_STRING,
            data: value as *mut c_void,
            data_size: value_len,
            return_size: 0,
        }
    }

    /// Locate a parameter by key in an array
    pub unsafe fn locate(params: *mut OsslParam, key: *const c_char) -> *mut OsslParam {
        if params.is_null() || key.is_null() {
            return ptr::null_mut();
        }

        let mut p = params;
        while !(*p).key.is_null() {
            if libc::strcmp((*p).key, key) == 0 {
                return p;
            }
            p = p.add(1);
        }
        ptr::null_mut()
    }

    /// Set a UTF8 string pointer parameter value
    pub unsafe fn set_utf8_ptr(&mut self, value: *const c_char) -> bool {
        if self.data_type != OSSL_PARAM_UTF8_PTR {
            return false;
        }

        let ptr_ref = self.data as *mut *const c_char;
        if ptr_ref.is_null() {
            return false;
        }

        *ptr_ref = value;
        true
    }

    /// Set an integer parameter value
    pub unsafe fn set_int(&mut self, value: c_int) -> bool {
        if self.data_type != OSSL_PARAM_INTEGER {
            return false;
        }

        let int_ref = self.data as *mut c_int;
        if int_ref.is_null() {
            return false;
        }

        *int_ref = value;
        true
    }

    /// Get an integer parameter value
    pub unsafe fn get_int(param: *const OsslParam) -> Option<c_int> {
        if param.is_null() || (*param).data_type != OSSL_PARAM_INTEGER {
            return None;
        }

        let int_ref = (*param).data as *const c_int;
        if int_ref.is_null() {
            return None;
        }

        Some(*int_ref)
    }

    /// Get a UTF8 string pointer parameter value
    pub unsafe fn get_utf8_string_ptr(param: *const OsslParam) -> Option<*const c_char> {
        if param.is_null() {
            return None;
        }

        if (*param).data_type == OSSL_PARAM_UTF8_PTR {
            let ptr_ref = (*param).data as *const *const c_char;
            if ptr_ref.is_null() {
                return None;
            }
            Some(*ptr_ref)
        } else if (*param).data_type == OSSL_PARAM_UTF8_STRING {
            Some((*param).data as *const c_char)
        } else {
            None
        }
    }
}

/// Static parameter array for gettable params
pub static PROVIDER_GETTABLE_PARAMS: [OsslParam; 5] = [
    OsslParam {
        key: OSSL_PROV_PARAM_NAME.as_ptr() as *const c_char,
        data_type: OSSL_PARAM_UTF8_PTR,
        data: ptr::null_mut(),
        data_size: 0,
        return_size: 0,
    },
    OsslParam {
        key: OSSL_PROV_PARAM_VERSION.as_ptr() as *const c_char,
        data_type: OSSL_PARAM_UTF8_PTR,
        data: ptr::null_mut(),
        data_size: 0,
        return_size: 0,
    },
    OsslParam {
        key: OSSL_PROV_PARAM_BUILDINFO.as_ptr() as *const c_char,
        data_type: OSSL_PARAM_UTF8_PTR,
        data: ptr::null_mut(),
        data_size: 0,
        return_size: 0,
    },
    OsslParam {
        key: OSSL_PROV_PARAM_STATUS.as_ptr() as *const c_char,
        data_type: OSSL_PARAM_INTEGER,
        data: ptr::null_mut(),
        data_size: std::mem::size_of::<c_int>(),
        return_size: 0,
    },
    OsslParam::end(),
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_param_end() {
        let param = OsslParam::end();
        assert!(param.key.is_null());
        assert_eq!(param.data_type, 0);
    }

    #[test]
    fn test_gettable_params_array() {
        assert_eq!(PROVIDER_GETTABLE_PARAMS.len(), 5);
        // Last element should be end marker
        assert!(PROVIDER_GETTABLE_PARAMS[4].key.is_null());
    }
}
