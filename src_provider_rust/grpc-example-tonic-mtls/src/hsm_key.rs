//! Load an EVP_PKEY from an OpenSSL provider via OSSL_STORE.
//!
//! The Rust `openssl` 0.10 crate has no safe wrapper around `OSSL_STORE_open`,
//! so we drop down to `openssl-sys` FFI. We only need the private-key load path;
//! the AKV provider registers a custom store loader for `managedhsm:` URIs that
//! returns an EVP_PKEY whose private operations dispatch to the HSM over REST.
//!
//! Preconditions:
//!   * `OPENSSL_CONF` must point at a config file that activates the akv_provider.
//!   * The provider's shared library must be reachable via the config's
//!     `module = ...` line or via `OSSL_MODULES`.
//!   * Azure auth env must be set (the provider uses az identity).
//!
//! On failure we surface the OpenSSL error stack as a single string so callers
//! get one actionable message instead of generic `errno`-style noise.

use openssl::error::ErrorStack;
use openssl::pkey::{PKey, Private};
use openssl_sys::EVP_PKEY;
use std::ffi::CString;
use std::os::raw::{c_char, c_int, c_void};
use std::ptr;

// OSSL_STORE_INFO type discriminants — values from OpenSSL 3.x <openssl/store.h>.
const OSSL_STORE_INFO_PKEY: c_int = 4;

// Opaque types we only ever hold as pointers.
#[repr(C)] pub struct OsslStoreCtx { _private: [u8; 0] }
#[repr(C)] pub struct OsslStoreInfo { _private: [u8; 0] }
#[repr(C)] pub struct OsslLibCtx { _private: [u8; 0] }
#[repr(C)] pub struct UiMethod { _private: [u8; 0] }
#[repr(C)] pub struct OsslParam { _private: [u8; 0] }

type UiReaderCb = Option<unsafe extern "C" fn(*mut c_void) -> c_int>;

// openssl-sys links libcrypto/libssl into the final binary, so these extern
// declarations resolve via the same dynamic library.
extern "C" {
    fn OSSL_STORE_open_ex(
        uri: *const c_char,
        libctx: *mut OsslLibCtx,
        propq: *const c_char,
        ui_method: *mut UiMethod,
        ui_data: *mut c_void,
        params: *const OsslParam,
        post_process: UiReaderCb,
        post_process_data: *mut c_void,
    ) -> *mut OsslStoreCtx;

    fn OSSL_STORE_load(ctx: *mut OsslStoreCtx) -> *mut OsslStoreInfo;
    fn OSSL_STORE_eof(ctx: *mut OsslStoreCtx) -> c_int;
    fn OSSL_STORE_close(ctx: *mut OsslStoreCtx) -> c_int;

    fn OSSL_STORE_INFO_get_type(info: *const OsslStoreInfo) -> c_int;
    fn OSSL_STORE_INFO_get1_PKEY(info: *const OsslStoreInfo) -> *mut EVP_PKEY;
    fn OSSL_STORE_INFO_free(info: *mut OsslStoreInfo);
}

/// Load a private key from the OpenSSL store at `uri`.
///
/// Iterates STORE info objects until the first private key is found; everything
/// else (certs, params, public keys) is freed and skipped. If no key is present
/// before EOF, returns an error.
pub fn load_pkey_from_store(uri: &str) -> Result<PKey<Private>, String> {
    let c_uri = CString::new(uri).map_err(|e| format!("uri has NUL byte: {e}"))?;

    unsafe {
        let ctx = OSSL_STORE_open_ex(
            c_uri.as_ptr(),
            ptr::null_mut(),
            ptr::null(),
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null(),
            None,
            ptr::null_mut(),
        );
        if ctx.is_null() {
            return Err(format!(
                "OSSL_STORE_open_ex({uri}) failed: {}",
                openssl_errors()
            ));
        }

        let mut found: *mut EVP_PKEY = ptr::null_mut();
        while OSSL_STORE_eof(ctx) == 0 {
            let info = OSSL_STORE_load(ctx);
            if info.is_null() {
                // OpenSSL returns NULL for transient errors as well as legit
                // "skip this item". Re-check EOF on next loop.
                if OSSL_STORE_eof(ctx) != 0 {
                    break;
                }
                continue;
            }
            let kind = OSSL_STORE_INFO_get_type(info);
            if kind == OSSL_STORE_INFO_PKEY {
                found = OSSL_STORE_INFO_get1_PKEY(info);
                OSSL_STORE_INFO_free(info);
                break;
            }
            OSSL_STORE_INFO_free(info);
        }

        OSSL_STORE_close(ctx);

        if found.is_null() {
            return Err(format!(
                "no private key returned by store '{uri}': {}",
                openssl_errors()
            ));
        }

        // Take ownership via openssl crate so Drop runs EVP_PKEY_free.
        Ok(PKey::<Private>::from_ptr(found))
    }
}

fn openssl_errors() -> String {
    let stack = ErrorStack::get();
    if stack.errors().is_empty() {
        "<no openssl error on stack>".to_string()
    } else {
        stack
            .errors()
            .iter()
            .map(|e| e.to_string())
            .collect::<Vec<_>>()
            .join("; ")
    }
}

// Bring `ForeignType::from_ptr` into scope so we can adopt the raw EVP_PKEY
// returned by OpenSSL into a Rust-owned `PKey<Private>` (Drop runs EVP_PKEY_free).
use foreign_types::ForeignType;
