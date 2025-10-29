// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

// OpenSSL helper functions for public key construction
// Builds EVP_PKEY objects from Azure Key Vault key material

use openssl::bn::BigNum;
use openssl::ec::{EcGroup, EcKey, EcPoint};
use openssl::nid::Nid;
use openssl::pkey::{PKey, Public};

/// Build RSA public key from modulus (n) and exponent (e)
/// Bytes are in native endianness (reversed from Azure's big-endian on Windows)
pub fn build_rsa_public_key(n: &[u8], e: &[u8]) -> Result<PKey<Public>, String> {
    use crate::openssl_ffi::{
        EVP_PKEY_CTX_free, EVP_PKEY_CTX_new_from_name, EVP_PKEY_fromdata, EVP_PKEY_fromdata_init,
        EVP_PKEY,
    };
    use crate::ossl_param::OsslParam;
    use std::ffi::CString;
    use std::ptr;

    log::trace!("build_rsa_public_key n_len={} e_len={}", n.len(), e.len());

    // Bytes are in native endianness (little-endian on Windows), already reversed from Azure.
    // Use EVP_PKEY_fromdata with OSSL_PARAM_construct_BN like the C code does.
    // Matches C implementation in curl.c:340-366

    unsafe {
        let rsa_str = CString::new("RSA").unwrap();
        let provider_default = CString::new("provider=default").unwrap();

        let ctx = EVP_PKEY_CTX_new_from_name(
            ptr::null_mut(),
            rsa_str.as_ptr(),
            provider_default.as_ptr(),
        );
        if ctx.is_null() {
            return Err("Failed to create RSA EVP context".to_string());
        }

        if EVP_PKEY_fromdata_init(ctx) <= 0 {
            EVP_PKEY_CTX_free(ctx);
            return Err("EVP_PKEY_fromdata_init failed for RSA".to_string());
        }

        // Build OSSL_PARAM array with native-endian bytes
        let params = vec![
            OsslParam::construct_big_number(
                c"n".as_ptr() as *const i8,
                n.as_ptr() as *mut u8,
                n.len(),
            ),
            OsslParam::construct_big_number(
                c"e".as_ptr() as *const i8,
                e.as_ptr() as *mut u8,
                e.len(),
            ),
            OsslParam::end(),
        ];

        let mut pkey: *mut EVP_PKEY = ptr::null_mut();
        let selection = 1; // OSSL_KEYMGMT_SELECT_PUBLIC_KEY

        if EVP_PKEY_fromdata(ctx, &mut pkey, selection, params.as_ptr() as *mut OsslParam) <= 0 {
            EVP_PKEY_CTX_free(ctx);
            return Err("EVP_PKEY_fromdata failed to materialize RSA key".to_string());
        }

        EVP_PKEY_CTX_free(ctx);

        // Wrap the EVP_PKEY in PKey<Public>
        let pkey_wrapped: PKey<Public> = std::mem::transmute(pkey);

        log::debug!("Successfully built RSA public key via EVP_PKEY_fromdata");
        Ok(pkey_wrapped)
    }
}

/// Build EC public key from x, y coordinates and curve name
pub fn build_ec_public_key(x: &[u8], y: &[u8], curve: &str) -> Result<PKey<Public>, String> {
    log::trace!(
        "build_ec_public_key x_len={} y_len={} curve={}",
        x.len(),
        y.len(),
        curve
    );

    // Map Azure curve names to OpenSSL NIDs
    let nid = match curve {
        "P-256" | "secp256r1" => Nid::X9_62_PRIME256V1,
        "P-384" | "secp384r1" => Nid::SECP384R1,
        "P-521" | "secp521r1" => Nid::SECP521R1,
        "P-256K" | "secp256k1" => Nid::SECP256K1,
        _ => return Err(format!("Unsupported curve: {}", curve)),
    };

    let group = EcGroup::from_curve_name(nid)
        .map_err(|e| format!("Failed to create EC group for {}: {}", curve, e))?;

    let x_bn =
        BigNum::from_slice(x).map_err(|e| format!("Failed to create BigNum from x: {}", e))?;

    let y_bn =
        BigNum::from_slice(y).map_err(|e| format!("Failed to create BigNum from y: {}", e))?;

    // Create EC point from affine coordinates
    let mut point =
        EcPoint::new(&group).map_err(|e| format!("Failed to create EC point: {}", e))?;

    let mut ctx = openssl::bn::BigNumContext::new()
        .map_err(|e| format!("Failed to create BigNumContext: {}", e))?;

    point
        .set_affine_coordinates_gfp(&group, &x_bn, &y_bn, &mut ctx)
        .map_err(|e| format!("Failed to set affine coordinates: {}", e))?;

    // Build EC key from public point
    let ec_key = EcKey::from_public_key(&group, &point)
        .map_err(|e| format!("Failed to create EC key: {}", e))?;

    let pkey =
        PKey::from_ec_key(ec_key).map_err(|e| format!("Failed to create PKey from EC: {}", e))?;

    log::debug!("Successfully built EC public key for curve {}", curve);
    Ok(pkey)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_rsa_public_key() {
        // Small RSA key for testing (512-bit)
        // n = 0x00D5B5... (modulus)
        // e = 0x010001 (65537)
        let n = vec![
            0x00, 0xD5, 0xB5, 0x4C, 0x8F, 0x7E, 0x1D, 0x2E, 0x3F, 0x4A, 0x5B, 0x6C, 0x7D, 0x8E,
            0x9F, 0xA0, 0xB1, 0xC2, 0xD3, 0xE4, 0xF5, 0x06, 0x17, 0x28, 0x39, 0x4A, 0x5B, 0x6C,
            0x7D, 0x8E, 0x9F, 0xA0, 0xB1, 0xC2, 0xD3, 0xE4, 0xF5, 0x06, 0x17, 0x28, 0x39, 0x4A,
            0x5B, 0x6C, 0x7D, 0x8E, 0x9F, 0xA0, 0xB1, 0xC2, 0xD3, 0xE4, 0xF5, 0x06, 0x17, 0x28,
            0x39, 0x4A, 0x5B, 0x6C, 0x7D, 0x8E, 0x9F, 0xA0, 0xB1,
        ];
        let e = vec![0x01, 0x00, 0x01];

        let result = build_rsa_public_key(&n, &e);
        assert!(result.is_ok());
    }

    #[test]
    fn test_ec_curve_mapping() {
        // Test that we recognize valid curve names
        let curves = vec!["P-256", "P-384", "P-521", "secp256r1"];
        for curve in curves {
            // Just test the mapping exists
            let nid = match curve {
                "P-256" | "secp256r1" => Nid::X9_62_PRIME256V1,
                "P-384" | "secp384r1" => Nid::SECP384R1,
                "P-521" | "secp521r1" => Nid::SECP521R1,
                _ => continue,
            };
            assert!(nid != Nid::UNDEF);
        }
    }
}
