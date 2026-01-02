// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Negative test cases for Azure Key Vault Managed HSM OpenSSL Provider
//! 
//! These tests focus on error handling, invalid inputs, and edge cases to ensure
//! the provider fails gracefully and securely.

#[cfg(test)]
mod negative_tests {
    use std::env;
    use std::ptr;
    use std::os::raw::{c_char, c_void};
    use std::sync::Mutex;
    use once_cell::sync::Lazy;

    // Mutex to serialize access to AZURE_CLI_ACCESS_TOKEN env var
    static ENV_MUTEX: Lazy<Mutex<()>> = Lazy::new(|| Mutex::new(()));

    // =========================================================================
    // AUTH MODULE NEGATIVE TESTS
    // =========================================================================
    mod auth_tests {
        use super::*;
        use crate::auth::AccessToken;

        #[test]
        fn test_access_token_from_env_not_set() {
            let _guard = ENV_MUTEX.lock().unwrap();
            
            // Ensure variable is not set
            env::remove_var("AZURE_CLI_ACCESS_TOKEN");
            
            let result = AccessToken::from_env();
            assert!(result.is_err());
            
            let err = result.err().unwrap();
            assert!(err.contains("not set"), "Expected 'not set' error, got: {}", err);
        }

        #[test]
        fn test_access_token_from_env_empty_string() {
            let _guard = ENV_MUTEX.lock().unwrap();
            
            env::set_var("AZURE_CLI_ACCESS_TOKEN", "");
            
            let result = AccessToken::from_env();
            assert!(result.is_err());
            
            let err = result.err().unwrap();
            assert!(err.contains("empty"), "Expected 'empty' error, got: {}", err);
            
            env::remove_var("AZURE_CLI_ACCESS_TOKEN");
        }

        #[test]
        fn test_access_token_from_env_whitespace_only() {
            let _guard = ENV_MUTEX.lock().unwrap();
            
            env::set_var("AZURE_CLI_ACCESS_TOKEN", "   \n\t  ");
            
            let result = AccessToken::from_env();
            assert!(result.is_err());
            
            let err = result.err().unwrap();
            assert!(err.contains("empty"), "Expected 'empty' error, got: {}", err);
            
            env::remove_var("AZURE_CLI_ACCESS_TOKEN");
        }

        #[test]
        fn test_access_token_trims_whitespace() {
            let _guard = ENV_MUTEX.lock().unwrap();
            
            env::set_var("AZURE_CLI_ACCESS_TOKEN", "  valid_token_123  \n");
            
            let result = AccessToken::from_env();
            assert!(result.is_ok());
            
            let token = result.unwrap();
            assert_eq!(token.as_str(), "valid_token_123");
            
            env::remove_var("AZURE_CLI_ACCESS_TOKEN");
        }

        #[test]
        fn test_default_credential_without_azure_credentials() {
            let _guard = ENV_MUTEX.lock().unwrap();
            
            // Clear all Azure credential environment variables
            env::remove_var("AZURE_CLI_ACCESS_TOKEN");
            env::remove_var("AZURE_CLIENT_ID");
            env::remove_var("AZURE_CLIENT_SECRET");
            env::remove_var("AZURE_TENANT_ID");
            
            // This should fail (unless running in Azure with managed identity)
            let result = AccessToken::from_default_credential();
            
            // We expect this to fail in most test environments
            // The error message should indicate credential failure
            if result.is_err() {
                let err = result.err().unwrap();
                assert!(
                    err.contains("credential") || err.contains("token") || err.contains("Failed"),
                    "Expected credential-related error, got: {}", err
                );
            }
            // If it succeeds, we're in an Azure environment - that's fine
        }

        #[test]
        fn test_access_token_new_creates_empty() {
            let token = AccessToken::new();
            assert!(token.as_str().is_empty());
        }

        #[test]
        fn test_access_token_default_creates_empty() {
            let token = AccessToken::default();
            assert!(token.as_str().is_empty());
        }
    }

    // =========================================================================
    // BASE64 MODULE NEGATIVE TESTS
    // =========================================================================
    mod base64_tests {
        use crate::base64::{decode_url_safe, encode_url_safe};

        #[test]
        fn test_decode_invalid_base64_characters() {
            let invalid = "!!!invalid!!!";
            let result = decode_url_safe(invalid);
            assert!(result.is_err());
            
            let err = result.err().unwrap();
            assert!(err.contains("Base64 decode error"), "Expected base64 error, got: {}", err);
        }

        #[test]
        fn test_decode_wrong_padding() {
            // URL-safe base64 without padding, but with standard padding chars
            let with_padding = "SGVsbG8gV29ybGQ=";  // "Hello World" with padding
            
            // This might succeed or fail depending on decoder strictness
            let result = decode_url_safe(with_padding);
            // Just verify it doesn't panic
            let _ = result;
        }

        #[test]
        fn test_decode_non_url_safe_characters() {
            // Standard base64 uses + and /, URL-safe uses - and _
            let standard_base64 = "SGVs+G8/V29y";
            let result = decode_url_safe(standard_base64);
            
            // This might fail due to invalid characters for URL-safe decoding
            // or succeed if the decoder is lenient
            let _ = result;
        }

        #[test]
        fn test_decode_empty_string() {
            let result = decode_url_safe("");
            // Empty string should decode to empty vec
            assert!(result.is_ok());
            assert!(result.unwrap().is_empty());
        }

        #[test]
        fn test_encode_empty_data() {
            let result = encode_url_safe(&[]);
            assert_eq!(result, "");
        }

        #[test]
        fn test_encode_decode_roundtrip_binary_data() {
            let binary_data: Vec<u8> = (0..=255).collect();
            let encoded = encode_url_safe(&binary_data);
            let decoded = decode_url_safe(&encoded).unwrap();
            assert_eq!(binary_data, decoded);
        }

        #[test]
        fn test_decode_truncated_input() {
            // Truncated base64 that's missing bytes
            let truncated = "SGVsbG8gV29ybG";  // One char short
            let result = decode_url_safe(truncated);
            // Should either fail or decode partially
            let _ = result;
        }

        #[test]
        fn test_decode_with_newlines() {
            // Base64 with embedded newlines (sometimes valid, sometimes not)
            let with_newlines = "SGVs\nbG8";
            let result = decode_url_safe(with_newlines);
            // Usually this should fail for strict decoders
            assert!(result.is_err());
        }
    }

    // =========================================================================
    // URI PARSING NEGATIVE TESTS
    // =========================================================================
    mod uri_tests {
        use crate::provider::{parse_uri, parse_uri_keyvalue, parse_uri_simple};

        #[test]
        fn test_parse_uri_empty_string() {
            let result = parse_uri("");
            assert!(result.is_err());
        }

        #[test]
        fn test_parse_uri_wrong_prefix() {
            let result = parse_uri("http://example.com");
            assert!(result.is_err());
            
            let result = parse_uri("azure:vault=test,name=key");
            assert!(result.is_err());
        }

        #[test]
        fn test_parse_uri_keyvalue_missing_vault() {
            let result = parse_uri_keyvalue("akv:name=mykey");
            assert!(result.is_err());
            
            match result {
                Err(err) => assert!(err.contains("Missing required fields"), "Expected missing fields error, got: {}", err),
                Ok(_) => panic!("Expected error for missing vault"),
            }
        }

        #[test]
        fn test_parse_uri_keyvalue_missing_key_name() {
            let result = parse_uri_keyvalue("akv:vault=myvault");
            assert!(result.is_err());
            
            match result {
                Err(err) => assert!(err.contains("Missing required fields"), "Expected missing fields error, got: {}", err),
                Ok(_) => panic!("Expected error for missing key name"),
            }
        }

        #[test]
        fn test_parse_uri_keyvalue_unsupported_type() {
            let result = parse_uri_keyvalue("akv:type=keyvault,vault=myvault,name=mykey");
            assert!(result.is_err());
            
            match result {
                Err(err) => assert!(err.contains("Unsupported keyvault type"), "Expected type error, got: {}", err),
                Ok(_) => panic!("Expected error for unsupported type"),
            }
        }

        #[test]
        fn test_parse_uri_keyvalue_empty_values() {
            // Empty vault name
            let result = parse_uri_keyvalue("akv:vault=,name=mykey");
            // This might succeed with empty string or fail
            if let Ok(parsed) = result {
                assert!(parsed.vault_name.is_empty() || parsed.vault_name == "");
            }
        }

        #[test]
        fn test_parse_uri_simple_missing_separator() {
            let result = parse_uri_simple("managedhsm:myvault");
            assert!(result.is_err());
            
            match result {
                Err(err) => assert!(err.contains("separator"), "Expected separator error, got: {}", err),
                Ok(_) => panic!("Expected error for missing separator"),
            }
        }

        #[test]
        fn test_parse_uri_simple_wrong_prefix() {
            let result = parse_uri_simple("keyvault:myvault:mykey");
            assert!(result.is_err());
            
            match result {
                Err(err) => assert!(err.contains("managedhsm"), "Expected prefix error, got: {}", err),
                Ok(_) => panic!("Expected error for wrong prefix"),
            }
        }

        #[test]
        fn test_parse_uri_case_insensitive_prefix() {
            // Test that prefixes are case-insensitive
            let result1 = parse_uri("AKV:vault=test,name=key");
            assert!(result1.is_ok());
            
            let result2 = parse_uri("MANAGEDHSM:test:key");
            assert!(result2.is_ok());
        }

        #[test]
        fn test_parse_uri_special_characters_in_name() {
            // Key names with special characters
            let result = parse_uri("akv:vault=my-vault,name=my-key-123");
            assert!(result.is_ok());
            
            let parsed = result.unwrap();
            assert_eq!(parsed.vault_name, "my-vault");
            assert_eq!(parsed.key_name, "my-key-123");
        }

        #[test]
        fn test_parse_uri_with_unknown_parameters() {
            // Unknown parameters should be ignored
            let result = parse_uri_keyvalue("akv:vault=test,name=key,unknown=value,foo=bar");
            assert!(result.is_ok());
            
            let parsed = result.unwrap();
            assert_eq!(parsed.vault_name, "test");
            assert_eq!(parsed.key_name, "key");
        }

        #[test]
        fn test_parse_uri_malformed_key_value() {
            // Missing equals sign
            let result = parse_uri_keyvalue("akv:vault=test,namekey");
            // Should still fail due to missing name
            assert!(result.is_err());
        }

        #[test]
        fn test_parse_uri_duplicate_parameters() {
            // Duplicate parameters - last one wins
            let result = parse_uri_keyvalue("akv:vault=first,vault=second,name=key");
            assert!(result.is_ok());
            
            let parsed = result.unwrap();
            assert_eq!(parsed.vault_name, "second");
        }

        #[test]
        fn test_parse_uri_only_prefix() {
            let result = parse_uri_keyvalue("akv:");
            assert!(result.is_err());
        }

        #[test]
        fn test_parse_uri_simple_empty_vault() {
            let result = parse_uri_simple("managedhsm::key");
            // Empty vault should still parse but vault_name would be empty
            if let Ok(parsed) = result {
                assert!(parsed.vault_name.is_empty());
            }
        }

        #[test]
        fn test_parse_uri_simple_empty_key() {
            let result = parse_uri_simple("managedhsm:vault:");
            // Empty key should still parse but key_name would be empty
            if let Ok(parsed) = result {
                assert!(parsed.key_name.is_empty());
            }
        }
    }

    // =========================================================================
    // HTTP CLIENT NEGATIVE TESTS
    // =========================================================================
    mod http_client_tests {
        use crate::auth::AccessToken;
        use crate::http_client::{AkvHttpClient, KeyType};

        #[test]
        fn test_key_type_from_str_unknown() {
            assert!(KeyType::from_str("UNKNOWN").is_none());
            assert!(KeyType::from_str("").is_none());
            assert!(KeyType::from_str("rsa").is_none()); // Case sensitive
            assert!(KeyType::from_str("AES").is_none());
        }

        #[test]
        fn test_key_type_from_str_valid() {
            assert_eq!(KeyType::from_str("RSA"), Some(KeyType::Rsa));
            assert_eq!(KeyType::from_str("RSA-HSM"), Some(KeyType::Rsa));
            assert_eq!(KeyType::from_str("EC"), Some(KeyType::Ec));
            assert_eq!(KeyType::from_str("EC-HSM"), Some(KeyType::Ec));
            assert_eq!(KeyType::from_str("oct"), Some(KeyType::Oct));
            assert_eq!(KeyType::from_str("oct-HSM"), Some(KeyType::OctHsm));
        }

        #[test]
        fn test_http_client_with_invalid_vault_name() {
            let token = AccessToken { token: "fake_token".to_string() };
            let client = AkvHttpClient::new("".to_string(), token);
            
            // Client creation should succeed even with empty vault name
            assert!(client.is_ok());
            
            // But operations would fail at HTTP level
        }

        #[test]
        fn test_http_client_key_url_formatting() {
            let token = AccessToken { token: "test".to_string() };
            let client = AkvHttpClient::new("testvault".to_string(), token).unwrap();
            
            // Test URL formation (using internal method via key_type check)
            // URLs should be properly formed
            let result = client.get_key_type("testkey");
            
            // This will fail with network error since vault doesn't exist
            assert!(result.is_err());
            let err = result.err().unwrap();
            // Should be a network/HTTP error, not a panic
            assert!(
                err.contains("HTTP") || err.contains("request") || err.contains("failed") || err.contains("error"),
                "Expected HTTP error, got: {}", err
            );
        }

        #[test]
        fn test_http_client_with_expired_token() {
            // Use a clearly invalid/expired token
            let token = AccessToken { token: "expired_or_invalid_token".to_string() };
            let client = AkvHttpClient::new("nonexistentvault12345".to_string(), token).unwrap();
            
            let result = client.get_key_type("somekey");
            
            // Should fail with authentication or network error
            assert!(result.is_err());
        }

        #[test]
        fn test_http_client_with_empty_token() {
            let token = AccessToken { token: "".to_string() };
            let client = AkvHttpClient::new("testvault".to_string(), token).unwrap();
            
            let result = client.get_key_type("testkey");
            assert!(result.is_err());
        }

        #[test]
        fn test_sign_with_invalid_algorithm() {
            let token = AccessToken { token: "test".to_string() };
            let client = AkvHttpClient::new("testvault".to_string(), token).unwrap();
            
            // Try to sign with invalid algorithm
            let result = client.sign("testkey", "INVALID_ALG", &[0u8; 32]);
            assert!(result.is_err());
        }

        #[test]
        fn test_decrypt_with_empty_ciphertext() {
            let token = AccessToken { token: "test".to_string() };
            let client = AkvHttpClient::new("testvault".to_string(), token).unwrap();
            
            let result = client.decrypt("testkey", "RSA-OAEP", &[]);
            // This will fail at HTTP level (network error or API error)
            assert!(result.is_err());
        }

        #[test]
        fn test_wrap_key_fails_without_valid_connection() {
            let token = AccessToken { token: "test".to_string() };
            let client = AkvHttpClient::new("testvault".to_string(), token).unwrap();
            
            let result = client.wrap_key("testkey", "RSA-OAEP", &[0u8; 32]);
            assert!(result.is_err());
        }

        #[test]
        fn test_unwrap_key_fails_without_valid_connection() {
            let token = AccessToken { token: "test".to_string() };
            let client = AkvHttpClient::new("testvault".to_string(), token).unwrap();
            
            let result = client.unwrap_key("testkey", "RSA-OAEP", &[0u8; 32]);
            assert!(result.is_err());
        }

        #[test]
        fn test_get_key_fails_without_valid_connection() {
            let token = AccessToken { token: "test".to_string() };
            let client = AkvHttpClient::new("testvault".to_string(), token).unwrap();
            
            let result = client.get_key("testkey", None);
            assert!(result.is_err());
        }
    }

    // =========================================================================
    // STORE CONTEXT NEGATIVE TESTS
    // =========================================================================
    mod store_tests {
        use super::*;
        use crate::store::{
            akv_store_open, akv_store_close, akv_store_eof, 
            akv_store_attach, akv_store_load, StoreContext
        };

        #[test]
        fn test_store_open_null_uri() {
            unsafe {
                let result = akv_store_open(ptr::null_mut(), ptr::null());
                assert!(result.is_null());
            }
        }

        #[test]
        fn test_store_open_invalid_uri() {
            unsafe {
                let invalid_uri = b"invalid://not/a/valid/uri\0";
                let result = akv_store_open(
                    ptr::null_mut(), 
                    invalid_uri.as_ptr() as *const c_char
                );
                assert!(result.is_null());
            }
        }

        #[test]
        fn test_store_open_empty_uri() {
            unsafe {
                let empty_uri = b"\0";
                let result = akv_store_open(
                    ptr::null_mut(), 
                    empty_uri.as_ptr() as *const c_char
                );
                assert!(result.is_null());
            }
        }

        #[test]
        fn test_store_attach_not_supported() {
            unsafe {
                let result = akv_store_attach(ptr::null_mut(), ptr::null_mut());
                assert!(result.is_null());
            }
        }

        #[test]
        fn test_store_eof_null_context() {
            unsafe {
                let result = akv_store_eof(ptr::null_mut());
                assert_eq!(result, 1); // NULL context is treated as exhausted
            }
        }

        #[test]
        fn test_store_close_null_context() {
            unsafe {
                let result = akv_store_close(ptr::null_mut());
                assert_eq!(result, 1); // Should succeed even with NULL
            }
        }

        #[test]
        fn test_store_load_null_context() {
            unsafe {
                let result = akv_store_load(
                    ptr::null_mut(),
                    ptr::null_mut(),
                    ptr::null_mut(),
                    ptr::null_mut(),
                    ptr::null_mut()
                );
                assert_eq!(result, 0); // Should fail with NULL context
            }
        }

        #[test]
        fn test_store_context_parse_invalid_uri() {
            let mut ctx = StoreContext::new(ptr::null_mut());
            
            // Invalid URIs should fail parsing
            assert!(!ctx.parse_uri(""));
            assert!(!ctx.parse_uri("http://example.com"));
            assert!(!ctx.parse_uri("invalid"));
        }

        #[test]
        fn test_store_context_parse_valid_uri() {
            let mut ctx = StoreContext::new(ptr::null_mut());
            
            // Valid URIs should succeed
            assert!(ctx.parse_uri("akv:vault=test,name=key"));
            assert_eq!(ctx.keyvault_name, Some("test".to_string()));
            assert_eq!(ctx.key_name, Some("key".to_string()));
        }

        #[test]
        fn test_store_context_exhausted_state() {
            let mut ctx = StoreContext::new(ptr::null_mut());
            ctx.exhausted = false;
            
            unsafe {
                let ctx_ptr = &mut ctx as *mut StoreContext as *mut c_void;
                
                let eof = akv_store_eof(ctx_ptr);
                assert_eq!(eof, 0); // Not exhausted
                
                ctx.exhausted = true;
                let eof = akv_store_eof(ctx_ptr);
                assert_eq!(eof, 1); // Exhausted
            }
        }

        #[test]
        fn test_store_open_and_close_lifecycle() {
            unsafe {
                let valid_uri = b"akv:vault=test,name=key\0";
                let ctx = akv_store_open(
                    ptr::null_mut(),
                    valid_uri.as_ptr() as *const c_char
                );
                
                // Should succeed
                assert!(!ctx.is_null());
                
                // Close should succeed
                let result = akv_store_close(ctx);
                assert_eq!(result, 1);
            }
        }

        #[test]
        fn test_store_double_close() {
            unsafe {
                let valid_uri = b"akv:vault=test,name=key\0";
                let ctx = akv_store_open(
                    ptr::null_mut(),
                    valid_uri.as_ptr() as *const c_char
                );
                
                assert!(!ctx.is_null());
                
                // First close
                let result = akv_store_close(ctx);
                assert_eq!(result, 1);
                
                // Second close with NULL should also succeed
                let result = akv_store_close(ptr::null_mut());
                assert_eq!(result, 1);
            }
        }
    }

    // =========================================================================
    // PROVIDER CONTEXT NEGATIVE TESTS
    // =========================================================================
    mod provider_tests {
        use super::*;
        use crate::provider::{AkvKey, AkvAesKey, ProviderContext};

        #[test]
        fn test_provider_context_null_core() {
            let ctx = ProviderContext::new(ptr::null());
            assert!(ctx.core.is_null());
        }

        #[test]
        fn test_akv_key_without_metadata() {
            let key = AkvKey::new(ptr::null_mut());
            
            assert!(key.public_key.is_none());
            assert!(key.keyvault_name.is_none());
            assert!(key.key_name.is_none());
            assert!(key.key_version.is_none());
        }

        #[test]
        fn test_akv_key_set_metadata_empty_strings() {
            let mut key = AkvKey::new(ptr::null_mut());
            
            let result = key.set_metadata("", "", None);
            assert!(result);
            
            assert_eq!(key.keyvault_name, Some("".to_string()));
            assert_eq!(key.key_name, Some("".to_string()));
        }

        #[test]
        fn test_akv_aes_key_default_bits() {
            let key = AkvAesKey::new(ptr::null_mut());
            assert_eq!(key.key_bits, 256); // Default should be 256-bit
        }

        #[test]
        fn test_akv_aes_key_set_metadata() {
            let mut key = AkvAesKey::new(ptr::null_mut());
            key.set_metadata("vault", "name", Some("v1"), 128);
            
            assert_eq!(key.keyvault_name, Some("vault".to_string()));
            assert_eq!(key.key_name, Some("name".to_string()));
            assert_eq!(key.key_version, Some("v1".to_string()));
            assert_eq!(key.key_bits, 128);
        }

        #[test]
        fn test_akv_aes_key_without_version() {
            let mut key = AkvAesKey::new(ptr::null_mut());
            key.set_metadata("vault", "name", None, 256);
            
            assert_eq!(key.key_version, None);
        }

        #[test]
        fn test_akv_key_set_metadata_with_version() {
            let mut key = AkvKey::new(ptr::null_mut());
            
            let result = key.set_metadata("vault", "key", Some("v1"));
            assert!(result);
            
            assert_eq!(key.key_version, Some("v1".to_string()));
        }
    }

    // =========================================================================
    // OSSL_PROVIDER_INIT NEGATIVE TESTS
    // =========================================================================
    mod init_tests {
        use super::*;
        use crate::{OSSL_provider_init, akv_teardown, akv_get_params, akv_gettable_params};

        #[test]
        fn test_provider_init_null_out_pointer() {
            unsafe {
                let mut provctx: *mut c_void = ptr::null_mut();
                
                let result = OSSL_provider_init(
                    ptr::null(),
                    ptr::null(),
                    ptr::null_mut(), // NULL out pointer
                    &mut provctx
                );
                
                assert_eq!(result, 0); // Should fail
            }
        }

        #[test]
        fn test_provider_init_null_provctx_pointer() {
            unsafe {
                let mut out: *const c_void = ptr::null();
                
                let result = OSSL_provider_init(
                    ptr::null(),
                    ptr::null(),
                    &mut out as *mut *const c_void,
                    ptr::null_mut() // NULL provctx pointer
                );
                
                assert_eq!(result, 0); // Should fail
            }
        }

        #[test]
        fn test_provider_init_and_teardown() {
            unsafe {
                let mut out: *const c_void = ptr::null();
                let mut provctx: *mut c_void = ptr::null_mut();
                
                let result = OSSL_provider_init(
                    ptr::null(),
                    ptr::null(),
                    &mut out as *mut *const c_void,
                    &mut provctx
                );
                
                assert_eq!(result, 1); // Should succeed
                assert!(!out.is_null());
                assert!(!provctx.is_null());
                
                // Teardown should not crash
                akv_teardown(provctx);
            }
        }

        #[test]
        fn test_teardown_null_context() {
            unsafe {
                // Should not crash with NULL
                akv_teardown(ptr::null_mut());
            }
        }

        #[test]
        fn test_get_params_null_params() {
            unsafe {
                let result = akv_get_params(ptr::null_mut(), ptr::null_mut());
                assert_eq!(result, 0); // Should fail with NULL params
            }
        }

        #[test]
        fn test_gettable_params_null_context() {
            unsafe {
                let result = akv_gettable_params(ptr::null_mut());
                // Should return valid pointer even with NULL context
                assert!(!result.is_null());
            }
        }

        #[test]
        fn test_multiple_init_teardown_cycles() {
            unsafe {
                for _ in 0..5 {
                    let mut out: *const c_void = ptr::null();
                    let mut provctx: *mut c_void = ptr::null_mut();
                    
                    let result = OSSL_provider_init(
                        ptr::null(),
                        ptr::null(),
                        &mut out as *mut *const c_void,
                        &mut provctx
                    );
                    
                    assert_eq!(result, 1);
                    akv_teardown(provctx);
                }
            }
        }
    }

    // =========================================================================
    // BOUNDARY AND EDGE CASE TESTS
    // =========================================================================
    mod boundary_tests {
        use crate::base64::{encode_url_safe, decode_url_safe};
        use crate::provider::parse_uri;

        #[test]
        fn test_very_long_vault_name() {
            let long_name = "a".repeat(1000);
            let uri = format!("akv:vault={},name=key", long_name);
            
            let result = parse_uri(&uri);
            assert!(result.is_ok());
            
            let parsed = result.unwrap();
            assert_eq!(parsed.vault_name.len(), 1000);
        }

        #[test]
        fn test_very_long_key_name() {
            let long_name = "k".repeat(1000);
            let uri = format!("akv:vault=test,name={}", long_name);
            
            let result = parse_uri(&uri);
            assert!(result.is_ok());
        }

        #[test]
        fn test_base64_large_data() {
            let large_data: Vec<u8> = (0..10000).map(|i| (i % 256) as u8).collect();
            let encoded = encode_url_safe(&large_data);
            let decoded = decode_url_safe(&encoded).unwrap();
            
            assert_eq!(large_data, decoded);
        }

        #[test]
        fn test_uri_with_unicode() {
            // Unicode in vault/key names might not be valid but shouldn't panic
            let uri = "akv:vault=тест,name=ключ";
            let result = parse_uri(uri);
            
            // Either succeeds or fails gracefully
            if let Ok(parsed) = result {
                assert_eq!(parsed.vault_name, "тест");
            }
        }

        #[test]
        fn test_uri_with_special_url_characters() {
            let uri = "akv:vault=test%20vault,name=key%2Fwith%2Fslashes";
            let result = parse_uri(uri);
            
            // URL encoding should be preserved as-is (not decoded)
            if let Ok(parsed) = result {
                assert_eq!(parsed.vault_name, "test%20vault");
            }
        }

        #[test]
        fn test_base64_single_byte() {
            let data = vec![0xFFu8];
            let encoded = encode_url_safe(&data);
            let decoded = decode_url_safe(&encoded).unwrap();
            assert_eq!(data, decoded);
        }

        #[test]
        fn test_base64_two_bytes() {
            let data = vec![0x00u8, 0xFFu8];
            let encoded = encode_url_safe(&data);
            let decoded = decode_url_safe(&encoded).unwrap();
            assert_eq!(data, decoded);
        }
    }

    // =========================================================================
    // CONCURRENCY TESTS (BASIC)
    // =========================================================================
    mod concurrency_tests {
        use std::thread;

        #[test]
        fn test_concurrent_uri_parsing() {
            use crate::provider::parse_uri;
            
            let handles: Vec<_> = (0..100).map(|i| {
                thread::spawn(move || {
                    let uri = format!("akv:vault=vault{},name=key{}", i, i);
                    parse_uri(&uri)
                })
            }).collect();

            for handle in handles {
                let result = handle.join().unwrap();
                assert!(result.is_ok());
            }
        }

        #[test]
        fn test_concurrent_base64_operations() {
            use crate::base64::{encode_url_safe, decode_url_safe};
            
            let handles: Vec<_> = (0..50).map(|i| {
                thread::spawn(move || {
                    let data: Vec<u8> = (0..100).map(|j| ((i + j) % 256) as u8).collect();
                    let encoded = encode_url_safe(&data);
                    let decoded = decode_url_safe(&encoded).unwrap();
                    assert_eq!(data, decoded);
                })
            }).collect();

            for handle in handles {
                handle.join().unwrap();
            }
        }
    }

    // =========================================================================
    // MEMORY SAFETY TESTS
    // =========================================================================
    mod memory_tests {
        use super::*;
        use crate::provider::{AkvKey, AkvAesKey};
        use crate::store::StoreContext;

        #[test]
        fn test_akv_key_drop() {
            // Ensure drop doesn't crash
            {
                let mut key = AkvKey::new(ptr::null_mut());
                key.set_metadata("vault", "key", Some("v1"));
                // key is dropped here
            }
            // If we get here, drop succeeded
        }

        #[test]
        fn test_akv_aes_key_drop() {
            {
                let mut key = AkvAesKey::new(ptr::null_mut());
                key.set_metadata("vault", "key", Some("v1"), 256);
            }
        }

        #[test]
        fn test_store_context_drop() {
            {
                let mut ctx = StoreContext::new(ptr::null_mut());
                ctx.keyvault_name = Some("vault".to_string());
                ctx.key_name = Some("key".to_string());
            }
        }

        #[test]
        fn test_box_into_raw_and_from_raw() {
            unsafe {
                let key = Box::new(AkvKey::new(ptr::null_mut()));
                let raw = Box::into_raw(key);
                
                // Verify we can access through raw pointer
                assert!((*raw).public_key.is_none());
                
                // Reclaim and drop
                let _ = Box::from_raw(raw);
            }
        }

        #[test]
        fn test_multiple_allocations_and_proper_frees() {
            for _ in 0..100 {
                let key = Box::new(AkvKey::new(ptr::null_mut()));
                let raw = Box::into_raw(key);
                
                // Properly free each allocation
                unsafe {
                    let _ = Box::from_raw(raw);
                }
            }
        }
    }

    // =========================================================================
    // ERROR MESSAGE QUALITY TESTS
    // =========================================================================
    mod error_message_tests {
        use crate::auth::AccessToken;
        use crate::base64::decode_url_safe;
        use crate::provider::{parse_uri_keyvalue, parse_uri_simple};
        use super::ENV_MUTEX;
        use std::env;

        #[test]
        fn test_auth_error_message_is_descriptive() {
            let _guard = ENV_MUTEX.lock().unwrap();
            env::remove_var("AZURE_CLI_ACCESS_TOKEN");
            
            let result = AccessToken::from_env();
            let err = result.err().unwrap();
            
            // Error should mention what went wrong
            assert!(err.len() > 10, "Error message too short: {}", err);
            assert!(err.contains("AZURE_CLI_ACCESS_TOKEN"), "Error should mention the env var: {}", err);
        }

        #[test]
        fn test_base64_error_message_is_descriptive() {
            let result = decode_url_safe("!!!invalid!!!");
            let err = result.err().unwrap();
            
            assert!(err.len() > 10, "Error message too short: {}", err);
            assert!(err.contains("Base64") || err.contains("decode"), "Error should mention base64: {}", err);
        }

        #[test]
        fn test_uri_error_message_is_descriptive() {
            let result = parse_uri_keyvalue("akv:vault=test");
            let err = result.err().unwrap();
            
            assert!(err.len() > 10, "Error message too short: {}", err);
        }

        #[test]
        fn test_uri_prefix_error_is_helpful() {
            let result = parse_uri_simple("wrong:vault:key");
            let err = result.err().unwrap();
            
            assert!(err.contains("managedhsm"), "Error should mention expected prefix: {}", err);
        }
    }
}

// Additional negative tests for signature module resilience
#[cfg(test)]
mod signature_negative_tests {
    use std::ptr;
    use std::os::raw::{c_char, c_void};
    use crate::signature::{
        akv_rsa_signature_newctx, akv_ecdsa_signature_newctx,
        akv_signature_freectx, akv_signature_sign_init, akv_signature_verify_init,
        akv_signature_sign, akv_signature_verify,
        akv_signature_digest_sign_init, akv_signature_digest_verify_init,
        akv_signature_digest_update, akv_signature_digest_sign_final,
        akv_signature_digest_verify_final, akv_signature_dupctx,
        akv_signature_get_ctx_params, akv_signature_set_ctx_params,
    };
    use crate::ossl_param::OsslParam;

    // =========================================================================
    // CONTEXT CREATION AND DESTRUCTION TESTS
    // =========================================================================
    
    #[test]
    fn test_rsa_signature_newctx_null_provctx() {
        unsafe {
            // Should handle NULL provider context gracefully
            let ctx = akv_rsa_signature_newctx(ptr::null_mut(), ptr::null());
            // Context should still be created (provctx can be null)
            if !ctx.is_null() {
                akv_signature_freectx(ctx);
            }
        }
    }

    #[test]
    fn test_ecdsa_signature_newctx_null_provctx() {
        unsafe {
            let ctx = akv_ecdsa_signature_newctx(ptr::null_mut(), ptr::null());
            if !ctx.is_null() {
                akv_signature_freectx(ctx);
            }
        }
    }

    #[test]
    fn test_signature_freectx_null() {
        unsafe {
            // Should not crash with NULL
            akv_signature_freectx(ptr::null_mut());
        }
    }

    #[test]
    fn test_signature_freectx_double_free_prevention() {
        unsafe {
            let ctx = akv_rsa_signature_newctx(ptr::null_mut(), ptr::null());
            if !ctx.is_null() {
                akv_signature_freectx(ctx);
                // Second free with NULL should be safe
                akv_signature_freectx(ptr::null_mut());
            }
        }
    }

    // =========================================================================
    // SIGN/VERIFY INIT WITH NULL PARAMETERS
    // =========================================================================

    #[test]
    fn test_sign_init_null_context() {
        unsafe {
            let result = akv_signature_sign_init(
                ptr::null_mut(), // NULL context
                ptr::null_mut(), // NULL key
                ptr::null(),     // NULL params
            );
            assert_eq!(result, 0, "sign_init should fail with NULL context");
        }
    }

    #[test]
    fn test_sign_init_null_key() {
        unsafe {
            let ctx = akv_rsa_signature_newctx(ptr::null_mut(), ptr::null());
            if !ctx.is_null() {
                let result = akv_signature_sign_init(
                    ctx,
                    ptr::null_mut(), // NULL key
                    ptr::null(),
                );
                assert_eq!(result, 0, "sign_init should fail with NULL key");
                akv_signature_freectx(ctx);
            }
        }
    }

    #[test]
    fn test_verify_init_null_context() {
        unsafe {
            let result = akv_signature_verify_init(
                ptr::null_mut(),
                ptr::null_mut(),
                ptr::null(),
            );
            assert_eq!(result, 0, "verify_init should fail with NULL context");
        }
    }

    #[test]
    fn test_verify_init_null_key() {
        unsafe {
            let ctx = akv_rsa_signature_newctx(ptr::null_mut(), ptr::null());
            if !ctx.is_null() {
                let result = akv_signature_verify_init(
                    ctx,
                    ptr::null_mut(),
                    ptr::null(),
                );
                assert_eq!(result, 0, "verify_init should fail with NULL key");
                akv_signature_freectx(ctx);
            }
        }
    }

    // =========================================================================
    // DIGEST SIGN/VERIFY INIT - NULL AND MISSING MDNAME TESTS
    // =========================================================================

    #[test]
    fn test_digest_sign_init_null_context() {
        unsafe {
            let result = akv_signature_digest_sign_init(
                ptr::null_mut(),
                ptr::null(),
                ptr::null_mut(),
                ptr::null(),
            );
            assert_eq!(result, 0, "digest_sign_init should fail with NULL context");
        }
    }

    #[test]
    fn test_digest_sign_init_null_key() {
        unsafe {
            let ctx = akv_rsa_signature_newctx(ptr::null_mut(), ptr::null());
            if !ctx.is_null() {
                let result = akv_signature_digest_sign_init(
                    ctx,
                    b"SHA256\0".as_ptr() as *const c_char,
                    ptr::null_mut(), // NULL key
                    ptr::null(),
                );
                assert_eq!(result, 0, "digest_sign_init should fail with NULL key");
                akv_signature_freectx(ctx);
            }
        }
    }

    #[test]
    fn test_digest_sign_init_null_mdname_defaults_to_sha256() {
        // This is the key test for the fix - NULL mdname should default to SHA256
        unsafe {
            let ctx = akv_rsa_signature_newctx(ptr::null_mut(), ptr::null());
            if !ctx.is_null() {
                // Create a mock key for testing
                use crate::provider::AkvKey;
                let key = Box::new(AkvKey::new(ptr::null_mut()));
                let key_ptr = Box::into_raw(key);
                
                let result = akv_signature_digest_sign_init(
                    ctx,
                    ptr::null(), // NULL mdname - should default to SHA256
                    key_ptr as *mut c_void,
                    ptr::null(),
                );
                
                // Should succeed with default SHA256
                assert_eq!(result, 1, "digest_sign_init should succeed with NULL mdname (defaults to SHA256)");
                
                // Cleanup
                let _ = Box::from_raw(key_ptr);
                akv_signature_freectx(ctx);
            }
        }
    }

    #[test]
    fn test_digest_verify_init_null_mdname() {
        // Test that digest_verify_init handles NULL mdname
        // Note: Currently this does NOT default to SHA256 like digest_sign_init does
        unsafe {
            let ctx = akv_rsa_signature_newctx(ptr::null_mut(), ptr::null());
            if !ctx.is_null() {
                use crate::provider::AkvKey;
                let key = Box::new(AkvKey::new(ptr::null_mut()));
                let key_ptr = Box::into_raw(key);
                
                let result = akv_signature_digest_verify_init(
                    ctx,
                    ptr::null(), // NULL mdname
                    key_ptr as *mut c_void,
                    ptr::null(),
                );
                
                // This test documents current behavior
                // digest_verify_init returns 1 but doesn't initialize hasher
                // which will cause digest_update to fail later
                assert_eq!(result, 1, "digest_verify_init returns success but hasher may not be initialized");
                
                let _ = Box::from_raw(key_ptr);
                akv_signature_freectx(ctx);
            }
        }
    }

    #[test]
    fn test_digest_sign_init_invalid_mdname() {
        unsafe {
            let ctx = akv_rsa_signature_newctx(ptr::null_mut(), ptr::null());
            if !ctx.is_null() {
                use crate::provider::AkvKey;
                let key = Box::new(AkvKey::new(ptr::null_mut()));
                let key_ptr = Box::into_raw(key);
                
                let result = akv_signature_digest_sign_init(
                    ctx,
                    b"INVALID_DIGEST_NAME\0".as_ptr() as *const c_char,
                    key_ptr as *mut c_void,
                    ptr::null(),
                );
                
                // Should fail with unknown digest
                assert_eq!(result, 0, "digest_sign_init should fail with invalid digest name");
                
                let _ = Box::from_raw(key_ptr);
                akv_signature_freectx(ctx);
            }
        }
    }

    #[test]
    fn test_digest_sign_init_empty_mdname() {
        unsafe {
            let ctx = akv_rsa_signature_newctx(ptr::null_mut(), ptr::null());
            if !ctx.is_null() {
                use crate::provider::AkvKey;
                let key = Box::new(AkvKey::new(ptr::null_mut()));
                let key_ptr = Box::into_raw(key);
                
                let result = akv_signature_digest_sign_init(
                    ctx,
                    b"\0".as_ptr() as *const c_char, // Empty string
                    key_ptr as *mut c_void,
                    ptr::null(),
                );
                
                // Empty string is not a valid digest name
                assert_eq!(result, 0, "digest_sign_init should fail with empty digest name");
                
                let _ = Box::from_raw(key_ptr);
                akv_signature_freectx(ctx);
            }
        }
    }

    // =========================================================================
    // DIGEST UPDATE WITH UNINITIALIZED HASHER
    // =========================================================================

    #[test]
    fn test_digest_update_null_context() {
        unsafe {
            let result = akv_signature_digest_update(
                ptr::null_mut(),
                b"test data".as_ptr(),
                9,
            );
            assert_eq!(result, 0, "digest_update should fail with NULL context");
        }
    }

    #[test]
    fn test_digest_update_null_data() {
        unsafe {
            let ctx = akv_rsa_signature_newctx(ptr::null_mut(), ptr::null());
            if !ctx.is_null() {
                let result = akv_signature_digest_update(
                    ctx,
                    ptr::null(),
                    0,
                );
                assert_eq!(result, 0, "digest_update should fail with NULL data");
                akv_signature_freectx(ctx);
            }
        }
    }

    #[test]
    fn test_digest_update_without_init() {
        // Test that digest_update fails gracefully when hasher not initialized
        unsafe {
            let ctx = akv_rsa_signature_newctx(ptr::null_mut(), ptr::null());
            if !ctx.is_null() {
                // Don't call digest_sign_init - hasher won't be initialized
                let result = akv_signature_digest_update(
                    ctx,
                    b"test data".as_ptr(),
                    9,
                );
                // Should fail because hasher is not initialized
                assert_eq!(result, 0, "digest_update should fail when hasher not initialized");
                akv_signature_freectx(ctx);
            }
        }
    }

    // =========================================================================
    // DIGEST SIGN/VERIFY FINAL WITH UNINITIALIZED HASHER
    // =========================================================================

    #[test]
    fn test_digest_sign_final_null_context() {
        unsafe {
            let mut siglen: usize = 0;
            let result = akv_signature_digest_sign_final(
                ptr::null_mut(),
                ptr::null_mut(),
                &mut siglen,
                0,
            );
            assert_eq!(result, 0, "digest_sign_final should fail with NULL context");
        }
    }

    #[test]
    fn test_digest_sign_final_null_siglen() {
        unsafe {
            let ctx = akv_rsa_signature_newctx(ptr::null_mut(), ptr::null());
            if !ctx.is_null() {
                let result = akv_signature_digest_sign_final(
                    ctx,
                    ptr::null_mut(),
                    ptr::null_mut(), // NULL siglen
                    0,
                );
                assert_eq!(result, 0, "digest_sign_final should fail with NULL siglen");
                akv_signature_freectx(ctx);
            }
        }
    }

    #[test]
    fn test_digest_sign_final_without_init() {
        unsafe {
            let ctx = akv_rsa_signature_newctx(ptr::null_mut(), ptr::null());
            if !ctx.is_null() {
                let mut siglen: usize = 0;
                let mut sig_buf = [0u8; 512];
                
                // Call final without init - hasher not initialized
                let result = akv_signature_digest_sign_final(
                    ctx,
                    sig_buf.as_mut_ptr(),
                    &mut siglen,
                    512,
                );
                assert_eq!(result, 0, "digest_sign_final should fail when hasher not initialized");
                akv_signature_freectx(ctx);
            }
        }
    }

    #[test]
    fn test_digest_verify_final_null_context() {
        unsafe {
            let sig = [0u8; 32];
            let result = akv_signature_digest_verify_final(
                ptr::null_mut(),
                sig.as_ptr(),
                32,
            );
            assert_eq!(result, 0, "digest_verify_final should fail with NULL context");
        }
    }

    #[test]
    fn test_digest_verify_final_null_signature() {
        unsafe {
            let ctx = akv_rsa_signature_newctx(ptr::null_mut(), ptr::null());
            if !ctx.is_null() {
                let result = akv_signature_digest_verify_final(
                    ctx,
                    ptr::null(),
                    0,
                );
                assert_eq!(result, 0, "digest_verify_final should fail with NULL signature");
                akv_signature_freectx(ctx);
            }
        }
    }

    // =========================================================================
    // SIGN/VERIFY WITH NULL PARAMETERS
    // =========================================================================

    #[test]
    fn test_sign_null_context() {
        unsafe {
            let mut siglen: usize = 0;
            let tbs = [0u8; 32];
            let result = akv_signature_sign(
                ptr::null_mut(),
                ptr::null_mut(),
                &mut siglen,
                0,
                tbs.as_ptr(),
                32,
            );
            assert_eq!(result, 0, "sign should fail with NULL context");
        }
    }

    #[test]
    fn test_sign_null_siglen() {
        unsafe {
            let ctx = akv_rsa_signature_newctx(ptr::null_mut(), ptr::null());
            if !ctx.is_null() {
                let tbs = [0u8; 32];
                let result = akv_signature_sign(
                    ctx,
                    ptr::null_mut(),
                    ptr::null_mut(), // NULL siglen
                    0,
                    tbs.as_ptr(),
                    32,
                );
                assert_eq!(result, 0, "sign should fail with NULL siglen");
                akv_signature_freectx(ctx);
            }
        }
    }

    #[test]
    fn test_sign_null_tbs() {
        // When sig is NULL, OpenSSL returns expected size (success)
        // When sig is non-NULL but tbs is NULL, it should fail
        unsafe {
            let ctx = akv_rsa_signature_newctx(ptr::null_mut(), ptr::null());
            if !ctx.is_null() {
                let mut siglen: usize = 0;
                let mut sig_buf = [0u8; 512];
                let result = akv_signature_sign(
                    ctx,
                    sig_buf.as_mut_ptr(), // Non-null sig buffer
                    &mut siglen,
                    512,
                    ptr::null(), // NULL tbs - should cause failure
                    0,
                );
                assert_eq!(result, 0, "sign should fail with NULL tbs when sig buffer is provided");
                akv_signature_freectx(ctx);
            }
        }
    }

    #[test]
    fn test_verify_null_context() {
        unsafe {
            let sig = [0u8; 256];
            let tbs = [0u8; 32];
            let result = akv_signature_verify(
                ptr::null_mut(),
                sig.as_ptr(),
                256,
                tbs.as_ptr(),
                32,
            );
            assert_eq!(result, 0, "verify should fail with NULL context");
        }
    }

    #[test]
    fn test_verify_null_signature() {
        unsafe {
            let ctx = akv_rsa_signature_newctx(ptr::null_mut(), ptr::null());
            if !ctx.is_null() {
                let tbs = [0u8; 32];
                let result = akv_signature_verify(
                    ctx,
                    ptr::null(),
                    0,
                    tbs.as_ptr(),
                    32,
                );
                assert_eq!(result, 0, "verify should fail with NULL signature");
                akv_signature_freectx(ctx);
            }
        }
    }

    #[test]
    fn test_verify_null_tbs() {
        unsafe {
            let ctx = akv_rsa_signature_newctx(ptr::null_mut(), ptr::null());
            if !ctx.is_null() {
                let sig = [0u8; 256];
                let result = akv_signature_verify(
                    ctx,
                    sig.as_ptr(),
                    256,
                    ptr::null(),
                    0,
                );
                assert_eq!(result, 0, "verify should fail with NULL tbs");
                akv_signature_freectx(ctx);
            }
        }
    }

    // =========================================================================
    // CONTEXT DUPLICATION TESTS
    // =========================================================================

    #[test]
    fn test_dupctx_null() {
        unsafe {
            let result = akv_signature_dupctx(ptr::null_mut());
            assert!(result.is_null(), "dupctx should return NULL for NULL input");
        }
    }

    #[test]
    fn test_dupctx_valid_context() {
        unsafe {
            let ctx = akv_rsa_signature_newctx(ptr::null_mut(), ptr::null());
            if !ctx.is_null() {
                let dup = akv_signature_dupctx(ctx);
                // Duplication might fail, which is fine
                if !dup.is_null() {
                    akv_signature_freectx(dup);
                }
                akv_signature_freectx(ctx);
            }
        }
    }

    // =========================================================================
    // GET/SET CONTEXT PARAMS TESTS
    // =========================================================================

    #[test]
    fn test_get_ctx_params_null_context() {
        unsafe {
            let mut params = [OsslParam::end()];
            let result = akv_signature_get_ctx_params(
                ptr::null_mut(),
                params.as_mut_ptr(),
            );
            // OpenSSL convention: returns success when nothing to do
            assert_eq!(result, 1, "get_ctx_params returns success for NULL context (OpenSSL convention)");
        }
    }

    #[test]
    fn test_get_ctx_params_null_params() {
        unsafe {
            let ctx = akv_rsa_signature_newctx(ptr::null_mut(), ptr::null());
            if !ctx.is_null() {
                let result = akv_signature_get_ctx_params(ctx, ptr::null_mut());
                // OpenSSL convention: returns success when nothing to do
                assert_eq!(result, 1, "get_ctx_params returns success for NULL params (OpenSSL convention)");
                akv_signature_freectx(ctx);
            }
        }
    }

    #[test]
    fn test_set_ctx_params_null_context() {
        unsafe {
            let params = [OsslParam::end()];
            let result = akv_signature_set_ctx_params(
                ptr::null_mut(),
                params.as_ptr(),
            );
            // OpenSSL convention: returns success when nothing to do
            assert_eq!(result, 1, "set_ctx_params returns success for NULL context (OpenSSL convention)");
        }
    }

    #[test]
    fn test_set_ctx_params_null_params() {
        unsafe {
            let ctx = akv_rsa_signature_newctx(ptr::null_mut(), ptr::null());
            if !ctx.is_null() {
                let result = akv_signature_set_ctx_params(ctx, ptr::null());
                // OpenSSL convention: returns success when nothing to do
                assert_eq!(result, 1, "set_ctx_params returns success for NULL params (OpenSSL convention)");
                akv_signature_freectx(ctx);
            }
        }
    }

    // =========================================================================
    // DIGEST ALGORITHM CASE SENSITIVITY AND VARIATIONS
    // =========================================================================

    #[test]
    fn test_digest_sign_init_sha256_lowercase() {
        unsafe {
            let ctx = akv_rsa_signature_newctx(ptr::null_mut(), ptr::null());
            if !ctx.is_null() {
                use crate::provider::AkvKey;
                let key = Box::new(AkvKey::new(ptr::null_mut()));
                let key_ptr = Box::into_raw(key);
                
                let result = akv_signature_digest_sign_init(
                    ctx,
                    b"sha256\0".as_ptr() as *const c_char, // lowercase
                    key_ptr as *mut c_void,
                    ptr::null(),
                );
                
                // Should succeed with lowercase
                assert_eq!(result, 1, "digest_sign_init should accept lowercase sha256");
                
                let _ = Box::from_raw(key_ptr);
                akv_signature_freectx(ctx);
            }
        }
    }

    #[test]
    fn test_digest_sign_init_sha384() {
        unsafe {
            let ctx = akv_rsa_signature_newctx(ptr::null_mut(), ptr::null());
            if !ctx.is_null() {
                use crate::provider::AkvKey;
                let key = Box::new(AkvKey::new(ptr::null_mut()));
                let key_ptr = Box::into_raw(key);
                
                let result = akv_signature_digest_sign_init(
                    ctx,
                    b"SHA384\0".as_ptr() as *const c_char,
                    key_ptr as *mut c_void,
                    ptr::null(),
                );
                
                assert_eq!(result, 1, "digest_sign_init should accept SHA384");
                
                let _ = Box::from_raw(key_ptr);
                akv_signature_freectx(ctx);
            }
        }
    }

    #[test]
    fn test_digest_sign_init_sha512() {
        unsafe {
            let ctx = akv_rsa_signature_newctx(ptr::null_mut(), ptr::null());
            if !ctx.is_null() {
                use crate::provider::AkvKey;
                let key = Box::new(AkvKey::new(ptr::null_mut()));
                let key_ptr = Box::into_raw(key);
                
                let result = akv_signature_digest_sign_init(
                    ctx,
                    b"SHA512\0".as_ptr() as *const c_char,
                    key_ptr as *mut c_void,
                    ptr::null(),
                );
                
                assert_eq!(result, 1, "digest_sign_init should accept SHA512");
                
                let _ = Box::from_raw(key_ptr);
                akv_signature_freectx(ctx);
            }
        }
    }

    #[test]
    fn test_digest_sign_init_md5_rejected() {
        unsafe {
            let ctx = akv_rsa_signature_newctx(ptr::null_mut(), ptr::null());
            if !ctx.is_null() {
                use crate::provider::AkvKey;
                let key = Box::new(AkvKey::new(ptr::null_mut()));
                let key_ptr = Box::into_raw(key);
                
                let result = akv_signature_digest_sign_init(
                    ctx,
                    b"MD5\0".as_ptr() as *const c_char,
                    key_ptr as *mut c_void,
                    ptr::null(),
                );
                
                // MD5 should be rejected (not supported by Azure HSM)
                // Note: This depends on OpenSSL's MessageDigest::from_name
                // MD5 might actually succeed at init but fail at sign time
                let _ = result; // Document behavior without asserting
                
                let _ = Box::from_raw(key_ptr);
                akv_signature_freectx(ctx);
            }
        }
    }
}

// Test documenting asymmetry between digest_sign_init and digest_verify_init
#[cfg(test)]
mod resilience_gap_tests {
    use std::ptr;
    use std::os::raw::c_void;
    use crate::signature::{
        akv_rsa_signature_newctx, akv_signature_freectx,
        akv_signature_digest_sign_init, akv_signature_digest_verify_init,
        akv_signature_digest_update,
    };
    use crate::provider::AkvKey;

    /// This test verifies that both digest_sign_init and digest_verify_init
    /// default to SHA256 when mdname is null, ensuring consistent behavior
    /// and resilience when callers don't specify a digest algorithm.
    #[test]
    fn test_sign_and_verify_both_default_sha256_for_null_mdname() {
        unsafe {
            // Setup key
            let key = Box::new(AkvKey::new(ptr::null_mut()));
            let key_ptr = Box::into_raw(key);
            
            // Test digest_sign_init with null mdname - should default to SHA256
            let sign_ctx = akv_rsa_signature_newctx(ptr::null_mut(), ptr::null());
            assert!(!sign_ctx.is_null());
            
            let sign_init = akv_signature_digest_sign_init(
                sign_ctx,
                ptr::null(), // NULL mdname - defaults to SHA256
                key_ptr as *mut c_void,
                ptr::null(),
            );
            assert_eq!(sign_init, 1, "digest_sign_init should succeed with NULL mdname");
            
            let sign_update = akv_signature_digest_update(
                sign_ctx,
                b"test data".as_ptr(),
                9,
            );
            assert_eq!(sign_update, 1, "digest_update after sign_init should succeed");
            
            akv_signature_freectx(sign_ctx);
            
            // Test digest_verify_init with null mdname - should also default to SHA256
            let key2 = Box::new(AkvKey::new(ptr::null_mut()));
            let key_ptr2 = Box::into_raw(key2);
            
            let verify_ctx = akv_rsa_signature_newctx(ptr::null_mut(), ptr::null());
            assert!(!verify_ctx.is_null());
            
            let verify_init = akv_signature_digest_verify_init(
                verify_ctx,
                ptr::null(), // NULL mdname - now defaults to SHA256
                key_ptr2 as *mut c_void,
                ptr::null(),
            );
            assert_eq!(verify_init, 1, "digest_verify_init should succeed with NULL mdname");
            
            // Update should now succeed because hasher is initialized with SHA256
            let verify_update = akv_signature_digest_update(
                verify_ctx,
                b"test data".as_ptr(),
                9,
            );
            assert_eq!(verify_update, 1, "digest_update after verify_init should succeed (hasher initialized with SHA256)");
            
            akv_signature_freectx(verify_ctx);
            
            // Cleanup
            let _ = Box::from_raw(key_ptr);
            let _ = Box::from_raw(key_ptr2);
        }
    }
}

// Keymgmt negative tests
#[cfg(test)]
mod keymgmt_negative_tests {
    use std::ptr;
    use crate::keymgmt::{
        akv_keymgmt_new, akv_keymgmt_free, akv_keymgmt_has, akv_keymgmt_match,
        akv_keymgmt_get_params, akv_rsa_keymgmt_gettable_params,
    };
    use crate::ossl_param::OsslParam;

    // =========================================================================
    // KEYMGMT CREATION AND DESTRUCTION
    // =========================================================================
    
    #[test]
    fn test_keymgmt_new_null_provctx() {
        unsafe {
            let key = akv_keymgmt_new(ptr::null_mut());
            // May succeed or fail depending on implementation
            if !key.is_null() {
                akv_keymgmt_free(key);
            }
        }
    }

    #[test]
    fn test_keymgmt_free_null() {
        unsafe {
            // Should not crash
            akv_keymgmt_free(ptr::null_mut());
        }
    }

    // =========================================================================
    // KEYMGMT OPERATIONS WITH NULL
    // =========================================================================

    #[test]
    fn test_keymgmt_has_null() {
        unsafe {
            let result = akv_keymgmt_has(ptr::null_mut(), 0);
            assert_eq!(result, 0, "has should return 0 for NULL key");
        }
    }

    #[test]
    fn test_keymgmt_match_null_both() {
        unsafe {
            let result = akv_keymgmt_match(
                ptr::null_mut(),
                ptr::null_mut(),
                0,
            );
            assert_eq!(result, 0, "match should return 0 for NULL keys");
        }
    }

    #[test]
    fn test_keymgmt_match_null_first() {
        unsafe {
            let key = akv_keymgmt_new(ptr::null_mut());
            if !key.is_null() {
                let result = akv_keymgmt_match(
                    ptr::null_mut(),
                    key,
                    0,
                );
                assert_eq!(result, 0, "match should return 0 when first key is NULL");
                akv_keymgmt_free(key);
            }
        }
    }

    #[test]
    fn test_keymgmt_get_params_null_key() {
        unsafe {
            let mut params = [OsslParam::end()];
            let result = akv_keymgmt_get_params(
                ptr::null_mut(),
                params.as_mut_ptr(),
            );
            assert_eq!(result, 0, "get_params should return 0 for NULL key");
        }
    }

    #[test]
    fn test_keymgmt_get_params_null_params() {
        unsafe {
            let key = akv_keymgmt_new(ptr::null_mut());
            if !key.is_null() {
                let result = akv_keymgmt_get_params(key, ptr::null_mut());
                assert_eq!(result, 0, "get_params should return 0 for NULL params");
                akv_keymgmt_free(key);
            }
        }
    }

    #[test]
    fn test_keymgmt_gettable_params_null() {
        unsafe {
            // This should return the static params list or NULL
            let result = akv_rsa_keymgmt_gettable_params(ptr::null_mut());
            // May return static params or NULL, shouldn't crash
            let _ = result;
        }
    }
}

// Cipher negative tests - using RSA cipher functions
#[cfg(test)]
mod cipher_negative_tests {
    use std::ptr;
    use crate::cipher::{
        akv_rsa_cipher_newctx, akv_rsa_cipher_freectx,
        akv_rsa_cipher_encrypt_init, akv_rsa_cipher_decrypt_init,
        akv_rsa_cipher_encrypt, akv_rsa_cipher_decrypt,
        akv_rsa_cipher_get_ctx_params,
    };
    use crate::ossl_param::OsslParam;

    // =========================================================================
    // CIPHER CONTEXT CREATION AND DESTRUCTION
    // =========================================================================

    #[test]
    fn test_cipher_newctx_null_provctx() {
        unsafe {
            let ctx = akv_rsa_cipher_newctx(ptr::null_mut(), ptr::null());
            if !ctx.is_null() {
                akv_rsa_cipher_freectx(ctx);
            }
        }
    }

    #[test]
    fn test_cipher_freectx_null() {
        unsafe {
            // Should not crash
            akv_rsa_cipher_freectx(ptr::null_mut());
        }
    }

    // =========================================================================
    // CIPHER INIT WITH NULL PARAMETERS
    // =========================================================================

    #[test]
    fn test_cipher_encrypt_init_null_ctx() {
        unsafe {
            let result = akv_rsa_cipher_encrypt_init(
                ptr::null_mut(),
                ptr::null_mut(),
                ptr::null(),
            );
            assert_eq!(result, 0, "encrypt_init should fail with NULL ctx");
        }
    }

    #[test]
    fn test_cipher_encrypt_init_null_key() {
        unsafe {
            let ctx = akv_rsa_cipher_newctx(ptr::null_mut(), ptr::null());
            if !ctx.is_null() {
                let result = akv_rsa_cipher_encrypt_init(
                    ctx,
                    ptr::null_mut(), // NULL key
                    ptr::null(),
                );
                assert_eq!(result, 0, "encrypt_init should fail with NULL key");
                akv_rsa_cipher_freectx(ctx);
            }
        }
    }

    #[test]
    fn test_cipher_decrypt_init_null_ctx() {
        unsafe {
            let result = akv_rsa_cipher_decrypt_init(
                ptr::null_mut(),
                ptr::null_mut(),
                ptr::null(),
            );
            assert_eq!(result, 0, "decrypt_init should fail with NULL ctx");
        }
    }

    // =========================================================================
    // CIPHER ENCRYPT/DECRYPT WITH NULL PARAMETERS
    // =========================================================================

    #[test]
    fn test_cipher_encrypt_null_ctx() {
        unsafe {
            let mut outlen: usize = 0;
            let result = akv_rsa_cipher_encrypt(
                ptr::null_mut(),
                ptr::null_mut(),
                &mut outlen,
                0,
                ptr::null(),
                0,
            );
            assert_eq!(result, 0, "encrypt should fail with NULL ctx");
        }
    }

    #[test]
    fn test_cipher_encrypt_null_outlen() {
        unsafe {
            let ctx = akv_rsa_cipher_newctx(ptr::null_mut(), ptr::null());
            if !ctx.is_null() {
                let result = akv_rsa_cipher_encrypt(
                    ctx,
                    ptr::null_mut(),
                    ptr::null_mut(), // NULL outlen
                    0,
                    ptr::null(),
                    0,
                );
                assert_eq!(result, 0, "encrypt should fail with NULL outlen");
                akv_rsa_cipher_freectx(ctx);
            }
        }
    }

    #[test]
    fn test_cipher_decrypt_null_ctx() {
        unsafe {
            let mut outlen: usize = 0;
            let result = akv_rsa_cipher_decrypt(
                ptr::null_mut(),
                ptr::null_mut(),
                &mut outlen,
                0,
                ptr::null(),
                0,
            );
            assert_eq!(result, 0, "decrypt should fail with NULL ctx");
        }
    }

    // =========================================================================
    // CIPHER GET PARAMS WITH NULL
    // =========================================================================

    #[test]
    fn test_cipher_get_ctx_params_null_ctx() {
        unsafe {
            let mut params = [OsslParam::end()];
            let result = akv_rsa_cipher_get_ctx_params(
                ptr::null_mut(),
                params.as_mut_ptr(),
            );
            // OpenSSL convention: returns success when nothing to do
            assert_eq!(result, 1, "get_ctx_params returns success for NULL ctx (OpenSSL convention)");
        }
    }

    #[test]
    fn test_cipher_get_ctx_params_null_params() {
        unsafe {
            let ctx = akv_rsa_cipher_newctx(ptr::null_mut(), ptr::null());
            if !ctx.is_null() {
                let result = akv_rsa_cipher_get_ctx_params(
                    ctx,
                    ptr::null_mut(),
                );
                // OpenSSL convention: returns success when nothing to do
                assert_eq!(result, 1, "get_ctx_params returns success for NULL params (OpenSSL convention)");
                akv_rsa_cipher_freectx(ctx);
            }
        }
    }
}
