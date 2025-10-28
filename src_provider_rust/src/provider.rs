// Provider core functionality
// Corresponds to akv_provider.c

use openssl::pkey::{PKey, Public};
use std::os::raw::c_void;

/// Provider context structure (corresponds to AKV_PROVIDER_CTX)
#[repr(C)]
pub struct ProviderContext {
    /// OpenSSL core handle
    pub core: *const c_void,
}

impl ProviderContext {
    pub fn new(core: *const c_void) -> Self {
        Self { core }
    }
}

/// Azure Key Vault key structure (corresponds to AKV_KEY)
pub struct AkvKey {
    pub provctx: *mut ProviderContext,
    pub public_key: Option<PKey<Public>>,
    pub keyvault_name: Option<String>,
    pub key_name: Option<String>,
    pub key_version: Option<String>,
}

impl AkvKey {
    /// Create a new AKV key with the given provider context
    pub fn new(provctx: *mut ProviderContext) -> Self {
        log::trace!("akv_key_new provctx={:p}", provctx);
        Self {
            provctx,
            public_key: None,
            keyvault_name: None,
            key_name: None,
            key_version: None,
        }
    }

    /// Set key metadata (vault name, key name, version)
    pub fn set_metadata(&mut self, vault: &str, name: &str, version: Option<&str>) -> bool {
        log::trace!(
            "akv_key_set_metadata vault={} name={} version={:?}",
            vault,
            name,
            version
        );

        self.keyvault_name = Some(vault.to_string());
        self.key_name = Some(name.to_string());
        self.key_version = version.map(|v| v.to_string());

        log::debug!("akv_key_set_metadata -> true");
        true
    }

    /// Set the public key
    pub fn set_public(&mut self, pkey: PKey<Public>) {
        log::trace!("akv_key_set_public");
        self.public_key = Some(pkey);
        log::debug!("akv_key_set_public complete");
    }
}

impl Drop for AkvKey {
    fn drop(&mut self) {
        log::trace!("akv_key_free");
        log::debug!("akv_key_free complete");
    }
}

/// AES key structure for symmetric operations
pub struct AkvAesKey {
    pub provctx: *mut ProviderContext,
    pub keyvault_name: Option<String>,
    pub key_name: Option<String>,
    pub key_version: Option<String>,
    pub key_bits: usize,
}

impl AkvAesKey {
    pub fn new(provctx: *mut ProviderContext) -> Self {
        Self {
            provctx,
            keyvault_name: None,
            key_name: None,
            key_version: None,
            key_bits: 256, // Default to 256-bit
        }
    }

    pub fn set_metadata(&mut self, vault: &str, name: &str, version: Option<&str>, bits: usize) {
        self.keyvault_name = Some(vault.to_string());
        self.key_name = Some(name.to_string());
        self.key_version = version.map(|v| v.to_string());
        self.key_bits = bits;
    }
}

/// URI parsing result for key-value style URIs
pub struct ParsedUri {
    pub vault_name: String,
    pub key_name: String,
    pub key_version: Option<String>,
}

/// Parse a Key Vault URI
fn has_case_prefix(input: &str, prefix: &str) -> bool {
    log::trace!("has_case_prefix input={} prefix={}", input, prefix);
    let result = input.len() >= prefix.len() && input[..prefix.len()].eq_ignore_ascii_case(prefix);
    log::debug!("has_case_prefix -> {}", result);
    result
}

/// Parse URI in key-value format: akv:type=managedhsm,vault=name,name=keyname,version=v1
pub fn parse_uri_keyvalue(uri: &str) -> Result<ParsedUri, String> {
    log::trace!("parse_uri_keyvalue uri={}", uri);

    if !has_case_prefix(uri, "akv:") {
        log::debug!("parse_uri_keyvalue -> Err (missing akv prefix)");
        return Err("URI must start with 'akv:' prefix".to_string());
    }

    let cursor = &uri[4..]; // Skip "akv:"
    let mut vault_name: Option<String> = None;
    let mut key_name: Option<String> = None;
    let mut key_version: Option<String> = None;
    let mut type_validated = false;

    for token in cursor.split(',') {
        if let Some(equals_pos) = token.find('=') {
            let key = &token[..equals_pos];
            let value = &token[equals_pos + 1..];

            match key.to_lowercase().as_str() {
                "keyvault_type" | "type" => {
                    if !value.eq_ignore_ascii_case("managedhsm") {
                        log::debug!("parse_uri_keyvalue -> Err (unsupported keyvault type)");
                        return Err(format!("Unsupported keyvault type: {}", value));
                    }
                    type_validated = true;
                }
                "keyvault_name" | "vault" => {
                    vault_name = Some(value.to_string());
                }
                "key_name" | "name" => {
                    key_name = Some(value.to_string());
                }
                "key_version" | "version" => {
                    key_version = Some(value.to_string());
                }
                _ => {
                    // Ignore unknown parameters
                }
            }
        }
    }

    // Treat missing type as managedhsm by default (for legacy URIs)
    if !type_validated {
        type_validated = true;
    }

    match (type_validated, vault_name, key_name) {
        (true, Some(vault), Some(name)) => {
            log::debug!(
                "parse_uri_keyvalue parsed vault={} name={} version={:?}",
                vault,
                name,
                key_version
            );
            Ok(ParsedUri {
                vault_name: vault,
                key_name: name,
                key_version,
            })
        }
        _ => {
            log::debug!("parse_uri_keyvalue -> Err (missing required fields)");
            Err("Missing required fields (vault and name)".to_string())
        }
    }
}

/// Parse URI in simple format: managedhsm:vaultname:keyname
pub fn parse_uri_simple(uri: &str) -> Result<ParsedUri, String> {
    log::trace!("parse_uri_simple uri={}", uri);

    if !has_case_prefix(uri, "managedhsm:") {
        log::debug!("parse_uri_simple -> Err (missing managedhsm prefix)");
        return Err("URI must start with 'managedhsm:' prefix".to_string());
    }

    let cursor = &uri[11..]; // Skip "managedhsm:"

    if let Some(sep_pos) = cursor.find(':') {
        let vault_name = cursor[..sep_pos].to_string();
        let key_name = cursor[sep_pos + 1..].to_string();

        log::debug!(
            "parse_uri_simple parsed vault={} name={}",
            vault_name,
            key_name
        );

        Ok(ParsedUri {
            vault_name,
            key_name,
            key_version: None,
        })
    } else {
        log::debug!("parse_uri_simple -> Err (missing separator)");
        Err("Missing ':' separator between vault and key name".to_string())
    }
}

/// Try to parse URI using both formats (keyvalue first, then simple)
pub fn parse_uri(uri: &str) -> Result<ParsedUri, String> {
    parse_uri_keyvalue(uri).or_else(|_| parse_uri_simple(uri))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_uri_keyvalue() {
        let uri = "akv:type=managedhsm,vault=myvault,name=mykey,version=v1";
        let result = parse_uri_keyvalue(uri).unwrap();
        assert_eq!(result.vault_name, "myvault");
        assert_eq!(result.key_name, "mykey");
        assert_eq!(result.key_version, Some("v1".to_string()));
    }

    #[test]
    fn test_parse_uri_keyvalue_no_version() {
        let uri = "akv:vault=myvault,name=mykey";
        let result = parse_uri_keyvalue(uri).unwrap();
        assert_eq!(result.vault_name, "myvault");
        assert_eq!(result.key_name, "mykey");
        assert_eq!(result.key_version, None);
    }

    #[test]
    fn test_parse_uri_simple() {
        let uri = "managedhsm:myvault:mykey";
        let result = parse_uri_simple(uri).unwrap();
        assert_eq!(result.vault_name, "myvault");
        assert_eq!(result.key_name, "mykey");
        assert_eq!(result.key_version, None);
    }

    #[test]
    fn test_has_case_prefix() {
        assert!(has_case_prefix("akv:test", "akv:"));
        assert!(has_case_prefix("AKV:test", "akv:"));
        assert!(!has_case_prefix("test", "akv:"));
    }
}
