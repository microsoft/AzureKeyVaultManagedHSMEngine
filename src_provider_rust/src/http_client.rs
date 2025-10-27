// HTTP client for Azure Key Vault API
// Corresponds to curl.c

use serde::{Deserialize, Serialize};
use reqwest::blocking::Client;
use std::time::Duration;
use crate::auth::AccessToken;
use crate::base64::{decode_url_safe, encode_url_safe};

/// Azure Key Vault error response
#[derive(Debug, Deserialize)]
struct AkvError {
    error: AkvErrorDetails,
}

#[derive(Debug, Deserialize)]
struct AkvErrorDetails {
    code: Option<String>,
    message: Option<String>,
}

/// Azure Key Vault key response
#[derive(Debug, Deserialize)]
struct AkvKeyResponse {
    key: AkvKeyMaterial,
}

/// Key material from Azure Key Vault
#[derive(Debug, Deserialize)]
struct AkvKeyMaterial {
    kty: String,              // Key type: RSA, EC, oct, oct-HSM
    n: Option<String>,        // RSA modulus (base64url)
    e: Option<String>,        // RSA exponent (base64url)
    x: Option<String>,        // EC x coordinate (base64url)
    y: Option<String>,        // EC y coordinate (base64url)
    crv: Option<String>,      // EC curve name
}

/// Sign request payload
#[derive(Debug, Serialize)]
struct SignRequest {
    alg: String,
    value: String, // Base64url encoded digest
}

/// Sign response
#[derive(Debug, Deserialize)]
struct SignResponse {
    value: String, // Base64url encoded signature
}

/// Decrypt request payload
#[derive(Debug, Serialize)]
struct DecryptRequest {
    alg: String,
    value: String, // Base64url encoded ciphertext
}

/// Decrypt response
#[derive(Debug, Deserialize)]
struct DecryptResponse {
    value: String, // Base64url encoded plaintext
}

/// Wrap key request
#[derive(Debug, Serialize)]
struct WrapKeyRequest {
    alg: String,
    value: String, // Base64url encoded key to wrap
}

/// Wrap key response
#[derive(Debug, Deserialize)]
struct WrapKeyResponse {
    value: String, // Base64url encoded wrapped key
}

/// Unwrap key request
#[derive(Debug, Serialize)]
struct UnwrapKeyRequest {
    alg: String,
    value: String, // Base64url encoded wrapped key
}

/// Unwrap key response
#[derive(Debug, Deserialize)]
struct UnwrapKeyResponse {
    value: String, // Base64url encoded unwrapped key
}

/// Key type enumeration
#[derive(Debug, Clone, PartialEq)]
pub enum KeyType {
    Rsa,
    Ec,
    OctHsm,  // AES symmetric key in HSM
    Oct,     // AES symmetric key
}

impl KeyType {
    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "RSA" | "RSA-HSM" => Some(KeyType::Rsa),
            "EC" | "EC-HSM" => Some(KeyType::Ec),
            "oct-HSM" => Some(KeyType::OctHsm),
            "oct" => Some(KeyType::Oct),
            _ => None,
        }
    }
}

/// RSA public key components
#[derive(Debug)]
pub struct RsaPublicKey {
    pub n: Vec<u8>,  // Modulus
    pub e: Vec<u8>,  // Exponent
}

/// EC public key components
#[derive(Debug)]
pub struct EcPublicKey {
    pub x: Vec<u8>,         // X coordinate
    pub y: Vec<u8>,         // Y coordinate
    pub curve: String,      // Curve name (e.g., "P-256")
}

/// Public key material
#[derive(Debug)]
pub enum PublicKeyMaterial {
    Rsa(RsaPublicKey),
    Ec(EcPublicKey),
    Symmetric { _bits: usize },
}

/// HTTP client for Azure Key Vault operations
pub struct AkvHttpClient {
    client: Client,
    vault_name: String,
    access_token: String,
}

impl AkvHttpClient {
    pub fn new(vault_name: String, access_token: AccessToken) -> Result<Self, String> {
        log::trace!("AkvHttpClient::new vault={}", vault_name);
        
        let client = Client::builder()
            .timeout(Duration::from_secs(30))
            .build()
            .map_err(|e| format!("Failed to create HTTP client: {}", e))?;
            
        Ok(Self {
            client,
            vault_name,
            access_token: access_token.as_str().to_string(),
        })
    }
    
    /// Build the base URL for a key
    fn key_url(&self, key_name: &str, key_version: Option<&str>) -> String {
        let mut url = format!(
            "https://{}.managedhsm.azure.net/keys/{}",
            self.vault_name, key_name
        );
        
        if let Some(version) = key_version {
            url.push_str("/");
            url.push_str(version);
        }
        
        url
    }
    
    /// Get key type (without fetching full key material)
    /// Corresponds to AkvGetKeyType in C
    pub fn get_key_type(&self, key_name: &str) -> Result<(KeyType, Option<usize>), String> {
        log::trace!("AkvHttpClient::get_key_type key={}", key_name);
        
        let url = self.key_url(key_name, None);
        log::debug!("GET {}", url);
        
        let response = self.client
            .get(&url)
            .header("Authorization", format!("Bearer {}", self.access_token))
            .header("Accept", "application/json")
            .send()
            .map_err(|e| format!("HTTP request failed: {}", e))?;
            
        if !response.status().is_success() {
            return self.handle_error_response(response);
        }
        
        let akv_response: AkvKeyResponse = response
            .json()
            .map_err(|e| format!("Failed to parse key response: {}", e))?;
            
        let key_type = KeyType::from_str(&akv_response.key.kty)
            .ok_or_else(|| format!("Unknown key type: {}", akv_response.key.kty))?;
            
        // For symmetric keys, try to determine size (default to 256)
        let key_size = if key_type == KeyType::Oct || key_type == KeyType::OctHsm {
            Some(256) // Default to AES-256
        } else {
            None
        };
        
        log::debug!("Key type: {:?}, size: {:?}", key_type, key_size);
        
        Ok((key_type, key_size))
    }
    
    /// Get public key material
    /// Corresponds to AkvGetKey in C
    pub fn get_key(&self, key_name: &str, key_version: Option<&str>) -> Result<PublicKeyMaterial, String> {
        log::trace!("AkvHttpClient::get_key key={} version={:?}", key_name, key_version);
        
        let url = self.key_url(key_name, key_version);
        log::debug!("GET {}", url);
        
        let response = self.client
            .get(&url)
            .header("Authorization", format!("Bearer {}", self.access_token))
            .header("Accept", "application/json")
            .send()
            .map_err(|e| format!("HTTP request failed: {}", e))?;
            
        if !response.status().is_success() {
            return self.handle_error_response(response);
        }
        
        let akv_response: AkvKeyResponse = response
            .json()
            .map_err(|e| format!("Failed to parse key response: {}", e))?;
            
        self.parse_key_material(akv_response.key)
    }
    
    /// Parse key material from Azure response
    fn parse_key_material(&self, key: AkvKeyMaterial) -> Result<PublicKeyMaterial, String> {
        log::trace!("parse_key_material kty={}", key.kty);
        
        match key.kty.as_str() {
            "RSA" | "RSA-HSM" => {
                let n = key.n.ok_or("Missing RSA modulus (n)")?;
                let e = key.e.ok_or("Missing RSA exponent (e)")?;
                
                let n_bytes = decode_url_safe(&n)?;
                let e_bytes = decode_url_safe(&e)?;
                
                log::debug!("RSA key: n={} bytes, e={} bytes", n_bytes.len(), e_bytes.len());
                
                Ok(PublicKeyMaterial::Rsa(RsaPublicKey {
                    n: n_bytes,
                    e: e_bytes,
                }))
            }
            "EC" | "EC-HSM" => {
                let x = key.x.ok_or("Missing EC x coordinate")?;
                let y = key.y.ok_or("Missing EC y coordinate")?;
                let curve = key.crv.ok_or("Missing EC curve")?;
                
                let x_bytes = decode_url_safe(&x)?;
                let y_bytes = decode_url_safe(&y)?;
                
                log::debug!("EC key: curve={}, x={} bytes, y={} bytes", curve, x_bytes.len(), y_bytes.len());
                
                Ok(PublicKeyMaterial::Ec(EcPublicKey {
                    x: x_bytes,
                    y: y_bytes,
                    curve,
                }))
            }
            "oct" | "oct-HSM" => {
                // Symmetric key - we don't get the actual key material
                log::debug!("Symmetric key detected");
                Ok(PublicKeyMaterial::Symmetric { _bits: 256 })
            }
            _ => Err(format!("Unsupported key type: {}", key.kty))
        }
    }
    
    /// Sign a digest
    /// Corresponds to AkvSign in C
    pub fn sign(&self, key_name: &str, algorithm: &str, digest: &[u8]) -> Result<Vec<u8>, String> {
        log::trace!("AkvHttpClient::sign key={} alg={}", key_name, algorithm);
        
        let url = format!("{}/sign?api-version=7.2", self.key_url(key_name, None));
        log::debug!("POST {} (digest {} bytes)", url, digest.len());
        
        let request = SignRequest {
            alg: algorithm.to_string(),
            value: encode_url_safe(digest),
        };
        
        let response = self.client
            .post(&url)
            .header("Authorization", format!("Bearer {}", self.access_token))
            .header("Content-Type", "application/json")
            .json(&request)
            .send()
            .map_err(|e| format!("Sign request failed: {}", e))?;
            
        if !response.status().is_success() {
            return self.handle_error_response(response);
        }
        
        let sign_response: SignResponse = response
            .json()
            .map_err(|e| format!("Failed to parse sign response: {}", e))?;
            
        let signature = decode_url_safe(&sign_response.value)?;
        
        log::debug!("Signature received: {} bytes", signature.len());
        
        Ok(signature)
    }
    
    /// Decrypt ciphertext
    /// Corresponds to AkvDecrypt in C
    pub fn decrypt(&self, key_name: &str, algorithm: &str, ciphertext: &[u8]) -> Result<Vec<u8>, String> {
        log::trace!("AkvHttpClient::decrypt key={} alg={}", key_name, algorithm);
        
        let url = format!("{}/decrypt?api-version=7.2", self.key_url(key_name, None));
        log::debug!("POST {} (ciphertext {} bytes)", url, ciphertext.len());
        
        let request = DecryptRequest {
            alg: algorithm.to_string(),
            value: encode_url_safe(ciphertext),
        };
        
        let response = self.client
            .post(&url)
            .header("Authorization", format!("Bearer {}", self.access_token))
            .header("Content-Type", "application/json")
            .json(&request)
            .send()
            .map_err(|e| format!("Decrypt request failed: {}", e))?;
            
        if !response.status().is_success() {
            return self.handle_error_response(response);
        }
        
        let decrypt_response: DecryptResponse = response
            .json()
            .map_err(|e| format!("Failed to parse decrypt response: {}", e))?;
            
        let plaintext = decode_url_safe(&decrypt_response.value)?;
        
        log::debug!("Plaintext received: {} bytes", plaintext.len());
        
        Ok(plaintext)
    }
    
    /// Wrap a key
    /// Corresponds to AkvWrap in C
    pub fn wrap_key(&self, key_name: &str, algorithm: &str, key_to_wrap: &[u8]) -> Result<Vec<u8>, String> {
        log::trace!("AkvHttpClient::wrap_key key={} alg={}", key_name, algorithm);
        
        let url = format!("{}/wrapkey?api-version=7.2", self.key_url(key_name, None));
        log::debug!("POST {} (key {} bytes)", url, key_to_wrap.len());
        
        let request = WrapKeyRequest {
            alg: algorithm.to_string(),
            value: encode_url_safe(key_to_wrap),
        };
        
        let response = self.client
            .post(&url)
            .header("Authorization", format!("Bearer {}", self.access_token))
            .header("Content-Type", "application/json")
            .json(&request)
            .send()
            .map_err(|e| format!("Wrap key request failed: {}", e))?;
            
        if !response.status().is_success() {
            return self.handle_error_response(response);
        }
        
        let wrap_response: WrapKeyResponse = response
            .json()
            .map_err(|e| format!("Failed to parse wrap response: {}", e))?;
            
        let wrapped_key = decode_url_safe(&wrap_response.value)?;
        
        log::debug!("Wrapped key received: {} bytes", wrapped_key.len());
        
        Ok(wrapped_key)
    }
    
    /// Unwrap a key
    /// Corresponds to AkvUnwrap in C
    pub fn unwrap_key(&self, key_name: &str, algorithm: &str, wrapped_key: &[u8]) -> Result<Vec<u8>, String> {
        log::trace!("AkvHttpClient::unwrap_key key={} alg={}", key_name, algorithm);
        
        let url = format!("{}/unwrapkey?api-version=7.2", self.key_url(key_name, None));
        log::debug!("POST {} (wrapped key {} bytes)", url, wrapped_key.len());
        
        let request = UnwrapKeyRequest {
            alg: algorithm.to_string(),
            value: encode_url_safe(wrapped_key),
        };
        
        let response = self.client
            .post(&url)
            .header("Authorization", format!("Bearer {}", self.access_token))
            .header("Content-Type", "application/json")
            .json(&request)
            .send()
            .map_err(|e| format!("Unwrap key request failed: {}", e))?;
            
        if !response.status().is_success() {
            return self.handle_error_response(response);
        }
        
        let unwrap_response: UnwrapKeyResponse = response
            .json()
            .map_err(|e| format!("Failed to parse unwrap response: {}", e))?;
            
        let unwrapped_key = decode_url_safe(&unwrap_response.value)?;
        
        log::debug!("Unwrapped key received: {} bytes", unwrapped_key.len());
        
        Ok(unwrapped_key)
    }
    
    /// Handle error responses from Azure Key Vault
    fn handle_error_response<T>(&self, response: reqwest::blocking::Response) -> Result<T, String> {
        let status = response.status();
        
        // Try to parse as Azure error
        if let Ok(error) = response.json::<AkvError>() {
            let code = error.error.code.as_deref().unwrap_or("unknown");
            let message = error.error.message.as_deref().unwrap_or("no message");
            
            log::error!("Azure Key Vault error: code={}, message={}", code, message);
            
            if code.eq_ignore_ascii_case("Unauthorized") {
                return Err(format!(
                    "Azure Key Vault rejected AZURE_CLI_ACCESS_TOKEN (code={}, message={})",
                    code, message
                ));
            } else {
                return Err(format!(
                    "Azure Key Vault request failed (code={}, message={})",
                    code, message
                ));
            }
        }
        
        // Generic error
        Err(format!("HTTP error {}", status))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_key_type_from_str() {
        assert_eq!(KeyType::from_str("RSA"), Some(KeyType::Rsa));
        assert_eq!(KeyType::from_str("RSA-HSM"), Some(KeyType::Rsa));
        assert_eq!(KeyType::from_str("EC"), Some(KeyType::Ec));
        assert_eq!(KeyType::from_str("EC-HSM"), Some(KeyType::Ec));
        assert_eq!(KeyType::from_str("oct"), Some(KeyType::Oct));
        assert_eq!(KeyType::from_str("oct-HSM"), Some(KeyType::OctHsm));
        assert_eq!(KeyType::from_str("unknown"), None);
    }
    
    #[test]
    fn test_key_url_without_version() {
        let token = AccessToken { token: "test".to_string() };
        let client = AkvHttpClient::new("myvault".to_string(), token).unwrap();
        let url = client.key_url("mykey", None);
        assert_eq!(url, "https://myvault.managedhsm.azure.net/keys/mykey");
    }
    
    #[test]
    fn test_key_url_with_version() {
        let token = AccessToken { token: "test".to_string() };
        let client = AkvHttpClient::new("myvault".to_string(), token).unwrap();
        let url = client.key_url("mykey", Some("v1"));
        assert_eq!(url, "https://myvault.managedhsm.azure.net/keys/mykey/v1");
    }
}

