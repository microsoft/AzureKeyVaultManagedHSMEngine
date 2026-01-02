// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

// Azure authentication utilities
// Supports both environment variable (for testing) and Azure SDK DefaultAzureCredential

use std::env;
use azure_identity::DefaultAzureCredential;
use azure_core::auth::TokenCredential;
use once_cell::sync::Lazy;
use tokio::runtime::Runtime;

const MANAGED_HSM_SCOPE: &str = "https://managedhsm.azure.net/.default";

// Lazily-initialized Tokio runtime (reused across all token acquisitions)
// Using a current-thread runtime is sufficient for token acquisition and reduces overhead
static TOKIO_RUNTIME: Lazy<Runtime> = Lazy::new(|| {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("Failed to create Tokio runtime for Azure authentication")
});

/// Memory structure for access token (corresponds to MemoryStruct in C)
#[derive(Debug, Clone)]
pub struct AccessToken {
    pub token: String,
}

impl AccessToken {
    pub fn new() -> Self {
        Self {
            token: String::new(),
        }
    }

    /// Get access token from environment variable
    /// Corresponds to GetAccessTokenFromEnv in C
    pub fn from_env() -> Result<Self, String> {
        log::trace!("AccessToken::from_env");

        let token = env::var("AZURE_CLI_ACCESS_TOKEN").map_err(|_| {
            log::error!("AZURE_CLI_ACCESS_TOKEN environment variable not set");
            "AZURE_CLI_ACCESS_TOKEN environment variable not set".to_string()
        })?;

        // Trim whitespace and newlines that may be included from shell output
        let token = token.trim().to_string();

        if token.is_empty() {
            log::error!("AZURE_CLI_ACCESS_TOKEN is empty");
            return Err("AZURE_CLI_ACCESS_TOKEN is empty".to_string());
        }

        log::debug!(
            "AccessToken::from_env -> OK (token length: {})",
            token.len()
        );

        Ok(Self { token })
    }

    /// Get the token as a string slice
    pub fn as_str(&self) -> &str {
        &self.token
    }

    /// Get access token using Azure SDK DefaultAzureCredential
    /// This will try multiple authentication methods in order:
    /// 1. Environment variables (AZURE_CLIENT_ID, AZURE_TENANT_ID, AZURE_CLIENT_SECRET)
    /// 2. Managed Identity (when running in Azure)
    /// 3. Azure CLI
    /// 4. Azure PowerShell
    pub fn from_default_credential() -> Result<Self, String> {
        log::trace!("AccessToken::from_default_credential");

        // Use the lazily-initialized static runtime (reused across calls for efficiency)
        let token = TOKIO_RUNTIME.block_on(async {
            let credential = DefaultAzureCredential::create(Default::default())
                .map_err(|e| {
                    log::error!("Failed to create DefaultAzureCredential: {}", e);
                    format!("Failed to create credential: {}", e)
                })?;
            
            log::debug!("Requesting token for scope: {}", MANAGED_HSM_SCOPE);
            
            let token_response = credential
                .get_token(&[MANAGED_HSM_SCOPE])
                .await
                .map_err(|e| {
                    log::error!("Failed to get token from DefaultAzureCredential: {}", e);
                    format!("Failed to get token: {}", e)
                })?;

            Ok::<String, String>(token_response.token.secret().to_string())
        })?;

        if token.is_empty() {
            log::error!("DefaultAzureCredential returned empty token");
            return Err("DefaultAzureCredential returned empty token".to_string());
        }

        log::debug!(
            "AccessToken::from_default_credential -> OK (token length: {})",
            token.len()
        );

        Ok(Self { token })
    }

    /// Get access token - tries environment variable first (fast), falls back to DefaultAzureCredential
    /// This is the recommended method for production use
    pub fn acquire() -> Result<Self, String> {
        log::trace!("AccessToken::acquire");

        // Try environment variable first (fast path for dev/testing)
        match Self::from_env() {
            Ok(token) => {
                log::debug!("Successfully acquired token from environment variable");
                return Ok(token);
            }
            Err(_) => {
                log::debug!("Environment variable not set, trying DefaultAzureCredential");
            }
        }

        // Fall back to DefaultAzureCredential
        Self::from_default_credential()
    }
}

impl Default for AccessToken {
    fn default() -> Self {
        Self::new()
    }
}


#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;
    use once_cell::sync::Lazy;

    // Mutex to serialize access to AZURE_CLI_ACCESS_TOKEN env var across all tests
    static ENV_MUTEX: Lazy<Mutex<()>> = Lazy::new(|| Mutex::new(()));

    #[test]
    fn test_access_token_creation() {
        let token = AccessToken::new();
        assert!(token.token.is_empty());
    }

    #[test]
    fn test_access_token_from_env_missing() {
        let _guard = ENV_MUTEX.lock().unwrap();
        
        // Clear the environment variable if it exists
        env::remove_var("AZURE_CLI_ACCESS_TOKEN");

        let result = AccessToken::from_env();
        assert!(result.is_err());
        assert!(result.err().unwrap().contains("not set"));
    }

    #[test]
    fn test_access_token_from_env_present() {
        let _guard = ENV_MUTEX.lock().unwrap();
        
        // Set a test token
        env::set_var("AZURE_CLI_ACCESS_TOKEN", "test_token_12345");

        let result = AccessToken::from_env();
        assert!(result.is_ok());

        let token = result.unwrap();
        assert_eq!(token.as_str(), "test_token_12345");

        // Clean up
        env::remove_var("AZURE_CLI_ACCESS_TOKEN");
    }

    #[test]
    fn test_access_token_from_env_empty() {
        let _guard = ENV_MUTEX.lock().unwrap();
        
        // Set an empty token
        env::set_var("AZURE_CLI_ACCESS_TOKEN", "");

        let result = AccessToken::from_env();
        assert!(result.is_err());
        assert!(result.err().unwrap().contains("empty"));

        // Clean up
        env::remove_var("AZURE_CLI_ACCESS_TOKEN");
    }

    #[test]
    fn test_default_credential_integration() {
        let _guard = ENV_MUTEX.lock().unwrap();
        
        // This test requires Azure credentials to be configured
        // It will be skipped in CI unless credentials are available
        if env::var("AZURE_CLI_ACCESS_TOKEN").is_ok() 
            || env::var("AZURE_CLIENT_ID").is_ok() 
            || std::process::Command::new("az")
                .args(&["account", "show"])
                .output()
                .map(|o| o.status.success())
                .unwrap_or(false)
        {
            // Only run if we have some form of Azure credentials
            let result = AccessToken::from_default_credential();
            // Don't assert success - just verify it doesn't panic
            match result {
                Ok(token) => {
                    assert!(!token.token.is_empty());
                    println!("DefaultAzureCredential succeeded, token length: {}", token.token.len());
                }
                Err(e) => {
                    println!("DefaultAzureCredential failed (expected in some environments): {}", e);
                }
            }
        } else {
            println!("Skipping DefaultAzureCredential test - no Azure credentials available");
        }
    }
}
