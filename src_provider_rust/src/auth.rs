// Azure authentication utilities
// Corresponds to GetAccessTokenFromEnv in C implementation

use std::env;

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
}

impl Default for AccessToken {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_access_token_creation() {
        let token = AccessToken::new();
        assert!(token.token.is_empty());
    }

    #[test]
    fn test_access_token_from_env_missing() {
        // Clear the environment variable if it exists
        env::remove_var("AZURE_CLI_ACCESS_TOKEN");

        let result = AccessToken::from_env();
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("not set"));
    }

    #[test]
    fn test_access_token_from_env_present() {
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
        // Set an empty token
        env::set_var("AZURE_CLI_ACCESS_TOKEN", "");

        let result = AccessToken::from_env();
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("empty"));

        // Clean up
        env::remove_var("AZURE_CLI_ACCESS_TOKEN");
    }
}
