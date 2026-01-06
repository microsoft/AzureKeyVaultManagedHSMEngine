#!/bin/bash
# Simple local test for Key Vault integration
# Usage: ./test_keyvault.sh <vault-name> <key-name>

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VAULT_NAME="${1:-kv-kvtls-dev-640}"
KEY_NAME="${2:-rsa-test-key}"

# Provider path
PROVIDER_PATH="$SCRIPT_DIR/target/release/akv_provider.so"

if [ ! -f "$PROVIDER_PATH" ]; then
    echo "ERROR: Provider not found at $PROVIDER_PATH"
    echo "Please build first: ./ubuntubuild.sh"
    exit 1
fi

# Copy provider to OpenSSL modules directory (or use -provider-path)
MODULESDIR=$(openssl version -m 2>/dev/null | grep -oP 'MODULESDIR: "\K[^"]+' || echo "/usr/lib/x86_64-linux-gnu/ossl-modules")
echo "OpenSSL MODULESDIR: $MODULESDIR"

# Create symlink if needed
if [ ! -f "$MODULESDIR/akv_provider.so" ]; then
    echo "Creating symlink to provider in modules directory..."
    sudo ln -sf "$PROVIDER_PATH" "$MODULESDIR/akv_provider.so" 2>/dev/null || {
        echo "Cannot create symlink, will use -provider-path flag"
    }
fi

export RUST_LOG=info

echo "=== Azure Key Vault OpenSSL Provider Test ==="
echo "Vault: $VAULT_NAME"
echo "Key: $KEY_NAME"
echo "Provider: $PROVIDER_PATH"
echo ""

# Check if logged in to Azure
echo "Checking Azure CLI login..."
if ! az account show > /dev/null 2>&1; then
    echo "ERROR: Not logged in to Azure CLI. Run: az login"
    exit 1
fi

# Get access token for Key Vault (not Managed HSM!)
echo "Getting access token for Key Vault..."
export AZURE_CLI_ACCESS_TOKEN=$(az account get-access-token --resource https://vault.azure.net --query accessToken -o tsv)
if [ -z "$AZURE_CLI_ACCESS_TOKEN" ]; then
    echo "ERROR: Failed to get access token"
    exit 1
fi
echo "Access token acquired (length: ${#AZURE_CLI_ACCESS_TOKEN} chars)"
echo ""

# Test 1: List providers
echo "=== Test 1: List OpenSSL Providers ==="
openssl list -providers -provider akv_provider -provider default
echo ""

# Test 2: Load key from Key Vault using URI  
echo "=== Test 2: Load Key from Key Vault ==="
KEY_URI="keyvault:${VAULT_NAME}:${KEY_NAME}"
echo "Key URI: $KEY_URI"
echo ""

# Try to extract public key using -provider flag
echo "Extracting public key from Key Vault..."
if openssl pkey -provider akv_provider -provider default -in "$KEY_URI" -pubout -out /tmp/kv_pubkey.pem 2>&1; then
    echo "SUCCESS: Public key extracted"
    cat /tmp/kv_pubkey.pem
else
    echo "Note: Direct key load may need debugging"
fi
echo ""

# Test 3: Sign and verify
echo "=== Test 3: Sign with Key Vault key ==="
echo "Hello from Azure Key Vault" > /tmp/test_data.txt

if openssl dgst -provider akv_provider -provider default -sha256 -sign "$KEY_URI" -out /tmp/signature.bin /tmp/test_data.txt 2>&1; then
    echo "SUCCESS: Data signed"
    echo "Signature size: $(wc -c < /tmp/signature.bin) bytes"
    
    # Verify locally with public key
    if [ -f /tmp/kv_pubkey.pem ]; then
        echo "Verifying signature..."
        if openssl dgst -sha256 -verify /tmp/kv_pubkey.pem -signature /tmp/signature.bin /tmp/test_data.txt; then
            echo "SUCCESS: Signature verified!"
        fi
    fi
else
    echo "Sign operation failed - check logs above"
fi

echo ""
echo "=== Test Complete ==="
