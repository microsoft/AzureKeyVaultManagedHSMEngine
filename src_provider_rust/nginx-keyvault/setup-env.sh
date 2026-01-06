#!/bin/bash
# Setup environment for Key Vault keyless TLS
# Creates .env file and processes templates

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo "🔧 Setting up Key Vault keyless TLS environment"
echo ""

# Create .env from example if not exists
if [ ! -f .env ]; then
    if [ -f .env.example ]; then
        cp .env.example .env
        echo "📝 Created .env from .env.example"
        echo "   Please edit .env with your Key Vault configuration"
        echo ""
        echo "   Required settings:"
        echo "   - KEYVAULT_NAME: Your Key Vault name"
        echo "   - RSA_KEY_NAME: RSA key name for TLS"
        echo "   - EC_KEY_NAME: EC key name for TLS"
        exit 0
    else
        echo "Error: .env.example not found"
        exit 1
    fi
fi

# Load environment
source .env

# Validate required settings
if [ -z "$KEYVAULT_NAME" ]; then
    echo "Error: KEYVAULT_NAME not set in .env"
    exit 1
fi

echo "📋 Configuration:"
echo "   Key Vault:  $KEYVAULT_NAME"
echo "   RSA Key:    $RSA_KEY_NAME"
echo "   EC Key:     $EC_KEY_NAME"
echo "   RSA Port:   ${RSA_PORT:-8443}"
echo "   EC Port:    ${EC_PORT:-8444}"
echo ""

# Set defaults
RSA_PORT=${RSA_PORT:-8443}
EC_PORT=${EC_PORT:-8444}
HTTP_PORT=${HTTP_PORT:-80}

# Find provider library
if [ -z "$AKV_PROVIDER_PATH" ]; then
    if [ -f "../target/release/akv_provider.so" ]; then
        AKV_PROVIDER_PATH="$(realpath ../target/release/akv_provider.so)"
    elif [ -f "../target/debug/akv_provider.so" ]; then
        AKV_PROVIDER_PATH="$(realpath ../target/debug/akv_provider.so)"
    else
        echo "⚠️  Warning: Provider library not found. Build with './ubuntubuild.sh'"
    fi
fi

echo "🔧 Provider: ${AKV_PROVIDER_PATH:-not found}"

# Process templates
echo ""
echo "📄 Processing templates..."

# Process OpenSSL config
envsubst < openssl-provider.cnf.template > openssl-provider.cnf
echo "   ✅ openssl-provider.cnf"

# Process nginx config
export KEYVAULT_NAME RSA_KEY_NAME EC_KEY_NAME RSA_PORT EC_PORT HTTP_PORT
envsubst < nginx.conf.template > nginx.conf
echo "   ✅ nginx.conf"

echo ""
echo "✅ Setup complete!"
echo ""
echo "🔑 Get access token for Key Vault:"
echo "   export AZURE_CLI_ACCESS_TOKEN=\$(az account get-access-token \\"
echo "       --resource https://vault.azure.net \\"
echo "       --query accessToken -o tsv)"
echo ""
echo "📜 Generate certificates:"
echo "   ./generate-cert.sh"
echo ""
echo "🚀 Start nginx:"
echo "   ./start-server.sh"
