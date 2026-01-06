#!/bin/bash
# Start nginx with Azure Key Vault keyless TLS
# Uses the AKV OpenSSL Provider for private key operations

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Load environment
if [ ! -f .env ]; then
    echo "Error: .env file not found. Run ./setup-env.sh first."
    exit 1
fi
source .env

echo "🚀 Starting nginx with Key Vault keyless TLS"
echo "   Vault: $KEYVAULT_NAME"
echo ""

# Check for access token
if [ -z "$AZURE_CLI_ACCESS_TOKEN" ]; then
    echo "⚠️  AZURE_CLI_ACCESS_TOKEN not set"
    echo "   Attempting to get token from Azure CLI..."
    export AZURE_CLI_ACCESS_TOKEN=$(az account get-access-token \
        --resource https://vault.azure.net \
        --query accessToken -o tsv 2>/dev/null)
    
    if [ -z "$AZURE_CLI_ACCESS_TOKEN" ]; then
        echo "❌ Failed to get access token"
        echo "   Run: az login"
        echo "   Then: export AZURE_CLI_ACCESS_TOKEN=\$(az account get-access-token --resource https://vault.azure.net --query accessToken -o tsv)"
        exit 1
    fi
    echo "   ✅ Got access token from Azure CLI"
fi

# Check for provider library
AKV_PROVIDER_PATH=${AKV_PROVIDER_PATH:-../target/release/akv_provider.so}
if [ ! -f "$AKV_PROVIDER_PATH" ]; then
    echo "❌ Provider library not found: $AKV_PROVIDER_PATH"
    echo "   Build with: cd .. && ./ubuntubuild.sh"
    exit 1
fi
AKV_PROVIDER_PATH=$(realpath "$AKV_PROVIDER_PATH")
echo "   Provider: $AKV_PROVIDER_PATH"

# Check for certificates
if [ ! -f "certs/rsa-server.crt" ] || [ ! -f "certs/ec-server.crt" ]; then
    echo "❌ Certificates not found. Run ./generate-cert.sh first."
    exit 1
fi

# Check for nginx config
if [ ! -f "nginx.conf" ]; then
    echo "❌ nginx.conf not found. Run ./setup-env.sh first."
    exit 1
fi

# Update OpenSSL config with absolute path
cat > openssl-provider.cnf << EOF
openssl_conf = openssl_init

[openssl_init]
providers = provider_section

[provider_section]
default = default_section
base = base_section
akv_provider = akv_provider_section

[default_section]
activate = 1

[base_section]
activate = 1

[akv_provider_section]
module = $AKV_PROVIDER_PATH
activate = 1
EOF

# Export environment for nginx
export OPENSSL_CONF="$SCRIPT_DIR/openssl-provider.cnf"
export RUST_LOG=${RUST_LOG:-info}
export AZURE_CLI_ACCESS_TOKEN

echo ""
echo "📋 Configuration:"
echo "   OPENSSL_CONF: $OPENSSL_CONF"
echo "   RUST_LOG: $RUST_LOG"
echo "   RSA Port: ${RSA_PORT:-8443}"
echo "   EC Port: ${EC_PORT:-8444}"
echo ""

# Check for existing nginx
if pgrep -f "nginx.*$SCRIPT_DIR" > /dev/null; then
    echo "⚠️  nginx already running. Stop with ./stop-server.sh"
    exit 1
fi

# Create log directory
mkdir -p logs

# Start nginx
echo "🌐 Starting nginx..."
nginx -c "$SCRIPT_DIR/nginx.conf" -p "$SCRIPT_DIR" \
    -e "$SCRIPT_DIR/logs/error.log" \
    -g "daemon off;" &

NGINX_PID=$!
echo $NGINX_PID > nginx.pid

echo ""
echo "✅ nginx started (PID: $NGINX_PID)"
echo ""
echo "🧪 Test endpoints:"
echo "   RSA: curl -k https://localhost:${RSA_PORT:-8443}/"
echo "   EC:  curl -k https://localhost:${EC_PORT:-8444}/"
echo ""
echo "📊 View logs:"
echo "   tail -f logs/error.log"
echo ""
echo "🛑 Stop server:"
echo "   ./stop-server.sh"
