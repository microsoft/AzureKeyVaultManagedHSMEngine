#!/bin/bash
# Start nginx with Azure Managed HSM keyless TLS
# Requires nginx 1.27+ for OSSL_STORE support

set -e

# Clear OPENSSL_CONF to avoid conflicts with any existing config
unset OPENSSL_CONF

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
NGINX_CONF="$SCRIPT_DIR/nginx.conf"
NGINX_TEMPLATE="$SCRIPT_DIR/nginx.conf.template"
OPENSSL_CONF_FILE="$SCRIPT_DIR/openssl-provider.cnf"
OPENSSL_TEMPLATE="$SCRIPT_DIR/openssl-provider.cnf.template"

# Load configuration from .env file
ENV_FILE="$SCRIPT_DIR/.env"
if [ -f "$ENV_FILE" ]; then
    echo "Loading configuration from $ENV_FILE"
    set -a  # Export all variables
    source "$ENV_FILE"
    set +a
else
    echo "Warning: No .env file found. Run ./setup-env.sh first or using defaults."
fi

# Configuration with defaults
HSM_NAME="${HSM_NAME:-ManagedHSMOpenSSLEngine}"
HSM_KEY_NAME="${HSM_KEY_NAME:-myrsakey}"
NGINX_PORT="${NGINX_PORT:-8443}"
SERVER_NAME="${SERVER_NAME:-localhost}"

# Export variables for templates - use absolute paths
export PROJECT_DIR="$SCRIPT_DIR"
export PROVIDER_PATH="$(cd "$SCRIPT_DIR/../target/release" && pwd)"

# Create symlink for provider if needed (cargo builds libakv_provider.so but OpenSSL expects akv_provider.so)
if [ -f "$PROVIDER_PATH/libakv_provider.so" ] && [ ! -f "$PROVIDER_PATH/akv_provider.so" ]; then
    ln -sf libakv_provider.so "$PROVIDER_PATH/akv_provider.so"
fi

export HSM_NAME HSM_KEY_NAME NGINX_PORT SERVER_NAME

echo "=== Starting nginx with Azure Managed HSM keyless TLS ==="
echo "HSM:  $HSM_NAME"
echo "Key:  $HSM_KEY_NAME"
echo "Port: $NGINX_PORT"
echo ""

# Check nginx version (need 1.27+ for OSSL_STORE support)
NGINX_VERSION=$(nginx -v 2>&1 | grep -oP 'nginx/\K[0-9]+\.[0-9]+')
REQUIRED_VERSION="1.27"

if [ "$(printf '%s\n' "$REQUIRED_VERSION" "$NGINX_VERSION" | sort -V | head -n1)" != "$REQUIRED_VERSION" ]; then
    echo "ERROR: nginx $NGINX_VERSION detected, but version 1.27+ is required for OSSL_STORE support."
    echo ""
    echo "To install nginx mainline on Ubuntu/Debian:"
    echo "  sudo apt install -y curl gnupg2 ca-certificates lsb-release ubuntu-keyring"
    echo "  curl https://nginx.org/keys/nginx_signing.key | gpg --dearmor | sudo tee /usr/share/keyrings/nginx-archive-keyring.gpg >/dev/null"
    echo "  echo 'deb [signed-by=/usr/share/keyrings/nginx-archive-keyring.gpg] http://nginx.org/packages/mainline/ubuntu '\$(lsb_release -cs)' nginx' | sudo tee /etc/apt/sources.list.d/nginx.list"
    echo "  sudo apt update && sudo apt install -y nginx"
    exit 1
fi

# Get Azure access token
if [ -z "$AZURE_CLI_ACCESS_TOKEN" ]; then
    echo "Getting Azure access token..."
    export AZURE_CLI_ACCESS_TOKEN=$(az account get-access-token --query accessToken -o tsv --resource https://managedhsm.azure.net)
fi

# Check for certificate
if [ ! -f "$SCRIPT_DIR/certs/server-rsa.crt" ] && [ ! -f "$SCRIPT_DIR/certs/server-ec.crt" ]; then
    echo "ERROR: Certificate not found. Run generate-cert.sh first."
    exit 1
fi

# Ensure server.crt symlink exists for template compatibility
if [ -f "$SCRIPT_DIR/certs/server-rsa.crt" ] && [ ! -f "$SCRIPT_DIR/certs/server.crt" ]; then
    ln -sf server-rsa.crt "$SCRIPT_DIR/certs/server.crt"
fi

# Create required directories
mkdir -p "$SCRIPT_DIR/logs"
mkdir -p "$SCRIPT_DIR/tmp"/{client_body,proxy,fastcgi,uwsgi,scgi}

# Use existing nginx.conf if present (supports RSA+EC dual servers)
# Delete nginx.conf to regenerate from template
if [ ! -f "$NGINX_CONF" ]; then
    if [ -f "$NGINX_TEMPLATE" ]; then
        echo "Generating nginx.conf from template..."
        envsubst '${PROJECT_DIR} ${HSM_NAME} ${HSM_KEY_NAME} ${NGINX_PORT} ${SERVER_NAME}' \
            < "$NGINX_TEMPLATE" > "$NGINX_CONF"
    else
        echo "ERROR: nginx.conf not found and no template available"
        exit 1
    fi
else
    echo "Using existing nginx.conf"
fi

# Always regenerate openssl-provider.cnf to ensure absolute paths
if [ -f "$OPENSSL_TEMPLATE" ]; then
    echo "Generating openssl-provider.cnf from template..."
    envsubst '${PROVIDER_PATH}' < "$OPENSSL_TEMPLATE" > "$OPENSSL_CONF_FILE"
else
    echo "Warning: openssl-provider.cnf.template not found, using existing config"
fi

# Set environment variables for nginx
export OPENSSL_CONF="$OPENSSL_CONF_FILE"
export AKV_LOG_FILE="$SCRIPT_DIR/logs/akv_provider.log"
export AKV_LOG_LEVEL="3"

# Clean up any old state
rm -f "$SCRIPT_DIR/logs/nginx.pid"
rm -f "$SCRIPT_DIR/logs"/*.log

echo "Starting nginx..."
# Use -e to specify error log before config is read (avoids permission error on /var/log/nginx/error.log)
nginx -e "$SCRIPT_DIR/logs/error.log" -c "$NGINX_CONF"

sleep 1

if [ -f "$SCRIPT_DIR/logs/nginx.pid" ]; then
    PID=$(cat "$SCRIPT_DIR/logs/nginx.pid")
    echo "nginx started successfully (PID: $PID)"
    echo ""
    echo "Test with: curl -k https://localhost:${NGINX_PORT}/"
    echo "Health:    curl -k https://localhost:${NGINX_PORT}/health"
    echo "Info:      curl -k https://localhost:${NGINX_PORT}/info"
    echo "Logs:      $SCRIPT_DIR/logs/"
else
    echo "ERROR: nginx failed to start. Check logs:"
    cat "$SCRIPT_DIR/logs/error.log" 2>/dev/null || echo "No error log found"
    exit 1
fi
