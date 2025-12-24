#!/bin/bash
# Start nginx with Azure Managed HSM keyless TLS
# Requires nginx 1.27+ for OSSL_STORE support

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
NGINX_CONF="$SCRIPT_DIR/nginx.conf"
NGINX_TEMPLATE="$SCRIPT_DIR/nginx.conf.template"
OPENSSL_CONF="$SCRIPT_DIR/openssl-provider.cnf"
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
AZURE_TENANT_ID="${AZURE_TENANT_ID:-72f988bf-86f1-41af-91ab-2d7cd011db47}"
NGINX_PORT="${NGINX_PORT:-8443}"
SERVER_NAME="${SERVER_NAME:-localhost}"

# Export variables for templates
export PROJECT_DIR="$SCRIPT_DIR"
export PROVIDER_PATH="$SCRIPT_DIR/../target/release"
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
    export AZURE_CLI_ACCESS_TOKEN=$(az account get-access-token --output tsv --query accessToken --tenant "$AZURE_TENANT_ID" --resource https://managedhsm.azure.net)
fi

# Check for certificate
if [ ! -f "$SCRIPT_DIR/certs/server.crt" ]; then
    echo "ERROR: Certificate not found. Run generate-cert.sh first."
    exit 1
fi

# Create required directories
mkdir -p "$SCRIPT_DIR/logs"
mkdir -p "$SCRIPT_DIR/tmp"/{client_body,proxy,fastcgi,uwsgi,scgi}

# Generate nginx.conf from template
if [ -f "$NGINX_TEMPLATE" ]; then
    echo "Generating nginx.conf from template..."
    envsubst '${PROJECT_DIR} ${HSM_NAME} ${HSM_KEY_NAME} ${NGINX_PORT} ${SERVER_NAME}' \
        < "$NGINX_TEMPLATE" > "$NGINX_CONF"
else
    echo "Warning: nginx.conf.template not found, using existing nginx.conf"
fi

# Generate openssl-provider.cnf from template
if [ -f "$OPENSSL_TEMPLATE" ]; then
    echo "Generating openssl-provider.cnf from template..."
    envsubst '${PROVIDER_PATH}' < "$OPENSSL_TEMPLATE" > "$OPENSSL_CONF"
else
    echo "Warning: openssl-provider.cnf.template not found, using existing config"
fi

# Set environment variables
export OPENSSL_CONF="$OPENSSL_CONF"
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
