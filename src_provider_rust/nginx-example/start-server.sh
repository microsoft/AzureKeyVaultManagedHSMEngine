#!/bin/bash
# Start nginx with Azure Managed HSM keyless TLS
# Requires nginx 1.27+ for OSSL_STORE support

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
NGINX_CONF="$SCRIPT_DIR/nginx.conf"
OPENSSL_CONF="$SCRIPT_DIR/openssl-provider.cnf"

echo "=== Starting nginx with Azure Managed HSM keyless TLS ==="

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
    export AZURE_CLI_ACCESS_TOKEN=$(az account get-access-token --output tsv --query accessToken --tenant 72f988bf-86f1-41af-91ab-2d7cd011db47 --resource https://managedhsm.azure.net)
fi

# Check for certificate
if [ ! -f "$SCRIPT_DIR/certs/server.crt" ]; then
    echo "ERROR: Certificate not found. Run generate-cert.sh first."
    exit 1
fi

# Create required directories
mkdir -p "$SCRIPT_DIR/logs"
mkdir -p "$SCRIPT_DIR/tmp"/{client_body,proxy,fastcgi,uwsgi,scgi}

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
    echo "Test with: curl -k https://localhost:8443/"
    echo "Logs:      $SCRIPT_DIR/logs/"
else
    echo "ERROR: nginx failed to start. Check logs:"
    cat "$SCRIPT_DIR/logs/error.log" 2>/dev/null || echo "No error log found"
    exit 1
fi
