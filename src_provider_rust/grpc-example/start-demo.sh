#!/bin/bash
# Start the gRPC mTLS demo with double-ended sidecar architecture
#
# This script:
# 1. Sets up OpenSSL provider configuration
# 2. Generates NGINX configs from templates
# 3. Starts NGINX server sidecar (TLS termination)
# 4. Starts gRPC server (listening on UDS)
# 5. Starts NGINX client sidecar (TLS origination)
#
# Usage: ./start-demo.sh

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Load configuration
ENV_FILE="$SCRIPT_DIR/.env"
if [ -f "$ENV_FILE" ]; then
    echo "Loading configuration from $ENV_FILE"
    set -a
    source "$ENV_FILE"
    set +a
else
    echo "Error: No .env file found. Copy .env.example to .env and configure."
    exit 1
fi

# Paths
PROVIDER_PATH="$SCRIPT_DIR/../target/release"
CERTS_DIR="$SCRIPT_DIR/certs"
LOGS_DIR="$SCRIPT_DIR/logs"
RUN_DIR="$SCRIPT_DIR/run"
NGINX_DIR="$SCRIPT_DIR/nginx"

# Configuration
HSM_NAME="${HSM_NAME:-ManagedHSMOpenSSLEngine}"
HSM_KEY_NAME="${HSM_KEY_NAME:-myrsakey}"
SERVER_HOST="${SERVER_HOST:-127.0.0.1}"
AZURE_TENANT_ID="${AZURE_TENANT_ID:-72f988bf-86f1-41af-91ab-2d7cd011db47}"

echo "=============================================="
echo "Starting gRPC mTLS Demo"
echo "=============================================="
echo "HSM: $HSM_NAME"
echo "Key: $HSM_KEY_NAME"
echo ""

# Check prerequisites
if [ ! -f "$PROVIDER_PATH/akv_provider.so" ]; then
    echo "Error: Provider not built. Run './ubuntubuild.sh' in parent directory."
    exit 1
fi

if [ ! -f "$CERTS_DIR/ca.crt" ]; then
    echo "Error: Certificates not generated. Run ./generate-certs.sh first."
    exit 1
fi

# Create directories
mkdir -p "$LOGS_DIR" "$RUN_DIR"

# Get Azure access token if not set
if [ -z "$AZURE_CLI_ACCESS_TOKEN" ]; then
    echo "Getting Azure access token..."
    export AZURE_CLI_ACCESS_TOKEN=$(az account get-access-token \
        --output tsv --query accessToken \
        --tenant "$AZURE_TENANT_ID" \
        --resource https://managedhsm.azure.net)
fi

# ============================================
# Step 1: Generate OpenSSL provider config
# ============================================
echo ""
echo "=== Step 1: Setting up OpenSSL provider ==="
OPENSSL_CONF="$SCRIPT_DIR/openssl-provider.cnf"

sed -e "s|PROVIDER_PATH|$PROVIDER_PATH|g" \
    "$SCRIPT_DIR/openssl-provider.cnf.template" > "$OPENSSL_CONF"

export OPENSSL_CONF
export AKV_LOG_FILE="$LOGS_DIR/akv-provider.log"
export AKV_LOG_LEVEL="${AKV_LOG_LEVEL:-debug}"

echo "OPENSSL_CONF=$OPENSSL_CONF"

# ============================================
# Step 2: Generate NGINX configs
# ============================================
echo ""
echo "=== Step 2: Generating NGINX configs ==="

# Server sidecar config
sed -e "s|WORK_DIR|$SCRIPT_DIR|g" \
    -e "s|HSM_NAME|$HSM_NAME|g" \
    -e "s|HSM_KEY_NAME|$HSM_KEY_NAME|g" \
    "$NGINX_DIR/nginx-server.conf" > "$NGINX_DIR/nginx-server-runtime.conf"

# Client sidecar config
sed -e "s|WORK_DIR|$SCRIPT_DIR|g" \
    -e "s|HSM_NAME|$HSM_NAME|g" \
    -e "s|HSM_KEY_NAME|$HSM_KEY_NAME|g" \
    -e "s|SERVER_HOST|$SERVER_HOST|g" \
    "$NGINX_DIR/nginx-client.conf" > "$NGINX_DIR/nginx-client-runtime.conf"

echo "Generated: $NGINX_DIR/nginx-server-runtime.conf"
echo "Generated: $NGINX_DIR/nginx-client-runtime.conf"

# ============================================
# Step 3: Build gRPC application
# ============================================
echo ""
echo "=== Step 3: Building gRPC application ==="
cd "$SCRIPT_DIR"
cargo build --release
cd "$SCRIPT_DIR"

# ============================================
# Step 4: Start NGINX server sidecar
# ============================================
echo ""
echo "=== Step 4: Starting NGINX server sidecar ==="
nginx -c "$NGINX_DIR/nginx-server-runtime.conf" -p "$SCRIPT_DIR"
echo "NGINX server sidecar started (PID: $(cat $LOGS_DIR/nginx-server.pid))"

# ============================================
# Step 5: Start gRPC server
# ============================================
echo ""
echo "=== Step 5: Starting gRPC server ==="
export GRPC_UDS_PATH="$RUN_DIR/grpc-server.sock"
"$SCRIPT_DIR/target/release/grpc-server" &
GRPC_SERVER_PID=$!
echo $GRPC_SERVER_PID > "$LOGS_DIR/grpc-server.pid"
sleep 1
echo "gRPC server started (PID: $GRPC_SERVER_PID)"

# ============================================
# Step 6: Start NGINX client sidecar
# ============================================
echo ""
echo "=== Step 6: Starting NGINX client sidecar ==="
nginx -c "$NGINX_DIR/nginx-client-runtime.conf" -p "$SCRIPT_DIR"
echo "NGINX client sidecar started (PID: $(cat $LOGS_DIR/nginx-client.pid))"

# ============================================
# Summary
# ============================================
echo ""
echo "=============================================="
echo "gRPC mTLS Demo Started!"
echo "=============================================="
echo ""
echo "Architecture:"
echo "  Client App --> [UDS] --> NGINX Client Sidecar"
echo "                               |"
echo "                               | (mTLS on port 50051)"
echo "                               v"
echo "  Server App <-- [UDS] <-- NGINX Server Sidecar"
echo ""
echo "To run the client:"
echo "  export GRPC_UDS_PATH=$RUN_DIR/grpc-client.sock"
echo "  ./target/release/grpc-client"
echo ""
echo "To stop: ./stop-demo.sh"
echo ""
echo "Logs:"
echo "  NGINX server: $LOGS_DIR/nginx-server-error.log"
echo "  NGINX client: $LOGS_DIR/nginx-client-error.log"
echo "  AKV provider: $LOGS_DIR/akv-provider.log"
