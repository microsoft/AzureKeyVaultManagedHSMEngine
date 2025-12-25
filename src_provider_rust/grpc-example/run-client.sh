#!/bin/bash
# Run the gRPC client through the client sidecar
# This connects via UDS to NGINX client sidecar, which handles mTLS

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RUN_DIR="$SCRIPT_DIR/run"

# Set the client to use the client sidecar UDS
export GRPC_UDS_PATH="$RUN_DIR/grpc-client.sock"

echo "Running gRPC client via client sidecar..."
echo "UDS: $GRPC_UDS_PATH"
echo ""

exec "$SCRIPT_DIR/target/release/grpc-client"
