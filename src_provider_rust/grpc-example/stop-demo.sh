#!/bin/bash
# Stop the gRPC mTLS demo

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOGS_DIR="$SCRIPT_DIR/logs"
RUN_DIR="$SCRIPT_DIR/run"

echo "Stopping gRPC mTLS Demo..."

# Stop NGINX server sidecar
if [ -f "$LOGS_DIR/nginx-server.pid" ]; then
    PID=$(cat "$LOGS_DIR/nginx-server.pid")
    if kill -0 "$PID" 2>/dev/null; then
        echo "Stopping NGINX server sidecar (PID: $PID)"
        kill "$PID" 2>/dev/null || true
    fi
    rm -f "$LOGS_DIR/nginx-server.pid"
fi

# Stop NGINX client sidecar
if [ -f "$LOGS_DIR/nginx-client.pid" ]; then
    PID=$(cat "$LOGS_DIR/nginx-client.pid")
    if kill -0 "$PID" 2>/dev/null; then
        echo "Stopping NGINX client sidecar (PID: $PID)"
        kill "$PID" 2>/dev/null || true
    fi
    rm -f "$LOGS_DIR/nginx-client.pid"
fi

# Stop gRPC server
if [ -f "$LOGS_DIR/grpc-server.pid" ]; then
    PID=$(cat "$LOGS_DIR/grpc-server.pid")
    if kill -0 "$PID" 2>/dev/null; then
        echo "Stopping gRPC server (PID: $PID)"
        kill "$PID" 2>/dev/null || true
    fi
    rm -f "$LOGS_DIR/grpc-server.pid"
fi

# Clean up sockets
rm -f "$RUN_DIR/grpc-server.sock" "$RUN_DIR/grpc-client.sock"

echo "Done."
