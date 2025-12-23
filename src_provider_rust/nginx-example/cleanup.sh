#!/bin/bash
# Clean up generated files and temporary data

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "=== Cleaning up nginx-example ==="

# Stop nginx if running
if [ -f "$SCRIPT_DIR/logs/nginx.pid" ]; then
    PID=$(cat "$SCRIPT_DIR/logs/nginx.pid")
    echo "Stopping nginx (PID: $PID)..."
    kill "$PID" 2>/dev/null
    sleep 1
fi

# Clean up certificates
if [ -d "$SCRIPT_DIR/certs" ]; then
    echo "Removing certificates..."
    rm -rf "$SCRIPT_DIR/certs"/*
fi

# Clean up logs
if [ -d "$SCRIPT_DIR/logs" ]; then
    echo "Removing logs..."
    rm -rf "$SCRIPT_DIR/logs"/*
fi

# Clean up tmp directories
if [ -d "$SCRIPT_DIR/tmp" ]; then
    echo "Removing tmp files..."
    rm -rf "$SCRIPT_DIR/tmp"/*
fi

echo "Cleanup complete!"
