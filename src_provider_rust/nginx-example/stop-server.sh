#!/bin/bash
# Stop nginx

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PID_FILE="$SCRIPT_DIR/logs/nginx.pid"

if [ -f "$PID_FILE" ]; then
    PID=$(cat "$PID_FILE")
    echo "Stopping nginx (PID: $PID)..."
    kill "$PID" 2>/dev/null
    rm -f "$PID_FILE"
    echo "nginx stopped"
else
    echo "nginx is not running (no pid file found)"
fi
