#!/bin/bash
# Stop nginx server

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

if [ -f nginx.pid ]; then
    PID=$(cat nginx.pid)
    if kill -0 $PID 2>/dev/null; then
        echo "🛑 Stopping nginx (PID: $PID)..."
        kill $PID
        rm nginx.pid
        echo "✅ nginx stopped"
    else
        echo "⚠️  nginx not running (stale PID file)"
        rm nginx.pid
    fi
else
    # Try to find and kill nginx by config
    PIDS=$(pgrep -f "nginx.*$SCRIPT_DIR" 2>/dev/null)
    if [ -n "$PIDS" ]; then
        echo "🛑 Stopping nginx processes: $PIDS"
        kill $PIDS
        echo "✅ nginx stopped"
    else
        echo "ℹ️  nginx not running"
    fi
fi
