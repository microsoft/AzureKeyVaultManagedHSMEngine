#!/bin/bash
# Cleanup generated files

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo "🧹 Cleaning up Key Vault nginx example..."

# Stop nginx if running
./stop-server.sh 2>/dev/null || true

# Remove generated files
rm -f nginx.conf
rm -f openssl-provider.cnf
rm -f nginx.pid
rm -rf certs/
rm -rf logs/

echo "✅ Cleanup complete"
echo ""
echo "To reconfigure:"
echo "  1. Edit .env with your Key Vault settings"
echo "  2. Run ./setup-env.sh"
echo "  3. Run ./generate-cert.sh"
echo "  4. Run ./start-server.sh"
