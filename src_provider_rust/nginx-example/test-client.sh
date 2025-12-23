#!/bin/bash
# Test nginx TLS connection

echo "=== Testing nginx keyless TLS ==="
echo ""

echo "--- HTTPS request to localhost:8443 ---"
curl -k -s https://localhost:8443/
echo ""

echo "--- Health check ---"
curl -k -s https://localhost:8443/health
echo ""

echo "--- TLS connection info ---"
echo | openssl s_client -connect localhost:8443 2>/dev/null | grep -E "(Protocol|Cipher|subject|issuer)" | head -6
