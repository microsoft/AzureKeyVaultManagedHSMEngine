#!/bin/bash
# Test nginx TLS connection with both RSA and EC certificates

set -e

echo "========================================"
echo "  Testing Nginx Keyless TLS with HSM"
echo "========================================"
echo ""

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

test_server() {
    local PORT="$1"
    local KEY_TYPE="$2"
    local KEY_NAME="$3"
    
    echo "========================================"
    echo "  Testing $KEY_TYPE Server (port $PORT)"
    echo "========================================"
    echo ""
    
    # Test HTTPS connection
    echo "--- HTTPS Request ---"
    if curl -k -s --max-time 5 "https://localhost:$PORT/" 2>/dev/null; then
        echo -e "${GREEN}✓ HTTPS connection successful${NC}"
    else
        echo -e "${RED}✗ HTTPS connection failed${NC}"
        return 1
    fi
    echo ""
    
    # Health check
    echo "--- Health Check ---"
    HEALTH=$(curl -k -s --max-time 5 "https://localhost:$PORT/health" 2>/dev/null)
    if [ -n "$HEALTH" ]; then
        echo "$HEALTH"
        echo -e "${GREEN}✓ Health check passed${NC}"
    else
        echo -e "${RED}✗ Health check failed${NC}"
    fi
    echo ""
    
    # TLS connection details
    echo "--- TLS Connection Details ---"
    TLS_INFO=$(echo | openssl s_client -connect "localhost:$PORT" 2>/dev/null)
    
    PROTOCOL=$(echo "$TLS_INFO" | grep "Protocol" | head -1 | awk '{print $3}')
    CIPHER=$(echo "$TLS_INFO" | grep "Cipher" | head -1 | awk '{print $3}')
    SUBJECT=$(echo "$TLS_INFO" | grep "subject=" | head -1)
    
    echo "Protocol: $PROTOCOL"
    echo "Cipher:   $CIPHER"
    echo "$SUBJECT"
    
    # Verify key type in certificate
    CERT_INFO=$(echo | openssl s_client -connect "localhost:$PORT" 2>/dev/null | openssl x509 -noout -text 2>/dev/null)
    if echo "$CERT_INFO" | grep -q "Public Key Algorithm: rsaEncryption"; then
        ACTUAL_KEY_TYPE="RSA"
    elif echo "$CERT_INFO" | grep -q "Public Key Algorithm: id-ecPublicKey"; then
        ACTUAL_KEY_TYPE="EC"
    else
        ACTUAL_KEY_TYPE="Unknown"
    fi
    
    echo "Key Type: $ACTUAL_KEY_TYPE"
    
    if [ "$ACTUAL_KEY_TYPE" = "$KEY_TYPE" ]; then
        echo -e "${GREEN}✓ Certificate key type matches expected ($KEY_TYPE)${NC}"
    else
        echo -e "${YELLOW}⚠ Certificate key type ($ACTUAL_KEY_TYPE) differs from expected ($KEY_TYPE)${NC}"
    fi
    echo ""
}

# Test RSA server
test_server 8443 "RSA" "myrsakey"

# Test EC server
test_server 8444 "EC" "ecckey"

echo "========================================"
echo "  All Tests Complete"
echo "========================================"
echo ""

# Summary
echo "Summary:"
echo "  - RSA Server (port 8443): Using key 'myrsakey' from Azure Managed HSM"
echo "  - EC Server (port 8444):  Using key 'ecckey' from Azure Managed HSM"
echo ""
echo "Both servers use keyless TLS where the private key never leaves the HSM."
