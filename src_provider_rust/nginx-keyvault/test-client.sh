#!/bin/bash
# Test Key Vault keyless TLS connections
# Tests both RSA and EC servers

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Load environment
if [ -f .env ]; then
    source .env
fi

RSA_PORT=${RSA_PORT:-8443}
EC_PORT=${EC_PORT:-8444}

echo "🧪 Testing Key Vault Keyless TLS Connections"
echo "   Vault: ${KEYVAULT_NAME:-unknown}"
echo ""

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

test_endpoint() {
    local name=$1
    local url=$2
    local expected=$3
    
    printf "   Testing %-20s " "$name..."
    
    response=$(curl -sk --connect-timeout 5 "$url" 2>&1)
    
    if echo "$response" | grep -q "$expected"; then
        echo -e "${GREEN}✅ PASS${NC}"
        return 0
    else
        echo -e "${RED}❌ FAIL${NC}"
        echo "      Expected: $expected"
        echo "      Got: $response"
        return 1
    fi
}

test_ssl_info() {
    local name=$1
    local port=$2
    
    printf "   SSL Info %-19s " "$name..."
    
    info=$(echo | openssl s_client -connect localhost:$port -brief 2>/dev/null | head -5)
    
    if [ -n "$info" ]; then
        echo -e "${GREEN}✅${NC}"
        echo "$info" | sed 's/^/      /'
    else
        echo -e "${RED}❌ Connection failed${NC}"
        return 1
    fi
}

echo "═══════════════════════════════════════════════════════════════"
echo "  RSA Server (Port $RSA_PORT)"
echo "═══════════════════════════════════════════════════════════════"

test_endpoint "RSA Health" "https://localhost:$RSA_PORT/health" "OK"
test_endpoint "RSA Home" "https://localhost:$RSA_PORT/" "Key Vault"
test_ssl_info "RSA" $RSA_PORT

echo ""
echo "═══════════════════════════════════════════════════════════════"
echo "  EC Server (Port $EC_PORT)"
echo "═══════════════════════════════════════════════════════════════"

test_endpoint "EC Health" "https://localhost:$EC_PORT/health" "OK"
test_endpoint "EC Home" "https://localhost:$EC_PORT/" "Key Vault"
test_ssl_info "EC" $EC_PORT

echo ""
echo "═══════════════════════════════════════════════════════════════"
echo "  Cipher Suite Verification"
echo "═══════════════════════════════════════════════════════════════"

# Test RSA cipher
printf "   RSA cipher suite...      "
rsa_cipher=$(echo | openssl s_client -connect localhost:$RSA_PORT 2>/dev/null | grep "Cipher is" | awk '{print $NF}')
if echo "$rsa_cipher" | grep -q "RSA"; then
    echo -e "${GREEN}✅ $rsa_cipher${NC}"
else
    echo -e "${YELLOW}⚠️  $rsa_cipher (expected RSA cipher)${NC}"
fi

# Test EC cipher
printf "   EC cipher suite...       "
ec_cipher=$(echo | openssl s_client -connect localhost:$EC_PORT 2>/dev/null | grep "Cipher is" | awk '{print $NF}')
if echo "$ec_cipher" | grep -q "ECDSA"; then
    echo -e "${GREEN}✅ $ec_cipher${NC}"
else
    echo -e "${YELLOW}⚠️  $ec_cipher (expected ECDSA cipher)${NC}"
fi

echo ""
echo "═══════════════════════════════════════════════════════════════"
echo "  ✅ Key Vault Keyless TLS Test Complete"
echo "═══════════════════════════════════════════════════════════════"
