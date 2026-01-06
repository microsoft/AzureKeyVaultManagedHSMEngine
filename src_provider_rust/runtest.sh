#!/bin/bash
# ============================================================================
# Azure Managed HSM OpenSSL Provider Test Suite - Linux/Ubuntu
# ============================================================================
#
# Usage: runtest.sh [--validate] [--noenv]
#
# Options:
#   --validate  Run full validation of Azure Managed HSM and keys
#               (slower, but verifies all prerequisites)
#   --noenv     Use DefaultAzureCredential instead of environment variable
#               (tests Azure SDK authentication chain)
#
# By default, validation is SKIPPED for faster testing.
#
# Environment Variables (optional):
#   AKV_VAULT    - Managed HSM name (default: ManagedHSMOpenSSLEngine)
#   AKV_RSA_KEY  - RSA key name (default: myrsakey)
#   AKV_EC_KEY   - EC key name (default: ecckey)
#   AKV_AES_KEY  - AES key name (default: myaeskey)
#
# ============================================================================

set -e

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Parse arguments
VALIDATE=0
USE_DEFAULT_CREDENTIAL=0

show_usage() {
    echo ""
    echo "Azure Managed HSM OpenSSL Provider Test Suite"
    echo "=============================================="
    echo ""
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "Options:"
    echo "  --validate   Run full validation of Azure Managed HSM and keys"
    echo "               (default is to skip validation for faster testing)"
    echo "  --noenv      Use DefaultAzureCredential instead of environment variable"
    echo "               (tests Azure SDK authentication chain)"
    echo "  -h, --help   Show this help message"
    echo ""
    echo "Environment Variables (optional):"
    echo "  AKV_VAULT    - Managed HSM name (default: ManagedHSMOpenSSLEngine)"
    echo "  AKV_RSA_KEY  - RSA key name (default: myrsakey)"
    echo "  AKV_EC_KEY   - EC key name (default: ecckey)"
    echo "  AKV_AES_KEY  - AES key name (default: myaeskey)"
    echo ""
    echo "Examples:"
    echo "  $0                      # Run tests (fast, skips validation)"
    echo "  $0 --validate           # Run tests with full validation"
    echo "  $0 --noenv              # Use DefaultAzureCredential"
    echo "  $0 --validate --noenv   # Full validation with DefaultAzureCredential"
    echo "  AKV_VAULT=MyVault $0    # Use custom vault name"
    echo ""
    exit 0
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --validate|-v)
            VALIDATE=1
            shift
            ;;
        --noenv|-n)
            USE_DEFAULT_CREDENTIAL=1
            shift
            ;;
        -h|--help)
            show_usage
            ;;
        *)
            echo "Unknown option: $1"
            show_usage
            ;;
    esac
done

echo ""
echo "=== Azure Managed HSM signing tests ==="
echo ""
echo "Working directory: $PWD"

# ============================================================================
# Pre-flight Checks
# ============================================================================

echo ""
echo "--- Checking prerequisites ---"

# Check if OpenSSL is installed
if ! command -v openssl &> /dev/null; then
    echo -e "${RED}ERROR: OpenSSL not found in PATH${NC}"
    echo "Please install OpenSSL 3.x: sudo apt-get install openssl libssl-dev"
    exit 1
fi

OPENSSL_VERSION=$(openssl version | cut -d' ' -f2)
echo -e "${GREEN}[OK]${NC} OpenSSL version: $OPENSSL_VERSION"

# Check OpenSSL version is 3.x
if [[ ! "$(openssl version)" =~ ^OpenSSL\ 3\. ]]; then
    echo -e "${YELLOW}[WARNING]${NC} OpenSSL 3.x recommended for provider support"
fi

# Get OpenSSL modules directory
MODULESDIR=$(openssl version -m | grep -oP 'MODULESDIR: "\K[^"]+' 2>/dev/null || \
             openssl version -m | sed 's/MODULESDIR: "\(.*\)"/\1/')
echo "MODULESDIR: $MODULESDIR"

# Check if akv_provider.so is installed
if [[ -f "$MODULESDIR/akv_provider.so" ]]; then
    echo -e "${GREEN}[OK]${NC} akv_provider.so is installed in modules directory"
    PROVIDER_INSTALLED="YES"
else
    echo -e "${YELLOW}[WARN]${NC} akv_provider.so is NOT installed in modules directory"
    echo "To install: sudo cp target/release/akv_provider.so \"$MODULESDIR/akv_provider.so\""
    PROVIDER_INSTALLED="NO"
fi

# Check if Azure CLI is installed
if ! command -v az &> /dev/null; then
    echo -e "${RED}ERROR: Azure CLI not found${NC}"
    echo "Please install Azure CLI from https://aka.ms/InstallAzureCLIDocs"
    exit 1
fi
echo -e "${GREEN}[OK]${NC} Azure CLI installed"

# Check if akv_provider can be loaded
echo "Checking if akv_provider is available..."
if openssl list -providers -provider akv_provider -provider default 2>/dev/null | grep -q "akv_provider"; then
    echo -e "${GREEN}[OK]${NC} akv_provider is loadable"
else
    echo -e "${RED}ERROR: akv_provider is not loadable${NC}"
    echo "Please verify:"
    echo "  1. akv_provider.so is in the correct location"
    echo "  2. OpenSSL can find the provider"
    echo "  3. All dependencies are available"
    exit 1
fi

# Authentication setup
echo ""
if [[ $USE_DEFAULT_CREDENTIAL -eq 1 ]]; then
    echo "--- Using DefaultAzureCredential ---"
    echo "[INFO] Skipping access token acquisition - will use Azure SDK authentication"
    echo "[INFO] Make sure you are logged in with 'az login' or have other credentials configured"
    unset AZURE_CLI_ACCESS_TOKEN
else
    echo "--- Fetching Azure CLI access token ---"
    AZURE_CLI_ACCESS_TOKEN=$(az account get-access-token \
        --output json \
        --tenant 72f988bf-86f1-41af-91ab-2d7cd011db47 \
        --resource https://managedhsm.azure.net 2>/dev/null | \
        grep -oP '"accessToken":\s*"\K[^"]+' || true)
    
    if [[ -z "$AZURE_CLI_ACCESS_TOKEN" ]]; then
        echo -e "${RED}ERROR: Failed to get access token${NC}"
        echo "Please verify you are logged in with 'az login'"
        exit 1
    fi
    export AZURE_CLI_ACCESS_TOKEN
    echo -e "${GREEN}[OK]${NC} Access token acquired"
fi

# Set up logging
mkdir -p logs
export AKV_LOG_FILE="$SCRIPT_DIR/logs/akv_provider.log"
export AKV_LOG_LEVEL=3
echo "Logging to $AKV_LOG_FILE at level $AKV_LOG_LEVEL"

# Enable verbose provider logging
export RUST_LOG="${RUST_LOG:-akv_provider=debug,reqwest=warn}"
export RUST_LOG_STYLE="${RUST_LOG_STYLE:-never}"
export RUST_BACKTRACE="${RUST_BACKTRACE:-1}"
echo "Provider logging enabled (RUST_LOG=$RUST_LOG)"

# Create timestamped temp folder for test files
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
TEMP_FOLDER="temp_$TIMESTAMP"
mkdir -p "$TEMP_FOLDER"
echo "Test files will be generated in ./$TEMP_FOLDER/"
echo ""

# Generate test payload
if [[ ! -f "$TEMP_FOLDER/input.bin" ]]; then
    echo "Generating $TEMP_FOLDER/input.bin payload..."
    echo "Azure Managed HSM signing test" > "$TEMP_FOLDER/input.bin"
else
    echo "Found existing $TEMP_FOLDER/input.bin payload."
fi

# Set vault and key names (with defaults)
AKV_VAULT="${AKV_VAULT:-ManagedHSMOpenSSLEngine}"
AKV_RSA_KEY="${AKV_RSA_KEY:-myrsakey}"
AKV_EC_KEY="${AKV_EC_KEY:-ecckey}"
AKV_AES_KEY="${AKV_AES_KEY:-myaeskey}"

RSA_PROVIDER_PATH="managedhsm:$AKV_VAULT:$AKV_RSA_KEY"
EC_PROVIDER_PATH="managedhsm:$AKV_VAULT:$AKV_EC_KEY"
AES_PROVIDER_PATH="managedhsm:$AKV_VAULT:$AKV_AES_KEY"

echo "Using vault '$AKV_VAULT' with RSA key '$AKV_RSA_KEY', EC key '$AKV_EC_KEY', and AES key '$AKV_AES_KEY'."
echo ""

# ============================================================================
# Validate Managed HSM and Keys (optional)
# ============================================================================

if [[ $VALIDATE -eq 1 ]]; then
    echo ""
    echo "--- Validating Managed HSM and Keys ---"
    
    # Check if vault exists and is accessible
    echo "Checking access to vault '$AKV_VAULT'..."
    if ! az keyvault show --hsm-name "$AKV_VAULT" --query "properties.provisioningState" -o tsv 2>/dev/null; then
        echo -e "${RED}ERROR: Cannot access Managed HSM '$AKV_VAULT'${NC}"
        echo "Please verify:"
        echo "  1. The Managed HSM name is correct"
        echo "  2. You have appropriate permissions"
        echo "  3. You are logged in with 'az login'"
        exit 1
    fi
    echo -e "${GREEN}[OK]${NC} Managed HSM '$AKV_VAULT' is accessible"
    
    # Check RSA key
    echo "Checking RSA key '$AKV_RSA_KEY'..."
    RSA_KEY_TYPE=$(az keyvault key show --hsm-name "$AKV_VAULT" --name "$AKV_RSA_KEY" --query "key.kty" -o tsv 2>/dev/null || true)
    if [[ -z "$RSA_KEY_TYPE" ]]; then
        echo -e "${RED}ERROR: RSA key '$AKV_RSA_KEY' not found in vault '$AKV_VAULT'${NC}"
        echo "Create the key with: az keyvault key create --hsm-name $AKV_VAULT --name $AKV_RSA_KEY --kty RSA-HSM --size 3072"
        exit 1
    fi
    echo -e "${GREEN}[OK]${NC} RSA key '$AKV_RSA_KEY' found (type: $RSA_KEY_TYPE)"
    
    # Check EC key
    echo "Checking EC key '$AKV_EC_KEY'..."
    EC_KEY_TYPE=$(az keyvault key show --hsm-name "$AKV_VAULT" --name "$AKV_EC_KEY" --query "key.kty" -o tsv 2>/dev/null || true)
    if [[ -z "$EC_KEY_TYPE" ]]; then
        echo -e "${RED}ERROR: EC key '$AKV_EC_KEY' not found in vault '$AKV_VAULT'${NC}"
        echo "Create the key with: az keyvault key create --hsm-name $AKV_VAULT --name $AKV_EC_KEY --kty EC-HSM --curve P-256"
        exit 1
    fi
    echo -e "${GREEN}[OK]${NC} EC key '$AKV_EC_KEY' found (type: $EC_KEY_TYPE)"
    
    # Check AES key
    echo "Checking AES key '$AKV_AES_KEY'..."
    AES_KEY_TYPE=$(az keyvault key show --hsm-name "$AKV_VAULT" --name "$AKV_AES_KEY" --query "key.kty" -o tsv 2>/dev/null || true)
    if [[ -z "$AES_KEY_TYPE" ]]; then
        echo -e "${RED}ERROR: AES key '$AKV_AES_KEY' not found in vault '$AKV_VAULT'${NC}"
        echo "Create the key with: az keyvault key create --hsm-name $AKV_VAULT --name $AKV_AES_KEY --kty oct-HSM --size 256"
        exit 1
    fi
    echo -e "${GREEN}[OK]${NC} AES key '$AKV_AES_KEY' found (type: $AES_KEY_TYPE)"
    
    echo ""
    echo "All prerequisites validated successfully!"
else
    echo "[INFO] Skipping Managed HSM validation (use --validate for full checks)"
fi
echo ""

# ============================================================================
# Run Tests
# ============================================================================

# Helper function for running tests
run_test() {
    local description="$1"
    shift
    echo "Running: $@"
    if ! "$@"; then
        echo -e "${RED}ERROR: $description failed${NC}"
        exit 1
    fi
}

echo "=== Azure Managed HSM signing tests ==="
echo ""

echo "--- Smoke test: RSA public key export ---"
run_test "RSA public key export" \
    openssl pkey -provider akv_provider -provider default \
    -in "$RSA_PROVIDER_PATH" -pubout -out "$TEMP_FOLDER/myrsakey_pub.pem"

# Compute digest for verification
echo "Computing SHA-256 digest for $TEMP_FOLDER/input.bin..."
openssl dgst -sha256 -binary -out "$TEMP_FOLDER/input.sha256.bin" "$TEMP_FOLDER/input.bin"

echo ""
echo "--- Exporting public keys via provider ---"
run_test "EC public key export" \
    openssl pkey -provider akv_provider -provider default \
    -in "$EC_PROVIDER_PATH" -pubout -out "$TEMP_FOLDER/ecckey_pub.pem"

echo ""
echo "--- RSA PS256 signing roundtrip ---"
run_test "RSA PS256 sign" \
    openssl dgst -sha256 -sign "$RSA_PROVIDER_PATH" \
    -provider akv_provider -provider default \
    -sigopt rsa_padding_mode:pss -sigopt rsa_pss_saltlen:digest -sigopt rsa_mgf1_md:sha256 \
    -out "$TEMP_FOLDER/ps256.sig" "$TEMP_FOLDER/input.bin"

run_test "RSA PS256 verify" \
    openssl dgst -sha256 -verify "$TEMP_FOLDER/myrsakey_pub.pem" \
    -signature "$TEMP_FOLDER/ps256.sig" \
    -sigopt rsa_padding_mode:pss -sigopt rsa_pss_saltlen:digest -sigopt rsa_mgf1_md:sha256 \
    "$TEMP_FOLDER/input.bin"

echo ""
echo "--- RSA RS256 signing roundtrip ---"
run_test "RSA RS256 sign" \
    openssl dgst -sha256 -sign "$RSA_PROVIDER_PATH" \
    -provider akv_provider -provider default \
    -sigopt rsa_padding_mode:pkcs1 \
    -out "$TEMP_FOLDER/rs256.sig" "$TEMP_FOLDER/input.bin"

run_test "RSA RS256 verify" \
    openssl dgst -sha256 -verify "$TEMP_FOLDER/myrsakey_pub.pem" \
    -signature "$TEMP_FOLDER/rs256.sig" \
    -sigopt rsa_padding_mode:pkcs1 \
    "$TEMP_FOLDER/input.bin"

echo ""
echo "--- RSA OAEP decrypt roundtrip ---"
run_test "RSA OAEP encrypt" \
    openssl pkeyutl -encrypt -pubin -inkey "$TEMP_FOLDER/myrsakey_pub.pem" \
    -in "$TEMP_FOLDER/input.bin" -out "$TEMP_FOLDER/rsa_cipher.bin" \
    -pkeyopt rsa_padding_mode:oaep -pkeyopt rsa_oaep_md:sha1 -pkeyopt rsa_mgf1_md:sha1

run_test "RSA OAEP decrypt" \
    openssl pkeyutl -decrypt -provider akv_provider -provider default \
    -inkey "$RSA_PROVIDER_PATH" \
    -in "$TEMP_FOLDER/rsa_cipher.bin" -out "$TEMP_FOLDER/rsa_roundtrip.bin"

if ! cmp -s "$TEMP_FOLDER/input.bin" "$TEMP_FOLDER/rsa_roundtrip.bin"; then
    echo -e "${RED}ERROR: RSA decrypt roundtrip does not match!${NC}"
    exit 1
fi
echo "RSA decrypt roundtrip matches input.bin."

echo ""
echo "--- EC ES256 signing roundtrip ---"
run_test "EC ES256 sign" \
    openssl dgst -sha256 -sign "$EC_PROVIDER_PATH" \
    -provider akv_provider -provider default \
    -out "$TEMP_FOLDER/es256.sig" "$TEMP_FOLDER/input.bin"

run_test "EC ES256 verify" \
    openssl dgst -sha256 -verify "$TEMP_FOLDER/ecckey_pub.pem" \
    -signature "$TEMP_FOLDER/es256.sig" "$TEMP_FOLDER/input.bin"

echo ""
echo ""
echo "=== X.509 CSR and Certificate Tests ==="
echo ""

echo "--- RSA CSR generation and verification ---"
if [[ -f "testOpenssl.cnf" ]]; then
    run_test "RSA CSR generation" \
        openssl req -config testOpenssl.cnf -new \
        -provider akv_provider -provider default \
        -key "$RSA_PROVIDER_PATH" -sha256 -sigopt rsa_padding_mode:pkcs1 \
        -out "$TEMP_FOLDER/cert.csr"
else
    run_test "RSA CSR generation" \
        openssl req -new \
        -provider akv_provider -provider default \
        -key "$RSA_PROVIDER_PATH" -sha256 -sigopt rsa_padding_mode:pkcs1 \
        -subj "/CN=Azure Managed HSM Test/O=Microsoft/C=US" \
        -out "$TEMP_FOLDER/cert.csr"
fi

run_test "RSA CSR verify" \
    openssl req -in "$TEMP_FOLDER/cert.csr" -noout -verify \
    -provider akv_provider -provider default
echo "CSR verification successful."

echo ""
echo "--- RSA self-signed certificate generation ---"
if [[ -f "testOpenssl.cnf" ]]; then
    run_test "RSA self-signed cert" \
        openssl req -config testOpenssl.cnf -new -x509 \
        -provider akv_provider -provider default \
        -propquery "?provider=akv_provider" \
        -key "$RSA_PROVIDER_PATH" -sha256 -days 365 \
        -out "$TEMP_FOLDER/cert.pem"
else
    run_test "RSA self-signed cert" \
        openssl req -new -x509 \
        -provider akv_provider -provider default \
        -propquery "?provider=akv_provider" \
        -key "$RSA_PROVIDER_PATH" -sha256 -days 365 \
        -subj "/CN=Azure Managed HSM Test/O=Microsoft/C=US" \
        -out "$TEMP_FOLDER/cert.pem"
fi

run_test "RSA cert verify" \
    openssl verify -provider akv_provider -provider default \
    -CAfile "$TEMP_FOLDER/cert.pem" "$TEMP_FOLDER/cert.pem"
echo "Self-signed certificate verification successful."

echo ""
echo "--- EC CSR generation and verification ---"
if [[ -f "testOpenssl.cnf" ]]; then
    run_test "EC CSR generation" \
        openssl req -config testOpenssl.cnf -new \
        -provider akv_provider -provider default \
        -key "$EC_PROVIDER_PATH" -sha256 \
        -out "$TEMP_FOLDER/ec_cert.csr"
else
    run_test "EC CSR generation" \
        openssl req -new \
        -provider akv_provider -provider default \
        -key "$EC_PROVIDER_PATH" -sha256 \
        -subj "/CN=Azure Managed HSM EC Test/O=Microsoft/C=US" \
        -out "$TEMP_FOLDER/ec_cert.csr"
fi

run_test "EC CSR verify" \
    openssl req -in "$TEMP_FOLDER/ec_cert.csr" -noout -verify \
    -provider akv_provider -provider default
echo "EC CSR verification successful."

echo ""
echo "--- EC self-signed certificate generation ---"
if [[ -f "testOpenssl.cnf" ]]; then
    run_test "EC self-signed cert" \
        openssl req -config testOpenssl.cnf -new -x509 \
        -provider akv_provider -provider default \
        -propquery "?provider=akv_provider" \
        -key "$EC_PROVIDER_PATH" -sha256 -days 365 \
        -out "$TEMP_FOLDER/ec_cert.pem"
else
    run_test "EC self-signed cert" \
        openssl req -new -x509 \
        -provider akv_provider -provider default \
        -propquery "?provider=akv_provider" \
        -key "$EC_PROVIDER_PATH" -sha256 -days 365 \
        -subj "/CN=Azure Managed HSM EC Test/O=Microsoft/C=US" \
        -out "$TEMP_FOLDER/ec_cert.pem"
fi

run_test "EC cert verify" \
    openssl verify -provider akv_provider -provider default \
    -CAfile "$TEMP_FOLDER/ec_cert.pem" "$TEMP_FOLDER/ec_cert.pem"
echo "EC self-signed certificate verification successful."

echo ""
echo ""
echo "=== AES Key Wrap/Unwrap Tests ==="
echo ""

echo "--- Generating 32-byte test key ---"
run_test "Generate random key" \
    openssl rand -out "$TEMP_FOLDER/local.key" 32
echo "Generated $TEMP_FOLDER/local.key ($(stat --printf="%s" "$TEMP_FOLDER/local.key" 2>/dev/null || stat -f%z "$TEMP_FOLDER/local.key") bytes)"

echo ""
echo "--- Wrapping key with Azure Managed HSM AES key ---"
run_test "AES wrap" \
    openssl pkeyutl -encrypt -inkey "$AES_PROVIDER_PATH" \
    -provider akv_provider -provider default \
    -in "$TEMP_FOLDER/local.key" -out "$TEMP_FOLDER/local.key.wrap"
echo "Wrapped successfully -> $TEMP_FOLDER/local.key.wrap ($(stat --printf="%s" "$TEMP_FOLDER/local.key.wrap" 2>/dev/null || stat -f%z "$TEMP_FOLDER/local.key.wrap") bytes)"

echo ""
echo "--- Unwrapping key with Azure Managed HSM AES key ---"
run_test "AES unwrap" \
    openssl pkeyutl -decrypt -inkey "$AES_PROVIDER_PATH" \
    -provider akv_provider -provider default \
    -in "$TEMP_FOLDER/local.key.wrap" -out "$TEMP_FOLDER/local.key.unwrapped"
echo "Unwrapped successfully -> $TEMP_FOLDER/local.key.unwrapped ($(stat --printf="%s" "$TEMP_FOLDER/local.key.unwrapped" 2>/dev/null || stat -f%z "$TEMP_FOLDER/local.key.unwrapped") bytes)"

echo ""
echo "--- Comparing original and unwrapped keys ---"
if ! cmp -s "$TEMP_FOLDER/local.key" "$TEMP_FOLDER/local.key.unwrapped"; then
    echo -e "${RED}ERROR: Keys do not match!${NC}"
    exit 1
fi
echo "Keys match perfectly!"

echo ""
echo "--- Negative test: Tamper with wrapped key ---"
echo "Attempting to unwrap tampered key (should fail)..."
cp "$TEMP_FOLDER/local.key.wrap" "$TEMP_FOLDER/local.key.wrap.tampered"
echo "X" >> "$TEMP_FOLDER/local.key.wrap.tampered"
if openssl pkeyutl -decrypt -inkey "$AES_PROVIDER_PATH" \
    -provider akv_provider -provider default \
    -in "$TEMP_FOLDER/local.key.wrap.tampered" \
    -out "$TEMP_FOLDER/local.key.bad" 2>/dev/null; then
    echo -e "${RED}ERROR: Tampered key unwrap should have failed!${NC}"
    exit 1
fi
echo "Expected failure on tampered key - PASSED"

echo ""
echo ""
echo -e "${GREEN}=== All tests completed successfully ===${NC}"
echo ""

# Write test summary
echo "Writing test summary to $TEMP_FOLDER/test_summary.txt..."
cat > "$TEMP_FOLDER/test_summary.txt" << EOF
Azure Managed HSM OpenSSL Provider - Test Summary
================================================

Test Run Date: $(date)
Working Directory: $PWD

Prerequisites:
  OpenSSL Version: $OPENSSL_VERSION
  Azure CLI: Installed
  Provider: Found

Environment:
  Vault: $AKV_VAULT
  RSA Key: $AKV_RSA_KEY
  EC Key: $AKV_EC_KEY
  AES Key: $AKV_AES_KEY

Test Results:
  [PASS] RSA PS256 signing roundtrip
  [PASS] RSA RS256 signing roundtrip
  [PASS] RSA OAEP decrypt roundtrip
  [PASS] EC ES256 signing roundtrip
  [PASS] RSA CSR generation and verification
  [PASS] RSA self-signed certificate generation
  [PASS] EC CSR generation and verification
  [PASS] EC self-signed certificate generation
  [PASS] AES key wrap/unwrap roundtrip
  [PASS] AES tamper detection test

Test Files Generated:
  - input.bin (test payload)
  - input.sha256.bin (digest)
  - myrsakey_pub.pem (RSA public key)
  - ecckey_pub.pem (EC public key)
  - ps256.sig, rs256.sig, es256.sig (signatures)
  - cert.csr, ec_cert.csr (certificate requests)
  - cert.pem, ec_cert.pem (self-signed certificates)
  - rsa_cipher.bin, rsa_roundtrip.bin (RSA encryption test)
  - local.key, local.key.wrap, local.key.unwrapped (AES wrap test)
  - local.key.wrap.tampered, local.key.bad (tamper test)

All tests completed successfully!
EOF

echo "Test files preserved in ./$TEMP_FOLDER/ folder"
echo "Test summary written to ./$TEMP_FOLDER/test_summary.txt"
echo ""
