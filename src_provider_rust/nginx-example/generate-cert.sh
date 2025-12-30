#!/bin/bash
# Generate certificates using HSM private keys (RSA and EC)
# The certificates are signed by the HSM, but the public portion is stored locally

set -e

# Clear OPENSSL_CONF to avoid conflicts
unset OPENSSL_CONF

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CERTS_DIR="$SCRIPT_DIR/certs"
PROVIDER_PATH="$SCRIPT_DIR/../target/release"

# Create symlink for provider if needed (cargo builds libakv_provider.so but OpenSSL expects akv_provider.so)
if [ -f "$PROVIDER_PATH/libakv_provider.so" ] && [ ! -f "$PROVIDER_PATH/akv_provider.so" ]; then
    ln -sf libakv_provider.so "$PROVIDER_PATH/akv_provider.so"
fi

# Load configuration from .env file
ENV_FILE="$SCRIPT_DIR/.env"
if [ -f "$ENV_FILE" ]; then
    echo "Loading configuration from $ENV_FILE"
    set -a  # Export all variables
    source "$ENV_FILE"
    set +a
else
    echo "Warning: No .env file found. Run ./setup-env.sh first or using defaults."
fi

# Configuration with defaults
HSM_NAME="${HSM_NAME:-ManagedHSMOpenSSLEngine}"
RSA_KEY_NAME="${RSA_KEY_NAME:-myrsakey}"
EC_KEY_NAME="${EC_KEY_NAME:-ecckey}"
AZURE_TENANT_ID="${AZURE_TENANT_ID:-72f988bf-86f1-41af-91ab-2d7cd011db47}"
CERT_CN="${CERT_CN:-localhost}"
CERT_ORG="${CERT_ORG:-Microsoft}"
CERT_OU="${CERT_OU:-Azure HSM Demo}"
CERT_COUNTRY="${CERT_COUNTRY:-US}"
CERT_STATE="${CERT_STATE:-Washington}"
CERT_CITY="${CERT_CITY:-Redmond}"
CERT_DAYS="${CERT_DAYS:-365}"

# Build derived values
CERT_SUBJECT="/C=${CERT_COUNTRY}/ST=${CERT_STATE}/L=${CERT_CITY}/O=${CERT_ORG}/OU=${CERT_OU}/CN=${CERT_CN}"

echo "=== Generating certificates using Azure Managed HSM ==="
echo "HSM:     $HSM_NAME"
echo "RSA Key: $RSA_KEY_NAME"
echo "EC Key:  $EC_KEY_NAME"
echo "Subject: $CERT_SUBJECT"
echo ""

# Check for access token
if [ -z "$AZURE_CLI_ACCESS_TOKEN" ]; then
    echo "Getting Azure access token..."
    export AZURE_CLI_ACCESS_TOKEN=$(az account get-access-token --output tsv --query accessToken --tenant "$AZURE_TENANT_ID" --resource https://managedhsm.azure.net)
fi

# Create certs directory
mkdir -p "$CERTS_DIR" "$SCRIPT_DIR/logs"

# Create extensions file for SAN
cat > "$CERTS_DIR/server.ext" << EXTEOF
basicConstraints=CA:FALSE
keyUsage=digitalSignature,keyEncipherment
subjectAltName=DNS:${CERT_CN},IP:127.0.0.1
EXTEOF

# Function to generate certificate
generate_cert() {
    local KEY_NAME="$1"
    local KEY_TYPE="$2"
    local OUTPUT_PREFIX="$3"
    
    local HSM_KEY_URI="managedhsm:${HSM_NAME}:${KEY_NAME}"
    
    echo ""
    echo "=== Generating $KEY_TYPE certificate ==="
    echo "Key URI: $HSM_KEY_URI"
    
    # Create CSR using the HSM key
    echo "Creating CSR with HSM key..."
    openssl req -new \
        -provider-path "$PROVIDER_PATH" \
        -provider akv_provider \
        -provider default \
        -key "$HSM_KEY_URI" \
        -subj "$CERT_SUBJECT" \
        -out "$CERTS_DIR/${OUTPUT_PREFIX}.csr"
    
    # Self-sign the certificate using the HSM key
    echo "Signing certificate with HSM key..."
    openssl x509 -req \
        -in "$CERTS_DIR/${OUTPUT_PREFIX}.csr" \
        -signkey "$HSM_KEY_URI" \
        -provider-path "$PROVIDER_PATH" \
        -provider akv_provider \
        -provider default \
        -days "$CERT_DAYS" \
        -sha256 \
        -extfile "$CERTS_DIR/server.ext" \
        -out "$CERTS_DIR/${OUTPUT_PREFIX}.crt"
    
    # Verify the certificate
    echo ""
    echo "=== $KEY_TYPE Certificate generated successfully ==="
    openssl x509 -in "$CERTS_DIR/${OUTPUT_PREFIX}.crt" -noout -subject -issuer -dates
    
    echo ""
    echo "Certificate: $CERTS_DIR/${OUTPUT_PREFIX}.crt"
    echo "CSR:         $CERTS_DIR/${OUTPUT_PREFIX}.csr"
}

# Generate RSA certificate
generate_cert "$RSA_KEY_NAME" "RSA" "server-rsa"

# Generate EC certificate
generate_cert "$EC_KEY_NAME" "EC" "server-ec"

echo ""
echo "=== All certificates generated successfully ==="
echo ""
echo "RSA Certificate: $CERTS_DIR/server-rsa.crt (key: $RSA_KEY_NAME)"
echo "EC Certificate:  $CERTS_DIR/server-ec.crt (key: $EC_KEY_NAME)"

# Create symlinks for backwards compatibility with nginx.conf.template
# (template uses server.crt, we generate server-rsa.crt)
ln -sf server-rsa.crt "$CERTS_DIR/server.crt"
ln -sf server-rsa.csr "$CERTS_DIR/server.csr"
