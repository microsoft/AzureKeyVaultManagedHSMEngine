#!/bin/bash
# Generate certificate using HSM private key
# The certificate is signed by the HSM, but the public portion is stored locally

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CERTS_DIR="$SCRIPT_DIR/certs"
PROVIDER_PATH="$SCRIPT_DIR/../target/release"

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
HSM_KEY_NAME="${HSM_KEY_NAME:-myrsakey}"
AZURE_TENANT_ID="${AZURE_TENANT_ID:-72f988bf-86f1-41af-91ab-2d7cd011db47}"
CERT_CN="${CERT_CN:-localhost}"
CERT_ORG="${CERT_ORG:-Microsoft}"
CERT_OU="${CERT_OU:-Azure HSM Demo}"
CERT_COUNTRY="${CERT_COUNTRY:-US}"
CERT_STATE="${CERT_STATE:-Washington}"
CERT_CITY="${CERT_CITY:-Redmond}"
CERT_DAYS="${CERT_DAYS:-365}"

# Build derived values
HSM_KEY_URI="managedhsm:${HSM_NAME}:${HSM_KEY_NAME}"
CERT_SUBJECT="/C=${CERT_COUNTRY}/ST=${CERT_STATE}/L=${CERT_CITY}/O=${CERT_ORG}/OU=${CERT_OU}/CN=${CERT_CN}"

echo "=== Generating certificate using Azure Managed HSM ==="
echo "HSM:     $HSM_NAME"
echo "Key:     $HSM_KEY_NAME"
echo "Subject: $CERT_SUBJECT"
echo ""

# Check for access token
if [ -z "$AZURE_CLI_ACCESS_TOKEN" ]; then
    echo "Getting Azure access token..."
    export AZURE_CLI_ACCESS_TOKEN=$(az account get-access-token --output tsv --query accessToken --tenant "$AZURE_TENANT_ID" --resource https://managedhsm.azure.net)
fi

# Create certs directory
mkdir -p "$CERTS_DIR"

# Create CSR using the HSM key
echo "Creating CSR with HSM key..."
openssl req -new \
    -provider-path "$PROVIDER_PATH" \
    -provider akv_provider \
    -provider default \
    -key "$HSM_KEY_URI" \
    -subj "$CERT_SUBJECT" \
    -out "$CERTS_DIR/server.csr"

# Create extensions file for SAN
cat > "$CERTS_DIR/server.ext" << EOF
basicConstraints=CA:FALSE
keyUsage=digitalSignature,keyEncipherment
subjectAltName=DNS:${CERT_CN},IP:127.0.0.1
EOF

# Self-sign the certificate using the HSM key
echo "Signing certificate with HSM key..."
openssl x509 -req \
    -in "$CERTS_DIR/server.csr" \
    -signkey "$HSM_KEY_URI" \
    -provider-path "$PROVIDER_PATH" \
    -provider akv_provider \
    -provider default \
    -days "$CERT_DAYS" \
    -sha256 \
    -extfile "$CERTS_DIR/server.ext" \
    -out "$CERTS_DIR/server.crt"

# Verify the certificate
echo ""
echo "=== Certificate generated successfully ==="
openssl x509 -in "$CERTS_DIR/server.crt" -noout -subject -issuer -dates

echo ""
echo "Certificate: $CERTS_DIR/server.crt"
echo "CSR:         $CERTS_DIR/server.csr"
