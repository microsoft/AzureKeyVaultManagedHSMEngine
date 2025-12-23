#!/bin/bash
# Generate certificate using HSM private key
# The certificate is signed by the HSM, but the public portion is stored locally

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CERTS_DIR="$SCRIPT_DIR/certs"
PROVIDER_PATH="$SCRIPT_DIR/../target/release"

# Configuration
HSM_KEY_URI="managedhsm:ManagedHSMOpenSSLEngine:myrsakey"
CERT_SUBJECT="/C=US/ST=Washington/L=Redmond/O=Microsoft/OU=Azure HSM Demo/CN=localhost"

echo "=== Generating certificate using Azure Managed HSM ==="

# Check for access token
if [ -z "$AZURE_CLI_ACCESS_TOKEN" ]; then
    echo "Getting Azure access token..."
    export AZURE_CLI_ACCESS_TOKEN=$(az account get-access-token --output tsv --query accessToken --tenant 72f988bf-86f1-41af-91ab-2d7cd011db47 --resource https://managedhsm.azure.net)
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

# Create extensions file
cat > "$CERTS_DIR/server.ext" << EOF
basicConstraints=CA:FALSE
keyUsage=digitalSignature,keyEncipherment
subjectAltName=DNS:localhost,IP:127.0.0.1
EOF

# Self-sign the certificate using the HSM key
echo "Signing certificate with HSM key..."
openssl x509 -req \
    -in "$CERTS_DIR/server.csr" \
    -signkey "$HSM_KEY_URI" \
    -provider-path "$PROVIDER_PATH" \
    -provider akv_provider \
    -provider default \
    -days 365 \
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
