#!/bin/bash
# Generate CA, server, and client certificates using HSM private key
# All certificates share the SAME RSA key from Azure Managed HSM but have different identities
#
# Certificate hierarchy:
#   CA (self-signed) ─┬─► Server cert (for server authentication)
#                     └─► Client cert (for client authentication)

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CERTS_DIR="$SCRIPT_DIR/certs"
PROVIDER_PATH="$SCRIPT_DIR/../target/release"

# Load configuration from .env file
ENV_FILE="$SCRIPT_DIR/.env"
if [ -f "$ENV_FILE" ]; then
    echo "Loading configuration from $ENV_FILE"
    set -a
    source "$ENV_FILE"
    set +a
else
    echo "Warning: No .env file found. Copy .env.example to .env and configure."
    exit 1
fi

# Configuration with defaults
HSM_NAME="${HSM_NAME:-ManagedHSMOpenSSLEngine}"
HSM_KEY_NAME="${HSM_KEY_NAME:-myrsakey}"
AZURE_TENANT_ID="${AZURE_TENANT_ID:-72f988bf-86f1-41af-91ab-2d7cd011db47}"

# Certificate parameters
CERT_ORG="${CERT_ORG:-Microsoft}"
CERT_OU="${CERT_OU:-Azure HSM gRPC Demo}"
CERT_COUNTRY="${CERT_COUNTRY:-US}"
CERT_STATE="${CERT_STATE:-Washington}"
CERT_CITY="${CERT_CITY:-Redmond}"
CERT_DAYS="${CERT_DAYS:-365}"

# Server and client identities (can be same host for demo)
SERVER_CN="${SERVER_CN:-localhost}"
CLIENT_CN="${CLIENT_CN:-grpc-client}"

# Build derived values
HSM_KEY_URI="managedhsm:${HSM_NAME}:${HSM_KEY_NAME}"

echo "=============================================="
echo "Generating certificates using Azure Managed HSM"
echo "=============================================="
echo "HSM:        $HSM_NAME"
echo "Key:        $HSM_KEY_NAME"
echo "Server CN:  $SERVER_CN"
echo "Client CN:  $CLIENT_CN"
echo ""

# Check for access token
if [ -z "$AZURE_CLI_ACCESS_TOKEN" ]; then
    echo "Getting Azure access token..."
    export AZURE_CLI_ACCESS_TOKEN=$(az account get-access-token \
        --output tsv --query accessToken \
        --tenant "$AZURE_TENANT_ID" \
        --resource https://managedhsm.azure.net)
fi

# Create directories
mkdir -p "$CERTS_DIR"

# ============================================
# Step 1: Generate CA certificate (self-signed)
# ============================================
echo ""
echo "=== Step 1: Generating CA certificate ==="
CA_SUBJECT="/C=${CERT_COUNTRY}/ST=${CERT_STATE}/L=${CERT_CITY}/O=${CERT_ORG}/OU=${CERT_OU}/CN=gRPC-mTLS-CA"

# CA extensions
cat > "$CERTS_DIR/ca.ext" << EOF
basicConstraints = critical, CA:TRUE, pathlen:0
keyUsage = critical, keyCertSign, cRLSign
subjectKeyIdentifier = hash
EOF

# Create CA CSR
openssl req -new \
    -provider-path "$PROVIDER_PATH" \
    -provider akv_provider \
    -provider default \
    -key "$HSM_KEY_URI" \
    -subj "$CA_SUBJECT" \
    -out "$CERTS_DIR/ca.csr"

# Self-sign CA certificate
openssl x509 -req \
    -in "$CERTS_DIR/ca.csr" \
    -signkey "$HSM_KEY_URI" \
    -provider-path "$PROVIDER_PATH" \
    -provider akv_provider \
    -provider default \
    -days "$CERT_DAYS" \
    -sha256 \
    -extfile "$CERTS_DIR/ca.ext" \
    -out "$CERTS_DIR/ca.crt"

echo "CA certificate: $CERTS_DIR/ca.crt"

# ============================================
# Step 2: Generate Server certificate
# ============================================
echo ""
echo "=== Step 2: Generating Server certificate ==="
SERVER_SUBJECT="/C=${CERT_COUNTRY}/ST=${CERT_STATE}/L=${CERT_CITY}/O=${CERT_ORG}/OU=${CERT_OU}/CN=${SERVER_CN}"

# Server extensions (for server authentication)
cat > "$CERTS_DIR/server.ext" << EOF
basicConstraints = CA:FALSE
keyUsage = critical, digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
subjectAltName = DNS:${SERVER_CN}, DNS:localhost, IP:127.0.0.1, IP:::1
EOF

# Create server CSR
openssl req -new \
    -provider-path "$PROVIDER_PATH" \
    -provider akv_provider \
    -provider default \
    -key "$HSM_KEY_URI" \
    -subj "$SERVER_SUBJECT" \
    -out "$CERTS_DIR/server.csr"

# Sign server certificate with CA
openssl x509 -req \
    -in "$CERTS_DIR/server.csr" \
    -CA "$CERTS_DIR/ca.crt" \
    -CAkey "$HSM_KEY_URI" \
    -provider-path "$PROVIDER_PATH" \
    -provider akv_provider \
    -provider default \
    -CAcreateserial \
    -days "$CERT_DAYS" \
    -sha256 \
    -extfile "$CERTS_DIR/server.ext" \
    -out "$CERTS_DIR/server.crt"

echo "Server certificate: $CERTS_DIR/server.crt"

# ============================================
# Step 3: Generate Client certificate
# ============================================
echo ""
echo "=== Step 3: Generating Client certificate ==="
CLIENT_SUBJECT="/C=${CERT_COUNTRY}/ST=${CERT_STATE}/L=${CERT_CITY}/O=${CERT_ORG}/OU=${CERT_OU}/CN=${CLIENT_CN}"

# Client extensions (for client authentication)
cat > "$CERTS_DIR/client.ext" << EOF
basicConstraints = CA:FALSE
keyUsage = critical, digitalSignature
extendedKeyUsage = clientAuth
subjectAltName = DNS:${CLIENT_CN}
EOF

# Create client CSR
openssl req -new \
    -provider-path "$PROVIDER_PATH" \
    -provider akv_provider \
    -provider default \
    -key "$HSM_KEY_URI" \
    -subj "$CLIENT_SUBJECT" \
    -out "$CERTS_DIR/client.csr"

# Sign client certificate with CA
openssl x509 -req \
    -in "$CERTS_DIR/client.csr" \
    -CA "$CERTS_DIR/ca.crt" \
    -CAkey "$HSM_KEY_URI" \
    -provider-path "$PROVIDER_PATH" \
    -provider akv_provider \
    -provider default \
    -CAcreateserial \
    -days "$CERT_DAYS" \
    -sha256 \
    -extfile "$CERTS_DIR/client.ext" \
    -out "$CERTS_DIR/client.crt"

echo "Client certificate: $CERTS_DIR/client.crt"

# ============================================
# Step 4: Verify certificates
# ============================================
echo ""
echo "=== Step 4: Verifying certificates ==="

echo ""
echo "CA Certificate:"
openssl x509 -in "$CERTS_DIR/ca.crt" -noout -subject -issuer -dates

echo ""
echo "Server Certificate:"
openssl x509 -in "$CERTS_DIR/server.crt" -noout -subject -issuer -dates
openssl verify -CAfile "$CERTS_DIR/ca.crt" "$CERTS_DIR/server.crt"

echo ""
echo "Client Certificate:"
openssl x509 -in "$CERTS_DIR/client.crt" -noout -subject -issuer -dates
openssl verify -CAfile "$CERTS_DIR/ca.crt" "$CERTS_DIR/client.crt"

# ============================================
# Summary
# ============================================
echo ""
echo "=============================================="
echo "Certificate generation complete!"
echo "=============================================="
echo ""
echo "Files created:"
echo "  CA:     $CERTS_DIR/ca.crt"
echo "  Server: $CERTS_DIR/server.crt"
echo "  Client: $CERTS_DIR/client.crt"
echo ""
echo "All certificates use the same HSM key: $HSM_KEY_URI"
echo "But have different identities (CN) and key usage extensions."
