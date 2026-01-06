#!/bin/bash
# Generate self-signed certificates for Key Vault keyless TLS testing
# These certificates use local keys for the public cert,
# while the actual TLS signing uses Key Vault keys.

set -e

# Load environment
if [ -f .env ]; then
    source .env
else
    echo "Error: .env file not found. Copy .env.example to .env first."
    exit 1
fi

CERT_DIR="./certs"
mkdir -p "$CERT_DIR"

echo "🔐 Generating self-signed certificates for Key Vault keyless TLS"
echo "   Vault: $KEYVAULT_NAME"
echo ""

# Generate RSA certificate
echo "📜 Generating RSA certificate..."
openssl req -x509 -newkey rsa:3072 -nodes \
    -keyout "$CERT_DIR/rsa-server.key" \
    -out "$CERT_DIR/rsa-server.crt" \
    -days 365 \
    -subj "/C=US/ST=Washington/L=Redmond/O=KeyVault Test/CN=rsa.$KEYVAULT_NAME.local" \
    -addext "subjectAltName=DNS:localhost,DNS:rsa.$KEYVAULT_NAME.local"

echo "   ✅ RSA certificate: $CERT_DIR/rsa-server.crt"

# Generate EC certificate
echo "📜 Generating EC certificate..."
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
    -keyout "$CERT_DIR/ec-server.key" \
    -out "$CERT_DIR/ec-server.crt" \
    -days 365 \
    -subj "/C=US/ST=Washington/L=Redmond/O=KeyVault Test/CN=ec.$KEYVAULT_NAME.local" \
    -addext "subjectAltName=DNS:localhost,DNS:ec.$KEYVAULT_NAME.local"

echo "   ✅ EC certificate: $CERT_DIR/ec-server.crt"

echo ""
echo "📁 Certificates generated in: $CERT_DIR"
echo ""
echo "⚠️  NOTE: The .key files are for reference only."
echo "   With keyless TLS, nginx uses Key Vault for signing:"
echo "   ssl_certificate_key \"store:keyvault:$KEYVAULT_NAME:$RSA_KEY_NAME\";"
