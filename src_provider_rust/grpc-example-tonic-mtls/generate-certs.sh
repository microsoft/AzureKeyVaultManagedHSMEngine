#!/bin/bash
# Generate CA, server, client certs all signed by the same MHSM RSA key.
# Mirrors ../grpc-example/generate-certs.sh but writes into ./certs/ so the
# two demos don't share state.

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CERTS_DIR="$SCRIPT_DIR/certs"
PROVIDER_PATH="$SCRIPT_DIR/../target/release"

. "$SCRIPT_DIR/check-openssl.sh"
require_openssl_minimum 3.0.7 || exit 1

ENV_FILE="$SCRIPT_DIR/.env"
if [ ! -f "$ENV_FILE" ]; then
    echo "ERROR: $ENV_FILE missing. cp .env.example .env and edit it." >&2
    exit 1
fi
set -a; . "$ENV_FILE"; set +a

HSM_NAME="${HSM_NAME:?HSM_NAME unset}"
HSM_KEY_NAME="${HSM_KEY_NAME:?HSM_KEY_NAME unset}"
AZURE_TENANT_ID="${AZURE_TENANT_ID:?AZURE_TENANT_ID unset}"
SERVER_CN="${SERVER_CN:-localhost}"
CLIENT_CN="${CLIENT_CN:-tonic-grpc-client}"
CERT_DAYS="${CERT_DAYS:-365}"

HSM_KEY_URI="managedhsm:${HSM_NAME}:${HSM_KEY_NAME}"
SUBJECT_BASE="/C=${CERT_COUNTRY:-US}/ST=${CERT_STATE:-Washington}/L=${CERT_CITY:-Redmond}/O=${CERT_ORG:-Microsoft}/OU=${CERT_OU:-Azure HSM gRPC Tonic Demo}"

echo "Generating certs against HSM key $HSM_KEY_URI"
mkdir -p "$CERTS_DIR"

if [ -z "${AZURE_CLI_ACCESS_TOKEN:-}" ]; then
    export AZURE_CLI_ACCESS_TOKEN=$(az account get-access-token \
        --output tsv --query accessToken \
        --tenant "$AZURE_TENANT_ID" \
        --resource https://managedhsm.azure.net)
fi

run_openssl() {
    openssl "$@" -provider-path "$PROVIDER_PATH" -provider akv_provider -provider default
}

# --- CA ---
cat > "$CERTS_DIR/ca.ext" <<EOF
basicConstraints = critical, CA:TRUE, pathlen:0
keyUsage = critical, keyCertSign, cRLSign
subjectKeyIdentifier = hash
EOF
run_openssl req -new -key "$HSM_KEY_URI" \
    -subj "$SUBJECT_BASE/CN=tonic-mTLS-CA" \
    -out "$CERTS_DIR/ca.csr"
run_openssl x509 -req -in "$CERTS_DIR/ca.csr" -signkey "$HSM_KEY_URI" \
    -days "$CERT_DAYS" -sha256 -extfile "$CERTS_DIR/ca.ext" \
    -out "$CERTS_DIR/ca.crt"

# --- Server ---
cat > "$CERTS_DIR/server.ext" <<EOF
basicConstraints = CA:FALSE
keyUsage = critical, digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
subjectAltName = DNS:${SERVER_CN}, DNS:localhost, IP:127.0.0.1, IP:::1
EOF
run_openssl req -new -key "$HSM_KEY_URI" \
    -subj "$SUBJECT_BASE/CN=${SERVER_CN}" \
    -out "$CERTS_DIR/server.csr"
run_openssl x509 -req -in "$CERTS_DIR/server.csr" \
    -CA "$CERTS_DIR/ca.crt" -CAkey "$HSM_KEY_URI" -CAcreateserial \
    -days "$CERT_DAYS" -sha256 -extfile "$CERTS_DIR/server.ext" \
    -out "$CERTS_DIR/server.crt"

# --- Client ---
cat > "$CERTS_DIR/client.ext" <<EOF
basicConstraints = CA:FALSE
keyUsage = critical, digitalSignature
extendedKeyUsage = clientAuth
subjectAltName = DNS:${CLIENT_CN}
EOF
run_openssl req -new -key "$HSM_KEY_URI" \
    -subj "$SUBJECT_BASE/CN=${CLIENT_CN}" \
    -out "$CERTS_DIR/client.csr"
run_openssl x509 -req -in "$CERTS_DIR/client.csr" \
    -CA "$CERTS_DIR/ca.crt" -CAkey "$HSM_KEY_URI" -CAcreateserial \
    -days "$CERT_DAYS" -sha256 -extfile "$CERTS_DIR/client.ext" \
    -out "$CERTS_DIR/client.crt"

echo
echo "=== Verifying chain ==="
openssl verify -CAfile "$CERTS_DIR/ca.crt" "$CERTS_DIR/server.crt"
openssl verify -CAfile "$CERTS_DIR/ca.crt" "$CERTS_DIR/client.crt"
echo "Certificates written to $CERTS_DIR/"
