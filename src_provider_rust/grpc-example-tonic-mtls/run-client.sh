#!/bin/bash
# Run the tonic-native mTLS client with HSM-resident private key.
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROVIDER_PATH="$SCRIPT_DIR/../target/release"
CERTS_DIR="$SCRIPT_DIR/certs"

. "$SCRIPT_DIR/check-openssl.sh"
require_openssl_minimum 3.0.7 || exit 1

if [ ! -f "$SCRIPT_DIR/.env" ]; then
    echo "ERROR: .env missing. cp .env.example .env and edit it." >&2; exit 1
fi
set -a; . "$SCRIPT_DIR/.env"; set +a

RENDERED_CNF="$SCRIPT_DIR/openssl-provider.cnf"
sed "s|PROVIDER_PATH|$PROVIDER_PATH|g" \
    "$SCRIPT_DIR/openssl-provider.cnf.template" > "$RENDERED_CNF"

if [ -z "${AZURE_CLI_ACCESS_TOKEN:-}" ]; then
    export AZURE_CLI_ACCESS_TOKEN=$(az account get-access-token \
        --output tsv --query accessToken \
        --tenant "$AZURE_TENANT_ID" \
        --resource https://managedhsm.azure.net)
fi

export OPENSSL_CONF="$RENDERED_CNF"
export HSM_KEY_URI="managedhsm:${HSM_NAME}:${HSM_KEY_NAME}"
export CLIENT_CERT_PEM="$CERTS_DIR/client.crt"
export CA_CERT_PEM="$CERTS_DIR/ca.crt"
export GRPC_SERVER_ADDR="${GRPC_SERVER_ADDR:-https://localhost:50443}"
export GRPC_SERVER_NAME="${GRPC_SERVER_NAME:-localhost}"
export RUST_LOG="${RUST_LOG:-info}"

(cd "$SCRIPT_DIR" && cargo build --release --bin tonic-mtls-client)

exec "$SCRIPT_DIR/../target/release/tonic-mtls-client"
