#!/bin/bash
# Run the tonic-native mTLS server with HSM-resident private key.
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROVIDER_PATH="$(cd "$SCRIPT_DIR/../target/release" 2>/dev/null && pwd)" || {
    echo "ERROR: provider build dir $SCRIPT_DIR/../target/release not found." >&2
    echo "       Build first:  (cd ..; cargo build --release)" >&2
    exit 1
}
CERTS_DIR="$SCRIPT_DIR/certs"
BIN_DIR="$SCRIPT_DIR/target/release"

# cargo builds libakv_provider.so; OpenSSL's `-provider akv_provider` flag
# expects akv_provider.so. Create the symlink once (idempotent).
if [ -f "$PROVIDER_PATH/libakv_provider.so" ] && [ ! -e "$PROVIDER_PATH/akv_provider.so" ]; then
    ln -sf libakv_provider.so "$PROVIDER_PATH/akv_provider.so"
fi

# Ensure host OpenSSL is >= 3.0.7 (avoids the OSSL_STORE callback bug in 3.0.2).
. "$SCRIPT_DIR/check-openssl.sh"
require_openssl_minimum 3.0.7 || exit 1

if [ ! -f "$SCRIPT_DIR/.env" ]; then
    echo "ERROR: .env missing. cp .env.example .env and edit it." >&2; exit 1
fi
# Allow ENV_FILE override (e.g. ENV_FILE=.env.ec ./start-server.sh).
ENV_FILE="${ENV_FILE:-$SCRIPT_DIR/.env}"
# Resolve to absolute path if a relative name was passed.
case "$ENV_FILE" in
    /*) ;;
    *) ENV_FILE="$SCRIPT_DIR/$ENV_FILE" ;;
esac
if [ ! -f "$ENV_FILE" ]; then
    echo "ERROR: ENV_FILE='$ENV_FILE' not found." >&2; exit 1
fi
echo "Loading config from $ENV_FILE"
set -a; . "$ENV_FILE"; set +a

# Render openssl.cnf with the actual provider path.
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
export SERVER_CERT_PEM="$CERTS_DIR/server.crt"
export CA_CERT_PEM="$CERTS_DIR/ca.crt"
export RUST_LOG="${RUST_LOG:-info}"

# Build once if needed (skip if SKIP_BUILD=1 or cargo not on PATH).
if [ "${SKIP_BUILD:-0}" != "1" ] && command -v cargo >/dev/null 2>&1; then
    (cd "$SCRIPT_DIR" && cargo build --release --bin tonic-mtls-server)
fi

if [ ! -x "$BIN_DIR/tonic-mtls-server" ]; then
    echo "ERROR: $BIN_DIR/tonic-mtls-server not found. Build first: cargo build --release" >&2
    exit 1
fi

exec "$BIN_DIR/tonic-mtls-server"
