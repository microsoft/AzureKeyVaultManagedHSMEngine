#!/bin/bash
# Verify the host OpenSSL version is new enough for the akv_provider OSSL_STORE
# callback path. OpenSSL 3.0.2 (Ubuntu 22.04 default) has a bug in
# OSSL_STORE_open()'s object callback where EVP_KEYMGMT_fetch with a NULL
# property query string returns the wrong provider's keymgmt — causing
# "RSA object callback failed (returned 0)" / "EC object callback failed"
# when loading HSM-resident keys via `managedhsm:<vault>:<key>` URIs.
#
# Upstream fix: https://github.com/openssl/openssl/issues/18221
# Available since OpenSSL 3.0.7.
#
# Source this file from any script that loads HSM keys through the provider.

require_openssl_minimum() {
    local required="${1:-3.0.7}"
    local actual
    actual=$(openssl version 2>/dev/null | awk '{print $2}')
    if [ -z "$actual" ]; then
        echo "ERROR: 'openssl' not found on PATH." >&2
        return 1
    fi
    # Strip any letter suffix (e.g., 3.0.13a -> 3.0.13) for sort -V.
    local actual_num
    actual_num=$(echo "$actual" | sed 's/[a-z]*$//')
    local lowest
    lowest=$(printf '%s\n%s\n' "$required" "$actual_num" | sort -V | head -n1)
    if [ "$lowest" != "$required" ]; then
        cat >&2 <<EOF
ERROR: OpenSSL $actual detected, but >= $required is required.

The akv_provider relies on OSSL_STORE provider callbacks that are broken in
OpenSSL 3.0.2 (Ubuntu 22.04 default). Loading HSM keys will fail with
"RSA/EC object callback failed (returned 0)".

Fix: upgrade to OpenSSL >= 3.0.7. Options:
  * Ubuntu 24.04+ ships OpenSSL 3.0.13 (recommended for WSL).
  * Build OpenSSL 3.0.x (>= 3.0.7) from source under /opt/openssl-3 and
    prepend it to PATH + LD_LIBRARY_PATH for this shell.
  * Use a container with a newer OpenSSL (e.g., debian:trixie, ubuntu:24.04).

Reference: https://github.com/openssl/openssl/issues/18221
EOF
        return 1
    fi
    return 0
}
