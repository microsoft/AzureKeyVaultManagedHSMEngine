# Nginx Keyless TLS with Azure Managed HSM

This example demonstrates using nginx with Azure Managed HSM for TLS private key operations.
The private key never leaves the HSM - all TLS signing operations are performed by the HSM.

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                         nginx                                    │
│  ┌─────────────────────────────────────────────────────────┐    │
│  │                    SSL/TLS Handshake                     │    │
│  │    Certificate (public) ──────────────────────────────► Client │
│  │    Private Key Operations ◄───────── Sign Request       │    │
│  └────────────────────┬────────────────────────────────────┘    │
│                       │                                          │
│  ┌────────────────────▼────────────────────────────────────┐    │
│  │              OpenSSL + AKV Provider                      │    │
│  │    OSSL_STORE_open("store:managedhsm:...:keyname")      │    │
│  └────────────────────┬────────────────────────────────────┘    │
└───────────────────────┼──────────────────────────────────────────┘
                        │ HTTPS (REST API)
                        ▼
              ┌─────────────────────┐
              │  Azure Managed HSM  │
              │   ┌─────────────┐   │
              │   │ Private Key │   │
              │   │ (RSA 3072)  │   │
              │   └─────────────┘   │
              └─────────────────────┘
```

## Requirements

- **nginx 1.27+** (for OSSL_STORE support)
- OpenSSL 3.x
- Azure CLI (for authentication)
- Azure Managed HSM with an RSA key

### Installing nginx 1.27+

Stock Ubuntu/Debian nginx (1.24) doesn't support OpenSSL 3.x providers via OSSL_STORE.
Install nginx from the official mainline repository:

```bash
# Ubuntu/Debian
sudo apt install -y curl gnupg2 ca-certificates lsb-release ubuntu-keyring
curl https://nginx.org/keys/nginx_signing.key | gpg --dearmor | \
    sudo tee /usr/share/keyrings/nginx-archive-keyring.gpg >/dev/null
echo "deb [signed-by=/usr/share/keyrings/nginx-archive-keyring.gpg] \
    http://nginx.org/packages/mainline/ubuntu $(lsb_release -cs) nginx" | \
    sudo tee /etc/apt/sources.list.d/nginx.list
sudo apt update && sudo apt install -y nginx
```

## Quick Start

1. **Build the provider** (from the parent directory):
   ```bash
   cd ..
   cargo build --release
   ```

2. **Generate certificate**:
   ```bash
   ./generate-cert.sh
   ```

3. **Start nginx**:
   ```bash
   ./start-server.sh
   ```

4. **Test the connection**:
   ```bash
   curl -k https://localhost:8443/
   ```

5. **Stop nginx**:
   ```bash
   ./stop-server.sh
   ```

## Files

| File | Description |
|------|-------------|
| `nginx.conf` | nginx configuration with HSM key reference |
| `openssl-provider.cnf` | OpenSSL configuration to load the AKV provider |
| `generate-cert.sh` | Generate certificate signed by HSM key |
| `start-server.sh` | Start nginx with proper environment |
| `stop-server.sh` | Stop nginx |
| `test-client.sh` | Test the TLS connection |

## How It Works

### Key Loading via OSSL_STORE

The private key is specified in `nginx.conf` using a special URI:

```nginx
ssl_certificate_key "store:managedhsm:ManagedHSMOpenSSLEngine:myrsakey";
```

- `store:` - Prefix that tells nginx to use `OSSL_STORE_open()` (nginx 1.27+)
- `managedhsm:` - Our provider's store scheme
- `ManagedHSMOpenSSLEngine` - HSM vault name
- `myrsakey` - Key name in the HSM

### Provider Configuration

The `openssl-provider.cnf` configures OpenSSL to load providers in the correct order:

```ini
[provider_section]
# Default provider FIRST - handles normal RSA operations
default = default_section
base = base_section
# AKV provider LAST - handles HSM operations via managedhsm: scheme
akv_provider = akv_provider_section
```

**Important**: Provider order matters! The default provider must be listed first
so that normal RSA public key operations work correctly.

### Environment Variables

The following environment variables must be set:

| Variable | Description |
|----------|-------------|
| `AZURE_CLI_ACCESS_TOKEN` | Azure access token for HSM authentication |
| `OPENSSL_CONF` | Path to `openssl-provider.cnf` |
| `AKV_LOG_FILE` | (Optional) Provider log file path |
| `AKV_LOG_LEVEL` | (Optional) Log level (0-3) |

The `nginx.conf` includes `env` directives to pass these to worker processes:

```nginx
env AZURE_CLI_ACCESS_TOKEN;
env OPENSSL_CONF;
```

## Security Notes

1. **Private key protection**: The private key never leaves the HSM. Only signing
   operations are performed by the HSM.

2. **Access token**: The access token is passed via environment variable. In
   production, consider using Managed Identity or a more secure token refresh
   mechanism.

3. **TLS settings**: The example uses secure defaults (TLS 1.2/1.3, strong ciphers)
   but review for your specific security requirements.

## Troubleshooting

### "decode error" when loading certificate

This happens when the AKV provider is listed before the default provider. OpenSSL
tries to use our provider for normal RSA operations, which fails.

**Solution**: Ensure `default` provider is listed before `akv_provider` in
`openssl-provider.cnf`.

### "unregistered scheme: managedhsm"

The AKV provider is not loaded or not found.

**Solution**: Check that `OPENSSL_CONF` points to `openssl-provider.cnf` and the
provider library exists at the configured path.

### TLS handshake fails with "internal error"

Usually means the signing operation failed.

**Check**:
1. `AZURE_CLI_ACCESS_TOKEN` is set and valid
2. The HSM key exists and has sign permission
3. Check `logs/akv_provider.log` for detailed errors

### nginx reports "OSSL_STORE_open() failed"

nginx version is too old. Need nginx 1.27+ for OSSL_STORE support.

**Solution**: Install nginx from the official mainline repository.

## Technical Note: Provider Order Issue

### The Problem

When generating the certificate with the AKV provider loaded, the public key embedded
in the certificate can become corrupted, showing:

```
Subject Public Key Info:
    Public Key Algorithm: rsaEncryption
    Unable to load Public Key
error:03000072:digital envelope routines::decode error
```

### Root Cause

OpenSSL searches providers in the order they are listed in the configuration. If the
AKV provider is listed **before** the default provider:

```ini
[provider_section]
akv_provider = akv_provider_section  # Listed FIRST - BAD!
default = default_section
base = base_section
```

When OpenSSL encounters an RSA public key (from the certificate), it tries the AKV
provider first. Our provider's `akv_keymgmt_import` function rejects the key (returning 0)
because it has no HSM metadata. However, by that point OpenSSL has already allocated
the key object using our provider and cannot properly fall back to the default provider.

### The Fix

Reorder the providers so **default comes FIRST**:

```ini
[provider_section]
default = default_section   # Listed FIRST - handles normal RSA keys
base = base_section
akv_provider = akv_provider_section  # Listed LAST - only for HSM keys
```

This ensures:
- Normal RSA public key operations → handled by default provider ✅
- Keys loaded via `managedhsm:` URI → handled by AKV provider ✅

The certificate generation works correctly after this fix, and nginx can load both the
certificate (with its embedded public key) and access the HSM-stored private key.
