# Nginx Keyless TLS with Azure Managed HSM

This example demonstrates using nginx with Azure Managed HSM for TLS private key operations.
The private key never leaves the HSM - all TLS signing operations are performed by the HSM.

**Supports both RSA and EC (ECDSA) keys** on separate ports for testing different key types.

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
              ┌─────────────────────────┐
              │    Azure Managed HSM    │
              │   ┌─────────────────┐   │
              │   │   RSA Key       │   │
              │   │   (3072 bit)    │   │
              │   ├─────────────────┤   │
              │   │   EC Key        │   │
              │   │   (P-256)       │   │
              │   └─────────────────┘   │
              └─────────────────────────┘
```

## Supported Key Types

| Key Type | Port | HSM Key Name | Cipher Suite |
|----------|------|--------------|--------------|
| RSA (3072-bit) | 8443 | `myrsakey` | ECDHE-RSA-AES256-GCM-SHA384 |
| EC (P-256) | 8444 | `ecckey` | ECDHE-ECDSA-AES256-GCM-SHA384 |

## Requirements

- **nginx 1.27+** (for OSSL_STORE support)
- OpenSSL 3.x
- Azure CLI (for authentication)
- Azure Managed HSM with RSA and/or EC keys

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

2. **Configure your environment**:
   ```bash
   ./setup-env.sh
   # Edit .env with your HSM name, key names, and tenant ID
   ```

3. **Generate certificates** (both RSA and EC):
   ```bash
   ./generate-cert.sh
   ```

4. **Start nginx**:
   ```bash
   ./start-server.sh
   ```

5. **Test the connections** (both RSA and EC):
   ```bash
   # Test both servers
   ./test-client.sh
   
   # Or test individually:
   # RSA server (port 8443)
   curl -k https://localhost:8443/
   curl -k https://localhost:8443/health
   
   # EC server (port 8444)
   curl -k https://localhost:8444/
   curl -k https://localhost:8444/health
   ```

6. **Stop nginx**:
   ```bash
   ./stop-server.sh
   ```

## Configuration

All settings are configured in `.env` (copy from `.env.example`):

| Variable | Description | Default |
|----------|-------------|---------|
| `HSM_NAME` | Azure Managed HSM name | `ManagedHSMOpenSSLEngine` |
| `RSA_KEY_NAME` | RSA key name in HSM | `myrsakey` |
| `EC_KEY_NAME` | EC key name in HSM | `ecckey` |
| `AZURE_TENANT_ID` | Azure tenant ID | (Microsoft tenant) |
| `CERT_CN` | Certificate common name | `localhost` |
| `CERT_DAYS` | Certificate validity | `365` |

## Files

| File | Description |
|------|-------------|
| `.env.example` | Template configuration (copy to .env) |
| `.env` | Local configuration (git-ignored) |
| `nginx.conf` | nginx config with RSA (8443) and EC (8444) servers |
| `openssl-provider.cnf` | OpenSSL configuration to load the AKV provider |
| `generate-cert.sh` | Generate both RSA and EC certificates signed by HSM keys |
| `setup-env.sh` | Create .env from template |
| `start-server.sh` | Start nginx with proper environment |
| `stop-server.sh` | Stop nginx |
| `test-client.sh` | Test both RSA and EC TLS connections |
| `certs/server-rsa.crt` | RSA certificate (generated) |
| `certs/server-ec.crt` | EC certificate (generated) |

## How It Works

### Key Loading via OSSL_STORE

The private keys are specified in `nginx.conf` using special URIs:

```nginx
# RSA server (port 8443)
ssl_certificate_key "store:managedhsm:ManagedHSMOpenSSLEngine:myrsakey";

# EC server (port 8444)
ssl_certificate_key "store:managedhsm:ManagedHSMOpenSSLEngine:ecckey";
```

- `store:` - Prefix that tells nginx to use `OSSL_STORE_open()` (nginx 1.27+)
- `managedhsm:` - Our provider's store scheme
- `ManagedHSMOpenSSLEngine` - HSM vault name
- `myrsakey` / `ecckey` - Key name in the HSM

### Provider Configuration

The `openssl-provider.cnf` configures OpenSSL to load providers in the correct order:

```ini
[provider_section]
# Default provider FIRST - handles normal RSA/EC operations
default = default_section
base = base_section
# AKV provider LAST - handles HSM operations via managedhsm: scheme
akv_provider = akv_provider_section
```

**Important**: Provider order matters! The default provider must be listed first
so that normal RSA/EC public key operations work correctly.

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

## Testing Both Key Types

The `test-client.sh` script tests both RSA and EC servers:

```bash
$ ./test-client.sh

========================================
  Testing Nginx Keyless TLS with HSM
========================================

========================================
  Testing RSA Server (port 8443)
========================================

--- HTTPS Request ---
Hello from Nginx with Azure Managed HSM keyless TLS!

Server Time: 29/Dec/2025:00:28:43 +0000
SSL Protocol: TLSv1.3
SSL Cipher: TLS_AES_256_GCM_SHA384
Key Type: RSA
HSM: ManagedHSMOpenSSLEngine
Key: myrsakey
✓ HTTPS connection successful

========================================
  Testing EC Server (port 8444)
========================================

--- HTTPS Request ---
Hello from Nginx with Azure Managed HSM keyless TLS!

Server Time: 29/Dec/2025:00:28:45 +0000
SSL Protocol: TLSv1.3
SSL Cipher: TLS_AES_256_GCM_SHA384
Key Type: EC (P-256)
HSM: ManagedHSMOpenSSLEngine
Key: ecckey
✓ HTTPS connection successful

========================================
  All Tests Complete
========================================
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
tries to use our provider for normal RSA/EC operations, which fails.

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

### EC key shows "EVP_PKEY_get_params failed" in logs

This is expected for EC keys when querying certain parameters. The signing operations
still work correctly.

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
AKV provider is listed **before** the default provider, when OpenSSL encounters an
RSA/EC public key (from the certificate), it tries the AKV provider first. Our 
provider's `akv_keymgmt_import` function rejects the key because it has no HSM 
metadata, but by that point OpenSSL cannot properly fall back to the default provider.

### The Fix

Reorder the providers so **default comes FIRST**:

```ini
[provider_section]
default = default_section   # Listed FIRST - handles normal RSA/EC keys
base = base_section
akv_provider = akv_provider_section  # Listed LAST - only for HSM keys
```

This ensures:
- Normal RSA/EC public key operations → handled by default provider ✅
- Keys loaded via `managedhsm:` URI → handled by AKV provider ✅
