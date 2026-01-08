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

### One-liner (recommended)

After first-time setup, run the complete test with a single command:

```bash
./run-all.sh
```

This will:
1. Clean up any previous state
2. Generate RSA and EC certificates
3. Start nginx with both servers
4. Run the test client

### Step-by-step

1. **Build the provider** (from the parent directory):
   ```bash
   cd ..
   cargo build --release
   ```

2. **Configure your environment** (first time only):
   ```bash
   ./setup-env.sh
   # Edit .env with your HSM name, key names, etc.
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
   ./test-client.sh
   ```

6. **Stop nginx**:
   ```bash
   ./stop-server.sh
   ```

7. **Clean up** (remove all generated files):
   ```bash
   ./cleanup.sh
   ```

## Configuration

All settings are configured in `.env` (copy from `.env.example`):

| Variable | Description | Default |
|----------|-------------|---------|
| `HSM_NAME` | Azure Managed HSM name | `ManagedHSMOpenSSLEngine` |
| `RSA_KEY_NAME` | RSA key name in HSM | `myrsakey` |
| `EC_KEY_NAME` | EC key name in HSM | `ecckey` |
| `NGINX_PORT` | RSA server port | `8443` |
| `NGINX_PORT_EC` | EC server port | `8444` |
| `CERT_CN` | Certificate common name | `localhost` |
| `CERT_DAYS` | Certificate validity | `365` |

## Files

| File | Description |
|------|-------------|
| `run-all.sh` | **One-liner**: cleanup + generate certs + start server + test |
| `cleanup.sh` | Remove all generated files and stop nginx |
| `generate-cert.sh` | Generate both RSA and EC certificates signed by HSM keys |
| `start-server.sh` | Start nginx with proper environment |
| `stop-server.sh` | Stop nginx |
| `test-client.sh` | Test both RSA and EC TLS connections |
| `setup-env.sh` | Create .env from template (first-time setup) |
| `.env.example` | Template configuration |
| `.env` | Local configuration (git-ignored) |
| `nginx.conf.template` | nginx config template (dual RSA/EC servers) |
| `openssl-provider.cnf.template` | OpenSSL provider config template |

### Generated Files (created by scripts)

| File | Description |
|------|-------------|
| `nginx.conf` | Generated nginx config |
| `openssl-provider.cnf` | Generated OpenSSL config |
| `certs/server-rsa.crt` | RSA certificate |
| `certs/server-ec.crt` | EC certificate |
| `logs/` | nginx and provider logs |

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
[provider_sect]
# Default provider FIRST - handles normal RSA/EC operations
default = default_sect
base = base_sect
# AKV provider LAST - handles HSM operations via managedhsm: scheme
akv_provider = akv_provider_sect
```

**Important**: Provider order matters! The default provider must be listed first
so that normal RSA/EC public key operations work correctly.

### Environment Variables

The following environment variables are set automatically by the scripts:

| Variable | Description |
|----------|-------------|
| `AZURE_CLI_ACCESS_TOKEN` | Azure access token for HSM authentication |
| `OPENSSL_CONF` | Path to `openssl-provider.cnf` |
| `AKV_LOG_FILE` | Provider log file path |
| `AKV_LOG_LEVEL` | Log level (0-3) |

The `nginx.conf` includes `env` directives to pass these to worker processes:

```nginx
env AZURE_CLI_ACCESS_TOKEN;
env OPENSSL_CONF;
```

## Example Output

```bash
$ ./run-all.sh

=== Cleaning up nginx-example ===
Stopping nginx (PID: 12345)...
Removing certificates...
Removing logs...
Cleanup complete!

=== Generating certificates using Azure Managed HSM ===
HSM:     ManagedHSMOpenSSLEngine
RSA Key: myrsakey
EC Key:  ecckey
...

=== Starting nginx with Azure Managed HSM keyless TLS ===
HSM:      ManagedHSMOpenSSLEngine
RSA Key:  myrsakey (port 8443)
EC Key:   ecckey (port 8444)

nginx started successfully (PID: 12346)

========================================
  Testing Nginx Keyless TLS with HSM
========================================

  Testing RSA Server (port 8443)
✓ HTTPS connection successful
✓ Health check passed
✓ Certificate key type matches expected (RSA)

  Testing EC Server (port 8444)
✓ HTTPS connection successful
✓ Health check passed
✓ Certificate key type matches expected (EC)

========================================
  All Tests Complete
========================================

Summary:
  - RSA Server (port 8443): Using key 'myrsakey' from Azure Managed HSM
  - EC Server (port 8444):  Using key 'ecckey' from Azure Managed HSM

Both servers use keyless TLS where the private key never leaves the HSM.
```

## Security Notes

1. **Private key protection**: The private key never leaves the HSM. Only signing
   operations are performed by the HSM.

2. **Access token**: The access token is obtained via Azure CLI. In production,
   consider using Managed Identity or a more secure token refresh mechanism.

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
[provider_sect]
default = default_sect   # Listed FIRST - handles normal RSA/EC keys
base = base_sect
akv_provider = akv_provider_sect  # Listed LAST - only for HSM keys
```

This ensures:
- Normal RSA/EC public key operations → handled by default provider ✅
- Keys loaded via `managedhsm:` URI → handled by AKV provider ✅

## Platform Compatibility

### Linux (Recommended) ✅

The nginx-example works well on Linux with the official nginx mainline packages:

| Platform | nginx | OpenSSL | Status |
|----------|-------|---------|--------|
| Ubuntu 24.04 (x86_64) | 1.27+ (64-bit, dynamic) | 3.0.x | ✅ Fully supported |
| Ubuntu 22.04 (x86_64) | 1.27+ (64-bit, dynamic) | 3.0.x | ✅ Fully supported |
| Debian 12 (x86_64) | 1.27+ (64-bit, dynamic) | 3.0.x | ✅ Fully supported |

Key requirements:
- nginx dynamically linked with OpenSSL (`libssl.so.3`, `libcrypto.so.3`)
- OpenSSL 3.x provider support
- nginx 1.27+ for OSSL_STORE support

### Windows ❌ (Not Supported)

**nginx on Windows does NOT work with OpenSSL 3.x providers** due to:

1. **32-bit binary**: The official nginx.org Windows binary is built as 32-bit (x86)

2. **Static OpenSSL linking**: OpenSSL is compiled with `no-shared` flag, embedding it directly into nginx.exe

**Evidence from nginx source code:**
- [auto/lib/openssl/makefile.msvc](https://github.com/nginx/nginx/blob/master/auto/lib/openssl/makefile.msvc): `no-shared no-threads`
- [auto/lib/openssl/make](https://github.com/nginx/nginx/blob/master/auto/lib/openssl/make): Default `VC-WIN32` target

This means:
   - Cannot use external OpenSSL providers
   - Cannot load `akv_provider.so` at runtime
   - No `OSSL_STORE_open()` provider support

```
# Official nginx build for Windows is 32-bit and statically linked with OpenSSL:
nginx.exe: PE32 executable (console) Intel 80386, statically linked
```

**Workarounds** (not recommended):
- Build nginx from source on Windows with dynamic OpenSSL 3.x linking (complex)
- Use a different web server that supports OpenSSL 3.x providers
- Use Linux (VM, WSL2, or container)

### macOS (Untested)

Should work with Homebrew nginx if dynamically linked with OpenSSL 3.x. Untested.

## References

- [nginx PR #436](https://github.com/nginx/nginx/pull/436) - The PR that added `store:` prefix support for OSSL_STORE keys (merged May 2025)
- [nginx-tests PR #16](https://github.com/nginx/nginx-tests/pull/16) - Test suite for provider keys
- [nginx trac #2449](https://trac.nginx.org/nginx/ticket/2449) - Original feature request for OpenSSL 3.x provider support
- [test-results.md](test-results.md) - Detailed test results and PR summary
