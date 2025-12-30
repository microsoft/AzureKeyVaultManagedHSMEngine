# Azure Managed HSM OpenSSL Provider - Development Guide

This document contains instructions for building, testing, and developing the Azure Managed HSM OpenSSL 3.x Provider.

## Project Overview

- **Location**: `src_provider_rust/`
- **Language**: Rust
- **Output**: `libakv_provider.so` (OpenSSL 3.x provider)
- **Purpose**: Enables OpenSSL to use keys stored in Azure Managed HSM for cryptographic operations

## Prerequisites

### System Requirements

- **OS**: Linux (Ubuntu 22.04+ recommended)
- **OpenSSL**: 3.0+ (verify with `openssl version`)
- **Rust**: Latest stable (install via rustup)
- **Azure CLI**: For authentication (`az login`)

### Azure Resources (Example Values)

> **Note**: The values below are examples. Configure your own Azure Managed HSM and keys, then set the corresponding environment variables.

- **Managed HSM**: e.g., `MyManagedHSM` (set via `AKV_VAULT` env var)
- **Keys**:
  - RSA key: e.g., `my-rsa-key` (RSA-HSM 2048/3072/4096-bit) - set via `AKV_RSA_KEY`
  - EC key: e.g., `my-ec-key` (EC-HSM P-256/P-384/P-521) - set via `AKV_EC_KEY`
  - AES key: e.g., `my-aes-key` (oct-HSM 128/192/256-bit) - set via `AKV_AES_KEY`

**Create keys in Azure Managed HSM**:
```bash
# RSA key (3072-bit)
az keyvault key create --hsm-name <your-hsm> --name <rsa-key-name> --kty RSA-HSM --size 3072

# EC key (P-256)
az keyvault key create --hsm-name <your-hsm> --name <ec-key-name> --kty EC-HSM --curve P-256

# AES key (256-bit)
az keyvault key create --hsm-name <your-hsm> --name <aes-key-name> --kty oct-HSM --size 256
```

### OpenSSL Modules Directory

```bash
# Find OpenSSL modules directory
openssl version -m
# Typically: /usr/lib/x86_64-linux-gnu/ossl-modules
```

## Building the Provider

### Option 1: Use the Build Script (Recommended)

The `ubuntubuild.sh` script handles dependency checks, building, and deployment:

```bash
cd ~/AzureKeyVaultManagedHSMEngine/src_provider_rust
./ubuntubuild.sh
```

**Options**:
- `--debug`: Build in debug mode instead of release
- `--skip-deps`: Skip dependency checks (faster for rebuilds)

The script will:
1. Check Rust toolchain
2. Check OpenSSL dependencies
3. Build the provider
4. Deploy to OpenSSL modules directory (requires sudo)

### Option 2: Manual Build Steps

#### 1. Navigate to Source Directory

```bash
cd ~/AzureKeyVaultManagedHSMEngine/src_provider_rust
```

#### 2. Build Release Version

```bash
cargo build --release
```

**Output**: `target/release/libakv_provider.so`

#### 3. Install Provider (requires sudo)

```bash
sudo cp target/release/libakv_provider.so /usr/lib/x86_64-linux-gnu/ossl-modules/akv_provider.so
```

#### 4. Verify Installation

```bash
openssl list -providers -provider akv_provider -provider default
```

## Authentication

### Option 1: Environment Variable (Recommended for Testing)

```bash
export AZURE_CLI_ACCESS_TOKEN=$(az account get-access-token \
    --resource https://managedhsm.azure.net \
    --query accessToken -o tsv)
```

### Option 2: DefaultAzureCredential

If `AZURE_CLI_ACCESS_TOKEN` is not set, the provider falls back to Azure SDK's DefaultAzureCredential chain (requires `az login`).

## Testing

### Run Full Test Suite

```bash
cd ~/AzureKeyVaultManagedHSMEngine/src_provider_rust
./runtest.sh
```

**Options**:
- `--validate`: Run full HSM/key validation (slower)
- `--noenv`: Use DefaultAzureCredential instead of env var

### Test Suite Coverage

| Test | Description |
|------|-------------|
| RSA PS256 | PSS padding with SHA-256 sign/verify |
| RSA RS256 | PKCS#1 v1.5 padding sign/verify |
| RSA OAEP | Encrypt/decrypt with OAEP padding |
| EC ES256 | ECDSA P-256 sign/verify |
| RSA CSR | Certificate signing request generation |
| RSA Cert | Self-signed certificate generation |
| EC CSR | EC certificate signing request |
| EC Cert | EC self-signed certificate |
| AES Wrap | Key wrap/unwrap operations |
| Tamper Test | Negative test for tamper detection |

### nginx TLS Testing

#### 1. Setup Environment Configuration

The nginx-example folder includes a template-based environment setup:

```bash
cd ~/AzureKeyVaultManagedHSMEngine/src_provider_rust/nginx-example

# Create .env from template
./setup-env.sh

# Edit .env with your settings
nano .env
```

**`.env.example` template settings**:
```ini
# Azure Managed HSM Configuration
HSM_NAME=<your-hsm-name>
HSM_KEY_NAME=<your-key-name>
AZURE_TENANT_ID=<your-tenant-id>

# Certificate Settings
CERT_CN=localhost
CERT_ORG=Microsoft
CERT_DAYS=365

# Nginx Settings
NGINX_PORT=8443
SERVER_NAME=localhost

# Logging (optional)
# AKV_LOG_FILE=./logs/akv_provider.log
# AKV_LOG_LEVEL=2
```

#### 2. Generate Certificates and Test

```bash
cd ~/AzureKeyVaultManagedHSMEngine/src_provider_rust/nginx-example

# Generate certificates (RSA and EC)
./generate-cert.sh

# Start nginx (requires nginx 1.27+ for OSSL_STORE support)
sudo nginx -c $(pwd)/nginx.conf

# Test both servers
./test-client.sh
```

**Ports**:
- `8443`: RSA TLS server (uses RSA key)
- `8444`: EC TLS server (uses EC key)

## Key URI Format

The provider uses `managedhsm:` URI scheme:

```
managedhsm:<vault-name>:<key-name>
```

**Examples**:
- `managedhsm:ManagedHSMOpenSSLEngine:myrsakey`
- `managedhsm:ManagedHSMOpenSSLEngine:ecckey`

## OpenSSL Configuration

### testOpenssl.cnf (for runtest.sh)

Located at `src_provider_rust/testOpenssl.cnf` - configures providers and certificate subject.

### nginx OpenSSL Config

Located at `src_provider_rust/nginx-example/openssl-provider.cnf`:

```ini
openssl_conf = openssl_init

[openssl_init]
providers = provider_sect

[provider_sect]
default = default_sect
akv_provider = akv_provider_sect

[default_sect]
activate = 1

[akv_provider_sect]
activate = 1
```

**Important**: `default` provider must come before `akv_provider` to avoid digest algorithm issues.

## Common Issues & Solutions

### 1. "no digest algorithm" Error

**Cause**: Provider order wrong or SHA256 not available
**Solution**: Ensure `default` provider is listed before `akv_provider` in config

### 2. Token Expired

**Symptoms**: HTTP 401 errors in logs
**Solution**: Refresh token:
```bash
export AZURE_CLI_ACCESS_TOKEN=$(az account get-access-token \
    --resource https://managedhsm.azure.net \
    --query accessToken -o tsv)
```

### 3. Provider Not Found

**Solution**: Verify installation:
```bash
ls -la /usr/lib/x86_64-linux-gnu/ossl-modules/akv_provider.so
```

### 4. nginx SSL_CTX_use_PrivateKey_file Error

**Cause**: nginx version < 1.27 doesn't support OSSL_STORE
**Solution**: Use nginx 1.27+ or build from source

## Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `AZURE_CLI_ACCESS_TOKEN` | Azure access token for HSM | (uses DefaultAzureCredential) |
| `AKV_VAULT` | Managed HSM name | `ManagedHSMOpenSSLEngine` |
| `AKV_RSA_KEY` | RSA key name | `myrsakey` |
| `AKV_EC_KEY` | EC key name | `ecckey` |
| `AKV_AES_KEY` | AES key name | `myaeskey` |
| `AKV_LOG_FILE` | Log file path | (none) |
| `AKV_LOG_LEVEL` | Log level (0-5) | `3` |
| `RUST_LOG` | Rust logging filter | `akv_provider=debug` |

## File Structure

```
src_provider_rust/
├── Cargo.toml              # Rust dependencies
├── src/
│   ├── lib.rs              # Provider entry point
│   ├── store.rs            # OSSL_STORE implementation
│   ├── keymgmt.rs          # Key management (RSA, EC, AES)
│   ├── signature.rs        # Signature operations
│   ├── asymcipher.rs       # RSA encrypt/decrypt
│   └── hsm_client.rs       # Azure Managed HSM client
├── testOpenssl.cnf         # OpenSSL config for tests
├── runtest.sh              # Main test script
└── nginx-example/
    ├── nginx.conf          # nginx configuration
    ├── openssl-provider.cnf
    ├── generate-cert.sh    # Certificate generation
    ├── test-client.sh      # TLS client tests
    └── README.md
```

## Quick Reference Commands

```bash
# Build
cd src_provider_rust && cargo build --release

# Install
sudo cp target/release/libakv_provider.so /usr/lib/x86_64-linux-gnu/ossl-modules/akv_provider.so

# Get token
export AZURE_CLI_ACCESS_TOKEN=$(az account get-access-token --resource https://managedhsm.azure.net --query accessToken -o tsv)

# Test
./runtest.sh

# nginx test
cd nginx-example && ./generate-cert.sh && sudo nginx -c $(pwd)/nginx.conf && ./test-client.sh
```
