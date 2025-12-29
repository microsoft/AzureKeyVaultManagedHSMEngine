# Azure Key Vault / Managed HSM OpenSSL Provider

An OpenSSL 3.x Provider that enables TLS applications to use private keys stored in Azure Key Vault or Azure Managed HSM without exposing the keys.

## Overview

This provider implements the OpenSSL 3.x Provider API to perform cryptographic operations (RSA and EC signing) using keys stored in Azure Managed HSM. The private key **never leaves the HSM** - all signing operations are performed remotely via the Azure REST API.

### Key Features

- **Keyless TLS**: Private keys remain in the HSM, only signatures are returned
- **RSA Support**: RSA-PSS and PKCS#1 v1.5 signing (2048, 3072, 4096 bit keys)
- **EC Support**: ECDSA signing with P-256, P-384, P-521 curves
- **OSSL_STORE Integration**: Load keys via URI scheme `managedhsm:<vault>:<keyname>`
- **Azure Authentication**: Environment variable, Managed Identity, or Azure CLI

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                    Your Application                              │
│              (nginx, gRPC, curl, custom app)                    │
│  ┌─────────────────────────────────────────────────────────┐    │
│  │                    OpenSSL 3.x                           │    │
│  │    ssl_certificate_key "store:managedhsm:vault:key"     │    │
│  └────────────────────┬────────────────────────────────────┘    │
│                       │                                          │
│  ┌────────────────────▼────────────────────────────────────┐    │
│  │              AKV Provider (Rust)                         │    │
│  │    OSSL_STORE → Key Management → Signature Operations   │    │
│  └────────────────────┬────────────────────────────────────┘    │
└───────────────────────┼──────────────────────────────────────────┘
                        │ HTTPS (REST API)
                        ▼
              ┌─────────────────────────┐
              │   Azure Managed HSM     │
              │   ┌─────────────────┐   │
              │   │  RSA / EC Keys  │   │
              │   │  (never leave)  │   │
              │   └─────────────────┘   │
              └─────────────────────────┘
```

## Quick Start

### Prerequisites

- Rust 1.70+ with Cargo
- OpenSSL 3.x development libraries
- Azure CLI (for authentication)
- Azure Managed HSM with RSA and/or EC keys

### Build

```bash
cd src_provider_rust
cargo build --release
```

The provider library will be at `target/release/libakv_provider.so` (Linux) or `target/release/akv_provider.dll` (Windows).

### Configure OpenSSL

Create an OpenSSL configuration file to load the provider:

```ini
openssl_conf = openssl_init

[openssl_init]
providers = provider_section

[provider_section]
default = default_section
base = base_section
akv_provider = akv_provider_section

[default_section]
activate = 1

[base_section]
activate = 1

[akv_provider_section]
module = /path/to/libakv_provider.so
activate = 1
```

### Use with nginx

See [nginx-example/README.md](src_provider_rust/nginx-example/README.md) for detailed instructions.

```nginx
ssl_certificate_key "store:managedhsm:ManagedHSMOpenSSLEngine:myrsakey";
```

### Use with gRPC

See [grpc-example/README.md](src_provider_rust/grpc-example/README.md) for mTLS setup with gRPC.

## Examples

| Example | Description |
|---------|-------------|
| [nginx-example](src_provider_rust/nginx-example/) | Keyless TLS for nginx (RSA & EC) |
| [grpc-example](src_provider_rust/grpc-example/) | mTLS for gRPC with sidecar pattern |

## Authentication

The provider supports multiple authentication methods (in order of precedence):

1. **Environment Variable**: `AZURE_CLI_ACCESS_TOKEN` - Token for Managed HSM
2. **Azure SDK DefaultAzureCredential**:
   - Environment variables (`AZURE_CLIENT_ID`, `AZURE_TENANT_ID`, `AZURE_CLIENT_SECRET`)
   - Managed Identity (when running in Azure)
   - Azure CLI (`az login`)

### Getting a Token

```bash
export AZURE_CLI_ACCESS_TOKEN=$(az account get-access-token \
    --resource https://managedhsm.azure.net \
    --query accessToken -o tsv)
```

## Project Structure

```
├── src_provider_rust/          # Rust OpenSSL Provider implementation
│   ├── src/                    # Provider source code
│   │   ├── lib.rs             # Provider entry point
│   │   ├── store.rs           # OSSL_STORE implementation
│   │   ├── keymgmt.rs         # Key management
│   │   ├── signature.rs       # Signature operations
│   │   └── auth.rs            # Azure authentication
│   ├── nginx-example/         # nginx keyless TLS example
│   └── grpc-example/          # gRPC mTLS example
├── deprecated/                 # Archived C implementation
└── .github/                    # GitHub workflows and templates
```

## Contributing

This project welcomes contributions. See [CONTRIBUTING.md](.github/CONTRIBUTING.md) for guidelines.

## License

MIT License - see [LICENSE.txt](LICENSE.txt)

## Security

See [SECURITY.md](SECURITY.md) for reporting security vulnerabilities.

## Support

See [SUPPORT.md](SUPPORT.md) for support options.
