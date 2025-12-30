# Azure Key Vault / Managed HSM OpenSSL Provider

An OpenSSL 3.x Provider that enables TLS applications to use private keys stored in Azure Key Vault or Azure Managed HSM without exposing the keys. **Private keys never leave the HSM** - all cryptographic operations are performed remotely via the Azure REST API.

## Key Features

- **Keyless TLS**: Private keys remain in the HSM, only signatures are returned
- **RSA Support**: RSA-PSS and PKCS#1 v1.5 signing (2048, 3072, 4096 bit keys)
- **EC Support**: ECDSA signing with P-256, P-384, P-521 curves
- **OSSL_STORE Integration**: Load keys via URI scheme `managedhsm:<vault>:<keyname>`
- **Cross-Platform**: Works on Linux and Windows (provider), Linux for nginx keyless TLS

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

### Build the Provider

```bash
cd src_provider_rust

# Linux
./ubuntubuild.sh

# Windows
winbuild.bat
```

### Run Tests

```bash
# Linux
./runtest.sh

# Windows
runtest.bat
```

For detailed build instructions, prerequisites, and configuration options, see [src_provider_rust/README.md](src_provider_rust/README.md).

## Examples

| Example | Platform | Description |
|---------|----------|-------------|
| [nginx-example](src_provider_rust/nginx-example/) | Linux | Keyless TLS for nginx with RSA & EC keys |
| [grpc-example](src_provider_rust/grpc-example/) | Linux/Windows | mTLS for gRPC with sidecar pattern |

### nginx Keyless TLS (Linux Only)

```bash
cd src_provider_rust/nginx-example
./run-all.sh  # Cleanup + generate certs + start nginx + test
```

> **Note**: Windows nginx from nginx.org doesn't support OpenSSL providers due to static linking (`no-shared`) and 32-bit build. See [nginx-example/README.md](src_provider_rust/nginx-example/README.md) for details.

## Documentation

| Document | Description |
|----------|-------------|
| [src_provider_rust/README.md](src_provider_rust/README.md) | Full technical documentation, build details, API reference |
| [nginx-example/README.md](src_provider_rust/nginx-example/README.md) | nginx keyless TLS setup and configuration |
| [nginx-example/test-results.md](src_provider_rust/nginx-example/test-results.md) | Test results and platform compatibility notes |
| [grpc-example/README.md](src_provider_rust/grpc-example/README.md) | gRPC mTLS with sidecar pattern |

## Authentication

The provider supports (in order of precedence):

1. **Environment Variable**: `AZURE_CLI_ACCESS_TOKEN`
2. **Azure SDK DefaultAzureCredential**: Managed Identity, Azure CLI, Environment Variables

```bash
# Quick setup
export AZURE_CLI_ACCESS_TOKEN=$(az account get-access-token \
    --resource https://managedhsm.azure.net --query accessToken -o tsv)
```

## Project Structure

```
├── src_provider_rust/          # Rust OpenSSL Provider
│   ├── src/                    # Provider source code
│   ├── nginx-example/          # nginx keyless TLS example
│   └── grpc-example/           # gRPC mTLS example
├── deprecated/                 # Archived C implementation
└── .github/                    # GitHub workflows
```

## Contributing

See [CONTRIBUTING.md](.github/CONTRIBUTING.md) for guidelines.

## License

MIT License - see [LICENSE.txt](LICENSE.txt)

## Security

See [SECURITY.md](SECURITY.md) for reporting vulnerabilities.
