# Azure Key Vault / Managed HSM OpenSSL Provider

An Azure Managed HSM Provider compatible with OpenSSL 3.x that enables applications to use private keys stored in Azure Managed HSM without exposing the keys. **Private keys never leave the HSM** - all cryptographic operations are performed remotely via the Azure REST API.

## Key Features
- **Support OpenSSL 3.0x Provider** In OpenSSL 3.0 and later, [Providers](https://docs.openssl.org/master/man7/provider) are the new way the library handles cryptographic algorithms. Supports include the self-signed x509 certificate with private keys in Azure Managed HSM. Details see [src_provider_rust/runtest.sh](src_provider_rust/runtest.sh) and [src_provider_rust/runtest.bat](src_provider_rust/runtest.bat).
- **NGINX/gRPC Keyless TLS (Transport Layer Security) Support (Linux only)**: During TLS handshake, private keys never leave the Azure Managed HSM. The private key is loaded via [OSSL_STORE integration](https://docs.openssl.org/master/man7/ossl_store). Details see [nginx-example](src_provider_rust/nginx-example/) and [grpc-example](src_provider_rust/grpc-example/)
- **RSA Support**: RSA-PSS and PKCS#1 v1.5 signing (2048, 3072, 4096 bit keys)
- **EC Support**: ECDSA signing with P-256, P-384, P-521 curves
- **RUST Cross-Platform support**: Works on Linux and Windows
- **AI enlightened** The Rust version provider is 100% built by Github Copilot (See the commits history, NO HUMAN DEVELOPER can ever develop in such a intensive way). See also [.github/copilot-instructions.md](.github/copilot-instructions.md)


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
