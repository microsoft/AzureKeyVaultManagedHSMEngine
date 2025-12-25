# Azure Key Vault Managed HSM OpenSSL Provider

Enable OpenSSL-based applications to use RSA/EC private keys protected by Azure Managed HSM. Cryptographic operations (signing, decryption) are performed inside the HSM - **private keys never leave the hardware security module**.

## Supported Implementations

| Implementation | Status | Platform | OpenSSL Version |
|----------------|--------|----------|-----------------|
| **Rust Provider** (src_provider_rust/) |  **Active** | Windows, Linux | OpenSSL 3.x |
| C Provider (src_provider/) | Maintenance | Windows, Linux | OpenSSL 3.x |
| C Engine (src/) | Legacy | Windows, Linux | OpenSSL 1.1.x |

> **Recommendation**: Use the **Rust provider** for new deployments. It provides better memory safety, modern error handling, and is actively maintained.

## Quick Start (Rust Provider)

### Prerequisites
- **Rust** toolchain (1.70+)
- **Azure CLI** (`az`)
- **OpenSSL 3.x** command-line tools
- **Azure Managed HSM** with RSA/EC keys

### Windows

```cmd
cd src_provider_rust
winbuild.bat
runtest.bat
```

### Linux/Ubuntu

```bash
cd src_provider_rust
./ubuntubuild.sh
./runtest.sh
```

## Use Cases

### 1. Nginx TLS with HSM-Protected Keys

Serve HTTPS traffic where the TLS private key never leaves the HSM:

```bash
cd src_provider_rust/nginx-example
./setup-env.sh        # Create .env config (edit with your HSM settings)
./generate-cert.sh    # Generate cert signed by HSM
./start-server.sh     # Start nginx with HSM key
curl -k https://localhost:8443/
```

See [nginx-example/README.md](src_provider_rust/nginx-example/README.md) for full setup instructions.

### 2. gRPC mTLS with Sidecar Proxy

Enable gRPC applications to use mTLS with HSM-protected keys via a sidecar proxy pattern:

```
gRPC Client → NGINX Client Sidecar ═══mTLS═══► NGINX Server Sidecar → gRPC Server
     │              │                                    │                │
     └──── UDS ─────┘                                    └──── UDS ───────┘
        (plaintext)                                         (plaintext)
```

**Why a sidecar?** gRPC libraries (tonic, grpc-go, etc.) do not support OpenSSL 3.x `store:` URIs. The sidecar pattern allows gRPC apps to benefit from HSM-backed TLS without any code changes.

```bash
cd src_provider_rust/grpc-example
./generate-certs.sh   # Generate certs with HSM key
./start-demo.sh       # Start sidecars + gRPC server
./run-client.sh       # Test gRPC through mTLS tunnel
./stop-demo.sh        # Clean up
```

See [grpc-example/README.md](src_provider_rust/grpc-example/README.md) for full setup and [sidecar-design-deep-dive.md](src_provider_rust/grpc-example/sidecar-design-deep-dive.md) for architecture details.


### 3. Certificate Signing Requests (CSR)

Generate CSRs with HSM-protected keys:

```bash
openssl req -new \
    -provider akv_provider -provider default \
    -key "managedhsm:MyHSM:mykey" \
    -subj "/CN=myserver.example.com" \
    -out server.csr
```

### 4. Self-Signed Certificates

```bash
openssl req -new -x509 \
    -provider akv_provider -provider default \
    -key "managedhsm:MyHSM:mykey" \
    -days 365 \
    -out server.crt
```

### 5. Digital Signatures

```bash
# Sign a file
openssl dgst -sha256 \
    -provider akv_provider -provider default \
    -sign "managedhsm:MyHSM:mykey" \
    -out signature.bin data.txt

# Verify (with public key)
openssl dgst -sha256 -verify pubkey.pem -signature signature.bin data.txt
```

## Testing Results (nginx Keyless TLS Example)

The following test demonstrates the complete workflow of using Azure Managed HSM for keyless TLS with nginx.

### Test Environment
- **nginx version**: 1.29.4
- **OpenSSL**: 3.x with akv_provider
- **HSM**: Azure Managed HSM

### Test Summary

| Step | Description | Result |
|------|-------------|--------|
| 1 | nginx version check | ✅ 1.27+ installed |
| 2 | Certificate generation with HSM | ✅ Signed by HSM |
| 3 | nginx startup with HSM provider | ✅ Running |
| 4 | TLS connection test | ✅ TLSv1.3 |
| 5 | HSM signing verification | ✅ Verified in logs |
| 6 | Cleanup | ✅ Stopped |

### Certificate Generation

```
=== Generating certificate using Azure Managed HSM ===
Creating CSR with HSM key...
Signing certificate with HSM key...
Certificate request self-signature ok
subject=C = US, ST = Washington, L = Redmond, O = Microsoft, OU = Azure HSM Demo, CN = localhost
```

### TLS Connection Test

```bash
$ curl -k https://localhost:8443/
Hello from Nginx with Azure Managed HSM keyless TLS!

Server Time: 23/Dec/2025:23:52:58 +0000
SSL Protocol: TLSv1.3
SSL Cipher: TLS_AES_256_GCM_SHA384
```

### Health Check Endpoint

```bash
$ curl -k https://localhost:8443/health
{"status": "healthy", "ssl": true, "hsm": "Azure Managed HSM"}
```

### TLS Certificate Verification

```
subject=C = US, ST = Washington, L = Redmond, O = Microsoft, OU = Azure HSM Demo, CN = localhost
issuer=C = US, ST = Washington, L = Redmond, O = Microsoft, OU = Azure HSM Demo, CN = localhost
New, TLSv1.3, Cipher is TLS_AES_256_GCM_SHA384
    Protocol  : TLSv1.3
    Cipher    : TLS_AES_256_GCM_SHA384
```

### HSM Signing Operations (from nginx logs)

```
[INFO akv_provider::signature] akv_signature_digest_sign -> 1 (signature 384 bytes)
[INFO akv_provider::signature] akv_signature_digest_sign -> 1 (signature 384 bytes)
[INFO akv_provider::signature] akv_signature_digest_sign -> 1 (signature 384 bytes)
```

> **Key Security**: The private key never left the HSM - all TLS signing operations were performed inside Azure Managed HSM!

### Run the Tests Yourself

```bash
cd src_provider_rust/nginx-example
./setup-env.sh        # Configure HSM settings
./generate-cert.sh    # Generate certificate
./start-server.sh     # Start nginx
./test-client.sh      # Run connection tests
./stop-server.sh      # Stop nginx
./cleanup.sh          # Clean up files
```

See [nginx-example/test-results.md](src_provider_rust/nginx-example/test-results.md) for detailed test output.
## Key URI Format

Reference keys using either format:

```
# Simple format (recommended)
managedhsm:<vault-name>:<key-name>

# With version
managedhsm:<vault-name>:<key-name>?version=<version>

# Key-value format
akv:vault=<vault-name>,name=<key-name>,version=<version>
```

## Supported Operations

| Operation | RSA | EC (P-256) | AES-256 |
|-----------|-----|------------|---------|
| Sign (RS256, PS256) |  | - | - |
| Sign (ES256) | - |  | - |
| Decrypt (OAEP) |  | - | - |
| Key Wrap/Unwrap | - | - |  |
| CSR Generation |  |  | - |
| Certificate Generation |  |  | - |

## Authentication

The provider supports two authentication methods:

### 1. Environment Variable (Fast - Recommended)
```bash
export AZURE_CLI_ACCESS_TOKEN=$(az account get-access-token --resource https://managedhsm.azure.net --query accessToken -o tsv)
```

### 2. Azure SDK DefaultAzureCredential (Automatic Fallback)
If no environment variable is set, the provider automatically tries:
- Managed Identity (Azure VMs, App Service)
- Azure CLI credentials
- Azure PowerShell credentials

## Setting Up Azure Managed HSM

### 1. Create Managed HSM

```bash
# Login and set subscription
az login
az account set --subscription <your-subscription>

# Create resource group
az group create --name "ContosoResourceGroup" --location westus3

# Get your admin ID
az ad signed-in-user show --query id -o tsv
# Output: xxxx-xxxx-xxxx-xxxx

# Create Managed HSM (replace [HSM-NAME] and admin ID)
az keyvault create --hsm-name "[HSM-NAME]" \
    --resource-group "ContosoResourceGroup" \
    --location "West US 3" \
    --administrators xxxx-xxxx-xxxx-xxxx \
    --retention-days 28
```

### 2. Activate the HSM (Security Domain)

A new HSM requires activation before use:

```bash
# Generate 3 RSA key pairs for security domain
openssl req -newkey rsa:2048 -nodes -keyout cert_1.key -x509 -days 365 -out cert_1.cer
openssl req -newkey rsa:2048 -nodes -keyout cert_2.key -x509 -days 365 -out cert_2.cer
openssl req -newkey rsa:2048 -nodes -keyout cert_3.key -x509 -days 365 -out cert_3.cer

# Download security domain (activates the HSM)
az keyvault security-domain download \
    --hsm-name "[HSM-NAME]" \
    --sd-wrapping-keys ./cert_1.cer ./cert_2.cer ./cert_3.cer \
    --sd-quorum 2 \
    --security-domain-file SD.json
```

> **Important**: Store the security domain file (SD.json) and keys securely. They are required for HSM recovery.

### 3. Create Keys in the HSM

```bash
# Grant yourself permissions to manage keys
oid=$(az ad signed-in-user show --query id -o tsv)
az keyvault role assignment create \
    --hsm-name [HSM-NAME] \
    --assignee $oid \
    --scope / \
    --role "Managed HSM Crypto User"

# Create RSA key (3072-bit recommended for TLS)
az keyvault key create \
    --hsm-name [HSM-NAME] \
    --name myrsakey \
    --kty RSA-HSM \
    --size 3072 \
    --ops sign decrypt

# Create EC key (P-256)
az keyvault key create \
    --hsm-name [HSM-NAME] \
    --name myeckey \
    --kty EC-HSM \
    --curve P-256 \
    --ops sign

# Create AES key (256-bit)
az keyvault key create \
    --hsm-name [HSM-NAME] \
    --name myaeskey \
    --kty oct-HSM \
    --size 256 \
    --ops wrapKey unwrapKey
```

### 4. Grant Access to Azure VMs (Optional)

For VMs using Managed Identity:

```bash
# Assign managed identity to VM
az vm identity assign --name myvm --resource-group myresourcegroup

# Get VM's principal ID
vm_principal=$(az vm identity show --name myvm --resource-group myresourcegroup --query principalId -o tsv)

# Grant VM access to HSM keys
az keyvault role assignment create \
    --hsm-name [HSM-NAME] \
    --assignee $vm_principal \
    --scope / \
    --role "Managed HSM Crypto User"
```

## Documentation

- [Rust Provider README](src_provider_rust/README.md) - Detailed build and configuration
- [Nginx Example](src_provider_rust/nginx-example/README.md) - TLS with HSM keys
- [gRPC Example](src_provider_rust/grpc-example/README.md) - mTLS sidecar proxy pattern
- [Architecture Guide](src_provider_rust/ARCHITECTURE.md) - Technical design
- [Security](src_provider_rust/README.md#security) - TLS and security considerations

## Legacy Implementations

### C Provider (OpenSSL 3.x)
Located in `src_provider/`. Use for compatibility with existing C deployments.

### C Engine (OpenSSL 1.1.x)
Located in `src/`. Only for systems that cannot upgrade to OpenSSL 3.x.

> **Note**: Azure Key Vault should only be used for development/testing. For production, use **Azure Managed HSM**. See [Azure Key Vault Service Limits](https://docs.microsoft.com/azure/key-vault/general/service-limits).

## Blog
[Introducing Azure Key Vault and Managed HSM Engine](https://techcommunity.microsoft.com/t5/azure-confidential-computing/introducing-azure-key-vault-and-managed-hsm-engine-an-open/ba-p/3032273)

## Contributing

This project welcomes contributions and suggestions. See [CONTRIBUTING.md](CONTRIBUTING.md) for details.

This project has adopted the [Microsoft Open Source Code of Conduct](https://opensource.microsoft.com/codeofconduct/).

## Trademark Notice

This project may contain trademarks or logos for projects, products, or services. Authorized use of Microsoft trademarks or logos is subject to and must follow [Microsoft's Trademark & Brand Guidelines](https://www.microsoft.com/legal/intellectualproperty/trademarks). Azure Key Vault and Managed HSM Engine is not affiliated with OpenSSL. OpenSSL is a registered trademark owned by OpenSSL Software Foundation.

## License

[MIT License](LICENSE.txt)
