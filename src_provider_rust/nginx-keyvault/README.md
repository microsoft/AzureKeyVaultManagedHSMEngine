# Nginx Keyless TLS with Azure Key Vault

This example demonstrates using nginx with **Azure Key Vault** (not Managed HSM) for TLS private key operations.
The private key never leaves Key Vault - all TLS signing operations are performed by the Key Vault service.

## Key Vault vs Managed HSM

| Feature | Key Vault | Managed HSM |
|---------|-----------|-------------|
| Cost | Pay per operation | Monthly commitment |
| HSM Protection | Optional (Premium) | Always |
| OAuth Scope | `https://vault.azure.net/.default` | `https://managedhsm.azure.net/.default` |
| Domain | `vault.azure.net` | `managedhsm.azure.net` |
| URI Prefix | `keyvault:` or `kv:` | `managedhsm:` |

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                         nginx                                    │
│  ┌─────────────────────────────────────────────────────────┐    │
│  │                    SSL/TLS Handshake                     │    │
│  │    ssl_certificate_key "store:keyvault:vault:key"        │    │
│  └────────────────────┬────────────────────────────────────┘    │
│                       │                                          │
│  ┌────────────────────▼────────────────────────────────────┐    │
│  │              OpenSSL + AKV Provider                      │    │
│  │    OSSL_STORE_open("store:keyvault:...:keyname")        │    │
│  └────────────────────┬────────────────────────────────────┘    │
└───────────────────────┼──────────────────────────────────────────┘
                        │ HTTPS (REST API)
                        ▼
              ┌─────────────────────────┐
              │    Azure Key Vault      │
              │   (Premium for HSM)     │
              │   ┌─────────────────┐   │
              │   │   RSA / EC Keys │   │
              │   └─────────────────┘   │
              └─────────────────────────┘
```

## URI Formats for Key Vault

| Format | Example |
|--------|---------|
| Simple (keyvault:) | `keyvault:myvault:mykey` |
| Simple (kv:) | `kv:myvault:mykey` |
| Key-value | `akv:type=keyvault,vault=myvault,name=mykey` |
| With version | `kv:myvault:mykey:abc123` |

## Supported Key Types

| Key Type | Port | Key Name | Cipher Suite |
|----------|------|----------|--------------|
| RSA (3072-bit) | 8443 | `rsa-tls-key` | ECDHE-RSA-AES256-GCM-SHA384 |
| EC (P-256) | 8444 | `ec-tls-key` | ECDHE-ECDSA-AES256-GCM-SHA384 |

## Quick Start

1. **Create Key Vault and keys** using the deployment notebook:
   ```bash
   cd ../../deploy-keyvault
   # Open deploy_keyvault_infra.ipynb in Jupyter/VS Code
   ```

2. **Build the provider**:
   ```bash
   cd ..
   cargo build --release
   ```

3. **Configure your environment**:
   ```bash
   cp .env.example .env
   # Edit .env with your Key Vault name and key names
   ```

4. **Get access token** (for Key Vault, NOT Managed HSM):
   ```bash
   # Key Vault uses a different resource than Managed HSM!
   export AZURE_CLI_ACCESS_TOKEN=$(az account get-access-token \
       --resource https://vault.azure.net \
       --query accessToken -o tsv)
   ```

5. **Generate certificates**:
   ```bash
   ./generate-cert.sh
   ```

6. **Start nginx**:
   ```bash
   ./start-server.sh
   ```

7. **Test the connection**:
   ```bash
   ./test-client.sh
   ```

## Configuration Files

| File | Description |
|------|-------------|
| `.env` | Environment configuration (vault name, key names) |
| `nginx.conf.template` | nginx configuration template |
| `openssl-provider.cnf.template` | OpenSSL provider configuration |
| `generate-cert.sh` | Generate self-signed certificates |
| `start-server.sh` | Start nginx with the provider |
| `test-client.sh` | Test TLS connections |

## Authentication

The provider supports multiple authentication methods:

1. **Environment Variable**: `AZURE_CLI_ACCESS_TOKEN`
   ```bash
   export AZURE_CLI_ACCESS_TOKEN=$(az account get-access-token \
       --resource https://vault.azure.net \
       --query accessToken -o tsv)
   ```

2. **Azure SDK DefaultAzureCredential**:
   - Environment variables (`AZURE_CLIENT_ID`, `AZURE_TENANT_ID`, `AZURE_CLIENT_SECRET`)
   - Managed Identity (in Azure)
   - Azure CLI (`az login`)

## Troubleshooting

### "Failed to get access token"
- Ensure you're using the correct scope: `https://vault.azure.net/.default`
- Check Azure CLI login: `az login`
- Verify Key Vault access: `az keyvault key list --vault-name <vault>`

### "Key not found"
- Verify key exists: `az keyvault key show --vault-name <vault> --name <key>`
- Check URI format: `keyvault:<vault>:<key>` (not `managedhsm:`)

### "Permission denied"
- Assign Key Vault Crypto User role to your identity
- For signing: needs `sign` permission on the key

## Differences from Managed HSM Example

| Aspect | Key Vault | Managed HSM |
|--------|-----------|-------------|
| URI prefix | `keyvault:` or `kv:` | `managedhsm:` |
| Token resource | `https://vault.azure.net` | `https://managedhsm.azure.net` |
| API domain | `vault.azure.net` | `managedhsm.azure.net` |
| SKU for HSM | Premium tier | Always HSM |
