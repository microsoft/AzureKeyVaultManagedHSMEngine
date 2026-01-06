# nginx with Azure Key Vault - Docker Testing

This Docker setup demonstrates nginx using Azure Key Vault for keyless TLS operations.

## Prerequisites

1. **Azure Key Vault** with RSA and EC keys
2. **Azure CLI** authenticated (`az login`)
3. **Docker** installed and running

## Quick Start

### 1. Set Environment Variables

```bash
# Your Key Vault name
export KEYVAULT_NAME="your-keyvault-name"

# Key names in your Key Vault
export RSA_KEY_NAME="rsa-tls-key"
export EC_KEY_NAME="ec-tls-key"

# Optional: Azure tenant ID
export AZURE_TENANT_ID="your-tenant-id"
```

### 2. Build the Docker Image

```bash
docker build -f Dockerfile.nginx-keyvault -t nginx-akv .
```

### 3. Get Azure Access Token

```bash
# Login to Azure
az login

# Get access token for Key Vault
export AZURE_CLI_ACCESS_TOKEN=$(az account get-access-token \
    --resource https://vault.azure.net \
    --query accessToken -o tsv)
```

### 4. Run the Container

```bash
docker run --rm -it \
    -p 8443:8443 \
    -p 8444:8444 \
    -e KEYVAULT_NAME="$KEYVAULT_NAME" \
    -e RSA_KEY_NAME="$RSA_KEY_NAME" \
    -e EC_KEY_NAME="$EC_KEY_NAME" \
    -e AZURE_CLI_ACCESS_TOKEN="$AZURE_CLI_ACCESS_TOKEN" \
    nginx-akv
```

### 5. Test the Connection

In another terminal:

```bash
# Test RSA TLS endpoint
curl -k https://localhost:8443

# Test EC TLS endpoint
curl -k https://localhost:8444

# Check certificate details
openssl s_client -connect localhost:8443 -showcerts < /dev/null

# Check EC certificate
openssl s_client -connect localhost:8444 -showcerts < /dev/null
```

## Using Docker Compose

Create a `docker-compose.yml`:

```yaml
services:
  nginx-akv:
    build:
      context: .
      dockerfile: Dockerfile.nginx-keyvault
    ports:
      - "8443:8443"
      - "8444:8444"
    environment:
      - KEYVAULT_NAME=${KEYVAULT_NAME}
      - RSA_KEY_NAME=${RSA_KEY_NAME}
      - EC_KEY_NAME=${EC_KEY_NAME}
      - AZURE_CLI_ACCESS_TOKEN=${AZURE_CLI_ACCESS_TOKEN}
      - AZURE_TENANT_ID=${AZURE_TENANT_ID}
```

Then run:

```bash
# Export variables (or use .env file)
export KEYVAULT_NAME="your-keyvault"
export RSA_KEY_NAME="rsa-tls-key"
export EC_KEY_NAME="ec-tls-key"
export AZURE_CLI_ACCESS_TOKEN=$(az account get-access-token --resource https://vault.azure.net --query accessToken -o tsv)

# Start
docker-compose up
```

## Environment Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `KEYVAULT_NAME` | Yes | Name of your Azure Key Vault |
| `RSA_KEY_NAME` | Yes | Name of RSA key in Key Vault |
| `EC_KEY_NAME` | Yes | Name of EC key in Key Vault |
| `AZURE_CLI_ACCESS_TOKEN` | No* | Access token for Key Vault (auto-acquired if not provided) |
| `AZURE_TENANT_ID` | No | Azure tenant ID (optional) |

*If not provided, the container will attempt to run `az account get-access-token`

## What Happens

1. **Provider loads**: The AKV OpenSSL provider loads successfully
2. **Certificate generation**: Self-signed certificates are generated using keys from Key Vault
3. **nginx starts**: nginx starts with TLS enabled on ports 8443 (RSA) and 8444 (EC)
4. **TLS handshakes**: All TLS signature operations use Key Vault (private key never leaves Azure)

## Verifying Provider Works

```bash
# Enter the running container
docker exec -it <container-id> bash

# List providers
openssl list -providers -provider akv_provider -provider default

# List store loaders (should show 'keyvault')
openssl list -store-loaders -provider akv_provider -provider default

# Check OpenSSL config
cat $OPENSSL_CONF

# Check nginx config
cat /etc/nginx/nginx.conf
```

## Troubleshooting

### "unable to load provider akv_provider"

Check provider path:
```bash
ls -la /usr/lib/x86_64-linux-gnu/ossl-modules/akv_provider.so
openssl version -m  # Check MODULESDIR
```

### "401 Unauthorized" from Key Vault

Refresh the access token:
```bash
export AZURE_CLI_ACCESS_TOKEN=$(az account get-access-token \
    --resource https://vault.azure.net \
    --query accessToken -o tsv)
```

### Certificate generation fails

1. Verify key names are correct
2. Check Key Vault permissions (Key User role or Crypto User)
3. Ensure correct resource URL: `https://vault.azure.net` (NOT `managedhsm.azure.net`)

## Architecture

```
Client (curl/browser)
  ↓ HTTPS
nginx (Container)
  ↓ OpenSSL + AKV Provider
  ↓ HTTPS REST API
Azure Key Vault
```

The private key operations (TLS handshake signatures) are performed by Azure Key Vault, while nginx handles the rest of the TLS protocol.
