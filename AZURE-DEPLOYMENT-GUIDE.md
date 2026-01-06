# Azure Key Vault + Container Instance Deployment Guide

## Overview

This guide walks you through deploying the nginx OpenSSL provider to Azure Container Instances with Azure Key Vault authentication using Managed Identity.

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│ Azure Container Instance (nginx + OpenSSL Provider)    │
│ ┌─────────────────────────────────────────────────────┐ │
│ │ nginx (TLS Server)                                  │ │
│ │  - Port 8443 (RSA TLS)                             │ │
│ │  - Port 8444 (EC TLS)                              │ │
│ │                                                     │ │
│ │ OpenSSL Provider (akv_provider.so)                 │ │
│ │  - Intercepts private key operations               │ │
│ │  - Routes to Key Vault for signing                 │ │
│ └─────────────────────────────────────────────────────┘ │
│                          │                              │
│         System-Assigned Managed Identity                │
│                          │                              │
└──────────────────────────┼──────────────────────────────┘
                           │
                           │ HTTPS + OAuth Token
                           │
                           ▼
         ┌──────────────────────────────────┐
         │ Azure Key Vault                  │
         │ ┌──────────────────────────────┐ │
         │ │ RSA Key (3072-bit)           │ │
         │ │ EC Key (P-256)               │ │
         │ └──────────────────────────────┘ │
         │                                  │
         │ Role: Key Vault Crypto User      │
         │ Assignee: Container MSI          │
         └──────────────────────────────────┘
```

## Prerequisites

1. **Azure CLI**: Authenticated to your subscription
   ```bash
   az login
   az account set --subscription <subscription-id>
   ```

2. **Docker**: For building the container image locally
   ```bash
   docker --version
   ```

3. **Python Environment**: For running the Jupyter notebook
   - Python 3.8+
   - Jupyter installed (`pip install jupyter`)

## Deployment Steps

### Step 1: Open the Notebook

Navigate to the deployment directory:

```bash
cd deploy-keyvault
```

Open the Jupyter notebook:

```bash
jupyter notebook deploy_keyvault_infra.ipynb
```

### Step 2: Configure Deployment

In **Cell 2** (Configuration), set your deployment parameters:

```python
INDEX = 1  # Change this for new deployments
WORKLOAD = "kvtls"
ENVIRONMENT = "dev"
LOCATION = "westus3"
KEYVAULT_SKU = "premium"  # or 'standard'
```

This will create resources with names like:
- Resource Group: `rg-kvtls-dev-001`
- Key Vault: `kv-kvtls-dev-001`
- Container Registry: `acrkvtlsdev001`
- Container Instance: `aci-kvtls-dev-001`

### Step 3: Run Deployment Cells

Execute cells in order:

1. **Cell 1**: Install Python packages
2. **Cell 2**: Configure deployment (auto-detects Azure credentials)
3. **Cell 3**: Create Resource Group
4. **Cell 4**: Create Key Vault
5. **Cell 5**: Assign Key Vault permissions to your user
6. **Cell 6**: Create RSA and EC keys in Key Vault
7. **Cell 7**: Generate self-signed certificates (for testing)
8. **Cell 9a**: Create Azure Container Registry
   - Creates ACR with admin user enabled
   - Returns login credentials

### Step 4: Build and Push Docker Image

After Cell 9a completes, you'll see output like:

```
📦 Container Registry Ready!
----------------------------------------------------------------------
  Registry:     acrkvtlsdev001.azurecr.io
  Username:     acrkvtlsdev001

🔨 Next Steps:
  1. Build the Docker image locally:
     docker build -f Dockerfile.nginx-keyvault -t acrkvtlsdev001.azurecr.io/nginx-akv:latest .

  2. Login to ACR:
     az acr login --name acrkvtlsdev001

  3. Push the image:
     docker push acrkvtlsdev001.azurecr.io/nginx-akv:latest
```

**Execute these commands in a terminal** (from the repo root):

```bash
# Build the image (includes Rust provider + nginx)
docker build -f src_provider_rust/Dockerfile.nginx-keyvault \
  -t acrkvtlsdev001.azurecr.io/nginx-akv:latest .

# Login to ACR
az acr login --name acrkvtlsdev001

# Push the image
docker push acrkvtlsdev001.azurecr.io/nginx-akv:latest
```

> **Note**: The build takes ~2-3 minutes. It compiles the Rust provider and creates a complete nginx environment.

### Step 5: Deploy Container Instance

Return to the notebook and execute **Cell 10** (Deploy Container Instance).

This will:
- Create an Azure Container Instance with your custom image
- Assign a system-managed identity to the container
- Configure environment variables (Key Vault name, key names)
- Expose ports 80, 443, 8443, 8444
- Create a public IP and FQDN
- Assign "Key Vault Crypto User" role to the container's identity

The deployment takes ~2-3 minutes.

### Step 6: Verify Deployment

Execute **Cell 11** (Summary) to see all deployment details:

```
🎉 AZURE KEY VAULT KEYLESS TLS DEPLOYMENT COMPLETE
======================================================================

📦 Resources Created:
----------------------------------------------------------------------
  Resource Group:     rg-kvtls-dev-001
  Key Vault:          kv-kvtls-dev-001
  Container Instance: aci-kvtls-dev-001
  Container FQDN:     aci-kvtls-dev-001.westus3.azurecontainer.io
  Container IP:       20.168.123.45

🔗 Test URLs:
----------------------------------------------------------------------
  HTTP:  http://aci-kvtls-dev-001.westus3.azurecontainer.io
  HTTPS RSA (8443): https://aci-kvtls-dev-001.westus3.azurecontainer.io:8443
  HTTPS EC (8444):  https://aci-kvtls-dev-001.westus3.azurecontainer.io:8444
```

## Testing the Deployment

### Test HTTP Endpoint

```bash
curl http://aci-kvtls-dev-001.westus3.azurecontainer.io
```

Expected: Redirect to HTTPS or a test message.

### Test RSA Keyless TLS

```bash
curl -k https://aci-kvtls-dev-001.westus3.azurecontainer.io:8443
```

Expected output:
```
RSA Keyless TLS with Azure Key Vault!
```

### Test EC Keyless TLS

```bash
curl -k https://aci-kvtls-dev-001.westus3.azurecontainer.io:8444
```

Expected output:
```
EC Keyless TLS with Azure Key Vault!
```

### Verify TLS Handshake

```bash
openssl s_client -connect aci-kvtls-dev-001.westus3.azurecontainer.io:8443 \
  -showcerts </dev/null
```

Look for:
- **Certificate chain**: Should show your RSA certificate
- **Server public key**: 3072-bit RSA key
- **TLS version**: TLSv1.3 or TLSv1.2

### Check Container Logs

```bash
az container logs \
  -g rg-kvtls-dev-001 \
  -n aci-kvtls-dev-001
```

Look for:
```
Azure Managed HSM Provider initialized
Provider: akv_provider (active)
Store loaders: keyvault, kv, managedhsm, hsm, akv
nginx: [notice] starting nginx
```

### Check Container Status

```bash
az container show \
  -g rg-kvtls-dev-001 \
  -n aci-kvtls-dev-001 \
  --query "{state:instanceView.state, ip:ipAddress.ip, fqdn:ipAddress.fqdn}"
```

Expected state: `Running`

## Troubleshooting

### Container Won't Start

Check logs:
```bash
az container logs -g rg-kvtls-dev-001 -n aci-kvtls-dev-001
```

Common issues:
- **"Failed to load provider"**: Provider library not found or wrong path
- **"Authentication failed"**: Managed identity not assigned or role missing
- **"Key not found"**: Key names in environment variables don't match Key Vault

### Authentication Errors

Verify managed identity role assignment:

```bash
az role assignment list \
  --scope /subscriptions/<sub-id>/resourceGroups/rg-kvtls-dev-001/providers/Microsoft.KeyVault/vaults/kv-kvtls-dev-001 \
  --query "[?principalType=='ServicePrincipal'].{Role:roleDefinitionName, Principal:principalId}"
```

Should show "Key Vault Crypto User" assigned to container's principal ID.

If missing, manually assign:

```bash
# Get container's managed identity principal ID
PRINCIPAL_ID=$(az container show \
  -g rg-kvtls-dev-001 \
  -n aci-kvtls-dev-001 \
  --query identity.principalId -o tsv)

# Get Key Vault resource ID
KV_ID=$(az keyvault show \
  -n kv-kvtls-dev-001 \
  --query id -o tsv)

# Assign role
az role assignment create \
  --role "Key Vault Crypto User" \
  --assignee $PRINCIPAL_ID \
  --scope $KV_ID
```

### Connection Timeout

Check network security:
- Azure Container Instances use public IP by default
- Ports 80, 443, 8443, 8444 should be accessible
- Check if your organization blocks outbound HTTPS to Azure

Verify ports are open:

```bash
az container show \
  -g rg-kvtls-dev-001 \
  -n aci-kvtls-dev-001 \
  --query "ipAddress.ports"
```

### Provider Not Loading

Check OpenSSL configuration in container:

```bash
# Exec into container (if possible)
az container exec \
  -g rg-kvtls-dev-001 \
  -n aci-kvtls-dev-001 \
  --exec-command "/bin/bash"

# Check provider file exists
ls -l /usr/lib/x86_64-linux-gnu/ossl-modules/akv_provider.so

# Check OpenSSL config
cat /etc/ssl/openssl.cnf

# Test provider
openssl list -providers
```

## Cleanup

To delete all resources, execute **Cell 11** (Cleanup) in the notebook:

```python
CONFIRM_DELETE = True  # Change to True
```

Or use Azure CLI:

```bash
az group delete --name rg-kvtls-dev-001 --yes --no-wait
```

This removes:
- Resource Group
- Key Vault (with all keys)
- Container Registry
- Container Instance
- All role assignments

## Cost Considerations

Approximate monthly costs (US West 3, as of 2024):

| Resource | SKU | Monthly Cost |
|----------|-----|-------------|
| Key Vault | Premium | $0.03/10,000 operations + $1/key |
| Container Instance | 1 vCPU, 2GB RAM | ~$35-40 (running 24/7) |
| Container Registry | Basic | $5 |
| **Total** | | **~$41-46/month** |

> **Cost Savings**: Stop container instances when not in use to save ~$35/month

```bash
# Stop container (stops charges)
az container stop -g rg-kvtls-dev-001 -n aci-kvtls-dev-001

# Start container
az container start -g rg-kvtls-dev-001 -n aci-kvtls-dev-001
```

## Security Best Practices

1. **Use Premium Key Vault**: For HSM-backed keys (recommended for production)
2. **Rotate Keys**: Implement key rotation policies
3. **Enable Soft Delete**: Protect against accidental deletion
   ```bash
   az keyvault update -n kv-kvtls-dev-001 --enable-soft-delete true
   ```
4. **Monitor Access**: Enable diagnostic logging
   ```bash
   az monitor diagnostic-settings create \
     --resource <key-vault-resource-id> \
     --name kv-diagnostics \
     --logs '[{"category":"AuditEvent","enabled":true}]' \
     --workspace <log-analytics-workspace-id>
   ```
5. **Use Private Endpoints**: For production, use VNET integration
6. **Disable Public Access**: Once testing is complete

## Next Steps

1. **Production Certificates**: Replace self-signed certs with CA-signed certificates
2. **Custom Domain**: Map a custom domain to the container FQDN
3. **Load Balancer**: Use Azure Application Gateway for production traffic
4. **Monitoring**: Set up Azure Monitor alerts for key operations
5. **Automation**: Convert notebook to Azure Pipeline or Terraform

## References

- [Azure Key Vault Documentation](https://docs.microsoft.com/azure/key-vault/)
- [Azure Container Instances Documentation](https://docs.microsoft.com/azure/container-instances/)
- [OpenSSL Provider API](https://www.openssl.org/docs/man3.0/man7/provider.html)
- [Managed Identity Documentation](https://docs.microsoft.com/azure/active-directory/managed-identities-azure-resources/)
