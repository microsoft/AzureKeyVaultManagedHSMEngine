# Azure Key Vault + Container Instance Deployment

This directory contains a complete end-to-end deployment of the Azure Key Vault OpenSSL Provider to Azure Container Instances with Managed Identity authentication.

## 🎯 Overview

This deployment creates:
- **Azure Key Vault** (standard or premium tier)
- **Azure Container Registry** (for custom nginx image)
- **Azure Container Instance** (nginx + OpenSSL provider)
- **Managed Identity** (for keyless authentication)
- **RSA and EC keys** for TLS signing

Unlike local Docker testing, this deployment:
- ✅ Runs in Azure (no local dependencies)
- ✅ Uses Managed Identity (no access tokens needed)
- ✅ Publicly accessible for testing
- ✅ Production-ready architecture

## 📋 Quick Start

1. **Open the Jupyter notebook:**
   ```bash
   cd deploy-keyvault
   jupyter notebook deploy_keyvault_infra.ipynb
   ```

2. **Configure deployment** (Cell 2):
   - Set `INDEX = 1` for your deployment
   - Adjust `LOCATION`, `KEYVAULT_SKU` as needed

3. **Run cells 1-9a** to create Azure resources

4. **Build and push Docker image** (in terminal):
   ```bash
   docker build -f src_provider_rust/Dockerfile.nginx-keyvault \
     -t <acr-name>.azurecr.io/nginx-akv:latest .
   
   az acr login --name <acr-name>
   docker push <acr-name>.azurecr.io/nginx-akv:latest
   ```

5. **Run cell 10** to deploy container instance

6. **Test the deployment:**
   ```bash
   curl -k https://<container-fqdn>:8443
   ```

## 🏗️ Architecture

```
┌──────────────────────────────────────────────────────────────┐
│ Azure Container Instance (nginx + OpenSSL Provider)         │
│ ┌──────────────────────────────────────────────────────────┐ │
│ │ nginx (TLS Server)                                       │ │
│ │  - Port 8443 (RSA TLS)                                  │ │
│ │  - Port 8444 (EC TLS)                                   │ │
│ │                                                          │ │
│ │ OpenSSL Provider (akv_provider.so)                      │ │
│ │  - Intercepts private key operations                    │ │
│ │  - Routes to Key Vault for signing                      │ │
│ └──────────────────────────────────────────────────────────┘ │
│                          │                                   │
│         System-Assigned Managed Identity                     │
│                          │                                   │
└──────────────────────────┼───────────────────────────────────┘
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

## 📦 Resources Created

| Resource | Purpose |
|----------|---------|
| Resource Group | Contains all resources |
| Key Vault | Stores RSA and EC keys |
| Container Registry | Hosts custom nginx image |
| Container Instance | Runs nginx + provider |
| Managed Identity | Keyless authentication |
| Role Assignment | Grants crypto permissions |

## 🔗 URI Formats Supported

| Format | Example |
|--------|---------|
| Simple Key Vault | `keyvault:myvault:mykey` or `kv:myvault:mykey` |
| Key-value format | `akv:type=keyvault,vault=myvault,name=mykey` |

## 📄 Files

| File | Description |
|------|-------------|
| `deploy_keyvault_infra.ipynb` | Jupyter notebook for complete deployment |
| `requirements.txt` | Python dependencies |
| `../AZURE-DEPLOYMENT-GUIDE.md` | Detailed deployment guide |
| `infra/main.bicep` | Main Bicep template for Key Vault infrastructure |
| `infra/modules/keyvault.bicep` | Key Vault module |
| `infra/modules/containerapp.bicep` | Container Apps module for nginx |

## Quick Start

1. **Install dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

2. **Run the notebook**:
   - Open `deploy_keyvault_infra.ipynb` in VS Code or Jupyter
   - Execute cells in order to:
     - Deploy Azure Key Vault
     - Create RSA and EC keys
     - Generate self-signed certificates
     - Deploy nginx container with the provider
     - Test TLS connections

3. **Cleanup**:
   - Run the cleanup cells at the end of the notebook

## Authentication

The provider uses Azure Managed Identity when running in Azure Container Instances.
For local development, use Azure CLI:

```bash
az login
export AZURE_CLI_ACCESS_TOKEN=$(az account get-access-token \
    --resource https://vault.azure.net \
    --query accessToken -o tsv)
```

## Key Vault vs Managed HSM

| Feature | Key Vault | Managed HSM |
|---------|-----------|-------------|
| Cost | Pay per operation | Monthly commitment |
| HSM Protection | Optional (Premium tier) | Always |
| FIPS 140-2 Level | Level 2 (Premium) | Level 3 |
| Use Case | Dev/Test, Low volume | Production, High security |
| OAuth Scope | `https://vault.azure.net/.default` | `https://managedhsm.azure.net/.default` |
| Domain | `vault.azure.net` | `managedhsm.azure.net` |

## Requirements

- Azure subscription
- Azure CLI installed and logged in
- Python 3.9+
- Docker (for local testing)
