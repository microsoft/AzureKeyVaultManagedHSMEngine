// Main Bicep Template for Azure Key Vault Keyless TLS Infrastructure
// Deploys Key Vault, Managed Identity, and Container Instance for nginx

targetScope = 'resourceGroup'

@description('Workload name for CAF naming')
param workload string = 'kvtls'

@description('Environment name (dev, test, prod)')
@allowed(['dev', 'test', 'staging', 'prod'])
param environment string = 'dev'

@description('Location for all resources')
param location string = resourceGroup().location

@description('Deployment index for multiple instances')
param index int = 1

@description('Object ID of the admin user')
param adminObjectId string

@description('Key Vault SKU (standard or premium)')
@allowed(['standard', 'premium'])
param keyVaultSku string = 'premium'

@description('Deploy container instance for nginx')
param deployContainer bool = true

// Variables
var indexStr = padLeft(string(index), 3, '0')
var baseName = '${workload}-${environment}-${indexStr}'

var keyVaultName = take('kv-${baseName}', 24)
var managedIdentityName = 'id-${baseName}'
var containerGroupName = 'ci-${baseName}-nginx'

var tags = {
  Environment: environment
  Workload: workload
  DeploymentIndex: string(index)
  Purpose: 'KeyVault-Keyless-TLS'
  ManagedBy: 'Bicep'
}

// Deploy Managed Identity first (needed for Key Vault access)
resource managedIdentity 'Microsoft.ManagedIdentity/userAssignedIdentities@2023-01-31' = {
  name: managedIdentityName
  location: location
  tags: tags
}

// Deploy Key Vault
module keyVault 'modules/keyvault.bicep' = {
  name: 'deploy-keyvault-${indexStr}'
  params: {
    keyVaultName: keyVaultName
    location: location
    tags: tags
    skuName: keyVaultSku
    adminObjectId: adminObjectId
    managedIdentityObjectId: managedIdentity.properties.principalId
    enableRbacAuthorization: true
    enableSoftDelete: true
    softDeleteRetentionInDays: 7
    enablePurgeProtection: false
  }
}

// Deploy Container Instance for nginx (optional)
module containerInstance 'modules/containerinstance.bicep' = if (deployContainer) {
  name: 'deploy-container-${indexStr}'
  params: {
    containerGroupName: containerGroupName
    location: location
    tags: tags
    managedIdentityName: '${managedIdentityName}-aci'
    keyVaultName: keyVaultName
    rsaKeyName: 'rsa-tls-key'
    ecKeyName: 'ec-tls-key'
  }
  dependsOn: [
    keyVault
  ]
}

// Outputs
output keyVaultName string = keyVault.outputs.keyVaultName
output keyVaultUri string = keyVault.outputs.keyVaultUri
output keyVaultId string = keyVault.outputs.keyVaultId

output managedIdentityName string = managedIdentity.name
output managedIdentityClientId string = managedIdentity.properties.clientId
output managedIdentityPrincipalId string = managedIdentity.properties.principalId

output containerFqdn string = deployContainer ? containerInstance.outputs.fqdn : ''
output containerIpAddress string = deployContainer ? containerInstance.outputs.ipAddress : ''
