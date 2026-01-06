// Azure Key Vault Module for Keyless TLS Testing
// Deploys a Key Vault with access for managed identity

@description('Name of the Key Vault')
param keyVaultName string

@description('Location for the Key Vault')
param location string = resourceGroup().location

@description('Tags for all resources')
param tags object = {}

@description('SKU for the Key Vault (standard or premium)')
@allowed(['standard', 'premium'])
param skuName string = 'premium'

@description('Object ID of the admin user for initial access')
param adminObjectId string = ''

@description('Object ID of the managed identity for key operations')
param managedIdentityObjectId string = ''

@description('Enable RBAC authorization (recommended)')
param enableRbacAuthorization bool = true

@description('Enable soft delete')
param enableSoftDelete bool = true

@description('Soft delete retention days')
param softDeleteRetentionInDays int = 7

@description('Enable purge protection')
param enablePurgeProtection bool = false

// Key Vault resource
resource keyVault 'Microsoft.KeyVault/vaults@2023-07-01' = {
  name: keyVaultName
  location: location
  tags: tags
  properties: {
    sku: {
      family: 'A'
      name: skuName
    }
    tenantId: subscription().tenantId
    enableRbacAuthorization: enableRbacAuthorization
    enableSoftDelete: enableSoftDelete
    softDeleteRetentionInDays: softDeleteRetentionInDays
    enablePurgeProtection: enablePurgeProtection ? true : null
    enabledForDeployment: false
    enabledForDiskEncryption: false
    enabledForTemplateDeployment: false
    publicNetworkAccess: 'Enabled'
    networkAcls: {
      defaultAction: 'Allow'
      bypass: 'AzureServices'
    }
  }
}

// Role definitions
var keyVaultCryptoUserRole = subscriptionResourceId('Microsoft.Authorization/roleDefinitions', '12338af0-0e69-4776-bea7-57ae8d297424')
var keyVaultSecretsUserRole = subscriptionResourceId('Microsoft.Authorization/roleDefinitions', '4633458b-17de-408a-b874-0445c86b69e6')
var keyVaultAdministratorRole = subscriptionResourceId('Microsoft.Authorization/roleDefinitions', '00482a5a-887f-4fb3-b363-3b7fe8e74483')

// Admin role assignment (if provided)
resource adminRoleAssignment 'Microsoft.Authorization/roleAssignments@2022-04-01' = if (!empty(adminObjectId)) {
  name: guid(keyVault.id, adminObjectId, keyVaultAdministratorRole)
  scope: keyVault
  properties: {
    roleDefinitionId: keyVaultAdministratorRole
    principalId: adminObjectId
    principalType: 'User'
  }
}

// Managed Identity - Crypto User role (for sign operations)
resource miCryptoRoleAssignment 'Microsoft.Authorization/roleAssignments@2022-04-01' = if (!empty(managedIdentityObjectId)) {
  name: guid(keyVault.id, managedIdentityObjectId, keyVaultCryptoUserRole)
  scope: keyVault
  properties: {
    roleDefinitionId: keyVaultCryptoUserRole
    principalId: managedIdentityObjectId
    principalType: 'ServicePrincipal'
  }
}

// Managed Identity - Secrets User role (for certificate retrieval)
resource miSecretsRoleAssignment 'Microsoft.Authorization/roleAssignments@2022-04-01' = if (!empty(managedIdentityObjectId)) {
  name: guid(keyVault.id, managedIdentityObjectId, keyVaultSecretsUserRole)
  scope: keyVault
  properties: {
    roleDefinitionId: keyVaultSecretsUserRole
    principalId: managedIdentityObjectId
    principalType: 'ServicePrincipal'
  }
}

// Outputs
output keyVaultId string = keyVault.id
output keyVaultName string = keyVault.name
output keyVaultUri string = keyVault.properties.vaultUri
