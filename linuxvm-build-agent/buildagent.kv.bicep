/*
 Summary: Provisions a Key Vault with private link and private DNS zone
*/

// ============================================================================
// Parameters

@description('Name of Key Vault')
param keyVaultName string

@description('Subnet resourceId to link the VM to')
param subnetResourceId string

@description('Azure AD principal id of the VM managed identity')
param vmPrincipalId string

@description('Full resource id of the virtual network in which to create the private endpoint')
param vnetResourceId string

@description('Role assigned to the VM')
param roleDef string

// ============================================================================
// Variables

// DNS zone name for the vault service
var privateLink_dns_zone = 'privatelink.vaultcore.azure.net'

// ============================================================================
// Resources

resource kv 'Microsoft.KeyVault/vaults@2019-09-01' = {
  name: keyVaultName
  location: resourceGroup().location
  properties: {
    enabledForDeployment: false
    enabledForDiskEncryption: false
    enabledForTemplateDeployment: false
    enablePurgeProtection: true
    enableRbacAuthorization: true
    enableSoftDelete: true
    softDeleteRetentionInDays: 7
    networkAcls: {
      bypass: 'None'
      defaultAction: 'Deny'
      virtualNetworkRules: []
    }
    tenantId: subscription().tenantId
    sku: {
      family: 'A'
      name: 'standard'
    }
  }
}

resource ra 'Microsoft.Authorization/roleAssignments@2020-04-01-preview' = {
  name: guid('${vmPrincipalId}${kv.id}${roleDef}')
  scope: kv
  properties: {
    principalId: vmPrincipalId
    roleDefinitionId: resourceId('Microsoft.Authorization/roleDefinitions',roleDef)
  }
}

resource pdns 'Microsoft.Network/privateDnsZones@2020-06-01' = {
  name: privateLink_dns_zone
  location: 'global'
}

resource pdnsLink 'Microsoft.Network/privateDnsZones/virtualNetworkLinks@2020-06-01' = {
  name: '${pdns.name}-link'
  location: 'global'
  parent: pdns
  properties: {
    registrationEnabled: false
    virtualNetwork: {
      id: vnetResourceId
    }
  }
}

resource pe 'Microsoft.Network/privateEndpoints@2021-02-01' = {
  name: '${kv.name}-pe'
  location: resourceGroup().location
  properties: {
    subnet: {
      id: subnetResourceId
    }
    privateLinkServiceConnections: [
      {
        name: '${kv.name}-svccon'
        properties: {
          privateLinkServiceId: kv.id
          groupIds: [
            'vault'
          ]
        }
      }
    ]
  }
}

resource pdnsZoneGroup 'Microsoft.Network/privateEndpoints/privateDnsZoneGroups@2021-02-01' = {
  name: '${kv.name}-dnszonegroup'
  parent: pe
  properties: {
    privateDnsZoneConfigs: [
      {
        name: 'config1'
        properties: {
          privateDnsZoneId: pdns.id
        }
      }
    ]
  }
}

// ============================================================================
// Outputs

output vault object = kv
output akvName string = keyVaultName
