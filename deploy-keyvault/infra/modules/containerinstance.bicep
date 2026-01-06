// Azure Container Instance Module for nginx with Key Vault Provider
// Deploys nginx container with managed identity for Key Vault access

@description('Name of the container group')
param containerGroupName string

@description('Location for the container group')
param location string = resourceGroup().location

@description('Tags for all resources')
param tags object = {}

@description('Name of the user-assigned managed identity')
param managedIdentityName string

@description('Key Vault name for the provider')
param keyVaultName string

@description('RSA key name in Key Vault')
param rsaKeyName string = 'rsa-tls-key'

@description('EC key name in Key Vault')
param ecKeyName string = 'ec-tls-key'

@description('Container image for nginx with OpenSSL provider')
param containerImage string = 'nginx:latest'

@description('CPU cores for the container')
param cpuCores int = 1

@description('Memory in GB for the container')
param memoryInGb int = 2

// User-assigned managed identity
resource managedIdentity 'Microsoft.ManagedIdentity/userAssignedIdentities@2023-01-31' = {
  name: managedIdentityName
  location: location
  tags: tags
}

// Container group with nginx
resource containerGroup 'Microsoft.ContainerInstance/containerGroups@2023-05-01' = {
  name: containerGroupName
  location: location
  tags: tags
  identity: {
    type: 'UserAssigned'
    userAssignedIdentities: {
      '${managedIdentity.id}': {}
    }
  }
  properties: {
    osType: 'Linux'
    restartPolicy: 'Always'
    ipAddress: {
      type: 'Public'
      ports: [
        {
          protocol: 'TCP'
          port: 80
        }
        {
          protocol: 'TCP'
          port: 443
        }
        {
          protocol: 'TCP'
          port: 8443
        }
        {
          protocol: 'TCP'
          port: 8444
        }
      ]
      dnsNameLabel: containerGroupName
    }
    containers: [
      {
        name: 'nginx'
        properties: {
          image: containerImage
          ports: [
            {
              protocol: 'TCP'
              port: 80
            }
            {
              protocol: 'TCP'
              port: 443
            }
            {
              protocol: 'TCP'
              port: 8443
            }
            {
              protocol: 'TCP'
              port: 8444
            }
          ]
          resources: {
            requests: {
              cpu: cpuCores
              memoryInGB: memoryInGb
            }
          }
          environmentVariables: [
            {
              name: 'KEYVAULT_NAME'
              value: keyVaultName
            }
            {
              name: 'RSA_KEY_NAME'
              value: rsaKeyName
            }
            {
              name: 'EC_KEY_NAME'
              value: ecKeyName
            }
            {
              name: 'AZURE_CLIENT_ID'
              value: managedIdentity.properties.clientId
            }
          ]
        }
      }
    ]
  }
}

// Outputs
output containerGroupId string = containerGroup.id
output containerGroupName string = containerGroup.name
output fqdn string = containerGroup.properties.ipAddress.fqdn
output ipAddress string = containerGroup.properties.ipAddress.ip
output managedIdentityId string = managedIdentity.id
output managedIdentityClientId string = managedIdentity.properties.clientId
output managedIdentityPrincipalId string = managedIdentity.properties.principalId
