/*
 Summary: Provisions a virtual network with one subnet, then assigns an NSG preventing inbound connections
*/

// ============================================================================
// Parameters

@description('Virtual network address prefix, e.g. 10.0.0.0/28')
param vNetBuildAgentDefinitions object

// ============================================================================
// Resources

resource vnet 'Microsoft.Network/virtualNetworks@2021-02-01' = {
  name: vNetBuildAgentDefinitions.name
  location: vNetBuildAgentDefinitions.location
  properties: {
    addressSpace: {
      addressPrefixes: [
        '192.168.128.0/24' // 192.168.128.0 - 192.168.128.255
      ]
    }
    subnets: [
      {
        name: 'worker'
        properties: {
          addressPrefix: '192.168.128.0/25' // // 192.168.128.0 - 192.168.128.127
          networkSecurityGroup: {
            id: nsg.id
          }
          privateEndpointNetworkPolicies: 'Disabled'
        }
      }
      {
        name: 'AzureBastionSubnet'
        properties: {
          addressPrefix: '192.168.128.128/27' // 192.168.128.128 - 192.168.128.159
        }
      }
    ]
  }
}

resource nsg 'Microsoft.Network/networkSecurityGroups@2021-02-01' = {
  name: 'buildagent-nsg'
  location: resourceGroup().location
  properties: {
    securityRules: []
  }
}

// ============================================================================
// Outputs

output virtualNetwork object = vnet
// We need the below as we can't currently output a resource,
// using the object output and assigning the resource does not give us the full resourceId
output subnetResourceId array = [ for (config, i) in vNetBuildAgentDefinitions.subnets: {
  id : resourceId('Microsoft.Network/virtualNetworks/subnets',vnet.name, vnet.properties.subnets[i].name)
}]

output vnetResourceId string = resourceId('Microsoft.Network/virtualNetworks',vnet.name)
