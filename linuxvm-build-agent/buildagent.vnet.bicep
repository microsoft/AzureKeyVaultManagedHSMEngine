
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
        vNetBuildAgentDefinitions.addressSpacePrefix
      ]
    }
    subnets: [ for s in vNetBuildAgentDefinitions.subnets: {
      name: s.name
      properties: {
        addressPrefix: s.subnetPrefix
      }
    }]
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
