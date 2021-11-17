/*
 Summary: Provisions an Ubuntu VM for testing the Engine
*/

// ============================================================================
// Parameters

@description('Admin username for VMs')
param adminUserName string

@description('VM name')
param vmName string

@description('VM SKU to use for VM')
param vmSku string

@description('Subnet resourceId to link the VM to')
param subnetResourceId string

@description('Administrative SSH key for the VM')
param adminSshPubKey string

// ============================================================================
// Resources

resource pip 'Microsoft.Network/publicIPAddresses@2020-05-01' = {
  name: '${vmName}-pip'
  location: resourceGroup().location
  properties: {
    publicIPAllocationMethod: 'Dynamic'
  }
  sku: {
    name: 'Basic'
  }
}

resource nic 'Microsoft.Network/networkInterfaces@2020-05-01' = {
  name: '${vmName}-nic'
  location: resourceGroup().location
  properties: {
    ipConfigurations: [
      {
        name: 'ipconfig'
        properties: {
          privateIPAllocationMethod: 'Dynamic'
          publicIPAddress: {
            id: pip.id
          }
          subnet: {
            id: subnetResourceId
          }
        }
      }
    ]
  }
}

resource vm 'Microsoft.Compute/virtualMachines@2019-07-01' = {
  name: vmName
  location: resourceGroup().location
  identity: {
    type: 'SystemAssigned'
  }
  properties: {
    hardwareProfile: {
      vmSize: vmSku
    }
    osProfile: {
      computerName: vmName
      adminUsername: adminUserName
      linuxConfiguration: {
        disablePasswordAuthentication: true
        provisionVMAgent: true
        ssh: {
          publicKeys: [
            {
              path: '/home/${adminUserName}/.ssh/authorized_keys'
              keyData: adminSshPubKey
            }
          ]
        }
      }
    }
    storageProfile: {
      imageReference: {
        publisher: 'Canonical'
        offer: 'UbuntuServer'
        sku: '18.04-LTS'
        version: 'latest'
      }
      osDisk: {
        name: '${vmName}-osdisk'
        caching: 'ReadWrite'
        createOption: 'FromImage'
        diskSizeGB: 30
      }
    }
    networkProfile: {
      networkInterfaces: [
        {
          id: nic.id
        }
      ]
    } 
  }
}

// ============================================================================
// Outputs

output principalId string = vm.identity.principalId
