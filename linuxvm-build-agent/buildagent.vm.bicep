/*
 Summary: Provisions an Ubuntu VM Scale Set for usew with Azure DevOps
*/

// ============================================================================
// Parameters

@description('Admin username for VMs')
param adminUserName string

@description('VM SKU to use for VM')
param vmSku string

@description('Subnet resourceId to link the VM to')
param subnetResourceId string

@description('Administrative SSH key for the VM')
param adminSshPubKey string

@description('Run build script')
param buildScriptPath string

@description('Azure Key Vault name')
param  akvName string

@description('run customer script')
param deployCustomerScript bool

// ============================================================================
// Resources

resource pip 'Microsoft.Network/publicIPAddresses@2020-05-01' = {
  name: 'linuxbuildagent-pip'
  location: resourceGroup().location
  properties: {
    publicIPAllocationMethod: 'Dynamic'
  }
  sku: {
    name: 'Basic'
  }
}

resource nic 'Microsoft.Network/networkInterfaces@2020-05-01' = {
  name: 'linuxbuildagent-nic'
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
  name: 'linuxbuildagent'
  location: resourceGroup().location
  identity: {
    type: 'SystemAssigned'
  }
  properties: {
    hardwareProfile: {
      vmSize: vmSku
    }
    osProfile: {
      computerName: 'linuxbuildagent'
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
        name: 'osdisk'
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

resource vm_build 'Microsoft.Compute/virtualMachines/extensions@2020-06-01' = if (deployCustomerScript) {
  parent: vm
  name: 'build_opensslengine'
  location: resourceGroup().location
  properties: {
    publisher: 'Microsoft.Azure.Extensions'
    type: 'CustomScript'
    typeHandlerVersion: '2.1'
    autoUpgradeMinorVersion: true
    settings: {
      skipDos2Unix: false
      timestamp : 123458
      fileUris: [
        buildScriptPath
      ]
    }
    protectedSettings: {
      commandToExecute: 'sh startbuild.sh ${akvName}'
    }
  }
}
// ============================================================================
// Outputs

output principalId string = vm.identity.principalId
