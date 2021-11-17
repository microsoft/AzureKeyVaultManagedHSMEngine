/*
 Summary: Run script in the VM
*/

// ============================================================================
// Parameters


@description('Vm name')
param vmName string

@description('Run build script')
param buildScriptPath string

@description('Azure Key Vault name')
param  akvName string


resource vm 'Microsoft.Compute/virtualMachines@2019-07-01' existing  =  {
  name: vmName
}

resource kv 'Microsoft.KeyVault/vaults@2019-09-01' existing = {
  name: akvName
}

resource vm_build 'Microsoft.Compute/virtualMachines/extensions@2020-06-01' = {
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
