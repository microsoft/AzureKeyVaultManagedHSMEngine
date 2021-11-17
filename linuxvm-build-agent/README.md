# Testing Linux VM
This template creates Linux VM as the build agent. It will provision all the resources for testing the Azure Key Vault and Managed HSM engine.
- An Azure Key Vault and RBAC assignment
- A Linux VM with the Managed Identity to access the Azure Key Vault
- An VNET with the private link to the Azure Key Vault

# How to build and deploy
Prepare your local SSH key by running `ssh-keygen`, then copy the content of id_rsa.pub to the place holder `<ssh-public-key>` in files buildagent1.parameters.json and buildagent2.parameters.json
- `az bicep build -f buildagent.main.bicep`
- `az deployment sub create --location westus3 --template-file buildagent.main.bicep --parameters @buildagent.parameters.json`

# Deploy to Azure
[![Deploy to Azure](https://aka.ms/deploytoazurebutton)](https://portal.azure.com/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2Fmicrosoft%2FAzureKeyVaultManagedHSMEngine%2Fmain%2Flinuxvm-build-agent%2Fbuildagent.main.json)

# Full transcript of testing
- Login into the Linux VM with the SSH key
- Go to /var/lib/waagent/custom-script/download and locate the logs