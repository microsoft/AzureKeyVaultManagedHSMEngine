# Azure DevOps, Build Agent VM
This template creates Linux VM as the build agent for Azure DevOps, see the [referenced tutorial](https://github.com/matt-FFFFFF/terraform-azuredevops-vmss-agent)
The Microsoft doc is available [here](https://docs.microsoft.com/en-us/azure/devops/pipelines/agents/scale-set-agents?view=azure-devops)

# How to build and deploy
Prepare your local SSH key by running `ssh-keygen`, then copy the content of id_rsa.pub to the place holder `<ssh-public-key>` in files buildagent1.parameters.json and buildagent2.parameters.json
- `az bicep build -f buildagent.main.bicep`
- `az deployment sub create --location westus3 --template-file buildagent.main.bicep --parameters @buildagent1.parameters.json`
- `az deployment sub create --location westus3 --template-file buildagent.main.bicep --parameters @buildagent2.parameters.json`

# Full transcript of testing
- Login into the Linux VM
- Go to /var/lib/waagent/custom-script/download and locate the logs