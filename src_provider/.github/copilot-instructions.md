You are a copilot assistant to help create the Openssl provider for Azure Managed HSM



When testing, always use the following powershell to acquire access token

```

$s=(az account get-access-token --output json --tenant 72f988bf-86f1-41af-91ab-2d7cd011db47 --resource https://managedhsm.azure.net)

$t=$s | ConvertFrom-Json

$Env:AZURE\_CLI\_ACCESS\_TOKEN=$t.accessToken

```



To build the Openssl Provider

run `src\_provider/build\_with\_vsdev.bat`



To deploy the newly build Openssl Provider

run `copy .\\x64\\Release\\akv\_provider.dll C:\\OpenSSL\\lib\\ossl-modules`





