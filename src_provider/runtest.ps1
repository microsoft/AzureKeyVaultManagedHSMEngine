$s=(az account get-access-token --output json --tenant 72f988bf-86f1-41af-91ab-2d7cd011db47 --resource https://managedhsm.azure.net); $t=$s | ConvertFrom-Json; $Env:AZURE_CLI_ACCESS_TOKEN=$t.accessToken

$Env:AKV_LOG_FILE='Q:\src\AzureKeyVaultManagedHSMEngine\src_provider\logs\akv_provider.log'       
$Env:AKV_LOG_LEVEL='3'           

openssl pkey -provider akv_provider -in "managedhsm:ManagedHSMOpenSSLEngine:myrsakey" -pubout -out myrsakey_pub.pem   
openssl dgst -sha256 -sign "managedhsm:ManagedHSMOpenSSLEngine:myrsakey" -provider akv_provider -out rs256.sig input.bin                                                                                     