"--Acquire access token--"
$s=(az account get-access-token --output json --tenant 72f988bf-86f1-41af-91ab-2d7cd011db47 --resource https://managedhsm.azure.net)
$t=$s | ConvertFrom-Json
$Env:AZURE_CLI_ACCESS_TOKEN=$t.accessToken
"--Generate CSR from mHSM key--"
openssl req -new -config openssl.cnf -engine e_akv -keyform engine -key managedHsm:ManagedHSMOpenSSLEngine:myrsakey -out cert.csr
"--Show CSR--"
openssl req -text -in cert.csr -noout -config openssl.cnf
"--Verify CSR--"
openssl req -in cert.csr -noout -verify -config openssl.cnf
