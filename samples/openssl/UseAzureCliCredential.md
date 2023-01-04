# Use Azure CLI credentials as Access Token
## Windows using Powershell script to set Access Token environment variable
### Step 1
Install Azure CLI tool and login
```
az login
az account set --name <default subscription name>
```
### Step 2
Get Tenant id via the following command and look for "tenantId" value like "yyyyyy-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
```
az account show --name <default subscription name>
{
  "environmentName": "AzureCloud",
  "homeTenantId": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxx",
  "id": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxx",
  "isDefault": true,
  "managedByTenants": [
    {
      "tenantId": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxx"
    }
  ],
  "name": "<default subscription name>",
  "state": "Enabled",
  "tenantId": "yyyyyy-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
  "user": {
    "name": "xxx@microsoft.com",
    "type": "user"
  }
}
```

### Step 3
In the powershell, retrieve the access token for managed HSM resource. NOTE: use the actual tenant ID from step 2
```
$s=(az account get-access-token --output json --tenant yyyyyy-xxxx-xxxx-xxxx-xxxxxxxxxxxx --resource https://managedhsm.azure.net)
$t=$s | ConvertFrom-Json
$Env:AZURE_CLI_ACCESS_TOKEN=$t.accessToken
```

### Step 4
Verify via Openssl, for example, using ECC KEY "managedHsm:ManagedHSMOpenSSLEngine:ecckey"
```
PS D:\AzureKeyVaultManagedHSMEngine\samples\openssl> openssl req -new -x509 -config openssl.cnf -engine e_akv -keyform engine -key managedHsm:ManagedHSMOpenSSLEngine:ecckey -out cert.pem
engine "e_akv" set.
PS D:\AzureKeyVaultManagedHSMEngine\samples\openssl> certutil cert.pem
X509 Certificate:
Version: 1
Serial Number: 478c9149047b501078d464adc6747704e5f2d2e3
Signature Algorithm:
    Algorithm ObjectId: 1.2.840.10045.4.3.2 sha256ECDSA
    Algorithm Parameters: NULL
Issuer:
    CN=www.Contoso.com
    OU=AKV
    O=Contoso
    L=Redmond
    S=WA
    C=US
  Name Hash(sha1): 247dd8791bb177892b789dc09563bb17c609949e
  Name Hash(md5): a455c6b8c5d48dc4563d3ef89d829ea3

 NotBefore: 1/1/2023 9:54 PM
 NotAfter: 1/31/2023 9:54 PM

Subject:
    CN=www.Contoso.com
    OU=AKV
    O=Contoso
    L=Redmond
    S=WA
    C=US
  Name Hash(sha1): 247dd8791bb177892b789dc09563bb17c609949e
  Name Hash(md5): a455c6b8c5d48dc4563d3ef89d829ea3

Public Key Algorithm:
    Algorithm ObjectId: 1.2.840.10045.2.1 ECC
    Algorithm Parameters:
    06 08 2a 86 48 ce 3d 03  01 07
        1.2.840.10045.3.1.7 ECDSA_P256 (x962P256v1)
Public Key Length: 0 bits
Public Key: UnusedBits = 0
    0000  03 4b 81 db e6 28 26 31  c8 17 ff ae 22 0a 30 39
    0010  3d 88 c6 d8 5f 41 76 b4  45 ef aa 05 92 1a aa 74
    0020  04
Certificate Extensions: 0
Signature Algorithm:
    Algorithm ObjectId: 1.2.840.10045.4.3.2 sha256ECDSA
    Algorithm Parameters: NULL
Signature: UnusedBits=0
    0000  89 fe 1c ee bb b1 1d af  95 e8 e4 bb 9b a1 bd ad
    0010  36 54 3e 5d 30 16 c3 35  02 e8 01 e2 fc 73 a5 b9
    0020  00 21 02 22 67 9f c0 59  85 0c f6 3c 2a 99 5d bd
    0030  90 aa d4 14 af d7 23 e3  37 9f de 24 33 da cd d0
    0040  d7 dc cd 00 21 02 46 30
Possible Root Certificate: Subject matches Issuer, but Signature check fails: 80090015
Key Id Hash(rfc-sha1): 09203400f0a763b88850844bca728ac5a22aa56a
Key Id Hash(sha1): c83256e40e0eb9ad8e0ed8a94ac9209927939baa
Key Id Hash(md5): 32a526def6cf2df25484d090cf914bfa
Key Id Hash(sha256): 855d60f65ab03eea3995cb572b625e46bec7fc8b92c0fa54da76ab89adee0093
Key Id Hash(pin-sha256): f8O316WyAbvUaa/8i01XaDfOGzPse+3F7MO2oWlOQTA=
Key Id Hash(pin-sha256-hex): 7fc3b7d7a5b201bbd469affc8b4d576837ce1b33ec7bedc5ecc3b6a1694e4130
Cert Hash(md5): 233b1b98cf0e91182ae85d466e29191c
Cert Hash(sha1): 03f5b11491a94614ce0ff6653eb33b77f4834afc
Cert Hash(sha256): 259eaea8456027509a38a693c66d52d5be821aa3e8f54c95b43bb6ea196c27ae
Signature Hash: 90b9d31f14acccc6d914846766c039c8003f1601151daf0b00c0ffcf7c018ea0
CertUtil: -dump command completed successfully.
```
## Linux (tested in WSL) using bash script to set Access Token environment variable
### Step 1
Install Azure CLI tool and login
```
curl -sL https://aka.ms/InstallAzureCLIDeb | sudo bash
az login
az account set --name <default subscription name>
```
### Step 2
Get Tenant id via the following command and look for "tenantId" value like "yyyyyy-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
```
az account show --name <default subscription name>
{
  "environmentName": "AzureCloud",
  "homeTenantId": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxx",
  "id": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxx",
  "isDefault": true,
  "managedByTenants": [
    {
      "tenantId": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxx"
    }
  ],
  "name": "<default subscription name>",
  "state": "Enabled",
  "tenantId": "yyyyyy-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
  "user": {
    "name": "xxx@microsoft.com",
    "type": "user"
  }
}
```

### Step 3
In the bash shell, retrieve the access token for managed HSM resource. NOTE: use the actual tenant ID from step 2
```
sudo apt install jq
t=$(az account get-access-token --output json --tenant yyyyyy-xxxx-xxxx-xxxx-xxxxxxxxxxxx --resource https://managedhsm.azure.net | jq -r '.accessToken')
export AZURE_CLI_ACCESS_TOKEN=$t
```

### Step 4
Verify via Openssl, for example, using ECC KEY "managedHsm:ManagedHSMOpenSSLEngine:ecckey"
```
puliu@popdev2:~/AzureKeyVaultManagedHSMEngine/src/build$ cp ../../samples/openssl/openssl.cnf .
puliu@popdev2:~/AzureKeyVaultManagedHSMEngine/src/build$ openssl req -new -x509 -config openssl.cnf -engine e_akv -keyform engine -key managedHsm:ManagedHSMOpenSSLEngine:ecckey -out cert.pem
Engine "e_akv" set.
[i] GetAccessTokenFromIMDS curl.c(99) Environment variable AZURE_CLI_ACCESS_TOKEN defined [2060]

[i] GetAccessTokenFromIMDS curl.c(99) Environment variable AZURE_CLI_ACCESS_TOKEN defined [2060]

puliu@popdev2:~/AzureKeyVaultManagedHSMEngine/src/build$ cat cert.pem
-----BEGIN CERTIFICATE-----
MIIBpzCCAU0CFBkwiKvYHfv1s2L4LYiIOesjYZzsMAoGCCqGSM49BAMCMGYxCzAJ
BgNVBAYTAlVTMQswCQYDVQQIDAJXQTEQMA4GA1UEBwwHUmVkbW9uZDEQMA4GA1UE
CgwHQ29udG9zbzEMMAoGA1UECwwDQUtWMRgwFgYDVQQDDA93d3cuQ29udG9zby5j
b20wHhcNMjMwMTAyMjA1MDQ5WhcNMjMwMjAxMjA1MDQ5WjBmMQswCQYDVQQGEwJV
UzELMAkGA1UECAwCV0ExEDAOBgNVBAcMB1JlZG1vbmQxEDAOBgNVBAoMB0NvbnRv
c28xDDAKBgNVBAsMA0FLVjEYMBYGA1UEAwwPd3d3LkNvbnRvc28uY29tMDkwEwYH
KoZIzj0CAQYIKoZIzj0DAQcDIgADS4Hb5igmMcgX/64iCjA5PYjG2F9BdrRF76oF
khqqdAQwCgYIKoZIzj0EAwIDSAAwRQIhAPyKM0512zAPM4N4zts8xBn3emjjAWF6
mW+PFBHxysR/AiBEUrt5bZQdxhypx8Z1ATbpXY7rqmG1PIsGH1W5Wj1erQ==
-----END CERTIFICATE-----
puliu@popdev2:~/AzureKeyVaultManagedHSMEngine/src/build$ openssl x509 -in cert.pem -text
Certificate:
    Data:
        Version: 1 (0x0)
        Serial Number:
            19:30:88:ab:d8:1d:fb:f5:b3:62:f8:2d:88:88:39:eb:23:61:9c:ec
        Signature Algorithm: ecdsa-with-SHA256
        Issuer: C = US, ST = WA, L = Redmond, O = Contoso, OU = AKV, CN = www.Contoso.com
        Validity
            Not Before: Jan  2 20:50:49 2023 GMT
            Not After : Feb  1 20:50:49 2023 GMT
        Subject: C = US, ST = WA, L = Redmond, O = Contoso, OU = AKV, CN = www.Contoso.com
        Subject Public Key Info:
            Public Key Algorithm: id-ecPublicKey
                Public-Key: (256 bit)
                pub:
                    03:4b:81:db:e6:28:26:31:c8:17:ff:ae:22:0a:30:
                    39:3d:88:c6:d8:5f:41:76:b4:45:ef:aa:05:92:1a:
                    aa:74:04
                ASN1 OID: prime256v1
                NIST CURVE: P-256
    Signature Algorithm: ecdsa-with-SHA256
    Signature Value:
        30:45:02:21:00:fc:8a:33:4e:75:db:30:0f:33:83:78:ce:db:
        3c:c4:19:f7:7a:68:e3:01:61:7a:99:6f:8f:14:11:f1:ca:c4:
        7f:02:20:44:52:bb:79:6d:94:1d:c6:1c:a9:c7:c6:75:01:36:
        e9:5d:8e:eb:aa:61:b5:3c:8b:06:1f:55:b9:5a:3d:5e:ad
-----BEGIN CERTIFICATE-----
MIIBpzCCAU0CFBkwiKvYHfv1s2L4LYiIOesjYZzsMAoGCCqGSM49BAMCMGYxCzAJ
BgNVBAYTAlVTMQswCQYDVQQIDAJXQTEQMA4GA1UEBwwHUmVkbW9uZDEQMA4GA1UE
CgwHQ29udG9zbzEMMAoGA1UECwwDQUtWMRgwFgYDVQQDDA93d3cuQ29udG9zby5j
b20wHhcNMjMwMTAyMjA1MDQ5WhcNMjMwMjAxMjA1MDQ5WjBmMQswCQYDVQQGEwJV
UzELMAkGA1UECAwCV0ExEDAOBgNVBAcMB1JlZG1vbmQxEDAOBgNVBAoMB0NvbnRv
c28xDDAKBgNVBAsMA0FLVjEYMBYGA1UEAwwPd3d3LkNvbnRvc28uY29tMDkwEwYH
KoZIzj0CAQYIKoZIzj0DAQcDIgADS4Hb5igmMcgX/64iCjA5PYjG2F9BdrRF76oF
khqqdAQwCgYIKoZIzj0EAwIDSAAwRQIhAPyKM0512zAPM4N4zts8xBn3emjjAWF6
mW+PFBHxysR/AiBEUrt5bZQdxhypx8Z1ATbpXY7rqmG1PIsGH1W5Wj1erQ==
-----END CERTIFICATE-----
```
