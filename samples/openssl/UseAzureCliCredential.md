# Windows Only: Use Azure CLI credentials as Access Token
## The powershell script to set Access Token environment variable
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
