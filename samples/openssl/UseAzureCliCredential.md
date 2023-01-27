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
### RSA testing powershell script
Set Environment variables
```
$Env:AZURE_SUBS="YOUR SUBSCRIPTION NAME"
$Env:AZURE_TENANT="YOUR TENANT ID"
$Env:AZURE_RSAKEY="YOUR RSA HSM KEY NAME"
```

Run the powershell script
```
az login
az account set --name "$Env:AZURE_SUBS"

$s=(az account get-access-token --output json --tenant $Env:AZURE_TENANT --resource https://managedhsm.azure.net)
$t=$s | ConvertFrom-Json
$Env:AZURE_CLI_ACCESS_TOKEN=$t.accessToken


echo "rsa key Managed HSM test" > readme.md
date >> readme.md
openssl pkey -engine e_akv -inform engine -in $Env:AZURE_RSAKEY -pubout -text -out leafpubkey.pem
openssl dgst -binary -sha256 -out hash256 readme.md
openssl pkeyutl -engine e_akv -sign -keyform engine -inkey $Env:AZURE_RSAKEY -in hash256 -out hash256.sig.pss -pkeyopt digest:sha256 -pkeyopt rsa_padding_mode:pss
openssl pkeyutl -verify -pubin -inkey leafpubkey.pem -in hash256 -sigfile hash256.sig.pss -pkeyopt digest:sha256  -pkeyopt rsa_padding_mode:pss
openssl pkeyutl -engine e_akv -sign -keyform engine -inkey $Env:AZURE_RSAKEY -in hash256 -out hash256.sig -pkeyopt digest:sha256
openssl pkeyutl -verify -pubin -inkey leafpubkey.pem -in hash256 -sigfile hash256.sig -pkeyopt digest:sha256
```

For example, using HSM RSA KEY "managedHsm:ManagedHSMOpenSSLEngine:myrsakey"
```
PS D:\AzureKeyVaultManagedHSMEngine\src\build> openssl version -a
OpenSSL 1.1.1n  15 Mar 2022
built on: Sat Dec 31 21:08:05 2022 UTC
platform: VC-WIN64A
options:  bn(64,64) rc4(16x,int) des(long) idea(int) blowfish(ptr)
compiler: cl /Zi /Fdossl_static.pdb /Gs0 /GF /Gy /MD /W3 /wd4090 /nologo /O2 -utf-8 -FS -DL_ENDIAN -DOPENSSL_PIC -DOPENSSL_CPUID_OBJ -DOPENSSL_IA32_SSE2 -DOPENSSL_BN_ASM_MONT -DOPENSSL_BN_ASM_MONT5 -DOPENSSL_BN_ASM_GF2m -DSHA1_ASM -DSHA256_ASM -DSHA512_ASM -DKECCAK1600_ASM -DRC4_ASM -DMD5_ASM -DAESNI_ASM -DVPAES_ASM -DGHASH_ASM -DECP_NISTZ256_ASM -DX25519_ASM -DPOLY1305_ASM
OPENSSLDIR: "D:\vcpkg\packages\openssl_x64-windows"
ENGINESDIR: "D:\vcpkg\packages\openssl_x64-windows\lib\engines-1_1"
Seeding source: os-specific

$Env:AZURE_RSAKEY="managedHsm:ManagedHSMOpenSSLEngine:myrsakey"
PS D:\AzureKeyVaultManagedHSMEngine\src\build> az login
PS D:\AzureKeyVaultManagedHSMEngine\src\build> az account set --name "$Env:AZURE_SUBS"
PS D:\AzureKeyVaultManagedHSMEngine\src\build> $s=(az account get-access-token --output json --tenant $Env:AZURE_TENANT --resource https://managedhsm.azure.net)
PS D:\AzureKeyVaultManagedHSMEngine\src\build> $t=$s | ConvertFrom-Json
PS D:\AzureKeyVaultManagedHSMEngine\src\build> $Env:AZURE_CLI_ACCESS_TOKEN=$t.accessToken
PS D:\AzureKeyVaultManagedHSMEngine\src\build> echo "rsa key Managed HSM test" > readme.md
PS D:\AzureKeyVaultManagedHSMEngine\src\build> date >> readme.md
PS D:\AzureKeyVaultManagedHSMEngine\src\build> openssl pkey -engine e_akv -inform engine -in $Env:AZURE_RSAKEY -pubout -text -out leafpubkey.pem
engine "e_akv" set.
[i] GetAccessTokenFromIMDS curl.c(81) Environment variable AZURE_CLI_ACCESS_TOKEN defined [2069]

PS D:\AzureKeyVaultManagedHSMEngine\src\build> openssl dgst -binary -sha256 -out hash256 readme.md
PS D:\AzureKeyVaultManagedHSMEngine\src\build> openssl pkeyutl -engine e_akv -sign -keyform engine -inkey $Env:AZURE_RSAKEY -in hash256 -out hash256.sig.pss -pkeyopt digest:sha256 -pkeyopt rsa_padding_mode:pss
engine "e_akv" set.
[i] GetAccessTokenFromIMDS curl.c(81) Environment variable AZURE_CLI_ACCESS_TOKEN defined [2069]

[i] GetAccessTokenFromIMDS curl.c(81) Environment variable AZURE_CLI_ACCESS_TOKEN defined [2069]

PS D:\AzureKeyVaultManagedHSMEngine\src\build> openssl pkeyutl -verify -pubin -inkey leafpubkey.pem -in hash256 -sigfile hash256.sig.pss -pkeyopt digest:sha256  -pkeyopt rsa_padding_mode:pss
Signature Verified Successfully
PS D:\AzureKeyVaultManagedHSMEngine\src\build> openssl pkeyutl -engine e_akv -sign -keyform engine -inkey $Env:AZURE_RSAKEY -in hash256 -out hash256.sig -pkeyopt digest:sha256
engine "e_akv" set.
[i] GetAccessTokenFromIMDS curl.c(81) Environment variable AZURE_CLI_ACCESS_TOKEN defined [2069]

[i] GetAccessTokenFromIMDS curl.c(81) Environment variable AZURE_CLI_ACCESS_TOKEN defined [2069]

PS D:\AzureKeyVaultManagedHSMEngine\src\build> openssl pkeyutl -verify -pubin -inkey leafpubkey.pem -in hash256 -sigfile hash256.sig -pkeyopt digest:sha256
Signature Verified Successfully
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

### RSA testing script
set environments variables
```
export AZURE_SUBS="YOUR SUBSCRIPT NAME"
export AZURE_TENANT="YOUR TENANT ID"
export AZURE_RSAKEY="YOUR HSM RSA KEY"
az login
az account set --name "$AZURE_SUBS"
```

test.sh
```
t=$(az account get-access-token --output json --tenant $AZURE_TENANT --resource https://managedhsm.azure.net | jq -r '.accessToken')
export AZURE_CLI_ACCESS_TOKEN=$t

echo "rsa key Managed HSM test" > readme.md
date >> readme.md
openssl pkey -engine e_akv -inform engine -in $AZURE_RSAKEY -pubout -text -out leafpubkey.pem
openssl dgst -binary -sha256 -out hash256 readme.md
openssl pkeyutl -engine e_akv -sign -keyform engine -inkey $AZURE_RSAKEY -in hash256 -out hash256.sig.pss -pkeyopt digest:sha256 -pkeyopt rsa_padding_mode:pss
openssl pkeyutl -verify -pubin -inkey leafpubkey.pem -in hash256 -sigfile hash256.sig.pss -pkeyopt digest:sha256  -pkeyopt rsa_padding_mode:pss
openssl pkeyutl -engine e_akv -sign -keyform engine -inkey $AZURE_RSAKEY -in hash256 -out hash256.sig -pkeyopt digest:sha256
openssl pkeyutl -verify -pubin -inkey leafpubkey.pem -in hash256 -sigfile hash256.sig -pkeyopt digest:sha256
```

Result
```
puliu@PopDevBox:~/AzureKeyVaultManagedHSMEngine/src/build$ openssl version -a
OpenSSL 1.1.1f  31 Mar 2020
built on: Mon Jul  4 11:24:28 2022 UTC
platform: debian-amd64
options:  bn(64,64) rc4(16x,int) des(int) blowfish(ptr)
compiler: gcc -fPIC -pthread -m64 -Wa,--noexecstack -Wall -Wa,--noexecstack -g -O2 -fdebug-prefix-map=/build/openssl-51ig8V/openssl-1.1.1f=. -fstack-protector-strong -Wformat -Werror=format-security -DOPENSSL_TLS_SECURITY_LEVEL=2 -DOPENSSL_USE_NODELETE -DL_ENDIAN -DOPENSSL_PIC -DOPENSSL_CPUID_OBJ -DOPENSSL_IA32_SSE2 -DOPENSSL_BN_ASM_MONT -DOPENSSL_BN_ASM_MONT5 -DOPENSSL_BN_ASM_GF2m -DSHA1_ASM -DSHA256_ASM -DSHA512_ASM -DKECCAK1600_ASM -DRC4_ASM -DMD5_ASM -DAESNI_ASM -DVPAES_ASM -DGHASH_ASM -DECP_NISTZ256_ASM -DX25519_ASM -DPOLY1305_ASM -DNDEBUG -Wdate-time -D_FORTIFY_SOURCE=2
OPENSSLDIR: "/usr/lib/ssl"
ENGINESDIR: "/usr/lib/x86_64-linux-gnu/engines-1.1"
Seeding source: os-specific

puliu@PopDevBox:~/AzureKeyVaultManagedHSMEngine/src/build$ ./test.sh
engine "e_akv" set.
[i] GetAccessTokenFromIMDS curl.c(99) Environment variable AZURE_CLI_ACCESS_TOKEN defined [2058]

engine "e_akv" set.
[i] GetAccessTokenFromIMDS curl.c(99) Environment variable AZURE_CLI_ACCESS_TOKEN defined [2058]

[i] GetAccessTokenFromIMDS curl.c(99) Environment variable AZURE_CLI_ACCESS_TOKEN defined [2058]

Signature Verified Successfully
engine "e_akv" set.
[i] GetAccessTokenFromIMDS curl.c(99) Environment variable AZURE_CLI_ACCESS_TOKEN defined [2058]

[i] GetAccessTokenFromIMDS curl.c(99) Environment variable AZURE_CLI_ACCESS_TOKEN defined [2058]

Signature Verified Successfully
```
