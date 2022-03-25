# Openssl Example
The environment variable $AKVKEY will refer to the private key stored in either Azure key vault or Managed HSM.
1. For Azure Key Vault key, it will be like vault:key_valut_name:key_name
2. For Azure Managed HSM key, it will be like managedHsm:hsm_name:key_name

## create an self-signed certificate
```
openssl req -new -x509 -config openssl.cnf -engine e_akv -keyform engine -key $AKVKEY -out cert.pem
```
## extract the public key from the public certificate
```
openssl x509 -pubkey -noout -in cert.pem > publickey.pem
```
## sign the hash
```
openssl dgst -binary -sha256 -out hash256 readme.md
openssl pkeyutl -engine e_akv -sign -keyform engine -inkey $AKVKEY -in hash256 -out hash256.sig -pkeyopt rsa_padding_mode:pss -pkeyopt digest:sha256
```

## verify the signature
```
openssl pkeyutl -verify -pubin -inkey publickey.pem -in hash256 -sigfile hash256.sig -pkeyopt digest:sha256 -pkeyopt rsa_padding_mode:pss
```