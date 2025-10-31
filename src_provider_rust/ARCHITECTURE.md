# Azure Managed HSM OpenSSL Provider - Architecture

This document provides detailed sequence diagrams showing how the OpenSSL provider interacts with OpenSSL, the Azure Managed HSM REST API, and handles various cryptographic operations.

## Table of Contents

1. [Overview](#overview)
2. [Key Loading Flow](#key-loading-flow)
3. [RSA Signing (PS256)](#rsa-signing-ps256)
4. [RSA Signing (RS256)](#rsa-signing-rs256)
5. [EC Signing (ES256)](#ec-signing-es256)
6. [RSA Decryption (OAEP)](#rsa-decryption-oaep)
7. [AES Key Wrap](#aes-key-wrap)
8. [AES Key Unwrap](#aes-key-unwrap)
9. [X.509 Certificate Generation](#x509-certificate-generation)

---

## Overview

The Azure Managed HSM OpenSSL Provider implements the OpenSSL 3.x Provider API to enable cryptographic operations using keys stored in Azure Managed HSM. The provider acts as a bridge between OpenSSL and Azure's REST API.

**Key Components:**
- **Store Loader**: Parses URIs and fetches keys from Azure Managed HSM
- **Key Management (KEYMGMT)**: Manages public key material and metadata
- **Signature**: Handles RSA and ECDSA signing operations
- **Cipher**: Handles RSA decryption and AES key wrap/unwrap
- **HTTP Client**: Communicates with Azure Managed HSM REST API
- **Authentication**: Manages Azure access tokens

### Supported Azure Managed HSM Operations

| Operation | Description |
|-----------|-------------|
| **Decrypt** | Decrypts a single block of encrypted data. |
| **Encrypt** | Encrypts an arbitrary sequence of bytes using an encryption key that is stored in a key vault. |
| **Wrap Key** | Wraps a symmetric key using a specified key. |
| **Unwrap Key** | Unwraps a symmetric key using the specified key that was initially used for wrapping that key. |
| **Sign** | Creates a signature from a digest using the specified key. |
| **Verify** | Verifies a signature using a specified key. |

**Note:** The provider currently implements Decrypt, Wrap Key, Unwrap Key, and Sign operations. Encrypt and Verify operations are performed locally by OpenSSL using the public key material.

**Reference:** [Azure Key Vault REST API Documentation](https://learn.microsoft.com/en-us/rest/api/keyvault/)

---

## Key Loading Flow

This diagram shows how a key is loaded from Azure Managed HSM when specified via a `managedhsm:` URI.

```mermaid
sequenceDiagram
    participant CLI as OpenSSL CLI
    participant OSSL as OpenSSL Core
    participant Provider as AKV Provider
    participant Store as Store Loader
    participant Auth as Authentication
    participant Azure as Azure HSM API
    participant KeyMgmt as Key Management

    CLI->>OSSL: openssl pkey -in managedhsm:vault:keyname
    OSSL->>Provider: Provider Init
    Provider-->>OSSL: Provider Context
    
    OSSL->>Store: akv_store_open()
    Store-->>OSSL: Store Context
    
    OSSL->>Store: akv_store_load("managedhsm:vault:keyname")
    Store->>Store: Parse URI (vault, key name, version)
    
    Store->>Auth: get_access_token()
    Auth->>Auth: Check env var AZURE_CLI_ACCESS_TOKEN
    Auth-->>Store: Access Token
    
    Store->>Azure: GET /keys/{keyname}?api-version=7.5
    Note over Store,Azure: Authorization: Bearer {token}
    Azure-->>Store: Key metadata (JWK format)
    
    Store->>Store: Parse JWK (key type, curve/size, public key)
    
    alt RSA Key
        Store->>Store: build_rsa_public_key(n, e)
        Store->>OSSL: EVP_PKEY_fromdata(RSA, n, e)
        OSSL-->>Store: EVP_PKEY*
    else EC Key
        Store->>Store: build_ec_public_key(x, y, curve)
        Store->>OSSL: EVP_PKEY_fromdata(EC, x, y, group)
        OSSL-->>Store: EVP_PKEY*
    end
    
    Store->>KeyMgmt: Create AkvKey with metadata
    Note over KeyMgmt: Stores vault, key name, version,<br/>and public_key (PKey)
    
    Store->>OSSL: Object Callback with key reference
    OSSL->>KeyMgmt: akv_keymgmt_get_params(bits, security-bits, max-size)
    KeyMgmt->>OSSL: EVP_PKEY_get_params() delegation
    OSSL-->>KeyMgmt: Parameters filled
    KeyMgmt-->>OSSL: Success
    
    Store-->>OSSL: Key Reference
    OSSL-->>CLI: Key Loaded
```

**Key Points:**
1. URI format: `managedhsm:{vault}:{keyname}[:{version}]`
2. Access token is retrieved from environment variable `AZURE_CLI_ACCESS_TOKEN`
3. Public key material is fetched from Azure and converted to OpenSSL `EVP_PKEY`
4. Private key operations are performed by the HSM; only metadata is stored locally

---

## RSA Signing (PS256)

RSA-PSS signing with SHA-256 digest and salt length equal to digest length.

```mermaid
sequenceDiagram
    participant CLI as OpenSSL CLI
    participant OSSL as OpenSSL Core
    participant Provider as AKV Provider
    participant Store as Store Loader
    participant Sig as Signature Ops
    participant Auth as Authentication
    participant Azure as Azure HSM API

    CLI->>OSSL: openssl dgst -sha256 -sign managedhsm:vault:rsakey<br/>-sigopt rsa_padding_mode:pss
    
    Note over OSSL: Load key via Store (see Key Loading Flow)
    OSSL->>Store: Load key
    Store-->>OSSL: Key reference
    
    OSSL->>Provider: Query operation (SIGNATURE)
    Provider-->>OSSL: RSA signature functions
    
    OSSL->>Sig: akv_signature_newctx(RSA)
    Sig->>Sig: Create SignatureContext<br/>(keytype=Rsa, padding=PKCS1)
    Sig-->>OSSL: Context
    
    OSSL->>Sig: akv_signature_digest_sign_init(md=sha256)
    Sig->>Sig: Store md=sha256, operation=SIGN
    Sig->>Sig: compute_algorithm_id()
    Note over Sig: Generate DER-encoded algorithm ID<br/>for X.509 compatibility
    Sig-->>OSSL: Success
    
    OSSL->>Sig: akv_signature_set_ctx_params(pad-mode=pss)
    Sig->>Sig: Set padding=RSA_PKCS1_PSS_PADDING
    Sig-->>OSSL: Success
    
    OSSL->>Sig: akv_signature_set_ctx_params(saltlen=digest)
    Sig->>Sig: Set pss_saltlen=RSA_PSS_SALTLEN_DIGEST (-1)
    Sig-->>OSSL: Success
    
    OSSL->>Sig: akv_signature_set_ctx_params(mgf1-digest=sha256)
    Sig->>Sig: Set mgf1_md=sha256
    Sig-->>OSSL: Success
    
    OSSL->>Sig: akv_signature_digest_sign(data)
    Sig->>Sig: Hash data with sha256 → digest
    Sig->>Sig: validate_pss_params()<br/>Check salt length matches digest
    
    Sig->>Auth: get_access_token()
    Auth-->>Sig: Access Token
    
    Sig->>Azure: POST /keys/{keyname}/sign?api-version=7.5
    Note over Sig,Azure: Body: {<br/>  "alg": "PS256",<br/>  "value": "{base64_digest}"<br/>}
    Azure->>Azure: Perform PSS signing in HSM
    Azure-->>Sig: {"value": "{base64_signature}"}
    
    Sig->>Sig: Base64 decode signature
    Sig->>Sig: Reverse byte order (Azure → OpenSSL)
    Sig-->>OSSL: Signature bytes
    OSSL-->>CLI: Signature written to file
```

**Key Points:**
1. PSS padding requires salt length equal to digest length for Azure HSM
2. MGF1 must use the same digest as the main signature digest
3. Signature bytes are returned in big-endian and reversed for OpenSSL
4. Algorithm identifier is pre-computed for X.509 CSR/certificate operations

---

## RSA Signing (RS256)

RSA PKCS#1 v1.5 signing with SHA-256 digest.

```mermaid
sequenceDiagram
    participant CLI as OpenSSL CLI
    participant OSSL as OpenSSL Core
    participant Sig as Signature Ops
    participant Auth as Authentication
    participant Azure as Azure HSM API

    CLI->>OSSL: openssl dgst -sha256 -sign managedhsm:vault:rsakey<br/>-sigopt rsa_padding_mode:pkcs1
    
    Note over OSSL: Load key and create context (similar to PS256)
    
    OSSL->>Sig: akv_signature_set_ctx_params(pad-mode=pkcs1)
    Sig->>Sig: Set padding=RSA_PKCS1_PADDING
    Sig-->>OSSL: Success
    
    OSSL->>Sig: akv_signature_digest_sign(data)
    Sig->>Sig: Hash data with sha256 → digest
    
    Sig->>Auth: get_access_token()
    Auth-->>Sig: Access Token
    
    Sig->>Azure: POST /keys/{keyname}/sign?api-version=7.5
    Note over Sig,Azure: Body: {<br/>  "alg": "RS256",<br/>  "value": "{base64_digest}"<br/>}
    Azure->>Azure: Perform PKCS#1 v1.5 signing in HSM
    Azure-->>Sig: {"value": "{base64_signature}"}
    
    Sig->>Sig: Base64 decode and reverse bytes
    Sig-->>OSSL: Signature bytes
    OSSL-->>CLI: Signature written to file
```

**Key Points:**
1. PKCS#1 v1.5 padding is simpler than PSS (no salt parameters)
2. Algorithm is RS256 (RSASSA-PKCS1-v1_5 with SHA-256)
3. Same byte order reversal applies

---

## EC Signing (ES256)

ECDSA signing with SHA-256 digest and P-256 curve.

```mermaid
sequenceDiagram
    participant CLI as OpenSSL CLI
    participant OSSL as OpenSSL Core
    participant Sig as Signature Ops
    participant Auth as Authentication
    participant Azure as Azure HSM API

    CLI->>OSSL: openssl dgst -sha256 -sign managedhsm:vault:ecckey
    
    Note over OSSL: Load EC key (P-256 curve)
    
    OSSL->>Sig: akv_signature_newctx(EC)
    Sig->>Sig: Create SignatureContext<br/>(keytype=Ec, padding=0)
    Sig-->>OSSL: Context
    
    OSSL->>Sig: akv_signature_digest_sign_init(md=sha256)
    Sig->>Sig: Store md=sha256
    Sig->>Sig: compute_algorithm_id()
    Note over Sig: Generate algorithm ID for ecdsa-with-SHA256
    Sig-->>OSSL: Success
    
    OSSL->>Sig: akv_signature_digest_sign(data)
    Sig->>Sig: Hash data with sha256 → digest
    
    Sig->>Auth: get_access_token()
    Auth-->>Sig: Access Token
    
    Sig->>Azure: POST /keys/{keyname}/sign?api-version=7.5
    Note over Sig,Azure: Body: {<br/>  "alg": "ES256",<br/>  "value": "{base64_digest}"<br/>}
    Azure->>Azure: Perform ECDSA signing in HSM
    Azure-->>Sig: {"value": "{base64_signature}"}
    
    Sig->>Sig: Base64 decode signature (DER format)
    Note over Sig: Signature is already in DER format<br/>(SEQUENCE of two INTEGERs r, s)
    Sig-->>OSSL: DER-encoded signature
    OSSL-->>CLI: Signature written to file
```

**Key Points:**
1. EC signatures use DER encoding (no byte reversal needed)
2. Algorithm is ES256 (ECDSA with SHA-256 and P-256 curve)
3. No padding parameters for ECDSA

---

## RSA Decryption (OAEP)

RSA OAEP decryption using SHA-1 for both padding and MGF1.

```mermaid
sequenceDiagram
    participant CLI as OpenSSL CLI
    participant OSSL as OpenSSL Core
    participant Cipher as Cipher Ops
    participant Auth as Authentication
    participant Azure as Azure HSM API

    CLI->>OSSL: openssl pkeyutl -decrypt -inkey managedhsm:vault:rsakey<br/>-pkeyopt rsa_padding_mode:oaep
    
    Note over OSSL: Load key
    
    OSSL->>Provider: Query operation (ASYM_CIPHER)
    Provider-->>OSSL: RSA cipher functions
    
    OSSL->>Cipher: akv_rsa_cipher_newctx()
    Cipher->>Cipher: Create RsaCipherContext<br/>(padding=RSA_PKCS1_OAEP_PADDING)
    Cipher-->>OSSL: Context
    
    OSSL->>Cipher: akv_rsa_cipher_decrypt_init(key)
    Cipher->>Cipher: Store key reference
    Cipher-->>OSSL: Success
    
    OSSL->>Cipher: akv_rsa_cipher_set_ctx_params(rsa_padding_mode=oaep)
    Cipher->>Cipher: Confirm padding=OAEP
    Cipher-->>OSSL: Success
    
    OSSL->>Cipher: akv_rsa_cipher_decrypt(ciphertext)
    Cipher->>Cipher: Reverse byte order (OpenSSL → Azure)
    Cipher->>Cipher: Base64 encode ciphertext
    
    Cipher->>Auth: get_access_token()
    Auth-->>Cipher: Access Token
    
    Cipher->>Azure: POST /keys/{keyname}/decrypt?api-version=7.5
    Note over Cipher,Azure: Body: {<br/>  "alg": "RSA-OAEP",<br/>  "value": "{base64_ciphertext}"<br/>}
    Azure->>Azure: Decrypt in HSM with OAEP
    Azure-->>Cipher: {"value": "{base64_plaintext}"}
    
    Cipher->>Cipher: Base64 decode plaintext
    Cipher-->>OSSL: Plaintext bytes
    OSSL-->>CLI: Decrypted data
```

**Key Points:**
1. Azure HSM uses RSA-OAEP with SHA-1 for both hash and MGF1
2. Ciphertext bytes are reversed before sending to Azure
3. Plaintext is returned directly in base64

---

## AES Key Wrap

Wrapping a symmetric key using AES-KW (RFC 3394).

```mermaid
sequenceDiagram
    participant CLI as OpenSSL CLI
    participant OSSL as OpenSSL Core
    participant Cipher as Cipher Ops
    participant Auth as Authentication
    participant Azure as Azure HSM API

    CLI->>OSSL: openssl pkeyutl -encrypt -inkey managedhsm:vault:aeskey<br/>-in plainkey
    
    Note over OSSL: Load AES key metadata
    
    OSSL->>Provider: Query operation (ASYM_CIPHER)
    Provider-->>OSSL: AES cipher functions
    
    OSSL->>Cipher: akv_aes_cipher_newctx()
    Cipher->>Cipher: Create AesCipherContext
    Cipher-->>OSSL: Context
    
    OSSL->>Cipher: akv_aes_cipher_encrypt_init(key)
    Cipher->>Cipher: Store key reference (vault, keyname)
    Cipher-->>OSSL: Success
    
    OSSL->>Cipher: akv_aes_cipher_encrypt(plainkey)
    Cipher->>Cipher: Base64 encode plainkey
    
    Cipher->>Auth: get_access_token()
    Auth-->>Cipher: Access Token
    
    Cipher->>Azure: POST /keys/{keyname}/wrapkey?api-version=7.5
    Note over Cipher,Azure: Body: {<br/>  "alg": "A256KW",<br/>  "value": "{base64_plainkey}"<br/>}
    Azure->>Azure: Wrap key using AES-256-KW in HSM
    Azure-->>Cipher: {"value": "{base64_wrappedkey}"}
    
    Cipher->>Cipher: Base64 decode wrapped key
    Cipher-->>OSSL: Wrapped key bytes
    OSSL-->>CLI: Wrapped key written to file
```

**Key Points:**
1. AES key wrapping follows RFC 3394 (AES-KW)
2. Algorithm is A256KW (AES-256 Key Wrap)
3. Wrapped key is 8 bytes longer than plaintext (64-bit IV prepended)

---

## AES Key Unwrap

Unwrapping a symmetric key using AES-KW.

```mermaid
sequenceDiagram
    participant CLI as OpenSSL CLI
    participant OSSL as OpenSSL Core
    participant Cipher as Cipher Ops
    participant Auth as Authentication
    participant Azure as Azure HSM API

    CLI->>OSSL: openssl pkeyutl -decrypt -inkey managedhsm:vault:aeskey<br/>-in wrappedkey
    
    Note over OSSL: Load AES key metadata
    
    OSSL->>Cipher: akv_aes_cipher_decrypt_init(key)
    Cipher->>Cipher: Store key reference
    Cipher-->>OSSL: Success
    
    OSSL->>Cipher: akv_aes_cipher_decrypt(wrappedkey)
    Cipher->>Cipher: Validate wrapped key length (must be multiple of 8)
    Cipher->>Cipher: Base64 encode wrapped key
    
    Cipher->>Auth: get_access_token()
    Auth-->>Cipher: Access Token
    
    Cipher->>Azure: POST /keys/{keyname}/unwrapkey?api-version=7.5
    Note over Cipher,Azure: Body: {<br/>  "alg": "A256KW",<br/>  "value": "{base64_wrappedkey}"<br/>}
    Azure->>Azure: Unwrap key using AES-256-KW in HSM
    
    alt Valid wrapped key
        Azure-->>Cipher: {"value": "{base64_plainkey}"}
        Cipher->>Cipher: Base64 decode plaintext key
        Cipher-->>OSSL: Plaintext key bytes
        OSSL-->>CLI: Unwrapped key
    else Invalid/Tampered key
        Azure-->>Cipher: HTTP 400 Bad Request
        Cipher-->>OSSL: Error
        OSSL-->>CLI: Decryption failed
    end
```

**Key Points:**
1. Unwrap validates the key integrity (detects tampering)
2. Wrapped key must be a multiple of 8 bytes
3. Returns HTTP 400 if wrapped key is invalid or tampered

---

## X.509 Certificate Generation

Generating a self-signed certificate or CSR using a key in Azure HSM.

```mermaid
sequenceDiagram
    participant CLI as OpenSSL CLI
    participant OSSL as OpenSSL Core
    participant Store as Store Loader
    participant KeyMgmt as Key Management
    participant Sig as Signature Ops
    participant Auth as Authentication
    participant Azure as Azure HSM API

    CLI->>OSSL: openssl req -new -x509 -key managedhsm:vault:rsakey<br/>-sha256 -days 365
    
    Note over OSSL,Store: Load key (see Key Loading Flow)
    
    OSSL->>OSSL: Generate certificate structure<br/>(subject, validity, serial, etc.)
    
    OSSL->>KeyMgmt: akv_keymgmt_export(selection=PUBLIC_KEY)
    KeyMgmt->>OSSL: EVP_PKEY_todata() delegation
    OSSL-->>KeyMgmt: Public key parameters (n, e for RSA)
    KeyMgmt-->>OSSL: Export callback with parameters
    Note over OSSL: Public key embedded in certificate
    
    OSSL->>OSSL: Create TBSCertificate (To Be Signed)
    OSSL->>OSSL: Encode TBSCertificate to DER
    
    OSSL->>Sig: akv_signature_digest_sign_init(md=sha256)
    Sig->>Sig: compute_algorithm_id()
    Sig-->>OSSL: Success
    
    OSSL->>Sig: akv_signature_get_ctx_params(ALGORITHM_ID)
    Sig->>Sig: Return pre-computed algorithm ID
    Sig-->>OSSL: DER-encoded algorithm ID
    Note over OSSL: Algorithm ID inserted into certificate
    
    OSSL->>Sig: akv_signature_digest_sign(TBSCertificate_DER)
    Sig->>Sig: Hash TBSCertificate with sha256
    
    Sig->>Auth: get_access_token()
    Auth-->>Sig: Access Token
    
    Sig->>Azure: POST /keys/{keyname}/sign?api-version=7.5
    Note over Sig,Azure: Body: {<br/>  "alg": "RS256",<br/>  "value": "{base64_digest}"<br/>}
    Azure->>Azure: Sign in HSM
    Azure-->>Sig: {"value": "{base64_signature}"}
    
    Sig->>Sig: Base64 decode and reverse bytes
    Sig-->>OSSL: Signature
    
    OSSL->>OSSL: Assemble final certificate:<br/>TBSCertificate + AlgorithmID + Signature
    OSSL->>OSSL: Encode to PEM
    OSSL-->>CLI: Certificate written to file
```

**Key Points:**
1. Provider exports only public key material
2. Algorithm ID is pre-computed during `digest_sign_init`
3. TBSCertificate is hashed and signed by Azure HSM
4. Same flow applies to CSR generation (Certificate Signing Request)

---

## Component Interaction Summary

```mermaid
graph TD
    A[OpenSSL CLI] --> B[OpenSSL Core]
    B --> C[AKV Provider]
    C --> D[Store Loader]
    C --> E[Key Management]
    C --> F[Signature Ops]
    C --> G[Cipher Ops]
    D --> H[HTTP Client]
    F --> H
    G --> H
    H --> I[Authentication]
    I --> J[Azure HSM API]
    H --> J
    
    style A fill:#e1f5ff
    style B fill:#fff4e1
    style C fill:#ffe1e1
    style J fill:#e1ffe1
```

**Data Flow:**
1. **CLI → OpenSSL**: User commands and options
2. **OpenSSL → Provider**: Operation requests via provider API
3. **Provider → Azure**: REST API calls for cryptographic operations
4. **Azure → Provider**: Operation results (signatures, plaintext, etc.)
5. **Provider → OpenSSL**: Results converted to OpenSSL format
6. **OpenSSL → CLI**: Final output to user

---

## Security Considerations

1. **Private Keys Never Leave HSM**: All private key operations (sign, decrypt, unwrap) are performed in Azure HSM
2. **Access Token Security**: Tokens are obtained from environment variable and passed via HTTPS
3. **TLS Protection**: All communication with Azure uses HTTPS (TLS 1.2+)
4. **Token Expiry**: Access tokens typically expire after 1 hour; refresh externally
5. **Audit Logging**: Azure HSM logs all key operations for compliance

---

## Performance Characteristics

**Typical Latencies** (from test logs):
- Key loading: ~250-350ms (includes HTTPS round-trip to Azure)
- RSA signing: ~200-300ms per signature
- EC signing: ~200-250ms per signature
- RSA decryption: ~200-250ms per decrypt
- AES wrap/unwrap: ~150-200ms per operation

**Optimization Tips:**
- Reuse loaded keys when possible (provider caches public key material)
- Use batch operations for multiple signatures
- Consider key caching at application level for repeated operations

---

## Error Handling

Common error scenarios and how the provider handles them:

1. **Invalid URI**: Store loader returns error, OpenSSL reports "file not found"
2. **Missing Access Token**: Authentication fails, returns clear error message
3. **Key Not Found**: Azure API returns 404, provider reports key not found
4. **Invalid Parameters**: Provider validates parameters and returns specific error
5. **Network Errors**: HTTP client retries and reports connection issues
6. **HSM Unavailable**: Azure returns 503, operation fails with service unavailable

All errors are logged to the provider log file for debugging.
