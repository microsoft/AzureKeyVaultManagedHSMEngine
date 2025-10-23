# Azure Key Vault Provider Test Plan
## main steps
1. Build the provider
2. Deploy the provider
3. Get the access token
4. Perform smoke testing
5. perform Signing test for both RSA and ECC key
6. Validate signatures with Azure CLI and OpenSSL

## Get Openssl settings
```
openssl version -a
```
Looking for OPENSSLDIR and MODULESDIR, for example
```
OPENSSLDIR: "C:\OpenSSL\ssl"
MODULESDIR: "C:\OpenSSL\lib\ossl-modules"
```
The openssl.cnf will be stored in OPENSSLDIR
The provider DLL will be deployed to MODULESDIR

## Get the access token for Azure managed HSM
use the following powershell
```
$s=(az account get-access-token --output json --tenant 72f988bf-86f1-41af-91ab-2d7cd011db47 --resource https://managedhsm.azure.net)
$t=$s | ConvertFrom-Json
$Env:AZURE_CLI_ACCESS_TOKEN=$t.accessToken
```
## Build 
run `src_provider/build_with_vsdev.bat`

## Deploy
run `copy .\x64\Release\akv_provider.dll C:\OpenSSL\lib\ossl-modules`

## Initialize the openssl.cnf
```
[openssl_init]
providers = provider_sect

[provider_sect]
default = default_sect
akv_provider = akv_provider_sect

[default_sect]
activate = 1
[akv_provider_sect]
activate = 1
```

## Check if provider is activated
run `openssl list -providers`

## Managed HSM keys
Ensure the Managed HSM contains the pre-provisioned keys: `myrsakey` (RSA 2048 sign/decrypt), `myaeskey` (AES-256 wrap/unwrap), and `ecckey` (P-256 sign). Run `az keyvault key list --id https://ManagedHSMOpenSSLEngine.managedhsm.azure.net/` and confirm each key reports `enabled: true`.

Update key usage if operations are missing:
```
az keyvault key set-attributes --hsm-name ManagedHSMOpenSSLEngine --name myrsakey --ops sign verify encrypt decrypt
az keyvault key set-attributes --hsm-name ManagedHSMOpenSSLEngine --name myaeskey --ops wrapKey unwrapKey encrypt decrypt
az keyvault key set-attributes --hsm-name ManagedHSMOpenSSLEngine --name ecckey --ops sign verify
```

## Smoke Test
Run `openssl list -signature-algorithms -provider akv_provider`

## Signing Testing
- RSA Export `myrsakey` public key, run `openssl pkey -provider akv_provider -in "managedhsm:ManagedHSMOpenSSLEngine:myrsakey" -pubout -out myrsakey_pub.pem`
- ECC Export `Ecckey` public key, run `openssl pkey -provider akv_provider -in "managedhsm:ManagedHSMOpenSSLEngine:ecckey" -pubout -out ecckey_pub.pem`
- RSA signing with `myrsakey`: sign `openssl dgst -sha256 -sign  "managedhsm:ManagedHSMOpenSSLEngine:myrsakey" -provider akv_provider -out rs256.sig input.bin`.
- Azure-side verification: capture the base64 signature and digest, then call `az keyvault key verify`:
	```powershell
	openssl base64 -in rs256.sig -out rs256.sig.b64
	$signature = (Get-Content rs256.sig.b64 -Raw).Replace("`r","").Replace("`n","")
	$digestBytes = [System.Security.Cryptography.SHA256]::Create().ComputeHash([IO.File]::ReadAllBytes('input.bin'))
	$digest = [Convert]::ToBase64String($digestBytes)
	az keyvault key verify --id "https://ManagedHSMOpenSSLEngine.managedhsm.azure.net/keys/myrsakey" --algorithm PS256 --digest $digest --signature $signature
	```
- Local verification: `openssl dgst -sha256 -verify myrsakey_pub.pem -signature rs256.sig -sigopt rsa_padding_mode:pss -sigopt rsa_pss_saltlen:digest -sigopt rsa_mgf1_md:sha256 input.bin`.
- ECC signing with `ecckey`: sign `openssl dgst -sha256 -sign "managedhsm:ManagedHSMOpenSSLEngine:ecckey" -provider akv_provider -out es256.sig input.bin`. Verify with the exported EC public key: `openssl dgst -sha256 -verify ecckey_pub.pem -signature es256.sig input.bin`.
- Negative test: request an unsupported hash/algorithm pairing (e.g. ES384 with `myrsakey`) and confirm a helpful error surfaces.

### Current Findings
- RSA signatures require RSA-PSS padding; provider defaults enforce this.
- Azure Managed HSM verifies PS256 signatures successfully via `az keyvault key verify`.
- Local OpenSSL verification succeeds with the provider-exported PEM (`myrsakey_pub.pem`).

## Decrypt Flow
- Encrypt sample plaintext locally with `myrsakey_pub.pem`: `openssl pkeyutl -encrypt -pubin -inkey myrsakey_pub.pem -in plain.txt -out rsa_cipher.bin -pkeyopt rsa_padding_mode:oaep -pkeyopt rsa_oaep_md:sha1 -pkeyopt rsa_mgf1_md:sha1`.
- Decrypt through AKV: `openssl pkeyutl -decrypt -inkey "managedhsm:ManagedHSMOpenSSLEngine:myrsakey" -provider akv_provider -in rsa_cipher.bin -out rsa_roundtrip.txt`. The provider defaults to Azure's `RSA-OAEP` profile (SHA-1 with matching MGF1), so the encrypt step must specify `rsa_oaep_md:sha1` and `rsa_mgf1_md:sha1` to ensure parameter parity.
- Compare `plain.txt` and `rsa_roundtrip.txt` to confirm success; add cases for oversized payloads or disabled algorithms to validate error handling.

## AES Wrap Flow
- Generate a 32-byte local key to wrap: `openssl rand 32 > local.key`.
- Wrap using `myaeskey`: `openssl pkeyutl -wrap -inkey "managedhsm:ManagedHSMOpenSSLEngine:myaeskey" -provider akv_provider  -in local.key -out local.key.wrap`.
- Unwrap with the same key: `openssl pkeyutl -unwrap -inkey "managedhsm:ManagedHSMOpenSSLEngine:myaeskey" -provider akv_provider  -in local.key.wrap -out local.key.unwrapped`.
- Compare `local.key` and `local.key.unwrapped`; tamper with the wrapped blob to ensure unwrap fails cleanly.

## Automation
- Wrap the commands in a PowerShell script that sets environment variables (`AKV_TYPE`, `AKV_VAULT`, `AKV_KEY`, credential secrets). Make the script exit non-zero on failures.
- Allow enabling verbose logging via `AKV_LOG_LEVEL=2` to capture REST traces during CI or troubleshooting.

## Critical Bug Fix: ALGORITHM_ID Implementation

### Problem: Heap Corruption in X509 Operations
**Symptom**: `openssl req -new -x509` crashed with `STATUS_HEAP_CORRUPTION (-1073740940)` immediately after `digest_init` returned successfully. No heap corruption debugging tools (ASAN, Valgrind, WinDbg) were available at the time.

**Initial Investigation**:
- Crash occurred in OpenSSL's ASN.1 code: `ossl_asn1_item_embed_free ← ASN1_item_d2i ← ASN1_item_sign_ctx`
- Happened AFTER provider's `digest_init` returned 1 (success)
- NO subsequent provider callbacks were invoked before crash
- Multiple fixes attempted: digest callback patterns, MD params forwarding, finalization logic - none resolved the issue

**Root Cause Discovery**:
By adding logging to `akv_signature_get_ctx_params`, discovered OpenSSL was requesting `OSSL_SIGNATURE_PARAM_ALGORITHM_ID` parameter. When the provider didn't handle this parameter, OpenSSL attempted to compute the algorithm identifier internally, which caused heap corruption.

**Key Finding**: p_ncrypt provider also doesn't implement ALGORITHM_ID, suggesting this is a known limitation for external providers that can't access OpenSSL's internal `ossl_DER_w_*` functions.

### Solution: X509_ALGOR Public API Implementation

Instead of using OpenSSL's internal provider utilities, implemented ALGORITHM_ID using **public X509_ALGOR APIs**:

```c
// 1. Create X509_ALGOR structure
X509_ALGOR *algor = X509_ALGOR_new();

// 2. Set algorithm OID (example: sha256WithRSAEncryption)
X509_ALGOR_set0(algor, OBJ_nid2obj(NID_sha256WithRSAEncryption), V_ASN1_NULL, NULL);

// 3. Encode to DER format
int der_len = i2d_X509_ALGOR(algor, NULL);  // Get size
unsigned char *der = OPENSSL_malloc(der_len);
unsigned char *der_ptr = der;
i2d_X509_ALGOR(algor, &der_ptr);  // Encode

// 4. Store and return via OSSL_PARAM_set_octet_string()
ctx->aid = der;
ctx->aid_len = der_len;
```

**Algorithm NID Mapping**:
- RSA PKCS#1 v1.5: `NID_sha{1,224,256,384,512}WithRSAEncryption`
- ECDSA: `NID_ecdsa_with_SHA{1,224,256,384,512}`
- RSA-PSS: `NID_rsassaPss` (requires PSS parameters - not fully implemented yet)

**Implementation Changes**:
1. Added fields to `AKV_SIGNATURE_CTX`: `unsigned char *aid` and `size_t aid_len`
2. Created `akv_signature_compute_algorithm_id()` function
3. Called it from `akv_signature_set_digest()` to regenerate AID when digest changes
4. Updated `get_ctx_params` to return DER bytes via `OSSL_PARAM_set_octet_string()`
5. Updated `dupctx` to copy AID
6. Updated `reset_digest` to free AID with `OPENSSL_free()`
7. Added `OSSL_SIGNATURE_PARAM_ALGORITHM_ID` to `gettable_ctx_params`

**Also Fixed**:
- Missing `MGF1_DIGEST` parameter handling in `get_ctx_params`
- Missing `digest_initialized` flag copy in `dupctx`

### Test Results
✅ **CSR Generation**: `openssl req -new` works perfectly  
✅ **Self-Signed Certificates**: `openssl req -new -x509` works perfectly  
✅ **Exit Code**: 0 (success, no crashes)  
✅ **Signature Algorithm**: Proper `sha256WithRSAEncryption` in output  
✅ **Verification**: CSR self-signature verify OK  

**Error Evolution**:
1. Initial: `STATUS_HEAP_CORRUPTION` (crash)
2. With empty ALGORITHM_ID: `digest and key type not supported` (proper error)
3. With proper ALGORITHM_ID: Full success ✅

### Key Lesson
External OpenSSL providers MUST implement `OSSL_SIGNATURE_PARAM_ALGORITHM_ID` parameter for X509 operations (CSR, certificate generation) to work. The parameter must return a valid DER-encoded algorithm identifier. This can be achieved using public X509_ALGOR APIs (`X509_ALGOR_new()`, `X509_ALGOR_set0()`, `i2d_X509_ALGOR()`) rather than relying on OpenSSL's internal provider utilities.

If you want to build a **custom OpenSSL provider** to support remote key management (e.g., Azure Managed HSM) and ensure it works seamlessly with OpenSSL for **signing, decryption, and X.509 certificate operations**, your provider must implement a set of **PARAMS** (parameters) for each algorithm class. These are needed for OpenSSL core integration and to interoperate with applications and commands.

Below is a practical summary based on OpenSSL's provider API and common cryptographic workflows:

---

## 1. **Key Management PARAMS**

Implement for key import/export, generation, and referencing remote keys.

- `OSSL_PKEY_PARAM_ID`  
  The key identifier, e.g., a URI to the key in Azure HSM.
- `OSSL_PKEY_PARAM_TYPE`  
  Type of the key (RSA, EC, etc.).
- `OSSL_PKEY_PARAM_BITS`  
  Key size in bits.
- `OSSL_PKEY_PARAM_SECURITY_BITS`  
  Security level.
- `OSSL_PKEY_PARAM_MAX_SIZE`  
  Maximum size supported.
- `OSSL_PKEY_PARAM_FRIENDLY_NAME`  
  Human-readable key name (optional, but useful).
- `OSSL_PKEY_PARAM_PUB_KEY`  
  Public key value (if available).
- `OSSL_PKEY_PARAM_PRIV_KEY`  
  Usually **not available**, but you may expose access token or reference for remote operations.

## 2. **Signature PARAMS**

Implement for sign/verify operations:

- `OSSL_SIGNATURE_PARAM_DIGEST`  
  Name of digest algorithm (e.g., "SHA256").
- `OSSL_SIGNATURE_PARAM_PAD_MODE`  
  Padding (for RSA: PKCS1, PSS, etc.).
- `OSSL_SIGNATURE_PARAM_SALT_LEN`  
  Salt length for PSS.
- `OSSL_SIGNATURE_PARAM_ALGORITHM_ID`  
  DER-encoded ASN.1 OID for the signature algorithm.
- `OSSL_SIGNATURE_PARAM_KEY_ID`  
  Reference to the key for remote signing.

## 3. **Asymmetric Cipher (Decryption) PARAMS**

Implement for RSA/EC decryption operations:

- `OSSL_ASYM_CIPHER_PARAM_PAD_MODE`  
  Padding scheme (PKCS1, OAEP).
- `OSSL_ASYM_CIPHER_PARAM_OAEP_DIGEST`  
  OAEP digest algorithm.
- `OSSL_ASYM_CIPHER_PARAM_OAEP_LABEL`  
  OAEP label (optional).
- `OSSL_ASYM_CIPHER_PARAM_KEY_ID`  
  Key identifier for remote decryption.

## 4. **X.509 Certificate Handling**

Provider must support exporting the public key in standard formats (DER/PEM).  
The provider should expose:

- `OSSL_PKEY_PARAM_PUB_KEY`  
  Exportable public key.
- `OSSL_PKEY_PARAM_ID`  
  Key reference for signature verification.

## 5. **General PARAMS**

- `OSSL_PARAM_KEYMGMT_SELECT_PUBLIC_IMPORT`  
- `OSSL_PARAM_KEYMGMT_SELECT_PRIVATE_IMPORT`  
  (Support for import/export as appropriate, though private key is remote-only.)

## 6. **Other Useful PARAMS**

- `OSSL_PARAM_PROV_VERSION`  
  Provider version string.
- `OSSL_PARAM_PROV_NAME`  
  Provider name string.

---

## **Reference: Core OpenSSL Headers**

- [`include/openssl/core_names.h`](https://github.com/openssl/openssl/blob/master/include/openssl/core_names.h) — canonical source of parameter names.
- [`doc/man7/provider-keymgmt.pod`](https://github.com/openssl/openssl/blob/master/doc/man7/provider-keymgmt.pod)
- [`doc/man7/provider-signature.pod`](https://github.com/openssl/openssl/blob/master/doc/man7/provider-signature.pod)

---

## **Summary Table**

| Operation       | Required PARAMS                                                        |
|-----------------|-----------------------------------------------------------------------|
| Key Management  | OSSL_PKEY_PARAM_ID, OSSL_PKEY_PARAM_TYPE, OSSL_PKEY_PARAM_BITS, OSSL_PKEY_PARAM_PUB_KEY, OSSL_PKEY_PARAM_FRIENDLY_NAME |
| Signature       | OSSL_SIGNATURE_PARAM_DIGEST, OSSL_SIGNATURE_PARAM_PAD_MODE, OSSL_SIGNATURE_PARAM_SALT_LEN, OSSL_SIGNATURE_PARAM_ALGORITHM_ID, OSSL_SIGNATURE_PARAM_KEY_ID |
| Decryption      | OSSL_ASYM_CIPHER_PARAM_PAD_MODE, OSSL_ASYM_CIPHER_PARAM_OAEP_DIGEST, OSSL_ASYM_CIPHER_PARAM_OAEP_LABEL, OSSL_ASYM_CIPHER_PARAM_KEY_ID |
| X.509 Export    | OSSL_PKEY_PARAM_PUB_KEY, OSSL_PKEY_PARAM_ID                          |

---

## **Implementation Tips**

- You must **store only references to private keys** (never the raw key material).
- Your provider should route sign/decrypt requests to Azure Managed HSM using the key reference.
- Implement all `get_params`, `set_params`, and context-related PARAMS for each operation.
- Support for `OSSL_SIGNATURE_PARAM_ALGORITHM_ID` is **recommended** for interoperability.

---

**If you want a concrete starting point, review OpenSSL's built-in providers (e.g., RSA, EC) and the parameter handling in files like `rsa_kmgmt.c`, `rsa_sig.c`, and `core_names.h`.**

