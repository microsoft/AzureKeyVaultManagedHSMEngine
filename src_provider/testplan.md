# Azure Key Vault Provider Plan

here's a comprehensive plan to convert this OpenSSL Engine to an OpenSSL Provider while maintaining all existing functionalities and continuing to use curl.c for remote HSM operations.

I'll create a comprehensive code structure for migrating the Azure Key Vault Managed HSM Engine to an OpenSSL Provider. Let me examine the existing codebase more carefully first.Let me search for the source files differently:Based on my analysis of the Azure Key Vault Managed HSM Engine repository, here's the complete code structure for migrating from OpenSSL Engine to OpenSSL Provider:

## Current Engine Architecture

```
src/
├── dllmain.c              # Engine initialization, RSA_METHOD, EC_KEY_METHOD setup
├── rsa.c                  # RSA signing, encryption, decryption operations
├── ec.c                   # EC key signing operations
├── key.c                  # Key loading and management
├── ctrl.c                 # Engine control commands
├── curl.c                 # Azure Key Vault REST API calls
├── base64.c               # Base64 encoding/decoding utilities
├── e_akv_err.c/.h         # Error handling
├── pch.h                  # Precompiled headers and main declarations
├── CMakeLists.txt         # Build configuration
└── e_akv.vcxproj          # Visual Studio project (Windows)
```

## OpenSSL Provider Migration Structure

Here's the recommended code structure for the provider version:

```
src/
├── provider/
│   ├── p_akv.c                    # Main provider entry point (OSSL_provider_init)
│   ├── p_akv.h                    # Provider core definitions
│   ├── p_akv_provider_ctx.c/.h    # Provider context management
│   ├── p_akv_signature.c          # EVP_SIGNATURE operations (RSA/EC signing)
│   ├── p_akv_asym_cipher.c        # EVP_ASYM_CIPHER operations (RSA enc/dec)
│   ├── p_akv_keyexch.c            # EVP_KEYEXCH operations (key exchange)
│   └── p_akv_dispatch.c           # OSSL_DISPATCH registration
│
├── common/                         # Shared code between engine and provider
│   ├── akv_azure.c/.h             # Azure Key Vault REST API (reused)
│   ├── akv_key.c/.h               # Key management (reused)
│   ├── akv_credentials.c/.h       # Azure credential handling (reused)
│   ├── akv_util.c/.h              # Utilities (reused)
│   └── akv_error.c/.h             # Error handling (reused)
│
├── engine/                         # Legacy engine code (for backward compatibility)
│   ├── e_akv_init.c/.h            # Engine initialization
│   ├── e_akv_rsa.c                # RSA operations (can call common functions)
│   ├── e_akv_ec.c                 # EC operations (can call common functions)
│   └── e_akv_ctrl.c               # Control commands
│
├── pch.h                          # Precompiled headers
├── CMakeLists.txt                 # Updated build (support both)
└── config.h                       # Configuration (enable/disable engine/provider)
```

## Core Files Overview with Function Mapping

### 1. **Provider Entry Point** (`p_akv.c`)
Maps to current `dllmain.c` - Engine initialization

```c
// Current Engine
static int akv_init(ENGINE *e)
  ├─ ENGINE_get_ex_new_index()
  ├─ RSA_get_ex_new_index()
  ├─ RSA_meth_set_priv_dec(akv_rsa_priv_dec)
  ├─ RSA_meth_set_priv_enc(akv_rsa_priv_enc)
  ├─ EC_KEY_get_ex_new_index()
  └─ EC_KEY_METHOD setup

// Provider Equivalent
OSSL_provider_init()
  ├─ Provider context creation
  ├─ Algorithm registration (via OSSL_DISPATCH)
  ├─ EVP_SIGNATURE registration (RSA/EC)
  ├─ EVP_ASYM_CIPHER registration (RSA)
  └─ Capability queries
```

### 2. **Signature Operations** (`p_akv_signature.c`)
Maps to current `rsa.c` and `ec.c`

```c
// Current Engine Functions
akv_rsa_priv_dec()      → RSA decryption
akv_rsa_priv_enc()      → RSA signing
akv_eckey_sign()        → EC signing
akv_eckey_sign_sig()    → EC signature generation

// Provider Equivalent (EVP_SIGNATURE)
signature_sign()        → unified signing interface
signature_verify()      → signature verification
signature_digset_update() → digest update
signature_final()       → final signature
```

### 3. **Key Management** (`akv_key.c` - moved to common)
Shared between engine and provider

```c
// Current Functions (preserved as-is)
acquire_akv_key()       → Create AKV_KEY structure
destroy_akv_key()       → Release AKV_KEY structure
akv_load_privkey()      → Load private key from AKV
AkvGetKey()             → Get public key from Azure
```

### 4. **Azure Integration** (`akv_azure.c` - moved to common)
Shared REST API layer

```c
// Current Functions (preserved as-is)
GetAccessTokenFromIMDS()   → Get Azure access token
AkvSign()                  → Remote signing via Azure
AkvDecrypt()               → Remote decryption via Azure
AkvEncrypt()               → Remote encryption via Azure
```

### 5. **Provider Context** (`p_akv_provider_ctx.c`)
New for provider architecture

```c
// Provider-specific context
struct PROVIDER_CTX {
    OSSL_LIB_CTX *libctx;
    const char *propq;      // property query string
    int debug_level;
    // Azure credential cache
    // Session management
};

// Functions
provider_ctx_new()
provider_ctx_free()
provider_ctx_get_libctx()
```

### 6. **Dispatch Table** (`p_akv_dispatch.c`)
Provider algorithm registration

```c
// Maps algorithms to implementations
const OSSL_DISPATCH p_akv_signature_fns[] = {
    { OSSL_FUNC_SIGNATURE_NEWCTX, (void (*)(void))signature_newctx },
    { OSSL_FUNC_SIGNATURE_SIGN, (void (*)(void))signature_sign },
    { OSSL_FUNC_SIGNATURE_VERIFY, (void (*)(void))signature_verify },
    { OSSL_FUNC_SIGNATURE_DIGSET_UPDATE, (void (*)(void))signature_digset_update },
    { OSSL_FUNC_SIGNATURE_FREECTX, (void (*)(void))signature_freectx },
    ...
};

const OSSL_DISPATCH p_akv_asym_cipher_fns[] = {
    { OSSL_FUNC_ASYM_CIPHER_NEWCTX, (void (*)(void))asym_cipher_newctx },
    { OSSL_FUNC_ASYM_CIPHER_ENCRYPT, (void (*)(void))asym_cipher_encrypt },
    { OSSL_FUNC_ASYM_CIPHER_DECRYPT, (void (*)(void))asym_cipher_decrypt },
    ...
};
```

### 7. **Updated CMakeLists.txt**

```cmake
# Shared source files
set(akv_common_src
  common/akv_azure.c
  common/akv_key.c
  common/akv_credentials.c
  common/akv_util.c
  common/akv_error.c
  base64.c
  curl.c
)

# Provider target (OpenSSL 3.x)
add_library(p_akv SHARED
  provider/p_akv.c
  provider/p_akv_provider_ctx.c
  provider/p_akv_signature.c
  provider/p_akv_asym_cipher.c
  provider/p_akv_dispatch.c
  ${akv_common_src}
)
target_link_libraries(p_akv PRIVATE ${CRYPTO_LIB} ${CURL_LIB} ${JSONC_LIB})
install(TARGETS p_akv DESTINATION "${OPENSSL_PROVIDERS_DIR}")

# Engine target (OpenSSL 1.1.x, legacy)
add_library(e_akv SHARED
  engine/e_akv_init.c
  engine/e_akv_rsa.c
  engine/e_akv_ec.c
  engine/e_akv_ctrl.c
  ${akv_common_src}
)
target_link_libraries(e_akv PRIVATE ${CRYPTO_LIB} ${SSL_LIB} ${CURL_LIB} ${JSONC_LIB})
install(TARGETS e_akv DESTINATION "${OPENSSL_ENGINES_DIR}")
```

## Function Preservation and Mapping

| Current Engine Function | Location | Provider Equivalent | Status |
|---|---|---|---|
| `akv_rsa_priv_dec()` | rsa.c | `asym_cipher_decrypt()` | Map |
| `akv_rsa_priv_enc()` | rsa.c | `signature_sign()` | Map |
| `akv_eckey_sign()` | ec.c | `signature_sign()` | Map |
| `akv_eckey_sign_sig()` | ec.c | `signature_final()` | Map |
| `AkvSign()` | curl.c | Reuse in common | Preserve |
| `AkvDecrypt()` | curl.c | Reuse in common | Preserve |
| `AkvEncrypt()` | curl.c | Reuse in common | Preserve |
| `AkvGetKey()` | key.c | Reuse in common | Preserve |
| `GetAccessTokenFromIMDS()` | pch.h | Reuse in common | Preserve |
| `acquire_akv_key()` | key.c | Reuse in common | Preserve |
| `destroy_akv_key()` | key.c | Reuse in common | Preserve |
| `akv_ctrl()` | ctrl.c | Provider params | Map |

## Header Files Structure

### `p_akv.h` - Provider Core
```c
#define PROVIDER_NAME "AKV"
#define PROVIDER_VERSION "1.0.0"

typedef struct provider_ctx_st PROVIDER_CTX;

PROVIDER_CTX *provider_ctx_new(OSSL_LIB_CTX *libctx, const OSSL_CORE_HANDLE *handle);
void provider_ctx_free(PROVIDER_CTX *ctx);

// Algorithm registration
int p_akv_register_signature(PROVIDER_CTX *ctx);
int p_akv_register_asym_cipher(PROVIDER_CTX *ctx);
```

### `p_akv_provider_ctx.h` - Context Management
```c
struct provider_ctx_st {
    OSSL_LIB_CTX *libctx;
    const char *propq;
    int debug_level;
    // Azure credential cache
    // HSM session management
};
```

## Build Integration Points

1. **CMakeLists.txt** - Add provider build targets
2. **Shared common functions** - Extract to `common/` directory
3. **Conditional compilation** - Support both engine and provider
4. **Installation paths** - 
   - Provider: `/usr/lib/ossl-modules/` (or appropriate provider dir)
   - Engine: `/usr/lib/x86_64-linux-gnu/engines-1.1/` (legacy)

## Key Design Principles

✅ **Preserve all existing functions** - Move to `common/` for reuse  
✅ **Dual support** - Engine and provider can coexist  
✅ **Minimal refactoring** - Azure integration remains unchanged  
✅ **Clean separation** - Provider logic isolated from core Azure functions  
✅ **OpenSSL 3.x compatible** - Uses OSSL_DISPATCH and provider API  
✅ **Backward compatible** - Applications can use either engine or provider  

This structure ensures all existing Azure Key Vault/HSM functionality is preserved while cleanly integrating the OpenSSL Provider architecture.

## Get the access token
use the following powershell
```
$s=(az account get-access-token --output json --tenant 72f988bf-86f1-41af-91ab-2d7cd011db47 --resource https://managedhsm.azure.net)
$t=$s | ConvertFrom-Json
$Env:AZURE_CLI_ACCESS_TOKEN=$t.accessToken
```
## Preparation
- Build the provider using `src_provider/winbuild.bat` or `src_provider/build_with_vsdev.bat`. Copy the resulting `akv_provider.dll` into a staging folder (e.g. `out/modules`).
- Ensure the Managed HSM contains the pre-provisioned keys: `myrsakey` (RSA 2048 sign/decrypt), `myaeskey` (AES-256 wrap/unwrap), and `ecckey` (P-256 sign). Run `az keyvault key list --id https://ManagedHSMOpenSSLEngine.managedhsm.azure.net/` and confirm each key reports `enabled: true`.
- Confirm the test host has credentials (Managed Identity or service principal) granting sign, decrypt, wrapKey, and unwrapKey permissions as applicable to the key type.
- Locate the OpenSSL 3 binary from vcpkg (e.g. `./vcpkg_installed/x64-windows/tools/openssl/openssl.exe`). Export `OPENSSL_MODULES=<stage-dir>` or prepare to pass `-provider_path` on the command line.
- Create a minimal OpenSSL config (e.g. `openssl_akv.cnf`) that loads both the default provider and `akv_provider`. Export `OPENSSL_CONF` or supply `-config` when running tests.

## Smoke Checks
- Run `openssl list -providers -provider akv_provider -provider_path <stage-dir>` to confirm the provider loads and exposes metadata.
- After algorithms are registered, verify they appear via `openssl list -signature-algorithms -provider akv_provider ...` and the equivalent decrypt listings.

## Signing Flow
- Export `myrsakey` or `ecckey` via the provider once URI support exists (e.g. `openssl pkey -provider akv_provider -provider_path <stage-dir> -in "akv:keyvault_type=managedHsm,keyvault_name=ManagedHSMOpenSSLEngine,key_name=myrsakey,alg=RS256" -pubout -out myrsakey_pub.pem`). Repeat for `ecckey` with `alg=ES256`.
- RSA signing: `openssl dgst -sha256 -sign "akv:keyvault_type=managedHsm,keyvault_name=ManagedHSMOpenSSLEngine,key_name=myrsakey,alg=RS256" -provider akv_provider -provider_path <stage-dir> -out rs256.sig input.bin`. Verify with the exported public key: `openssl dgst -sha256 -verify myrsakey_pub.pem -signature rs256.sig input.bin`.
- ECC signing: `openssl dgst -sha256 -sign "akv:keyvault_type=managedHsm,keyvault_name=ManagedHSMOpenSSLEngine,key_name=ecckey,alg=ES256" -provider akv_provider -provider_path <stage-dir> -out es256.sig input.bin`. Verify with the exported EC public key: `openssl dgst -sha256 -verify ecckey_pub.pem -signature es256.sig input.bin`.
- Negative test: request an unsupported hash/algorithm pairing (e.g. ES384 with `myrsakey`) and confirm a helpful error surfaces.

## Decrypt Flow
- Encrypt sample plaintext locally with `myrsakey_pub.pem`: `openssl pkeyutl -encrypt -pubin -inkey myrsakey_pub.pem -in plain.txt -out rsa_cipher.bin`.
- Decrypt through AKV: `openssl pkeyutl -decrypt -inkey "akv:keyvault_type=managedHsm,keyvault_name=ManagedHSMOpenSSLEngine,key_name=myrsakey,alg=RSA-OAEP" -provider akv_provider -provider_path <stage-dir> -in rsa_cipher.bin -out rsa_roundtrip.txt`.
- Compare `plain.txt` and `rsa_roundtrip.txt` to confirm success; add cases for oversized payloads or disabled algorithms to validate error handling.

## AES Wrap Flow
- Generate a 32-byte local key to wrap: `openssl rand 32 > local.key`.
- Wrap using `myaeskey`: `openssl pkeyutl -wrap -inkey "akv:keyvault_type=managedHsm,keyvault_name=ManagedHSMOpenSSLEngine,key_name=myaeskey,alg=A256KW" -provider akv_provider -provider_path <stage-dir> -in local.key -out local.key.wrap`.
- Unwrap with the same key: `openssl pkeyutl -unwrap -inkey "akv:keyvault_type=managedHsm,keyvault_name=ManagedHSMOpenSSLEngine,key_name=myaeskey,alg=A256KW" -provider akv_provider -provider_path <stage-dir> -in local.key.wrap -out local.key.unwrapped`.
- Compare `local.key` and `local.key.unwrapped`; tamper with the wrapped blob to ensure unwrap fails cleanly.

## Automation
- Wrap the commands in a PowerShell script that sets environment variables (`AKV_TYPE`, `AKV_VAULT`, `AKV_KEY`, credential secrets). Make the script exit non-zero on failures.
- Allow enabling verbose logging via `AKV_LOG_LEVEL=2` to capture REST traces during CI or troubleshooting.
