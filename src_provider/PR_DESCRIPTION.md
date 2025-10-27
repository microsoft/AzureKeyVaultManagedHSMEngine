# OpenSSL Provider for Azure Managed HSM - Testing & Automation Infrastructure

## Overview

This PR introduces comprehensive testing and automation infrastructure for the **OpenSSL 3.x Provider** that enables cryptographic operations with keys stored in **Azure Managed HSM**. This provider allows applications using OpenSSL to perform RSA/EC signing, decryption, and AES key wrapping operations with hardware-backed keys in Azure's FIPS 140-2 Level 3 certified Managed HSM, without ever exposing the private key material.

## Key Features

### 🔐 Provider Capabilities
The OpenSSL provider enables:
- **RSA Operations**: PS256 (RSA-PSS), RS256 (PKCS#1 v1.5) signing, and OAEP decryption with remote HSM keys
- **EC Operations**: ES256 (ECDSA P-256) signing with remote HSM keys
- **AES Operations**: AES-256-KW key wrap/unwrap for secure key exchange
- **X.509 Support**: CSR generation and self-signed certificate creation using HSM-backed keys
- **Standard OpenSSL CLI**: Works with `openssl` command-line tools (dgst, pkeyutl, req, etc.)

### 🚀 New Testing Infrastructure

#### 1. **Comprehensive Test Suite (`runtest.bat`)**
A pure CMD batch script that provides complete end-to-end testing:

**Test Coverage:**
- ✅ RSA PS256 (RSA-PSS with SHA-256) signing and verification
- ✅ RSA RS256 (PKCS#1 v1.5 with SHA-256) signing and verification  
- ✅ RSA OAEP (SHA-1) decryption roundtrip
- ✅ EC ES256 (ECDSA P-256) signing and verification
- ✅ X.509 RSA CSR generation and verification
- ✅ X.509 RSA self-signed certificate generation and verification
- ✅ X.509 EC CSR generation and verification
- ✅ X.509 EC self-signed certificate generation and verification
- ✅ AES-256-KW key wrap/unwrap roundtrip
- ✅ AES tamper detection (negative test)

**Features:**
- No PowerShell dependency - pure CMD batch scripting
- Timestamped test folders (`temp_YYYYMMDD_HHMM`) for organized test runs
- Comprehensive test summaries with environment details
- `/SKIPVALIDATION` flag for rapid development iteration
- Generates 19 test artifacts per successful run

**Critical Bug Fix:**
Discovered and fixed batch script hanging issue: `az` is actually `az.cmd` (a batch file), requiring `call az` instead of just `az` to prevent execution transfer without return.

#### 2. **Pre-flight Validation System**
Automated checks before running tests:
- ✅ OpenSSL 3.x version detection
- ✅ MODULESDIR detection via `openssl version -a`
- ✅ Provider DLL installation verification
- ✅ Azure CLI availability check
- ✅ Provider loadability via `openssl list -providers`
- ✅ Managed HSM accessibility validation
- ✅ Required keys validation (RSA, EC, AES)

Validation takes ~20-30 seconds but ensures all prerequisites are met before testing.

#### 3. **Standalone Validation (`validate_hsm.bat`)**
Reusable script for CI/CD pipelines:
- Progress indicators [1/4], [2/4], [3/4], [4/4]
- Validates vault and all three required keys
- Returns proper exit codes for automation
- Can be called independently or from other scripts

#### 4. **Automated HSM Provisioning (`setup_managed_hsm.bat`)**
Complete automation of Azure Managed HSM setup:

**8-Step Automated Workflow:**
1. Prerequisites check (Azure CLI, OpenSSL, Azure login status)
2. Get current user's object ID automatically
3. Create Azure resource group (if needed)
4. Create Managed HSM instance (~15-20 min)
5. Generate 3 security domain wrapping certificates (RSA 2048)
6. Download and activate security domain (HSM activation)
7. Assign "Managed HSM Crypto User" role to current user
8. Create required keys:
   - `myrsakey` - RSA-HSM 3072-bit for sign/verify/encrypt/decrypt
   - `ecckey` - EC-HSM P-256 for sign/verify
   - `myaeskey` - oct-HSM 256-bit for wrapKey/unwrapKey

**Benefits:**
- Reduces setup from 30+ manual commands to single script execution
- Security domain files automatically saved to `.\security_domain\`
- Comprehensive error handling and status reporting
- Idempotent - safe to re-run if interrupted

## Technical Implementation

### Provider Architecture
The provider implements OpenSSL 3.x Provider API:
- **Key Management**: Remote key references via URI `managedhsm:<vault>:<keyname>`
- **Signature Operations**: RSA-PSS, PKCS#1 v1.5, ECDSA with remote signing
- **Cipher Operations**: RSA-OAEP decryption, AES-KW wrap/unwrap
- **Parameter Support**: Full OSSL_PARAM implementation for algorithm configuration

### Azure Integration
- **Authentication**: Azure CLI access tokens via managed identity or user login
- **REST API**: Direct HTTPS calls to Managed HSM REST endpoints
- **Static Linking**: All dependencies (libcurl, json-c, zlib, OpenSSL) statically linked
- **Single DLL**: No runtime dependencies beyond system libraries

### Token Management
Pure batch JSON parsing without PowerShell:
```batch
for /f "tokens=2 delims=:," %%i in ('call az account get-access-token ... ^| findstr "accessToken"') do set TOKEN=%%i
```

## Files Changed

### Added
- `runtest.bat` - Comprehensive test suite (489 lines)
- `validate_hsm.bat` - Standalone HSM validation (115 lines)
- `setup_managed_hsm.bat` - Automated HSM provisioning (326 lines)

### Modified
- `.github/copilot-instructions.md` - Updated documentation and deployment instructions
- `.gitignore` - Added build artifacts and test outputs

### Removed
- `runtest.ps1` - Obsolete PowerShell test script (replaced by runtest.bat)

## Testing Results

All tests passing on Windows with OpenSSL 3.3.2:

```
✅ RSA PS256 signing roundtrip - Verified OK
✅ RSA RS256 signing roundtrip - Verified OK
✅ RSA OAEP decrypt roundtrip - Files match
✅ EC ES256 signing roundtrip - Verified OK
✅ RSA CSR generation - Certificate request self-signature verify OK
✅ RSA self-signed certificate - OK
✅ EC CSR generation - Certificate request self-signature verify OK
✅ EC self-signed certificate - OK
✅ AES key wrap/unwrap - Keys match perfectly
✅ AES tamper detection - Expected failure (PASSED)
```

## Usage Examples

### Quick Start
```cmd
# Setup Managed HSM (one-time)
cd src_provider
setup_managed_hsm.bat

# Build provider
winbuild.bat

# Deploy provider
copy x64\Release\akv_provider.dll C:\OpenSSL\lib\ossl-modules\

# Run tests
runtest.bat

# Or skip validation for faster iteration
runtest.bat /SKIPVALIDATION
```

### OpenSSL CLI Examples
```cmd
# Sign with RSA key in Managed HSM
openssl dgst -sha256 -sign managedhsm:ManagedHSMOpenSSLEngine:myrsakey ^
  -provider akv_provider -provider default ^
  -sigopt rsa_padding_mode:pss -out signature.bin input.txt

# Generate CSR with HSM key
openssl req -new -provider akv_provider -provider default ^
  -key managedhsm:ManagedHSMOpenSSLEngine:myrsakey ^
  -out request.csr

# Wrap AES key
openssl pkeyutl -encrypt ^
  -inkey managedhsm:ManagedHSMOpenSSLEngine:myaeskey ^
  -provider akv_provider -provider default ^
  -in local.key -out wrapped.key
```

## Benefits

### For Developers
- 🚀 Rapid testing with automated validation
- 📦 Single-script HSM provisioning
- 🔧 No PowerShell dependency - works everywhere
- 📊 Detailed test summaries and organized outputs
- ⚡ Fast iteration with `/SKIPVALIDATION` flag

### For Operations
- 🔐 Hardware-backed keys in FIPS 140-2 Level 3 HSM
- 🔄 Standard OpenSSL CLI compatibility
- 📝 Automated setup documentation
- ✅ Comprehensive validation before operations
- 🛡️ Security domain backup automation

### For Security
- 🔑 Private keys never leave the HSM
- 🎯 Minimal attack surface (static linking)
- 📋 Full audit trail via Azure logging
- 🔒 Role-based access control (Azure RBAC)
- 💾 Secure key backup via security domain

## Requirements

- **OpenSSL**: 3.0 or later
- **Azure CLI**: Latest version
- **Visual Studio 2022**: With C++ tools
- **vcpkg**: For dependency management
- **Windows**: Windows 10/11 or Server 2019/2022
- **Azure**: Valid subscription with Managed HSM quota

## Future Enhancements

Potential areas for expansion:
- [ ] Linux support for setup scripts
- [ ] GitHub Actions CI/CD integration
- [ ] Additional algorithm support (RSA 4096, Ed25519)
- [ ] Batch operations API
- [ ] Performance benchmarking suite

## References

- [OpenSSL Provider API](https://www.openssl.org/docs/man3.0/man7/provider.html)
- [Azure Managed HSM Documentation](https://docs.microsoft.com/azure/key-vault/managed-hsm/)
- [nginx-managedHsm Sample](../../samples/nginx-managedHsm/readme.md)

---

This infrastructure provides a solid foundation for production use of OpenSSL with Azure Managed HSM, enabling secure cryptographic operations without exposing key material.
