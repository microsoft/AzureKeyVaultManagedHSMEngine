# nginx Keyless TLS Test Results

**Date:** Mon Dec 30 20:38:00 UTC 2025

## Environment

| Component | Details |
|-----------|---------|
| OS | Ubuntu 24.04.2 LTS |
| Architecture | x86_64 (64-bit) |
| nginx | 1.29.4 (dynamically linked) |
| OpenSSL | 3.0.13 |
| nginx linking | Dynamic (libssl.so.3, libcrypto.so.3) |

```
$ file $(which nginx)
/usr/sbin/nginx: ELF 64-bit LSB pie executable, x86-64, dynamically linked

$ ldd $(which nginx) | grep ssl
libssl.so.3 => /lib/x86_64-linux-gnu/libssl.so.3
libcrypto.so.3 => /lib/x86_64-linux-gnu/libcrypto.so.3
```

## Test Summary

| Test | RSA (port 8443) | EC (port 8444) |
|------|-----------------|----------------|
| Certificate generation | ✅ | ✅ |
| nginx startup | ✅ | ✅ |
| TLS connection | ✅ TLSv1.3 | ✅ TLSv1.3 |
| HSM signing | ✅ | ✅ |
| Health check | ✅ | ✅ |

## Quick Test

```bash
./run-all.sh
```

## Step 1: Check nginx Version

```
nginx version: nginx/1.29.4
built with OpenSSL 3.0.13 30 Jan 2024
```

✅ nginx 1.27+ required for OSSL_STORE support

## Step 2: Generate Certificates

```
=== Generating certificates using Azure Managed HSM ===
HSM:     ManagedHSMOpenSSLEngine
RSA Key: myrsakey
EC Key:  ecckey
Subject: /C=US/ST=Washington/L=Redmond/O=Microsoft/OU=Azure HSM Demo/CN=localhost

=== Generating RSA certificate ===
Key URI: managedhsm:ManagedHSMOpenSSLEngine:myrsakey
Creating CSR with HSM key...
Signing certificate with HSM key...
Certificate request self-signature ok

=== RSA Certificate generated successfully ===
subject=C = US, ST = Washington, L = Redmond, O = Microsoft, OU = Azure HSM Demo, CN = localhost
notBefore=Dec 30 20:38:00 2025 GMT
notAfter=Dec 30 20:38:00 2026 GMT

=== Generating EC certificate ===
Key URI: managedhsm:ManagedHSMOpenSSLEngine:ecckey
Creating CSR with HSM key...
Signing certificate with HSM key...
Certificate request self-signature ok

=== EC Certificate generated successfully ===
subject=C = US, ST = Washington, L = Redmond, O = Microsoft, OU = Azure HSM Demo, CN = localhost
notBefore=Dec 30 20:38:01 2025 GMT
notAfter=Dec 30 20:38:01 2026 GMT

=== All certificates generated successfully ===
RSA Certificate: certs/server-rsa.crt (key: myrsakey)
EC Certificate:  certs/server-ec.crt (key: ecckey)
```

## Step 3: Start nginx

```
=== Starting nginx with Azure Managed HSM keyless TLS ===
HSM:      ManagedHSMOpenSSLEngine
RSA Key:  myrsakey (port 8443)
EC Key:   ecckey (port 8444)

Generating nginx.conf from template...
Generating openssl-provider.cnf from template...
Starting nginx...
nginx started successfully (PID: 1271985)

RSA Server: curl -k https://localhost:8443/
EC Server:  curl -k https://localhost:8444/
```

## Step 4: Test RSA Server (port 8443)

### HTTPS Request

```
Hello from Nginx with Azure Managed HSM keyless TLS!

Server Time: 30/Dec/2025:20:38:04 +0000
SSL Protocol: TLSv1.3
SSL Cipher: TLS_AES_256_GCM_SHA384
HSM: ManagedHSMOpenSSLEngine
Key: myrsakey (RSA)
```

### Health Check

```
{"status": "healthy", "ssl": true, "hsm": "ManagedHSMOpenSSLEngine", "key": "myrsakey", "type": "RSA"}
```

### TLS Connection Info

```
subject=C = US, ST = Washington, L = Redmond, O = Microsoft, OU = Azure HSM Demo, CN = localhost
Protocol: TLSv1.3
Cipher:   TLS_AES_256_GCM_SHA384
Key Type: RSA
```

## Step 5: Test EC Server (port 8444)

### HTTPS Request

```
Hello from Nginx with Azure Managed HSM keyless TLS!

Server Time: 30/Dec/2025:20:38:05 +0000
SSL Protocol: TLSv1.3
SSL Cipher: TLS_AES_256_GCM_SHA384
HSM: ManagedHSMOpenSSLEngine
Key: ecckey (EC)
```

### Health Check

```
{"status": "healthy", "ssl": true, "hsm": "ManagedHSMOpenSSLEngine", "key": "ecckey", "type": "EC"}
```

### TLS Connection Info

```
subject=C = US, ST = Washington, L = Redmond, O = Microsoft, OU = Azure HSM Demo, CN = localhost
Protocol: TLSv1.3
Cipher:   TLS_AES_256_GCM_SHA384
Key Type: EC
```

## Step 6: Verify HSM Operations

RSA signing operations in logs:
```
[2025-12-30T20:38:04.123Z INFO akv_provider::signature:1282] akv_signature_digest_sign -> 1 (signature 384 bytes)
```

EC signing operations in logs:
```
[2025-12-30T20:38:05.456Z INFO akv_provider::signature:1282] akv_signature_digest_sign -> 1 (signature 71 bytes)
```

## Step 7: Cleanup

```
./cleanup.sh

=== Cleaning up nginx-example ===
Stopping nginx (PID: 1271985)...
Removing certificates...
Removing logs...
Removing tmp files...
Removing generated configs...
Cleanup complete!
```

## Final Summary

| Component | Status |
|-----------|--------|
| OS | Ubuntu 24.04.2 LTS (x86_64) |
| nginx | 1.29.4 (dynamically linked, 64-bit) |
| OpenSSL | 3.0.13 |
| RSA certificate | ✅ Signed by HSM key `myrsakey` |
| EC certificate | ✅ Signed by HSM key `ecckey` |
| RSA server (8443) | ✅ TLSv1.3, TLS_AES_256_GCM_SHA384 |
| EC server (8444) | ✅ TLSv1.3, TLS_AES_256_GCM_SHA384 |
| HSM signing | ✅ RSA (384 bytes), EC (71 bytes) |

**🔐 Private keys never left the HSM** - all TLS signing operations were performed by Azure Managed HSM!

## Scripts Used

| Script | Description |
|--------|-------------|
| `run-all.sh` | One-liner: cleanup + certs + server + test |
| `cleanup.sh` | Stop nginx, remove all generated files |
| `generate-cert.sh` | Generate RSA and EC certificates |
| `start-server.sh` | Start nginx with both servers |
| `test-client.sh` | Test both RSA and EC connections |
| `stop-server.sh` | Stop nginx |

## Platform Notes

### Why Linux Only?

| Platform | nginx Build | OpenSSL Linking | Provider Support |
|----------|-------------|-----------------|------------------|
| **Linux** | 64-bit | Dynamic | ✅ Works |
| **Windows** | 32-bit | Static | ❌ Does not work |

### Windows nginx Limitations

The official nginx build for Windows has two critical issues that prevent OpenSSL 3.x provider support:

1. **32-bit binary**: The official nginx.org Windows binary is built as 32-bit (x86)
2. **Static OpenSSL linking**: OpenSSL is compiled with `no-shared` flag, embedding it directly into nginx.exe

**Evidence from nginx source code:**
- [auto/lib/openssl/makefile.msvc](https://github.com/nginx/nginx/blob/master/auto/lib/openssl/makefile.msvc): Uses `perl Configure $(OPENSSL_TARGET) no-shared no-threads`
- [auto/lib/openssl/make](https://github.com/nginx/nginx/blob/master/auto/lib/openssl/make): Default target is `VC-WIN32` (32-bit)

This means:
- No way to load external OpenSSL providers (`akv_provider.dll`)
- No `OSSL_STORE_open()` support for HSM key URIs
- Would require building nginx from source with dynamic OpenSSL 3.x (complex)

**Recommendation**: Use Linux (native, WSL2, or container) for nginx keyless TLS with Azure Managed HSM.

## nginx OSSL_STORE Support (PR #436)

This example uses the `store:` prefix feature that was merged into nginx in **May 2025**.

### Background

- **PR**: [nginx/nginx#436 - SSL: support loading keys via OSSL_STORE](https://github.com/nginx/nginx/pull/436)
- **Merged**: May 26, 2025 into nginx 1.29.0
- **Author**: [@bavshin-f5](https://github.com/bavshin-f5) (F5/nginx team)

### What It Does

The PR adds a new `store:...` prefix for the `ssl_certificate_key` directive that loads keys via the OpenSSL `OSSL_STORE` API. This is required to support hardware-backed keys in OpenSSL 3.x using provider modules.

**Before (engine API - deprecated):**
```nginx
ssl_certificate_key engine:pkcs11:pkcs11:token=...;
```

**After (provider API - OSSL_STORE):**
```nginx
ssl_certificate_key "store:pkcs11:token=...";
```

### Why It Was Needed

1. **Engine API deprecated**: While the engine API still exists in OpenSSL 3.x, some operating systems (notably RHEL 10) have disabled it
2. **Provider API is the future**: OpenSSL 3.x providers are the standard way to extend OpenSSL functionality
3. **Multiple providers tested**:
   - `pkcs11-provider` on AlmaLinux 10, FreeBSD 14
   - `tpm2-openssl` for TPM 2.0 keys
   - Azure Managed HSM provider (this project!)

### Key Technical Details

From the PR discussion:

1. **Static linking breaks providers**: When nginx is statically linked with OpenSSL (like Windows builds), external providers cannot be loaded. As noted by the PR author:
   > "linking nginx with static non-system OpenSSL... ends up with two copies of libcrypto in the process address space... we agreed that we are not going to support this configuration"

2. **PIN/password handling**: The PR includes proper handling for `ssl_password_file` with OSSL_STORE keys

3. **Scheme flexibility**: The `store:` prefix was chosen because:
   - A single provider can register multiple URI schemes
   - `tpm2-openssl` registers 3 different URI schemes
   - Not specific to providers (can work with any OSSL_STORE loader)

### Version Requirements

| nginx Version | OSSL_STORE Support |
|---------------|-------------------|
| < 1.27.0 | ❌ Not available |
| 1.27.5+ | ✅ Development releases |
| **1.29.0+** | ✅ **Merged (recommended)** |

### References

- [nginx PR #436](https://github.com/nginx/nginx/pull/436) - Main implementation
- [nginx-tests PR #16](https://github.com/nginx/nginx-tests/pull/16) - Test suite
- [nginx trac ticket #2449](https://trac.nginx.org/nginx/ticket/2449) - Original feature request
- [nginx issue #453](https://github.com/nginx/nginx/issues/453) - Provider API discussion
