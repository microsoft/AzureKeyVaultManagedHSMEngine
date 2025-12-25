# gRPC mTLS Sidecar Design Deep Dive

This document provides a detailed analysis of the double-ended sidecar proxy architecture, with log evidence proving the design works correctly.

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                          COMPLETE DATA FLOW                                      │
│                                                                                  │
│   gRPC Client ──► NGINX Client Sidecar ══════════► NGINX Server Sidecar ──► gRPC Server
│       │                   │              mTLS              │                    │
│       │                   │           (port 50051)         │                    │
│       │                   │                                │                    │
│       └─────── UDS ───────┘                                └─────── UDS ────────┘
│            (plaintext)                                          (plaintext)
│                                                                                  │
│                    ▼                                  ▼                          │
│              Azure Managed HSM                  Azure Managed HSM                │
│              (client signing)                   (server signing)                 │
└─────────────────────────────────────────────────────────────────────────────────┘
```

---

## Client Sidecar Configuration

### NGINX Config (`nginx/nginx-client.conf`)

```nginx
stream {
    upstream server_sidecar {
        server SERVER_HOST:50051;
    }

    server {
        # Listen on Unix Domain Socket (local only)
        listen unix:WORK_DIR/run/grpc-client.sock;

        # Initiate TLS to upstream server
        proxy_pass server_sidecar;
        proxy_ssl on;

        # Client certificate for mTLS (public)
        proxy_ssl_certificate WORK_DIR/certs/client.crt;

        # Client private key via OpenSSL 3.x provider (KEYLESS!)
        proxy_ssl_certificate_key "store:managedhsm:HSM_NAME:HSM_KEY_NAME";

        # Verify server certificate
        proxy_ssl_verify on;
        proxy_ssl_trusted_certificate WORK_DIR/certs/ca.crt;
        proxy_ssl_name localhost;

        # TLS settings
        proxy_ssl_protocols TLSv1.2 TLSv1.3;
        proxy_ssl_session_reuse on;

        # Timeouts for gRPC streaming
        proxy_connect_timeout 60s;
        proxy_timeout 3600s;
    }
}
```

### Design Diagram

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                      NGINX Client Sidecar                                   │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│   gRPC Client Application                                                   │
│   (any language: Rust, Go, Python, etc.)                                    │
│   - NO TLS configuration needed                                             │
│   - Connects to local UDS                                                   │
│                     │                                                       │
│                     │ Plaintext HTTP/2                                      │
│                     ▼                                                       │
│   ┌─────────────────────────────────────────────────────────────────────┐   │
│   │  listen unix:.../grpc-client.sock                                   │   │
│   │                                                                     │   │
│   │  proxy_ssl on                         ← Initiates TLS to upstream   │   │
│   │  proxy_ssl_certificate client.crt     ← Client cert (public)        │   │
│   │  proxy_ssl_certificate_key "store:managedhsm:..."  ← HSM KEY!       │   │
│   │  proxy_ssl_verify on                  ← Verify server cert          │   │
│   │  proxy_ssl_trusted_certificate ca.crt ← CA to trust                 │   │
│   └─────────────────────────────────────────────────────────────────────┘   │
│                     │                                                       │
│                     │ mTLS (TLS 1.2/1.3)                                    │
│                     │ Client authenticates with HSM-signed handshake        │
│                     ▼                                                       │
│   upstream server_sidecar { server 127.0.0.1:50051; }                       │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## Server Sidecar Configuration

### NGINX Config (`nginx/nginx-server.conf`)

```nginx
stream {
    upstream grpc_app {
        server unix:WORK_DIR/run/grpc-server.sock;
    }

    server {
        # Public mTLS endpoint
        listen 50051 ssl;

        # Server certificate (public)
        ssl_certificate WORK_DIR/certs/server.crt;

        # Server private key via OpenSSL 3.x provider (KEYLESS!)
        ssl_certificate_key "store:managedhsm:HSM_NAME:HSM_KEY_NAME";

        # mTLS: require and verify client certificate
        ssl_verify_client on;
        ssl_client_certificate WORK_DIR/certs/ca.crt;

        # TLS settings
        ssl_protocols TLSv1.2 TLSv1.3;
        ssl_prefer_server_ciphers on;
        ssl_ciphers 'ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-GCM-SHA256';

        # Session resumption (reduces HSM calls)
        ssl_session_cache shared:SSL:10m;
        ssl_session_timeout 1h;
        ssl_session_tickets off;

        # Forward to gRPC app
        proxy_pass grpc_app;
        proxy_connect_timeout 60s;
        proxy_timeout 3600s;
    }
}
```

### Design Diagram

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                      NGINX Server Sidecar                                   │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│   External Client (NGINX Client Sidecar)                                    │
│                     │                                                       │
│                     │ mTLS (TLS 1.2/1.3)                                    │
│                     │ Client presents certificate                           │
│                     ▼                                                       │
│   ┌─────────────────────────────────────────────────────────────────────┐   │
│   │  listen 50051 ssl                     ← Public mTLS endpoint        │   │
│   │                                                                     │   │
│   │  ssl_certificate server.crt           ← Server cert (public)        │   │
│   │  ssl_certificate_key "store:managedhsm:..."  ← HSM KEY!             │   │
│   │                                                                     │   │
│   │  ssl_verify_client on                 ← REQUIRE client cert (mTLS)  │   │
│   │  ssl_client_certificate ca.crt        ← CA to verify clients        │   │
│   │                                                                     │   │
│   │  ssl_session_cache shared:SSL:10m     ← Cache to reduce HSM calls   │   │
│   └─────────────────────────────────────────────────────────────────────┘   │
│                     │                                                       │
│                     │ Plaintext HTTP/2                                      │
│                     │ (TLS already terminated)                              │
│                     ▼                                                       │
│   upstream grpc_app { server unix:.../grpc-server.sock; }                   │
│                                                                             │
│   gRPC Server Application                                                   │
│   - NO TLS configuration needed                                             │
│   - Listens on local UDS                                                    │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## Log Evidence: Proof of Working Design

### 1. Traffic Flow (Access Logs)

**Client Sidecar** (`logs/nginx-client-access.log`):
```
unix: [25/Dec/2025:16:10:58 +0000] TCP 200 382 260 3.284 "127.0.0.1:50051"
  │                                     │   │   │     │          │
  │                                     │   │   │     │          └─ Upstream (server sidecar)
  │                                     │   │   │     └─ Duration (3.28s, includes streaming)
  │                                     │   │   └─ Bytes received from upstream
  │                                     │   └─ Bytes sent to upstream
  │                                     └─ HTTP status 200 OK
  └─ Client connected via UDS
```

**Server Sidecar** (`logs/nginx-server-access.log`):
```
127.0.0.1 [25/Dec/2025:16:10:58 +0000] TCP 200 382 260 3.283 "unix:...grpc-server.sock"
    │                                       │   │   │           │
    │                                       │   │   │           └─ Forwarded to gRPC app via UDS
    │                                       │   │   └─ Bytes received from client
    │                                       │   └─ Bytes sent to client
    │                                       └─ HTTP status 200 OK
    └─ Client IP (from client sidecar)
```

**Bytes Match:** Client sent 260 → Server received 260; Server sent 382 → Client received 382 ✅

---

### 2. HSM Signing Operations (Provider Log)

**Key Loading:**
```
[2025-12-25T16:10:48.959Z INFO] Loading key myrsakey (type: Rsa)  ← Server loads HSM key
[2025-12-25T16:10:50.347Z INFO] Loading key myrsakey (type: Rsa)  ← Client loads HSM key
```

**Server-Side TLS Handshake (Server Authentication):**
```
[2025-12-25T16:10:55.307Z INFO] akv_signature_digest_sign_init CALLED: mdname=SHA2-256
[2025-12-25T16:10:55.308Z INFO] akv_signature_digest_sign CALLED: sigsize=384 tbslen=146
[2025-12-25T16:10:55.686Z INFO] akv_signature_digest_sign -> 1 (signature 384 bytes)
                                                                      │
                                                    RSA-3072 signature (384 bytes = 3072 bits)
```

**Client-Side TLS Handshake (Client Authentication / mTLS):**
```
[2025-12-25T16:10:55.688Z INFO] akv_signature_digest_sign_init CALLED: mdname=SHA2-256
[2025-12-25T16:10:55.688Z INFO] akv_signature_digest_sign CALLED: sigsize=384 tbslen=146
[2025-12-25T16:10:56.076Z INFO] akv_signature_digest_sign -> 1 (signature 384 bytes)
                                                                      │
                                                    RSA-3072 signature (384 bytes = 3072 bits)
```

**Key Evidence:**
- ✅ Two separate HSM signing operations (server auth + client auth = mTLS)
- ✅ 384-byte signatures confirm RSA-3072 key from Azure Managed HSM
- ✅ SHA-256 digest algorithm used (TLS 1.2/1.3 standard)

---

### 3. Connection Flow (Server Error Log)

```
2025/12/25 16:10:55 [info] client 127.0.0.1:50442 connected to 0.0.0.0:50051
                           │                              │
                           │                              └─ mTLS endpoint
                           └─ Client sidecar IP

2025/12/25 16:10:56 [info] proxy unix: connected to unix:.../grpc-server.sock
                                  │
                                  └─ Forwarded to gRPC app via UDS (after TLS termination)

2025/12/25 16:10:58 [info] client disconnected, bytes from/to client:260/382, bytes from/to upstream:382/260
                                               │                           │
                                               └─ mTLS side                └─ UDS side (matches!)
```

---

## Summary: What the Logs Prove

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                              VERIFIED BY LOGS                                   │
├─────────────────────────────────────────────────────────────────────────────────┤
│                                                                                 │
│   gRPC Client ──► NGINX Client Sidecar ══════════► NGINX Server Sidecar ──► gRPC Server
│       │                   │                               │                    │
│       │              [16:10:55.686]                  [16:10:55.308]            │
│       │           HSM sign (client auth)          HSM sign (server auth)       │
│       │              384 bytes ✅                     384 bytes ✅              │
│       │                   │                               │                    │
│       │                   └───────── mTLS :50051 ─────────┘                    │
│       │                                                                        │
│       └──────────────────── UDS ──────────────────────────────────── UDS ──────┘
│                                                                                 │
│   Data Transfer:                                                                │
│   • Request:  260 bytes (client → server)                                      │
│   • Response: 382 bytes (server → client)                                      │
│   • Duration: 3.28 seconds (includes 5 streaming messages with 500ms delays)   │
│                                                                                 │
└─────────────────────────────────────────────────────────────────────────────────┘
```

| Verification Point | Evidence | Status |
|--------------------|----------|--------|
| Server uses HSM key | `Loading key myrsakey` in provider log | ✅ |
| Client uses HSM key | Second `Loading key myrsakey` in provider log | ✅ |
| Server signs with HSM | `signature 384 bytes` at 16:10:55.686 | ✅ |
| Client signs with HSM (mTLS) | `signature 384 bytes` at 16:10:56.076 | ✅ |
| Traffic flows through UDS | `proxy unix: connected to unix:...sock` | ✅ |
| Bytes match both sides | 260/382 on client = 382/260 on server | ✅ |
| mTLS connection established | Client connected to :50051 ssl | ✅ |

---

## Security Properties Achieved

| Property | How It's Achieved |
|----------|-------------------|
| **Keyless TLS** | Private keys stay in HSM via `store:managedhsm:...` URI |
| **Mutual Authentication** | `ssl_verify_client on` + `proxy_ssl_certificate` |
| **Zero Trust Network** | Both sides verify certificates |
| **App Isolation** | Apps only see plaintext on local UDS |
| **Reduced Attack Surface** | No private key files on disk |
| **Audit Trail** | All HSM operations logged in Azure Monitor |

---

## Performance Notes

| Operation | Time | Notes |
|-----------|------|-------|
| HSM key load | ~300ms | One-time per NGINX worker |
| HSM sign (server) | ~380ms | During TLS handshake |
| HSM sign (client) | ~390ms | During TLS handshake |
| Total handshake | ~800ms | First connection only |
| Session reuse | ~0ms | `ssl_session_cache` avoids re-signing |

**Optimization:** With `ssl_session_cache shared:SSL:10m`, subsequent connections within 1 hour reuse the TLS session and skip HSM signing entirely.

---

## End-to-End Testing Guide

This section provides detailed step-by-step instructions to test the complete gRPC mTLS sidecar architecture.

### Prerequisites

#### 1. Azure Managed HSM Setup

```bash
# Verify you have an Azure Managed HSM with a key
# Required: ManagedHSMOpenSSLEngine vault with myrsakey (RSA-3072)

# Authenticate to Azure (if not already)
az login

# Verify HSM access
az keyvault key show --hsm-name ManagedHSMOpenSSLEngine --name myrsakey
```

#### 2. OpenSSL Provider Installation

```bash
# Verify the AKV provider is installed
ls -la /usr/lib/x86_64-linux-gnu/ossl-modules/libakv_provider.so

# Test provider loads correctly
openssl list -providers -provider-path /usr/lib/x86_64-linux-gnu/ossl-modules -provider akv
```

Expected output:
```
Providers:
  akv
    name: Azure Key Vault Provider
    ...
```

#### 3. NGINX with OpenSSL 3.x Support

```bash
# Verify NGINX version (must be compiled with OpenSSL 3.x)
nginx -V 2>&1 | grep -i openssl

# Should show: built with OpenSSL 3.x.x
```

#### 4. Rust Toolchain

```bash
# Verify Rust is installed
rustc --version
cargo --version

# Should be Rust 1.70+ for tonic 0.12
```

### Step 1: Build the gRPC Application

```bash
# Navigate to the grpc-example directory
cd ~/AzureKeyVaultManagedHSMEngine/src_provider_rust/grpc-example

# Build both server and client binaries
cargo build --release

# Verify binaries were created
ls -la target/release/grpc-server target/release/grpc-client
```

Expected output:
```
-rwxrwxr-x 1 user user 5234567 Dec 25 12:00 target/release/grpc-server
-rwxrwxr-x 1 user user 4123456 Dec 25 12:00 target/release/grpc-client
```

### Step 2: Generate Certificates

```bash
# Run the certificate generation script
./generate-certs.sh

# This script will:
# 1. Create certs/ directory
# 2. Generate CA certificate (self-signed, HSM key)
# 3. Generate server certificate (signed by CA, HSM key)
# 4. Generate client certificate (signed by CA, HSM key)
```

Expected output:
```
=== Generating CA certificate ===
[INFO] Loading key myrsakey (type: Rsa)
[INFO] akv_signature_digest_sign -> 1 (signature 384 bytes)
CA certificate generated: certs/ca.crt

=== Generating server certificate ===
[INFO] akv_signature_digest_sign -> 1 (signature 384 bytes)
Server certificate generated: certs/server.crt

=== Generating client certificate ===
[INFO] akv_signature_digest_sign -> 1 (signature 384 bytes)
Client certificate generated: certs/client.crt

=== Certificate generation complete ===
```

Verify certificates:
```bash
# Check all certs exist
ls -la certs/

# Verify certificate chain
openssl verify -CAfile certs/ca.crt certs/server.crt
openssl verify -CAfile certs/ca.crt certs/client.crt

# Both should output: certs/xxx.crt: OK
```

### Step 3: Start the Demo Environment

```bash
# Start all components (NGINX sidecars + gRPC server)
./start-demo.sh
```

This script performs the following:
1. Creates `run/` directory for Unix Domain Sockets
2. Creates `logs/` directory for log files
3. Processes NGINX config templates (replaces placeholders)
4. Starts NGINX server sidecar (listens on port 50051)
5. Starts NGINX client sidecar (listens on UDS)
6. Starts gRPC server (listens on UDS)

Expected output:
```
=== Starting gRPC mTLS Demo ===

[1/6] Creating directories...
Created: run/, logs/

[2/6] Processing NGINX configs...
Server config: /tmp/nginx-server-processed.conf
Client config: /tmp/nginx-client-processed.conf

[3/6] Starting NGINX server sidecar...
nginx: [info] start server process
Server sidecar listening on :50051

[4/6] Starting NGINX client sidecar...
nginx: [info] start server process
Client sidecar listening on unix:run/grpc-client.sock

[5/6] Starting gRPC server...
gRPC server listening on unix:run/grpc-server.sock

[6/6] Verifying all components...
✓ Server sidecar PID: 12345
✓ Client sidecar PID: 12346
✓ gRPC server PID: 12347
✓ Server UDS exists: run/grpc-server.sock
✓ Client UDS exists: run/grpc-client.sock

=== Demo ready! ===
Run: ./run-client.sh
```

### Step 4: Verify Components Are Running

```bash
# Check all processes
ps aux | grep -E "nginx|grpc-server" | grep -v grep

# Check port 50051 is listening
ss -tlnp | grep 50051

# Check UDS files exist
ls -la run/*.sock

# Check NGINX error logs for startup issues
tail logs/nginx-server-error.log
tail logs/nginx-client-error.log
```

Expected process list:
```
user  12345  nginx: master process (server sidecar)
user  12346  nginx: worker process
user  12347  nginx: master process (client sidecar)
user  12348  nginx: worker process
user  12349  target/release/grpc-server
```

### Step 5: Run the gRPC Client

```bash
# Execute the client through the sidecar tunnel
./run-client.sh

# Or manually:
GRPC_UDS_PATH=run/grpc-client.sock ./target/release/grpc-client
```

Expected output:
```
=== gRPC Client (via mTLS sidecar) ===

Connecting to unix:run/grpc-client.sock...
Connected!

--- Testing Unary RPC ---
Request: SayHello("World")
Response: "Hello, World!"
✓ Unary RPC successful

--- Testing Server Streaming RPC ---
Request: StreamNumbers(5)
Received: Number 1
Received: Number 2
Received: Number 3
Received: Number 4
Received: Number 5
✓ Server streaming RPC successful (5 messages)

=== All tests passed! ===
```

### Step 6: Verify Logs

#### 6.1 Check HSM Operations

```bash
# View HSM signing operations
cat logs/akv-provider.log | grep -E "Loading key|signature_digest_sign|signature.*bytes"
```

Expected (TWO signature operations for mTLS):
```
[2025-12-25T16:10:48.959Z INFO] Loading key myrsakey (type: Rsa)
[2025-12-25T16:10:50.347Z INFO] Loading key myrsakey (type: Rsa)
[2025-12-25T16:10:55.308Z INFO] akv_signature_digest_sign CALLED: sigsize=384 tbslen=146
[2025-12-25T16:10:55.686Z INFO] akv_signature_digest_sign -> 1 (signature 384 bytes)
[2025-12-25T16:10:55.688Z INFO] akv_signature_digest_sign CALLED: sigsize=384 tbslen=146
[2025-12-25T16:10:56.076Z INFO] akv_signature_digest_sign -> 1 (signature 384 bytes)
```

**Key verification:**
- Two `Loading key` entries = both sidecars loaded the HSM key
- Two `signature 384 bytes` entries = mTLS (server auth + client auth)
- 384 bytes = RSA-3072 signature (3072 bits / 8 = 384 bytes)

#### 6.2 Check Traffic Flow

```bash
# Server sidecar access log
cat logs/nginx-server-access.log
```

Expected:
```
127.0.0.1 [25/Dec/2025:16:10:58 +0000] TCP 200 382 260 3.283 "unix:.../grpc-server.sock"
```

```bash
# Client sidecar access log
cat logs/nginx-client-access.log
```

Expected:
```
unix: [25/Dec/2025:16:10:58 +0000] TCP 200 382 260 3.284 "127.0.0.1:50051"
```

**Verify bytes match:**
- Client sent 260 bytes → Server received 260 bytes ✓
- Server sent 382 bytes → Client received 382 bytes ✓

#### 6.3 Check TLS Handshake

```bash
# Server sidecar error log (connection details)
grep -E "client|proxy|SSL" logs/nginx-server-error.log
```

Expected:
```
2025/12/25 16:10:55 [info] *1 client 127.0.0.1:50442 connected to 0.0.0.0:50051
2025/12/25 16:10:56 [info] *1 proxy unix:.../grpc-server.sock connected to unix:...
2025/12/25 16:10:58 [info] *1 client disconnected, bytes from/to client:260/382
```

### Step 7: Stop the Demo

```bash
# Stop all components
./stop-demo.sh
```

Expected output:
```
=== Stopping gRPC mTLS Demo ===

Stopping NGINX server sidecar (PID 12345)... done
Stopping NGINX client sidecar (PID 12347)... done
Stopping gRPC server (PID 12349)... done
Cleaning up UDS files... done

=== Demo stopped ===
```

### Troubleshooting

#### Issue: "Permission denied" on UDS

```bash
# Check UDS permissions
ls -la run/*.sock

# Fix: ensure run/ directory is writable
chmod 755 run/
```

#### Issue: "Connection refused" on port 50051

```bash
# Check if NGINX is running
ps aux | grep nginx

# Check NGINX error log
tail -20 logs/nginx-server-error.log

# Common cause: OpenSSL provider not loading
# Fix: Verify OPENSSL_MODULES path
export OPENSSL_MODULES=/usr/lib/x86_64-linux-gnu/ossl-modules
```

#### Issue: "SSL certificate verify failed"

```bash
# Verify certificate chain
openssl verify -CAfile certs/ca.crt certs/server.crt
openssl verify -CAfile certs/ca.crt certs/client.crt

# Common cause: certificates expired or wrong CA
# Fix: Regenerate certificates with ./generate-certs.sh
```

#### Issue: HSM signing timeout

```bash
# Check Azure connectivity
curl -I https://managedhsmopensslenginehsm.managedhsm.azure.net

# Check Azure authentication
az account show

# Common cause: Token expired
# Fix: Re-authenticate with az login
```

#### Issue: "No signature operations in log"

```bash
# Verify provider is loaded
grep "akv" logs/nginx-server-error.log

# Common cause: NGINX using default OpenSSL, not provider
# Fix: Ensure ssl_certificate_key uses store: URI
grep "ssl_certificate_key" /tmp/nginx-server-processed.conf
# Should show: ssl_certificate_key "store:managedhsm:..."
```

### Complete Test Checklist

| Step | Command | Expected Result |
|------|---------|-----------------|
| 1. Build | `cargo build --release` | Exit code 0, binaries created |
| 2. Gen certs | `./generate-certs.sh` | 3 certs in `certs/` |
| 3. Start | `./start-demo.sh` | All 3 PIDs shown |
| 4. Verify | `ss -tlnp \| grep 50051` | Port listening |
| 5. Run client | `./run-client.sh` | "All tests passed!" |
| 6. Check HSM | `grep signature logs/akv-provider.log` | 2 signatures (384 bytes each) |
| 7. Check traffic | `cat logs/nginx-server-access.log` | TCP 200, bytes match |
| 8. Stop | `./stop-demo.sh` | All processes stopped |

### Running Tests Multiple Times

To test TLS session resumption (HSM optimization):

```bash
# First run (cold start - 2 HSM signatures)
./run-client.sh

# Second run within 1 hour (session reuse - 0 HSM signatures)
./run-client.sh

# Check provider log - should NOT have new signature entries
tail -5 logs/akv-provider.log
```

The second run should complete faster (~800ms saved) because `ssl_session_cache` reuses the TLS session.
