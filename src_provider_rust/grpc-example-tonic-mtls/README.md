# Tonic gRPC + Native mTLS with Azure Managed HSM

This example demonstrates **end-to-end mTLS in pure Rust + Tonic** where both
the gRPC server and the gRPC client hold their TLS private keys in **Azure
Managed HSM**. There is **no NGINX sidecar** — the OpenSSL AKV provider is
loaded directly into the Tonic process and handles every private-key
operation by calling Managed HSM over REST.

> Companion to the sidecar-based `../grpc-example/`. Use that one if you
> need a pattern that works for non-Rust gRPC stacks (Go, Java, Python,
> .NET, …). Use this one for Rust services that want a single-process
> deployment without an extra proxy in the cert path.

## Architecture

```
┌──────────────────────────────────────────────────────────────────┐
│                          HOST                                     │
│                                                                   │
│  ┌──────────────────────────────┐         mTLS (port 50443)       │
│  │ tonic-mtls-client (Rust)     │ ◄─────────────────────────────► │
│  │  ┌────────────────────────┐  │     ┌──────────────────────────┐│
│  │  │ tonic + tokio-openssl  │  │     │ tonic-mtls-server (Rust) ││
│  │  │ openssl SslConnector   │  │     │ openssl SslAcceptor      ││
│  │  │ akv_provider (in-proc) │  │     │ akv_provider (in-proc)   ││
│  │  └────────────┬───────────┘  │     └────────────┬─────────────┘│
│  └───────────────┼──────────────┘                  │              │
│                  │                                 │              │
└──────────────────┼─────────────────────────────────┼──────────────┘
                   │                                 │
                   │  signRSA over HTTPS             │  signRSA over HTTPS
                   ▼                                 ▼
                ┌────────────────────────────────────────┐
                │       Azure Managed HSM                │
                │  (RSA private key, never exported)     │
                └────────────────────────────────────────┘
```

Both client and server reference the **same RSA key in MHSM** for the
private operation, but present **different certificate identities** (CA,
Server, Client) — exactly as in the sidecar demo.

## Why this layout

* `tonic` 0.12 supports custom transports via `serve_with_incoming` (server)
  and `connect_with_connector` (client). We use both to plug in our own
  `tokio_openssl::SslStream` and avoid Tonic's built-in rustls path.
* The Rust `openssl` 0.10 crate has **no safe wrapper for `OSSL_STORE`**, so
  `src/hsm_key.rs` calls `OSSL_STORE_open_ex` / `OSSL_STORE_load` /
  `OSSL_STORE_INFO_get1_PKEY` directly via `openssl-sys` FFI. That's the
  only unsafe code in this crate.
* The handshake yields an `SslStream` that already implements
  `AsyncRead + AsyncWrite`, so wrapping it in `hyper_util::rt::TokioIo`
  hands Tonic exactly what it expects.

## Prerequisites

1. OpenSSL **3.x** development headers (the `openssl-sys` crate links
   against `libssl`/`libcrypto` and the provider lives in the same process).
2. The AKV provider built in release mode:
   ```bash
   cd ..        # src_provider_rust/
   cargo build --release
   ls target/release/libakv_provider.*    # .so on Linux, .dll on Windows
   ```
3. Azure CLI logged in to a tenant that can access the MHSM:
   ```bash
   az login --tenant <YOUR_TENANT>
   ```
4. An RSA key in MHSM. Either provision one or reuse an existing key — the
   demo expects PKCS#1 v1.5 / PSS sign capability.

## Setup

```bash
cd src_provider_rust/grpc-example-tonic-mtls
cp .env.example .env
$EDITOR .env       # set HSM_NAME, HSM_KEY_NAME, AZURE_TENANT_ID, SERVER_CN
```

## Generate certs (signed by the HSM key)

```bash
./generate-certs.sh
# certs/ca.crt, certs/server.crt, certs/client.crt
```

## Run

Terminal 1:
```bash
./start-server.sh
# ...
# listening on 0.0.0.0:50443
```

Terminal 2:
```bash
./run-client.sh
# == tonic-mtls-client ==
# ...
# response: Hello World (mTLS via HSM)!
#   stream: Hello Streamer - mTLS message 1!
#   stream: Hello Streamer - mTLS message 2!
#   ...
```

## How keys flow

1. `start-server.sh` renders `openssl-provider.cnf` with the actual
   `PROVIDER_PATH` and exports it as `OPENSSL_CONF`.
2. The binary calls `tls::build_acceptor` → `hsm_key::load_pkey_from_store`
   → `OSSL_STORE_open_ex("managedhsm:<hsm>:<key>", ...)` →
   AKV provider returns an `EVP_PKEY` bound to the HSM key.
3. `SslAcceptorBuilder::set_private_key()` stores that EVP_PKEY in the
   SSL context. Every TLS handshake's `ServerKeyExchange`/`CertVerify`
   signature is a remote HSM call.
4. Same flow on the client side for `CertVerify` in the mTLS leg.

## Troubleshooting

| Symptom | Likely cause |
|---|---|
| `OSSL_STORE_open_ex(managedhsm:...) failed: no suitable loader` | `OPENSSL_CONF` not set or `module = ...libakv_provider.so` path wrong. Check rendered `openssl-provider.cnf`. |
| `HSM key does not match leaf cert` | The cert in `certs/server.crt` was generated against a different HSM key than the one in `.env`. Re-run `generate-certs.sh`. |
| `TLS handshake failed: ... alert handshake failure` | ALPN mismatch (server didn't advertise `h2`) or client cert not trusted. Check `tls::ALPN_H2` is set on both sides and that `certs/ca.crt` is the issuer of both leaves. |
| `azure: AADSTS70011 invalid scope` | `AZURE_CLI_ACCESS_TOKEN` was minted for the wrong resource. Re-run the `az account get-access-token` line in `start-server.sh` manually. |
| `tonic ... connect error: tcp connect error: Connection refused` | Server died during handshake. Check server stderr for `load_pkey_from_store` errors. |

## Limitations

* Linux-first. `start-server.sh` / `run-client.sh` are bash. On Windows the
  same Rust code works but you'll need PowerShell wrappers (open an issue
  if you need them).
* The HSM RSA key is used for **every** TLS handshake — there's no per-conn
  key cache. For high-RPS workloads, terminate TLS upstream and use the
  HSM only for session-resumption keys, or use shorter ticket lifetimes.
* No revocation checking (CRL/OCSP). Same as the sidecar example.
* `OPENSSL_CONF` is a process-wide env var. Running this binary in the
  same process as another OpenSSL consumer with a different provider
  config will behave unpredictably.

## See also

* `../grpc-example/` — same demo with NGINX sidecar (language-agnostic).
* `../README.md` — provider build instructions.
* `../../PQC_STRATEGY.md` — why we're staying on classical TLS / RSA today
  and how this scaffold evolves once MHSM ships native PQ.
