# gRPC mTLS with OpenSSL 3.x Providers - Double-Ended Sidecar Design

## Overview

As of late 2025, gRPC does **not** natively support the OpenSSL 3.x Provider architecture (it still relies on the deprecated Engine API). This design uses a **Double-Ended Sidecar Proxy** pattern with NGINX to bridge that gap, allowing gRPC applications to use TPMs, HSMs, or FIPS providers via NGINX.

## The Problem

| Framework | TLS Backend | OpenSSL 3.x Provider Support |
|-----------|-------------|------------------------------|
| **tonic** (Rust) | rustls | ❌ No OpenSSL |
| **grpcio** (Rust) | gRPC C core | ❌ `engine:` only |
| **gRPC C++** | OpenSSL | ❌ `engine:` only |
| **gRPC Go** | Go crypto | ❌ No OpenSSL |
| **gRPC Python** | gRPC C core | ❌ `engine:` only |

gRPC only supports `engine:<id>:<key>` (deprecated) or PEM files. **No `store:` URI support** for OpenSSL 3.x providers.

---

## Architecture: Double-Ended Sidecar Proxy

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                                 CLIENT HOST                                      │
│                                                                                  │
│   ┌──────────────────┐              ┌─────────────────────────────────────────┐ │
│   │                  │              │         NGINX Client Sidecar            │ │
│   │  gRPC Client App │              │                                         │ │
│   │                  │    (1)       │  ┌─────────────────────────────────┐    │ │
│   │  (any language:  │─────────────►│  │     OpenSSL 3.x Provider        │    │ │
│   │   Rust, Go,      │   Plaintext  │  │     (TPM / HSM / FIPS)          │    │ │
│   │   Python, etc.)  │   HTTP/2     │  │                                 │    │ │
│   │                  │   over UDS   │  │  - Performs client-side signing │    │ │
│   └──────────────────┘              │  │  - Private key never exposed    │    │ │
│                                     │  └─────────────────────────────────┘    │ │
│                                     │                    │                     │ │
│                                     └────────────────────┼─────────────────────┘ │
└──────────────────────────────────────────────────────────┼───────────────────────┘
                                                           │
                                                           │ (2) mTLS Encrypted
                                                           │     Tunnel (Network)
                                                           │
┌──────────────────────────────────────────────────────────┼───────────────────────┐
│                                 SERVER HOST              │                        │
│                                     ┌────────────────────┼─────────────────────┐ │
│                                     │         NGINX Server Sidecar            │ │
│                                     │                    │                     │ │
│                                     │                    ▼                     │ │
│   ┌──────────────────┐              │  ┌─────────────────────────────────┐    │ │
│   │                  │              │  │     Client Cert Validation      │    │ │
│   │  gRPC Server App │    (3)       │  │                                 │    │ │
│   │                  │◄─────────────│  │  - Verifies client certificate  │    │ │
│   │  (any language:  │   Plaintext  │  │  - TLS termination              │    │ │
│   │   Rust, Go,      │   HTTP/2     │  │  - Optional: HSM for server key │    │ │
│   │   Python, etc.)  │   over UDS   │  │                                 │    │ │
│   │                  │              │  └─────────────────────────────────┘    │ │
│   └──────────────────┘              │                                         │ │
│                                     └─────────────────────────────────────────┘ │
└──────────────────────────────────────────────────────────────────────────────────┘
```

---

## Data Flow

| Step | From | To | Transport | Security |
|------|------|-----|-----------|----------|
| **(1)** | gRPC Client App | NGINX Client Sidecar | Unix Domain Socket | Plaintext (localhost) |
| **(2)** | NGINX Client Sidecar | NGINX Server Sidecar | TCP/Network | **mTLS Encrypted** |
| **(3)** | NGINX Server Sidecar | gRPC Server App | Unix Domain Socket | Plaintext (localhost) |

**Key Points:**
- gRPC apps speak **plaintext HTTP/2** to local sidecar via UDS (zero network exposure)
- NGINX handles **all TLS/mTLS** using OpenSSL 3.x providers
- Private keys **never leave** the TPM/HSM

---

## NGINX Configuration

### Client Sidecar (`nginx-client.conf`)

```nginx
# Client sidecar: accepts plaintext gRPC, initiates mTLS to server
stream {
    upstream server_sidecar {
        server server-host:50051;  # Remote server sidecar
    }

    server {
        listen unix:/var/run/grpc-client.sock;  # App connects here
        
        proxy_pass server_sidecar;
        proxy_ssl on;
        
        # Client certificate (public)
        proxy_ssl_certificate /etc/nginx/certs/client.crt;
        
        # Client private key via OpenSSL 3.x provider (keyless!)
        proxy_ssl_certificate_key "store:akv:myvault:client-key";
        
        # Verify server certificate
        proxy_ssl_verify on;
        proxy_ssl_trusted_certificate /etc/nginx/certs/ca.crt;
        proxy_ssl_name server-host;
    }
}
```

### Server Sidecar (`nginx-server.conf`)

```nginx
# Server sidecar: terminates mTLS, forwards plaintext gRPC to app
stream {
    upstream grpc_app {
        server unix:/var/run/grpc-server.sock;  # App listens here
    }

    server {
        listen 50051 ssl;  # External mTLS endpoint
        
        # Server certificate (public)
        ssl_certificate /etc/nginx/certs/server.crt;
        
        # Server private key via OpenSSL 3.x provider (keyless!)
        ssl_certificate_key "store:akv:myvault:server-key";
        
        # mTLS: require and verify client certificate
        ssl_verify_client on;
        ssl_client_certificate /etc/nginx/certs/ca.crt;
        
        # TLS settings
        ssl_protocols TLSv1.3;
        ssl_prefer_server_ciphers off;
        
        proxy_pass grpc_app;
    }
}
```

---

## OpenSSL Provider Configuration

**`/etc/ssl/openssl.cnf`:**

```ini
openssl_conf = openssl_init

[openssl_init]
providers = provider_sect

[provider_sect]
default = default_sect
akv = akv_sect

[default_sect]
activate = 1

[akv_sect]
module = /usr/lib/x86_64-linux-gnu/ossl-modules/akv_provider.so
activate = 1
```

---

## gRPC Application Code

### Client (connects to local UDS)

```rust
// Rust (tonic) - connects to local NGINX sidecar
let channel = Endpoint::from_static("http://localhost")
    .connect_with_connector(service_fn(|_| {
        UnixStream::connect("/var/run/grpc-client.sock")
    }))
    .await?;

let mut client = GreeterClient::new(channel);
```

```python
# Python (grpcio) - connects to local NGINX sidecar
channel = grpc.insecure_channel('unix:///var/run/grpc-client.sock')
stub = greeter_pb2_grpc.GreeterStub(channel)
```

```go
// Go - connects to local NGINX sidecar
conn, _ := grpc.Dial("unix:///var/run/grpc-client.sock", grpc.WithInsecure())
client := pb.NewGreeterClient(conn)
```

### Server (listens on local UDS)

```rust
// Rust (tonic) - listens on local UDS for NGINX sidecar
let uds = UnixListener::bind("/var/run/grpc-server.sock")?;
let incoming = UnixListenerStream::new(uds);

Server::builder()
    .add_service(GreeterServer::new(MyGreeter::default()))
    .serve_with_incoming(incoming)
    .await?;
```

```python
# Python (grpcio) - listens on local UDS
server = grpc.server(futures.ThreadPoolExecutor())
greeter_pb2_grpc.add_GreeterServicer_to_server(Greeter(), server)
server.add_insecure_port('unix:///var/run/grpc-server.sock')
```

---

## Deployment: Docker Compose

```yaml
version: '3.8'

services:
  # ─────────────── CLIENT SIDE ───────────────
  grpc-client:
    build: ./client
    volumes:
      - client-sock:/var/run
    depends_on:
      - nginx-client

  nginx-client:
    image: nginx:latest
    volumes:
      - ./nginx-client.conf:/etc/nginx/nginx.conf:ro
      - ./certs:/etc/nginx/certs:ro
      - ./openssl.cnf:/etc/ssl/openssl.cnf:ro
      - /usr/lib/x86_64-linux-gnu/ossl-modules:/usr/lib/x86_64-linux-gnu/ossl-modules:ro
      - client-sock:/var/run
    environment:
      - AZURE_CLIENT_ID=${AZURE_CLIENT_ID}
      - AZURE_TENANT_ID=${AZURE_TENANT_ID}

  # ─────────────── SERVER SIDE ───────────────
  nginx-server:
    image: nginx:latest
    ports:
      - "50051:50051"  # External mTLS port
    volumes:
      - ./nginx-server.conf:/etc/nginx/nginx.conf:ro
      - ./certs:/etc/nginx/certs:ro
      - ./openssl.cnf:/etc/ssl/openssl.cnf:ro
      - /usr/lib/x86_64-linux-gnu/ossl-modules:/usr/lib/x86_64-linux-gnu/ossl-modules:ro
      - server-sock:/var/run
    environment:
      - AZURE_CLIENT_ID=${AZURE_CLIENT_ID}
      - AZURE_TENANT_ID=${AZURE_TENANT_ID}

  grpc-server:
    build: ./server
    volumes:
      - server-sock:/var/run
    depends_on:
      - nginx-server

volumes:
  client-sock:
  server-sock:
```

---

## Security Model

```
┌─────────────────────────────────────────────────────────────────┐
│                    TRUST BOUNDARY: Host/Container               │
│                                                                 │
│  ┌─────────────┐    UDS     ┌─────────────┐                    │
│  │ gRPC App    │◄──────────►│ NGINX       │                    │
│  │ (untrusted  │  (local)   │ Sidecar     │                    │
│  │  plaintext) │            │ (TLS)       │                    │
│  └─────────────┘            └──────┬──────┘                    │
│                                    │                            │
└────────────────────────────────────┼────────────────────────────┘
                                     │ Provider API
                                     ▼
                    ┌────────────────────────────────┐
                    │   TPM / HSM / Cloud KMS        │
                    │   (FIPS 140-2/3 boundary)      │
                    │                                │
                    │   - Private key storage        │
                    │   - Signing operations         │
                    │   - Key never exported         │
                    └────────────────────────────────┘
```

| Threat | Mitigation |
|--------|------------|
| App compromise | App never sees private key |
| Memory dump | Key only in HSM, not in process memory |
| Disk forensics | No key file on disk |
| Network sniff | mTLS encryption on wire |
| MITM attack | Mutual certificate verification |

---

## Performance

| Metric | Impact | Mitigation |
|--------|--------|------------|
| TLS handshake | +10-50ms (HSM call) | Connection reuse, session tickets |
| UDS overhead | ~0.1ms | Negligible |
| Data transfer | None | Symmetric crypto after handshake |

```nginx
# Session resumption (add to server sidecar)
ssl_session_cache shared:SSL:50m;
ssl_session_timeout 1d;
ssl_session_tickets on;
```

---

## Implementation Phases

| Phase | Description | Status |
|-------|-------------|--------|
| **1** | Basic gRPC client/server (plaintext) | ✅ Complete |
| **2** | Add UDS support to gRPC apps | ⬜ TODO |
| **3** | NGINX server sidecar (TLS termination) | ⬜ TODO |
| **4** | NGINX client sidecar (TLS origination) | ⬜ TODO |
| **5** | HSM integration via provider | ⬜ TODO |
| **6** | Docker Compose deployment | ⬜ TODO |

---

## References

- [NGINX Stream SSL Module](https://nginx.org/en/docs/stream/ngx_stream_ssl_module.html)
- [NGINX Stream Proxy Module](https://nginx.org/en/docs/stream/ngx_stream_proxy_module.html)
- [OpenSSL 3.x Provider Guide](https://www.openssl.org/docs/man3.0/man7/provider.html)
- [gRPC Unix Domain Sockets](https://grpc.io/docs/guides/custom-name-resolution/)
- [Azure Managed HSM](https://docs.microsoft.com/en-us/azure/key-vault/managed-hsm/)
