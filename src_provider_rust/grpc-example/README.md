# gRPC mTLS Example with Azure Managed HSM

This example demonstrates **keyless mTLS** for gRPC using the **Double-Ended Sidecar Proxy** pattern with NGINX and Azure Managed HSM.

## Architecture

\`\`\`
┌──────────────────────────────────────────────────────────────────┐
│                          HOST                                     │
│                                                                   │
│  ┌─────────────┐    UDS     ┌────────────────────────────────┐   │
│  │ gRPC Client │ ────────►  │ NGINX Client Sidecar           │   │
│  │ (plaintext) │            │   - Initiates mTLS             │   │
│  └─────────────┘            │   - Client cert via HSM        │   │
│                             └────────────┬───────────────────┘   │
│                                          │                        │
│                                          │ mTLS (port 50051)      │
│                                          │                        │
│                             ┌────────────▼───────────────────┐   │
│  ┌─────────────┐    UDS     │ NGINX Server Sidecar           │   │
│  │ gRPC Server │ ◄────────  │   - Terminates mTLS            │   │
│  │ (plaintext) │            │   - Server cert via HSM        │   │
│  └─────────────┘            │   - Verifies client cert       │   │
│                             └────────────────────────────────┘   │
│                                          │                        │
└──────────────────────────────────────────┼────────────────────────┘
                                           │
                                           ▼
                              ┌────────────────────────┐
                              │  Azure Managed HSM     │
                              │  (private key ops)     │
                              └────────────────────────┘
\`\`\`

**Key Feature:** The same RSA key in Azure Managed HSM is used for both client and server certificates (different certificate identities).

## Prerequisites

1. **Azure Managed HSM** with an RSA key
2. **Azure CLI** authenticated (\`az login\`)
3. **NGINX** with stream module and SSL support
4. **Rust** toolchain
5. **Provider built**: \`../target/release/libakv_provider.so\`

## Quick Start

\`\`\`bash
# 1. Copy and configure environment
cp .env.example .env
# Edit .env with your HSM settings

# 2. Generate certificates (uses HSM for signing)
./generate-certs.sh

# 3. Start the demo (NGINX sidecars + gRPC server)
./start-demo.sh

# 4. Run the client (in another terminal)
./run-client.sh

# 5. Stop everything
./stop-demo.sh
\`\`\`

## Files

\`\`\`
grpc-example/
├── src/
│   ├── server.rs          # gRPC server (supports TCP or UDS)
│   └── client.rs          # gRPC client (supports TCP or UDS)
├── proto/
│   └── greeter.proto      # gRPC service definition
├── nginx/
│   ├── nginx-server.conf  # Server sidecar template
│   └── nginx-client.conf  # Client sidecar template
├── certs/                 # Generated certificates
│   ├── ca.crt             # CA certificate
│   ├── server.crt         # Server certificate
│   └── client.crt         # Client certificate
├── .env.example           # Environment template
├── generate-certs.sh      # Certificate generation script
├── start-demo.sh          # Start the demo
├── stop-demo.sh           # Stop the demo
├── run-client.sh          # Run client via sidecar
└── grpc-mtls-sidecar.md   # Design document
\`\`\`

## Running Modes

### Mode 1: Direct TCP (no TLS, for testing)

\`\`\`bash
# Terminal 1: Start server on TCP
cargo run --release --bin grpc-server
# Listens on [::1]:50051

# Terminal 2: Run client
cargo run --release --bin grpc-client
\`\`\`

### Mode 2: UDS + NGINX Sidecar (mTLS)

\`\`\`bash
# Start everything
./start-demo.sh

# Run client through sidecar
./run-client.sh
\`\`\`

## Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| \`GRPC_UDS_PATH\` | Unix socket path | (uses TCP if not set) |
| \`GRPC_ADDR\` | TCP address (if no UDS) | \`[::1]:50051\` |
| \`HSM_NAME\` | HSM vault name | \`ManagedHSMOpenSSLEngine\` |
| \`HSM_KEY_NAME\` | HSM key name | \`myrsakey\` |

## How It Works

1. **gRPC Server** listens on a Unix Domain Socket (\`run/grpc-server.sock\`)
2. **NGINX Server Sidecar** terminates mTLS on port 50051 and forwards plaintext to the server UDS
3. **NGINX Client Sidecar** listens on a UDS (\`run/grpc-client.sock\`) and initiates mTLS to port 50051
4. **gRPC Client** connects to the client sidecar UDS (plaintext)

**All TLS private key operations** are performed by the Azure Managed HSM via the OpenSSL provider.

## Troubleshooting

### Check logs

\`\`\`bash
# NGINX logs
tail -f logs/nginx-server-error.log
tail -f logs/nginx-client-error.log

# Provider logs
tail -f logs/akv-provider.log
\`\`\`

### Common issues

1. **"Provider not found"**: Build the provider first: \`cd .. && cargo build --release\`
2. **"Access token expired"**: Re-run \`az login\` and restart demo
3. **"Socket already in use"**: Run \`./stop-demo.sh\` to clean up

## Design Document

See [grpc-mtls-sidecar.md](grpc-mtls-sidecar.md) for the full design rationale.
