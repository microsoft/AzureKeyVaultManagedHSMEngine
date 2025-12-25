# gRPC Example for Azure Managed HSM Provider

This example demonstrates a basic gRPC client/server setup using Tonic.

## Current Status

- **Phase 1 (Current)**: Plain gRPC (no TLS)
- **Phase 2 (Next)**: Add TLS with Azure Managed HSM provider

## Prerequisites

```bash
# Install protobuf compiler
sudo apt-get install protobuf-compiler
```

## Project Structure

```
grpc-example/
├── Cargo.toml          # Dependencies
├── build.rs            # Proto compilation script
├── proto/
│   └── greeter.proto   # Service definition
├── src/
│   ├── server.rs       # gRPC server
│   └── client.rs       # gRPC client
└── README.md
```

## Building

```bash
cd grpc-example
cargo build --release
```

## Running

### Start the Server

```bash
cargo run --bin grpc-server
```

Output:
```
GreeterServer listening on [::1]:50051
```

### Run the Client (in another terminal)

```bash
cargo run --bin grpc-client
```

Output:
```
=== Unary Request ===
RESPONSE: "Hello World!"

=== Streaming Request ===
STREAM RESPONSE: "Hello Streamer - message 1!"
STREAM RESPONSE: "Hello Streamer - message 2!"
STREAM RESPONSE: "Hello Streamer - message 3!"
STREAM RESPONSE: "Hello Streamer - message 4!"
STREAM RESPONSE: "Hello Streamer - message 5!"

Done!
```

## Service Definition

The `greeter.proto` defines two RPC methods:

1. **SayHello** - Unary RPC: Send a name, get a greeting back
2. **SayHelloStream** - Server streaming RPC: Send a name, get multiple greetings back

## Next Steps (Phase 2: TLS with Azure Managed HSM)

To enable TLS with keys stored in Azure Managed HSM:

1. Generate a certificate using the HSM key
2. Configure the server with TLS using the HSM-backed private key
3. Configure the client to verify the server certificate

```rust
// Server with TLS (coming next)
Server::builder()
    .tls_config(ServerTlsConfig::new()
        .identity(Identity::from_pem(cert, key)))?
    .add_service(GreeterServer::new(greeter))
    .serve(addr)
    .await?;
```
