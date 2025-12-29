# Deprecated - Legacy C Engine

This folder contains the archived legacy C implementation of the Azure Key Vault / Managed HSM OpenSSL Engine.

## Contents

`legacy-c-engine.zip` contains:
- `src/` - Original C OpenSSL Engine implementation
- `src_provider/` - Original C OpenSSL 3.x Provider implementation
- `samples/` - Sample configurations for nginx, gRPC, and OpenSSL
- `linuxvm-build-agent/` - Azure VM build agent setup scripts
- `azure-pipelines.yml` - Original CI/CD pipeline
- `README.md` - Original documentation
- `design.png` - Original architecture diagram

## Current Implementation

The active implementation is now in **Rust** and located in `src_provider_rust/`.

The Rust provider offers:
- Full OpenSSL 3.x Provider API support
- RSA and EC key operations via Azure Managed HSM
- OSSL_STORE integration for seamless key loading
- Examples for nginx and gRPC mTLS

## Why Deprecated?

The C implementation has been replaced with a Rust implementation for:
- Better memory safety
- Improved maintainability
- Modern async HTTP client
- Better error handling
