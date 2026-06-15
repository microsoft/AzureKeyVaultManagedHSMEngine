---
mode: agent
description: Run the tonic mTLS gRPC end-to-end demo using an Azure Managed HSM key (RSA or EC) for the server identity.
---

# Test the Tonic mTLS gRPC Demo

End-to-end demo of a Rust `tonic` gRPC server whose **TLS private key never
leaves the HSM** — every server-side TLS handshake signature is generated
by Azure Managed HSM via the `akv_provider` OpenSSL provider.

Lives under `src_provider_rust/grpc-example-tonic-mtls/`. Supports both
RSA-3072 and EC P-256 server keys via swappable `.env` files.

## Prerequisites

- [ ] `akv_provider` built (see `/build-provider`). On Linux, OpenSSL **>= 3.0.7** required.
- [ ] An HSM key exists. Default test keys in tenant
      `72f988bf-86f1-41af-91ab-2d7cd011db47`, HSM
      `ManagedHSMOpenSSLEngine`:
  - `myrsakey` (RSA-3072) — used by `.env.rsa`
  - `ecckey` (EC P-256) — used by `.env.ec`
- [ ] Azure CLI logged in with HSM crypto-user role on the key:
      `az login --tenant 72f988bf-86f1-41af-91ab-2d7cd011db47`
- [ ] `protoc` installed (`sudo apt install protobuf-compiler` or via vcpkg on Windows)

## Step 1 — Pick an `.env` file

```bash
cd src_provider_rust/grpc-example-tonic-mtls
cp .env.rsa.example .env.rsa   # or
cp .env.ec.example  .env.ec
# Edit if your HSM/key names differ
```

The selector is `ENV_FILE` (bash) or `-EnvFile` (PowerShell). The
scripts default to `.env.rsa` when neither is set.

## Step 2 — Bootstrap the HSM access token

```bash
# Linux / WSL
export AZURE_CLI_ACCESS_TOKEN=$(az account get-access-token \
  --resource https://managedhsm.azure.net \
  --query accessToken -o tsv)
```

```powershell
# Windows
$env:AZURE_CLI_ACCESS_TOKEN = (az account get-access-token `
  --resource https://managedhsm.azure.net `
  --query accessToken -o tsv)

# WSL bridge (if running scripts in WSL after az login on Windows)
$env:WSLENV = "AZURE_CLI_ACCESS_TOKEN/u"
```

## Step 3 — Generate certificates (CA + client cert + HSM-keyed server cert)

```bash
ENV_FILE=.env.ec ./generate-certs.sh        # or .env.rsa
```

Output goes to `certs/`. The server certificate's public key is fetched
from the HSM; the matching private key never leaves Azure.

## Step 4 — Start the server

```bash
ENV_FILE=.env.ec ./start-server.sh
```

You should see `gRPC server listening on https://127.0.0.1:50051` and
each TLS handshake will log an HSM `sign` REST call.

## Step 5 — Run the client (separate terminal)

```bash
cd src_provider_rust/grpc-example-tonic-mtls
ENV_FILE=.env.ec ./run-client.sh
```

Successful run prints `Greeter response: Hello, tonic-mtls-client!`.

## Troubleshooting

- **`RSA/EC object callback failed (returned 0)`** → OpenSSL on this host
  is `< 3.0.7`. See `/diagnose-provider-load`. Move to Ubuntu 24.04+.
- **`Tonic status: Status { code: Unauthenticated, ... bad certificate }`**
  → Server is using a stale or mismatched cert. Re-run
  `generate-certs.sh` with the **same** `ENV_FILE` you'll start the
  server with.
- **`401 from https://...managedhsm.azure.net/...`** → `AZURE_CLI_ACCESS_TOKEN`
  expired (1h lifetime). Re-export per Step 2.
- **`scripts not found / $'\r': command not found`** → Shell script saved
  with CRLF. Run `dos2unix *.sh` or check `.gitattributes`.

## Key Files

- `start-server.sh` / `start-server.ps1` — load `.env`, source
  `check-openssl.sh`, ensure symlink, launch `tonic-mtls-server`.
- `run-client.sh` / `run-client.ps1` — same env loading, run client.
- `generate-certs.sh` — produces CA, client cert+key, and HSM-keyed server
  cert (`openssl req` with `-provider akv_provider`).
- `check-openssl.sh` — shared OpenSSL version gate (aborts if < 3.0.7).
- `.env.rsa.example` / `.env.ec.example` — templates; the only difference
  is `HSM_KEY_NAME` and the OpenSSL key-gen algorithm.
- `src/bin/server.rs` — Tonic server wiring; loads the cert from disk and
  the HSM key URI from `HSM_KEY_NAME`.
- `proto/helloworld.proto` — service definition.
