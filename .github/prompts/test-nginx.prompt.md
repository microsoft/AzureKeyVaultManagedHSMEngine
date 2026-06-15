---
mode: agent
description: Test nginx keyless TLS where the private key never leaves Azure Managed HSM.
---

# Test nginx Keyless TLS with Azure Managed HSM

Run the nginx mainline (>= 1.27) keyless TLS demo where every TLS handshake
signature is delegated to Azure Managed HSM via the `akv_provider` OpenSSL
provider.

> The canonical, full-detail version of this prompt lives next to the
> example itself at
> `src_provider_rust/nginx-example/.github/prompts/test-nginx-keyless-tls.prompt.md`.
> This file mirrors it from the repo root so it is discoverable as
> `/test-nginx` in Copilot Chat and the Copilot CLI.

## Prerequisites

- [ ] `akv_provider` built (see `/build-provider`). On Linux, OpenSSL **>= 3.0.7**.
- [ ] nginx **>= 1.27** (`nginx -v`). Earlier versions lack provider support.
- [ ] HSM key `myrsakey` (RSA-3072) in HSM `ManagedHSMOpenSSLEngine`, or
      adapt `HSM_NAME` / `HSM_KEY_NAME`.
- [ ] `az login --tenant 72f988bf-86f1-41af-91ab-2d7cd011db47`.

## Quick Run

```bash
cd src_provider_rust/nginx-example

# 1. Token for HSM access
export AZURE_CLI_ACCESS_TOKEN=$(az account get-access-token \
  --resource https://managedhsm.azure.net --query accessToken -o tsv)

# 2. Generate the public cert (private key stays in HSM)
./generate-cert.sh

# 3. Render nginx.conf with absolute paths
./render-config.sh

# 4. Run nginx in the foreground
sudo -E nginx -p "$PWD" -c nginx.conf -g 'daemon off;'

# 5. In another terminal, verify
curl --cacert certs/server-cert.pem https://localhost:8443/
```

The handshake will trigger an HSM `sign` REST call visible in
`logs/akv_provider.log` if `AKV_LOG_LEVEL=3` is set.

## Troubleshooting

- **`RSA object callback failed (returned 0)`** → OpenSSL on this host is
  `< 3.0.7`. Use Ubuntu 24.04+. See `/diagnose-provider-load`.
- **`unable to load provider akv_provider`** → Missing symlink on Linux:
  `ln -sf libakv_provider.so target/release/akv_provider.so`.
- **`nginx: [emerg] SSL_CTX_use_PrivateKey_file(... ) failed`** → Cert
  was regenerated but nginx config still points at a stale path; re-run
  `render-config.sh`.

## Key Files

- `generate-cert.sh` — produces `certs/server-cert.pem` whose pubkey comes
  from the HSM; matching private key never leaves Azure.
- `render-config.sh` — expands `nginx.conf.in` with absolute paths.
- `nginx.conf.in` — template loading `akv_provider` and `default`.
- `openssl.cnf.in` — provider section template.

See the linked example-local prompt for full step-by-step explanations,
verification scripts, and screenshots of expected output.
