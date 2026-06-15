---
mode: ask
description: Diagnose why the akv_provider fails to load or sign on Linux/Windows. Walks through the common root causes.
---

# Diagnose akv_provider Load & Sign Failures

Help the user figure out **why** the provider is failing. Do not assume —
walk through these checks in order and stop as soon as one matches.

## Decision tree

### 1. Error contains "object callback failed" / "callback failed"

This is almost always the **OpenSSL 3.0.2 OSSL_STORE bug** on Linux
([openssl#18221](https://github.com/openssl/openssl/issues/18221)),
fixed in 3.0.7.

```bash
openssl version            # If this prints "OpenSSL 3.0.2", that's the bug.
```

**Fix**: Upgrade host OpenSSL to >= 3.0.7. Practically that means
**Ubuntu 24.04+** (ships 3.0.13), or building OpenSSL from source.
Do **not** try to patch the provider — the bug is upstream, and we
verified by reverting attempted workarounds.

### 2. Error contains "cannot open shared object file: No such file"

`-provider akv_provider` looks for `akv_provider.so`, but cargo emits
`libakv_provider.so`.

```bash
ls src_provider_rust/target/release/*akv_provider.so
ln -sf libakv_provider.so src_provider_rust/target/release/akv_provider.so
```

All example runners do this automatically; if you're invoking openssl
manually, do it once.

### 3. Error contains "unable to load provider" / "could not load the shared library"

Provider directory mismatch. The CLI flag `-provider akv_provider`
searches `MODULESDIR` unless you also pass `-provider-path`.

```bash
openssl version -a | grep MODULESDIR     # Linux
openssl version -a | findstr MODULESDIR  # Windows

# Either deploy the .so/.dll there...
sudo cp target/release/libakv_provider.so /usr/lib/x86_64-linux-gnu/ossl-modules/akv_provider.so

# ...or pass -provider-path explicitly:
openssl list -providers \
  -provider-path src_provider_rust/target/release \
  -provider akv_provider -provider default
```

### 4. Error contains "401" / "Unauthorized" / "AADSTS"

The `AZURE_CLI_ACCESS_TOKEN` env var is missing or expired (1h lifetime).

```bash
# Re-mint
export AZURE_CLI_ACCESS_TOKEN=$(az account get-access-token \
  --resource https://managedhsm.azure.net --query accessToken -o tsv)
```

If `az` isn't logged in: `az login --tenant 72f988bf-86f1-41af-91ab-2d7cd011db47`.
If the token is present but you still get 401, the signed-in identity
lacks the **Managed HSM Crypto User** role on the key.

### 5. Error contains "$'\\r': command not found" or scripts mysteriously die on line 1

A shell script was saved with CRLF (typically by editing on Windows then
copying to WSL).

```bash
dos2unix src_provider_rust/grpc-example-tonic-mtls/*.sh
# Or check .gitattributes — every example dir should pin *.sh to LF.
```

### 6. Cert validation fails (`bad certificate`, `signature mismatch`)

Server is using a stale cert from a previous run with a different key.

```bash
rm -rf certs
ENV_FILE=.env.ec ./generate-certs.sh   # Use the same ENV_FILE you'll start the server with
```

### 7. "could not find protoc" during build

```bash
sudo apt install protobuf-compiler        # Linux
# Windows: vcpkg install protobuf, or use winget install Google.Protobuf
```

## Quick verification sequence (paste into a fresh terminal)

```bash
openssl version
ls src_provider_rust/target/release/{libakv_provider.so,akv_provider.so} 2>/dev/null
echo "Token set: ${AZURE_CLI_ACCESS_TOKEN:+yes}${AZURE_CLI_ACCESS_TOKEN:-no}"
openssl list -providers \
  -provider-path src_provider_rust/target/release \
  -provider akv_provider -provider default
```

If all four lines succeed, the provider is healthy and the issue lies in
the **calling** application (nginx, tonic, your code), not the provider.
