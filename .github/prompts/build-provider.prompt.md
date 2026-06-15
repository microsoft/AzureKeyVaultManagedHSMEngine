---
mode: agent
description: Build the akv_provider Rust crate for the current platform and verify it loads in OpenSSL.
---

# Build the akv_provider OpenSSL Provider

Build the Azure Managed HSM OpenSSL provider for the current platform
(Windows or Linux) and verify it loads correctly.

## Step 1 — Sanity-check the environment

- Run `rustc --version`. If `cargo` is missing, install via rustup
  (https://rustup.rs/) and source `~/.cargo/env`.
- Run `openssl version`.
  - **On Linux** the version must be **>= 3.0.7**. Ubuntu 22.04 ships
    3.0.2 which has the
    [OSSL_STORE callback bug (openssl#18221)](https://github.com/openssl/openssl/issues/18221).
    If older, stop and ask the user to upgrade to Ubuntu 24.04+.
  - On Windows the bundled vcpkg OpenSSL (3.6+) handles itself; no check
    needed.

## Step 2 — Build

```bash
# Linux
cd src_provider_rust
cargo build --release -p akv_provider
ls target/release/libakv_provider.so
```

```powershell
# Windows
cd src_provider_rust
.\winbuild.bat
dir target\release\akv_provider.dll
```

The first Linux build takes ~2 minutes (downloads + compiles `reqwest`,
`tokio`, `azure_identity`). Subsequent builds are incremental.

## Step 3 — Verify load

```bash
# Linux
openssl list -providers \
  -provider-path target/release \
  -provider akv_provider \
  -provider default
```

If you see `unable to load provider akv_provider` on Linux, create the
symlink that the CLI flag expects (cargo emits `lib*.so`, OpenSSL looks
for `*.so`):

```bash
ln -sf libakv_provider.so target/release/akv_provider.so
```

The expected output lists both `default` and `akv_provider` providers
and prints `Azure Key Vault HSM provider for OpenSSL 3.x`.

## Step 4 — (Optional) Run the regression suite

```bash
# Linux
./runtest.sh
```

```cmd
:: Windows
runtest.bat
```

Both scripts use explicit `-provider akv_provider -provider default`
flags so they pass on all OpenSSL 3.x versions, including 3.0.2.

## Common failures

| Symptom | Cause | Fix |
|---|---|---|
| `dlfcn_load … akv_provider.so: cannot open shared object file` | Symlink missing on Linux | `ln -sf libakv_provider.so target/release/akv_provider.so` |
| `openssl-sys` build error mentioning headers | `libssl-dev` not installed | `sudo apt install libssl-dev pkg-config` |
| `protobuf-compiler not found` (only for examples) | Tonic example needs protoc | `sudo apt install protobuf-compiler` |
| Long build hang at "Updating crates.io index" | Cargo offline / proxy | Check `~/.cargo/config.toml`, verify network |
