---
applyTo: "src_provider_rust/src/**"
---

# Rust provider source conventions

These instructions apply when editing files under `src_provider_rust/src/`.

## Architecture map

| File | Responsibility |
|---|---|
| `lib.rs` | `OSSL_provider_init` entry point, libctx wiring, dispatch tables |
| `provider.rs` | `ProviderContext`, `AkvKey` (the opaque key handle) |
| `store.rs` | URI parser (`managedhsm:<vault>:<key>`), object loader callback |
| `keymgmt.rs` | `EVP_KEYMGMT` ops — load/export RSA + EC public material |
| `signature.rs` | `EVP_SIGNATURE` ops — RSA-PSS (PS256), RSA-PKCS1 (RS256), ECDSA (ES256) |
| `cipher.rs` | `EVP_CIPHER` ops — RSA-OAEP decrypt, AES-KW/KWP wrap/unwrap |
| `dispatch.rs` | Static dispatch arrays handed to OpenSSL |
| `http_client.rs` | Azure HSM REST client (reqwest blocking + async) |
| `auth.rs` | `AZURE_CLI_ACCESS_TOKEN` env reading + bearer header |
| `ossl_param.rs` | Safe `OSSL_PARAM` reading/writing helpers |
| `openssl_ffi.rs` | Raw FFI declarations not in `openssl-sys` |

## Hard rules

- **Do not "fix" the OpenSSL 3.0.2 `OSSL_STORE` bug from provider code.**
  We tried (commit reverted). The fix is upstream in 3.0.7; runners now
  gate on it. Any patch that special-cases `EVP_KEYMGMT_fetch` callers
  must be reviewed against [openssl#18221](https://github.com/openssl/openssl/issues/18221).
- **Do not break the Windows vcpkg build.** `winbuild.bat` statically
  links a bundled OpenSSL. Any new C dependency must be in vcpkg.
- **URI parsing is strict**: only `managedhsm:<vault>:<key>` and the
  legacy `akv:<vault>:<key>`. Don't introduce new schemes without
  updating both `store.rs` and the README URI table.
- **Every Azure HTTP call must use `auth::access_token()`**, never read
  env vars directly — token refresh logic belongs there.
- **DUPCTX must clone, not share**, the key handle's `Arc`. OpenSSL
  signs concurrently across threads and a non-cloning dup will corrupt
  state.
- **Logging**: use the `log` macros (`debug!`, `trace!`) at module
  scope. Don't `println!` — `AKV_LOG_FILE` / `AKV_LOG_LEVEL` /
  `RUST_LOG` form the supported observability surface.
- **No panics across the FFI boundary.** Every exported
  `extern "C"` function must catch panics or return a sentinel
  (`std::ptr::null_mut()` / `0`).

## Tests

After changing anything here, run both:

```bash
cd src_provider_rust && ./runtest.sh         # Linux
cd src_provider_rust && runtest.bat          # Windows
```

If you touch signature/keymgmt, also exercise the tonic-mtls demo
(`/test-tonic-mtls`) to catch handshake-time regressions.
