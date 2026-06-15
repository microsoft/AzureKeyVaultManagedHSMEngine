---
applyTo: "**/*.sh"
---

# Shell script conventions for this repo

These instructions apply to every Bash script under the repository.

- **LF line endings only**. The `.gitattributes` files in
  `nginx-example/`, `grpc-example/`, and `grpc-example-tonic-mtls/`
  enforce LF for `*.sh`, `*.cnf`, and `*.env*`. If you add a new
  example directory, add a `.gitattributes` to it before adding scripts.
- **Source `check-openssl.sh`** at the top of any script that runs the
  provider on Linux. It aborts (exit 1) when the host OpenSSL is older
  than 3.0.7, sparing the user a confusing `object callback failed`
  later. Pattern:
  ```bash
  SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
  source "$SCRIPT_DIR/check-openssl.sh"
  ```
- **Use `$SCRIPT_DIR` for all relative paths**, never `../something`
  with cwd assumptions. Builds go to `$SCRIPT_DIR/target/release/`
  (not `$SCRIPT_DIR/../target/release/` — that bug existed and was fixed).
- **Honor `ENV_FILE`** in any example that supports multiple keys
  (currently `grpc-example-tonic-mtls`). Default to `.env.rsa` when
  unset. Load with:
  ```bash
  ENV_FILE="${ENV_FILE:-.env.rsa}"
  set -a; . "$SCRIPT_DIR/$ENV_FILE"; set +a
  ```
- **Honor `SKIP_BUILD=1`** so the user can iterate without recompiling.
- **Create the Linux symlink** before invoking `openssl … -provider akv_provider`:
  ```bash
  ln -sf libakv_provider.so "$PROVIDER_PATH/akv_provider.so"
  ```
- **Quote `.env` values containing spaces** in the `.example` templates,
  e.g. `CERT_OU="Azure HSM Demo"`. Unquoted spaces break `set -a; .file`.
- **Never `set -e` blindly** in token-bootstrap blocks — `az` returning
  a stale-but-valid token still has exit 0; check for empty string
  explicitly.
