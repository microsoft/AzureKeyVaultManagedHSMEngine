# Reusable Copilot Prompts

These `.prompt.md` files are reusable, agent-mode prompts for this repo.
They are picked up automatically by **VS Code Copilot Chat** (as slash
commands like `/build-provider`) and by the **GitHub Copilot CLI**.

| Prompt | Purpose |
|---|---|
| [`build-provider`](./build-provider.prompt.md) | Build `libakv_provider.so` / `akv_provider.dll` and verify it loads. |
| [`test-tonic-mtls`](./test-tonic-mtls.prompt.md) | Run the Tonic mTLS gRPC demo end-to-end, RSA or EC, on WSL/Linux/Windows. |
| [`test-nginx`](./test-nginx.prompt.md) | Run the nginx >= 1.27 keyless TLS demo. |
| [`diagnose-provider-load`](./diagnose-provider-load.prompt.md) | Decision tree for "why is my provider failing?" — covers the OpenSSL 3.0.2 bug, missing symlinks, auth, etc. |

## See also

- **Repo-wide instructions**: [`../copilot-instructions.md`](../copilot-instructions.md)
- **Scoped instructions** (auto-applied via `applyTo:` glob):
  - [`../instructions/shell-scripts.instructions.md`](../instructions/shell-scripts.instructions.md)
  - [`../instructions/rust-provider.instructions.md`](../instructions/rust-provider.instructions.md)
- **Example-local prompts**:
  - [`../../src_provider_rust/nginx-example/.github/prompts/test-nginx-keyless-tls.prompt.md`](../../src_provider_rust/nginx-example/.github/prompts/test-nginx-keyless-tls.prompt.md)
    — full-detail nginx walkthrough (the root `/test-nginx` is a thin pointer).

## Adding a new prompt

1. Filename: `<verb-noun>.prompt.md` under `.github/prompts/`.
2. Start with YAML frontmatter:
   ```yaml
   ---
   mode: agent           # or `ask` for diagnostic prompts
   description: One sentence shown in the slash-command picker.
   ---
   ```
3. Follow the structure: **H1 title → Prerequisites → Steps → Troubleshooting → Key Files**.
4. Add a row to the table above.
