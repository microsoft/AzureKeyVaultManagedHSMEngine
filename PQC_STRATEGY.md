# PQC Strategy for the MHSM OpenSSL Provider

**Status:** Draft proposal
**Drafted:** 2026-06-14 (via Copilot CLI session)
**Target repo:** `microsoft/AzureKeyVaultManagedHSMEngine`
**Scope:** Add post-quantum signature and KEM support to the Rust OpenSSL
provider (`src_provider_rust/`) by tracking native Managed HSM PQC support
and preparing the provider in advance, rather than shipping a software
bridge.

---

## 1. Position

> **We will not build a software PQ bridge for MHSM.** We will wait for
> native MHSM PQ key support and pre-stage the OpenSSL provider so the
> integration is a small, well-bounded change at that point.

Rationale summary:

- A `liboqs`-based bridge port from `microsoft/azure-cloudhsm-pqc-bridge`
  is technically feasible but earns most of its security claims on Cloud
  HSM specifically (PKCS#11 + STC channel binding). MHSM's REST + classical
  TLS substrate weakens those claims to a point where the cost/value is
  unfavourable.
- MHSM PQ key support is on the public Microsoft roadmap, with preview
  tracking through 2026 and GA expected in the 2026–2027 window. The
  bridge's useful lifetime would be short and its FIPS posture would be
  non-validated (`liboqs`) for that entire window.
- Native MHSM PQ keys eliminate the wire-exposure concern entirely (PQ
  private key generated inside the HSM, never crosses the network in
  plaintext), which is the architectural property we actually want.

## 2. Roadmap context (as of mid-2026)

| Item | Status | Source |
|---|---|---|
| NIST FIPS 203 (ML-KEM), 204 (ML-DSA), 205 (SLH-DSA) | Final, Aug 2024 | NIST |
| SymCrypt ML-KEM / ML-DSA | Merged late 2024 | Public SymCrypt repo |
| OpenSSL 3.5 native ML-KEM / ML-DSA | Shipping | OpenSSL upstream |
| MHSM `kty=ML-DSA` / `kty=ML-KEM` REST API | Not present | `learn.microsoft.com/.../about-keys` |
| MHSM PQ public preview | Targeted 2026, no announcement yet | Microsoft public communications |
| MHSM PQ GA | Not committed | — |
| Azure data-plane hybrid TLS (`X25519MLKEM768`) | Rolling out 2024–2026, coverage non-uniform | Azure infrastructure rollouts |

**The single highest-leverage open question is the MHSM PQ preview date.**
Until that lands, this provider has no PQ backend to talk to.

## 3. Strategy

Three parallel workstreams, ordered by what we can act on today:

1. **Pre-stage the provider** so that when MHSM exposes PQ keys, integration
   is a backend swap, not a redesign.
2. **Harden the existing classical path** with PQ-relevant hygiene
   (hybrid TLS enforcement) that has value independent of PQ keys.
3. **Track MHSM PG commitments** and align the provider's algorithm
   identifiers, parameter shapes, and OSSL_STORE semantics with what
   MHSM will actually ship.

## 4. Pre-work we can do now (independent of MHSM PQ GA)

Each item below is achievable with no dependency on MHSM firmware.

### 4.1 Reserve algorithm names, OIDs, and dispatch slots

Goal: when MHSM ships PQ keys, the provider's `OSSL_ALGORITHM` tables
already contain entries pointing at stub implementations. Going live is
flipping a feature flag, not writing new dispatch code.

- Add a Cargo feature `pqc` (default off).
- In `src/provider.rs`, register algorithm tables for the candidate set:
  - **Signatures:** `mldsa44`, `mldsa65`, `mldsa87`,
    `slhdsa-sha2-128s`, `slhdsa-sha2-128f`, `slhdsa-sha2-192s`,
    `slhdsa-sha2-192f`, `slhdsa-sha2-256s`, `slhdsa-sha2-256f`.
  - **KEM:** `mlkem512`, `mlkem768`, `mlkem1024`.
- Use the canonical NIST OIDs (FIPS 203/204/205).
- Use the OpenSSL 3.5 upstream provider's algorithm name spelling
  exactly, so applications written against the default provider port
  without changes.
- Each entry initially dispatches to a stub that returns
  `OSSL_PROV_R_UNSUPPORTED_KEY_TYPE` with a clear error string referencing
  this strategy doc. This lets us land the surface and tests early.

### 4.2 Crypto-agility plumbing in `keymgmt.rs` / `signature.rs`

The existing dispatch is RSA/EC-specific. Refactor (incrementally) so that:

- Key-type dispatch goes through a small enum (`KeyKind::Rsa | Ec | Pq(PqAlg)`).
- Per-algorithm capability flags (`supports_sign`, `supports_decapsulate`,
  `supports_verify`, `requires_message_digest`) live in tables, not in
  match arms scattered across the code.
- Parameter mapping (`OSSL_PARAM` ↔ MHSM REST JSON) is centralized in
  `ossl_param.rs` with one converter per key kind, so adding PQ kinds is
  additive.

This refactor pays for itself even before PQ — the current RSA/EC code
has duplicated parameter-conversion logic across `signature.rs` and
`keymgmt.rs`.

### 4.3 Hybrid TLS posture in `http_client.rs`

Independent of PQ keys, the provider's TLS to MHSM should prefer
PQ-safe key exchange today:

- Configure the `reqwest`/`rustls` stack to **advertise**
  `X25519MLKEM768` ahead of classical groups when the runtime supports it
  (rustls 0.23+ with the `aws-lc-rs` crypto provider, or future
  `rustls-post-quantum`).
- **Log the negotiated group** at the first connection per process so
  operators can verify their MHSM endpoint is PQ-safe.
- Add an opt-in env var `AKV_PROVIDER_REQUIRE_PQ_TLS=1` that fails-closed
  if the negotiation lands on a classical group. Off by default in v1 to
  avoid breaking customers in regions where MHSM hasn't enabled hybrid;
  flip the default once Azure rollout is universal.

Document the verification command in the README:

```bash
openssl s_client -connect <vault>.managedhsm.azure.net:443 \
  -groups X25519MLKEM768:X25519:P-256 -tls1_3 2>&1 | grep "Server Temp Key"
```

### 4.4 Test scaffolding using OpenSSL's native PQ as a stand-in

We can write end-to-end provider tests *today* without any MHSM PQ
support by using OpenSSL 3.5's native ML-DSA / ML-KEM for the
*verification / encapsulation* counterparty:

- Provider stub generates a PQ key (placeholder mock backend).
- Test verifies the public key parses through OpenSSL's native PQ
  algorithms.
- Test exercises `OSSL_FUNC_SIGNATURE_VERIFY` end-to-end (verify needs no
  HSM, so it can be exercised before MHSM PQ ships).

This proves out the OpenSSL provider surface and the OID / parameter
plumbing without any MHSM dependency. When the real MHSM backend lands,
the existing tests should pass with the mock swapped for the real
client.

### 4.5 OSSL_STORE plumbing for PQ key URIs

MHSM exposes keys at well-known URIs of the form
`https://<vault>.managedhsm.azure.net/keys/<name>/<version>`. Extend the
provider's `OSSL_STORE` loader (`src/store.rs`) to:

- Parse the `kty` field from the JWK response generically (already does
  this for RSA/EC; today it errors on unknown types).
- Route unknown PQ `kty` values to the registered keymgmt slots from
  §4.1. With the stubs in place, this fails cleanly with an actionable
  error today, and works end-to-end the moment the keymgmt slots get
  real implementations.

## 5. When MHSM PQ preview lands

Trigger criteria: any MHSM region successfully returns a `200` from
`POST /keys/<name>/create` with `kty=ML-DSA` or `kty=ML-KEM`.

Activities:

1. **Capture the actual REST shape** — request/response JSON, parameter
   names, error codes. Document in `docs/mhsm-pq-rest.md`.
2. **Implement the real keymgmt and signature/kem callbacks** behind the
   `pqc` feature, calling MHSM via the existing `http_client.rs`.
3. **Run the test suite from §4.4** against a real MHSM preview instance.
4. **Add KAT tests** using NIST ACVP vectors (the harness layout in
   `microsoft/azure-cloudhsm-pqc-bridge` is reusable as a reference).
5. **Ship as preview** behind a clear "Preview — requires MHSM PQ
   preview-enabled region" README note. Do not enable the feature flag
   by default.

Estimated effort once preview lands: **2–3 sprints** assuming §4 is done.

## 6. When MHSM PQ GAs

1. Flip the `pqc` Cargo feature to default-on.
2. Promote the provider PQ surface from preview to GA in README and
   `Cargo.toml` metadata.
3. Add ML-DSA / ML-KEM examples to `runtest.sh` / `runtest.bat`.
4. Add a PQ certificate example to `nginx-example/` (hybrid ECDHE+ML-KEM
   TLS, then pure ML-KEM once the wider ecosystem catches up).
5. Remove the "preview" qualifier and the stub fallbacks.

## 7. What we explicitly will not build

For the audit trail — these were considered and rejected.

- **Software-side PQ key generation + envelope-wrap to MHSM (the
  bridge).** Useful lifetime too short relative to engineering cost;
  weaker substrate than Cloud HSM's PKCS#11+STC makes the security
  claim hard to defend.
- **A two-level KEK hierarchy with enclave-bound DEK.** Architecturally
  stronger than the bridge, but still requires a non-FIPS `liboqs` path
  and a one-time classical BYOK bootstrap. Same lifetime concern.
- **Importing externally-generated PQ keys into MHSM via BYOK.** Not
  supported by MHSM today and not the right shape even if it were —
  hardware-generated keys are what the HSM trust story requires.

## 8. Open questions / dependencies

| # | Question | Owner | Blocks |
|---|---|---|---|
| 1 | What is the committed MHSM PQ preview date and initial region list? | MHSM PG | §5 |
| 2 | Exact REST API shape for `kty=ML-DSA` / `kty=ML-KEM` (parameter names, JWK encoding of public keys, signing algorithm identifiers)? | MHSM PG | §4.1, §5 |
| 3 | Will MHSM expose ML-KEM as a BYOK Key Exchange Key (enabling PQ-safe key import for `oct-HSM`)? | MHSM PG | Unblocks §7 reconsideration |
| 4 | Is the Marvell LiquidSecurity firmware update for PQ on a published vendor roadmap? | MHSM PG / Marvell | §5 |
| 5 | Which Azure regions have `X25519MLKEM768` enabled on MHSM data-plane endpoints today? | Azure infrastructure | §4.3 default flip |
| 6 | Will OpenSSL 3.5's default provider's PQ algorithm naming change before our GA? | OpenSSL upstream | §4.1 stability |

## 9. Action items (next 4 weeks)

| Item | Owner | Effort |
|---|---|---|
| Reach out to MHSM PG with questions 1–4 from §8 | _(assign)_ | 1 day |
| Implement §4.1 (algorithm reservations + stubs) | _(assign)_ | 1 sprint |
| Implement §4.3 (hybrid TLS posture + logging) | _(assign)_ | 0.5 sprint |
| Implement §4.4 (test scaffolding with OpenSSL native PQ) | _(assign)_ | 1 sprint |

## 10. Success criteria

- When MHSM ships PQ preview, the integration PR is **≤ 1500 lines** and
  lands in **≤ 3 sprints**, because the surface, dispatch, tests, and
  TLS posture are already in place.
- Hybrid TLS is confirmed negotiated to MHSM in every supported region
  before PQ GA.
- The provider's PQ algorithm names and OIDs match OpenSSL upstream
  exactly, so applications targeting the default provider work
  unmodified.
- No `liboqs` or other non-FIPS PQ library ships in the provider binary.

## 11. References

- Microsoft Learn: *About keys in Managed HSM* (current supported-key-types reference).
- Microsoft Security Blog: *Quantum-safe security: progress towards next-generation cryptography* (Aug 2025).
- NIST FIPS 203 (ML-KEM), 204 (ML-DSA), 205 (SLH-DSA).
- OpenSSL 3.x Provider docs: `provider-keymgmt(7)`, `provider-signature(7)`, `provider-kem(7)`, `provider-storemgmt(7)`.
- `microsoft/azure-cloudhsm-pqc-bridge` — reference for envelope format and KAT harness layout (consulted, not consumed).
