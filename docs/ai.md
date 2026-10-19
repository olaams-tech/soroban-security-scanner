# Optional AI Assistance

The scanner's deterministic engine is authoritative. Assistance is an optional,
clearly labeled layer that helps developers understand findings. It is **off by
default**, performs **no network access by default**, and can never change the
deterministic result.

## Guarantees

- The scanner is fully functional with assistance disabled.
- Assistance never creates, removes, suppresses, or overrides findings.
- Assistance never invents source locations or evidence.
- Assistance never claims certainty beyond the observed evidence.
- Assistance never accesses secrets, submits transactions, or modifies code.
- Assistance output is always labeled as assistance.

## Offline guidance (no model, no network)

`--guidance` prints deterministic, rule-based guidance derived solely from the
finding and its rule documentation:

```bash
soroban-scan scan ./contracts --guidance
```

Output starts with a summary and then one labeled explanation per finding:

```
GUIDANCE (offline, rule-based)

Scanned with 5 deterministic findings: critical 0, high 2, ...
```

This is not model-generated. It is a deterministic restatement of the rule's
description, evidence, and remediation, plus prioritization hints.

## Assistance cache

Repeated assistance requests for the same finding are cached by
**fingerprint + provider + model** (`crates/soroban-scan-core/src/ai/cache.rs`).
A cache hit avoids calling the provider again, which saves latency and (for a
model provider) tokens.

- Entries live under the scan cache directory (`.scanner-cache/ai`, excluded
  from discovery).
- The cache is content-addressed: keys are SHA-256 digests and filenames contain
  no evidence or source text.
- Only the rendered explanation is stored. Source files, secrets, environment
  variables, and request payloads are never cached.
- Storage is bounded to `DEFAULT_MAX_ENTRIES` (256). When full, the
  least-recently-used entry is evicted deterministically (oldest access first,
  ties by key).
- Cache I/O is best-effort: a missing, corrupt, or read-only cache directory
  never breaks assistance or changes findings.


## Enabling a model-backed provider

Configuration has an `[ai]` section:

```toml
[ai]
enabled = false
# provider = "openai"
# model = "..."
```

No model provider is bundled. If you set `enabled = true` without a bundled
provider — or name a provider that is not compiled in — the CLI **fails closed**:

```
error: assistance is unavailable: assistance provider 'openai' is not available in this build
```

This is deliberate. Enabling assistance can never silently fall back to
unverified behavior.

## Implementing a provider

A provider implements the `Assistant` trait in
`crates/soroban-scan-core/src/ai/mod.rs`:

```rust
pub trait Assistant {
    fn name(&self) -> &str;
    fn explain_finding(&self, finding: &Finding, rule: Option<&RuleMetadata>) -> Explanation;
    fn summarize(&self, findings: &[Finding]) -> Explanation;
}
```

Requirements for any provider:

1. Set `ai_generated: true` and use [`AI_LABEL`](../crates/soroban-scan-core/src/ai/mod.rs)
   so output is clearly identified as model-generated.
2. Accept only existing findings and rule metadata as input. Never synthesize
   findings or locations.
3. Never include environment variables, secrets, or absolute user paths in
   output.
4. Obey the network policy below.

## Network policy for providers

The default build performs no network access. A provider that needs the network
must:

- Be explicitly opt-in and disabled by default.
- Enforce an allowlist of destinations.
- Enforce request timeouts and response-size limits.
- Validate URLs and reject unsafe redirects.
- Protect against SSRF (no access to internal endpoints or metadata services).
- Fail closed on any error.
- Never send source code or secrets off-device without explicit, informed
  user consent.

The non-default `ai-http` feature provides the audited transport in
`crates/soroban-scan-core/src/ai/http.rs`. It is absent from the default feature
set:

```toml
# crates/soroban-scan-core/Cargo.toml
[features]
default = []
ai-http = ["dep:ureq", "dep:url"]
```

A provider builds a [`NetworkPolicy`](../crates/soroban-scan-core/src/ai/http.rs)
with an explicit allowlist (bare host names with optional ports, for example
`api.example.com` or `*.example.com:443`) and hands it to `HttpClient`:

```rust
use soroban_scan_core::ai::http::{HttpClient, NetworkPolicy};
use std::time::Duration;

let policy = NetworkPolicy::new(["api.example.com"])?
    .with_limits(
        Duration::from_secs(5),   // connect
        Duration::from_secs(15),  // read headers/body
        1024 * 1024,              // hard response-size limit
        3,                        // redirect budget
    )?;
let client = HttpClient::new(policy);
let response = client.get("https://api.example.com/v1/respond")?;
let body: serde_json::Value = response.json()?;
```

The client enforces HTTPS, rejects embedded credentials, re-validates every
redirect target, resolves every destination and rejects loopback, private,
link-local, carrier-grade NAT, documentation, multicast, and metadata addresses,
and fails closed on malformed responses or non-2xx statuses. The allowlist
itself is validated when the policy is built: empty or wildcard-only entries,
private IPs, schemes, paths, and userinfo are rejected.

Provider output is passed through the deterministic redaction pass in
`ai::redact` before rendering. It removes common token formats, secret-like
assignments, PEM private keys, and absolute home directories; `Explanation`
applies the same pass again at render time as a final gate.

## What AI must never do

- Invent findings or source locations.
- Override or suppress deterministic findings.
- Claim certainty without evidence.
- Access secrets or execute actions.
- Modify code automatically.
