# humarch-spec

Public specification of the **Humarch** evidence format.

> *Official distribution channel: **github.com/humarch-org** (source and
> signed release binaries). Humarch is **not** published on npm or PyPI —
> any package with this name on a registry is not ours.*

Humarch is a passive evidence registry for AI-automation agencies: it receives
events (agent actions, human approvals, errors…) via webhooks from
Make/n8n/Zapier/custom agents, normalizes them, signs them (Ed25519), chains
them per tenant (append-only), and anchors them to Bitcoin (OpenTimestamps).
This repository contains everything needed to **understand the format** and
**verify the integrity** of an export — nothing here requires access to the
Humarch core.

| File | Content |
|---|---|
| [`event.schema.json`](event.schema.json) | JSON Schema (draft 2020-12) of the normalized event envelope |
| [`SPEC.md`](SPEC.md) | Normative spec: JCS canonicalization, `event_hash` pre-image, Ed25519 signature, per-tenant genesis, daily-anchor formula, OTS lifecycle, `humarch-export/v1` |
| [`ERROR_CODES.md`](ERROR_CODES.md) | Stable error registry of the ingestion API, with retry semantics |
| [`KEYS.md`](KEYS.md) | Current and historical public signing keys (self-certifying ids) |
| [`vectors/`](vectors/README.md) | Conformance vectors — the contract every implementation must reproduce. See [`vectors/README.md`](vectors/README.md) for the authoritative list (crypto V0–V6 and W1, the schema cases, the qualified-timestamp vectors, the message-id vectors) |
| `CHANGELOG.md` | Versioned history of the spec (SemVer, D33) |

## Verify an export

Use the reference CLI from the
[`humarch-verify`](https://github.com/humarch-org/humarch-verify) repository:

```
humarch-verify export.json
```

or reimplement the verifier in any language from `SPEC.md` + `vectors/` alone —
that is the acceptance test of this spec.

Scope of the proof, stated plainly: verification proves the events were
recorded by the holder of the trusted keys, unaltered, in this order, at the
anchored time — **as received, not as true**. The truth of what a payload
asserts stays outside any cryptographic proof; attribution proves the key,
not the truth.

## Send events

See the [`humarch-adapters`](https://github.com/humarch-org/humarch-adapters)
repository for ready-made Make / n8n / Zapier templates and `generic` examples
for custom agents.

## Run the conformance suite

```sh
deno task test
```

## License

MIT
