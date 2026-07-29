# Changelog

All notable changes to the Humarch public spec. SemVer (D33): additive = minor,
breaking = new major with a new `$id` path (and a new pre-image domain prefix
when hashing is touched).

## 1.3.0 — 2026-07-27

Dual anchor (additive, D33; SPEC.md §7.1, §8):

- New OPTIONAL per-anchor export field `qualified_timestamp`
  (`token_base64` + `tsa_name`/`policy_oid`/`gen_time` metadata): an RFC 3161
  timestamp token — a qualified electronic timestamp under eIDAS (art. 42)
  when issued by an accredited trust service provider — on the SAME daily
  aggregate hash the Bitcoin anchor commits to. Two independent proofs, one
  hash: independent failure modes
- Normative semantics (§7.1): the art. 42 presumption attaches to the daily
  aggregate; every event verifiably contained in it inherits that
  anteriority through deterministic, reproducible recomputation. Stating
  that each event carries its own qualified timestamp is forbidden
- Normative export rule (§8 rule 8): the token is the authoritative
  artifact, metadata is convenience; presence of the field asserts nothing —
  qualification is established in verification; parse caps and declared
  `invalid` on unreadable tokens
- Normative binding (§7.1 step 2): the token is checked against the
  aggregate hash **recomputed** from `anchor_entries_for_aggregate`, never
  against the `aggregate_hash` field carried by the export — that field is
  supplied by the document's producer
- New additive vectors (`vectors/qualified/`): valid mark, digest mismatch,
  malformed token, valid-but-untrusted TSA (raw `.tst` tokens from two
  independent TSA implementations included); absence of the field is pinned
  by the existing export vectors
- Declared lifecycle note: ~20-year verifiability horizon of qualified
  timestamps, re-timestamping strategy declared like key rotation (§6)

No crypto change and no new obligation: exports without the field are the
pre-1.3 form and verify identically — vectors V0–V6, W1, the 23 schema cases
and the export format remain valid as published. Verification outcome and
exit codes of the reference verifier are unchanged (the check is additive).

## 1.2.0 — 2026-07-21

Payload conventions (additive, D33; SPEC.md §1.2):

- `payload.tool_call` (optional object): `name` (required), `params`,
  `result`, `status` — the normative way to record a tool invocation.
  Meaningful on `agent_action`, admitted on `custom`. `subject.tool` stays
  the surface; `tool_call.name` is the specific function invoked
- `payload.delegation` (optional object, admitted on every event type):
  `parent.ref` (required; the source-native run/execution id),
  `parent.event_id` (optional strengthening from the 202 echo), `root`,
  `depth`. Declarative semantics: no referential check at ingestion —
  the reference is signed and chained at reception time
- The §1.1 personal-data rule restated for `params`/`result`: personal data
  of natural persons only in `payload.personal`, with the pseudonymous
  reference / content-hash pattern shown in §1.2.3
- Conditional MUST on the shape, no obligation of presence; no new
  validation at ingestion in v1.2
- Two new valid schema cases (v09, v10) pin the canonical field names:
  the schema-case count grows **21 → 23** (10 valid + 13 invalid)

No crypto change: convention fields hash, chain and sign like any other
payload content — vectors V0–V6, W1 and the export format are untouched.
Designed to support third-party audit requirements for agent activity
logging (e.g. AIUC-1 control E015.2, as of 2026-07); recording in this
shape does not by itself make a system compliant with any standard.

## 1.1.1 — 2026-07-18

Clarification, no format or vector change (third independent audit, V1):

- SPEC.md §1: non-finite numbers (`NaN`, `Infinity`) do not exist in the
  format — RFC 8785 §3.2.2.3 forbids serializing them, and verifiers MUST
  reject them (at any depth of `actor`/`subject`/`payload`) as malformed
  input. The rule was implicit in the IEEE 754 bullet; a lenient parser
  turns `1e999` into `Infinity`, so it is now explicit.

## 1.1.0 — 2026-07-06

GDPR amendment (additive, pre-announced by §5.7 of the guide; B8 §8.6):

- `payload.personal` container (optional object): clear form at ingestion,
  AES-256-GCM envelope `{enc, v, subject, iv, ct, tag}` in the stored and
  exported form — a documented `oneOf` in `event.schema.json`
- Normative rule: `label` and `ref` MUST NOT contain personal data of natural
  persons (SPEC.md §1.1)
- Note to verifiers: integrity is verified on the stored form, without
  decrypting; a crypto-shredded event verifies identically (SPEC.md §1.1, §8)
- New conformance vectors: **V6** (`vectors/shredding/`, envelope + shred)
  and **W1** (`vectors/wrapping/`, DEK wrapping at rest — AES-256-CBC +
  HMAC-SHA256 Encrypt-then-MAC, HKDF-Expand subkeys)

No existing vector changes: V0–V5, the 21 schema cases and the export format
remain valid as published (the container is optional).

## 1.0.0 — 2026-07-05

Initial public release:

- `event.schema.json` (draft 2020-12), `$id` `https://spec.humarchive.com/v1/event.schema.json`
- Canonicalization JCS (RFC 8785), pre-image `humarch:event:v1` (12 lines),
  Ed25519 over the raw digest, per-tenant genesis, daily-anchor formula
- Error-code registry v1
- Conformance vectors V0–V5 and the 21 schema cases
- Export format `humarch-export/v1`
