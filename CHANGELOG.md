# Changelog

All notable changes to the Humarch public spec. SemVer (D33): additive = minor,
breaking = new major with a new `$id` path (and a new pre-image domain prefix
when hashing is touched).

## 1.5.0 — 2026-08-05

On-demand chain seal (additive, D33; SPEC.md §7.2, §8):

- new §7.2: an **on-demand chain seal** — an RFC 3161 timestamp token
  (§7.1 profile) issued on the 32 bytes of ONE `event_hash`, the tenant
  chain's **head** at sealing time. Closes the intra-day window the daily
  anchor leaves open; the daily registry (§7) is unchanged and unaware of
  it. Normative semantics: the art. 42 presumption attaches to the chain
  head at sealing time; every prior event inherits that anteriority through
  deterministic, reproducible recomputation — a seal covers a chain
  **prefix**, never per-event marks
- binding rule (§7.2 step 2): verifiers MUST bind the token to the event
  hash **recomputed from the §5 pre-image at the declared sequence, within
  the verified prefix** (§8 rule 10) — never to the event's declared
  `event_hash` field or to anything the seal element carries; a seal whose
  sequence the export does not contain, or that falls beyond the verified
  prefix, is a declared `invalid`
- export format (§8): new OPTIONAL top-level array `chain_seals`
  (`{sequence_number, token_base64, tsa_name, policy_oid, gen_time}`,
  ordered, one seal per head), governed by the new rule 12 — token
  authoritative, metadata convenience, 64 KiB reference parse cap,
  unreadable token ⇒ declared `invalid`, never a verification failure. The
  element deliberately carries **no event hash**: the binding target exists
  only as the recomputed value
- new vectors `vectors/seal/` (valid / imprint-mismatch / malformed /
  oversize / unknown-sequence, plus the raw tokens and a `humarch-tsa/v1`
  trust fixture); the qualified 1.3 vectors reproduce byte-identically

**No crypto change**: hashing, chaining, signing, the daily anchor and the
qualified timestamp of §7.1 are untouched — vectors V0–V6, W1, the 25 schema
cases and the qualified vectors reproduce byte-identically, and
`event.schema.json` is unchanged. Exports produced before 1.5.0 remain valid
and verify to the same outcome; verification outcome and exit codes of the
reference verifier are unchanged (the check is additive). A malformed
`chain_seals` field (wrong shape, duplicate or unordered sealed sequences)
is malformed input, rule-8 class.

## 1.4.0 — 2026-08-02

Probative conventions (additive, D33; SPEC.md §1.2.5, §1.2.6, §1):

- `payload.external_refs` (optional array of objects, admitted on every
  event type): declared references to evidence held outside both the
  registry operator and the tenant. Three canonical member shapes —
  `{artifact_sha256}` (SHA-256 of **stable content only**: attachment,
  document, API body — never an email body), `{system, ref}` (third-party
  native id, declared as a value, never as a map key),
  `{message_id_sha256}` (the digest of an email's Message-ID under the
  normative four-step algorithm of §1.2.5: select — zero or several
  `Message-ID` fields means the field is not declared — unfold per RFC 5322
  §2.2.3, parse the §3.6.4 `msg-id` production and take the bracketed token
  discarding CFWS, hash it UTF-8 with no case-folding; new vectors
  `vectors/message-id/` pin it, omission cases included; the clear
  Message-ID SHOULD NOT be recorded). `filename` SHOULD NOT appear in the
  clear — `payload.personal` is the place for it (§1.2.3 pattern)
- `payload.execution` (optional object, admitted on every event type):
  `ref` (required) — the source-native run id of the execution that emits
  THIS event. Normative three-way distinction: `execution.ref` (own run) vs
  `delegation.parent.ref` (parent's run) vs `x-idempotency-key` (transport
  header, never an event field)
- Declarative semantics of §1.2.2 extended verbatim to both fields:
  declared, never resolved or checked at ingestion; an unresolved or
  non-matching reference is not tampering. Output and derived material MUST
  say "declared", never "verified"/"bound"/"proven"
- Success response body (§1, ERROR_CODES.md): `event_hash` added as an
  additive **echo field** of the `202` — the stored event's hash, echoed on
  first write and on idempotent replay alike; positional value only (the
  slot in the dense per-tenant sequence), never called a receipt or proof;
  error bodies never carry it
- Declared detection limits: bare numeric ids of 13–19 digits in
  `system`/`ref` pairs trip card-checksum heuristics in ~10% of cases
  (suppression on the operator side is the remedy; detection is not
  weakened)
- Two new valid schema cases (v11, v12) pin the canonical field names:
  the schema-case count grows **23 → 25** (12 valid + 13 invalid)
- Export rules 8, 9 and 10 (§8), from an independent audit of this release:
  `sequence_number` and `event_id` are unique **within one export** and a
  repetition is malformed input, not a tampering verdict; and verification
  status is a property of the verified **prefix**, never of a sequence
  interval — deriving "verified" from `sequence_number ≤ verified_through`
  credits a duplicated, unverified event with its twin's integrity; and
  export-supplied strings are hostile input at the point of display

**No crypto change**: convention fields hash, chain and sign like any other
payload content — vectors V0–V6, W1 and the qualified vectors reproduce
byte-identically, and `event.schema.json` is unchanged (the payload is open,
D30). Exports produced before 1.4.0 remain valid and verify to the same
outcome.

**New obligations, stated plainly** (this release is not purely additive for
implementers, and the reference verifier's behaviour changes on inputs it
previously assessed):

- export rules 8, 9 and 10 add MUSTs for verifiers and consumers: uniqueness
  of `sequence_number`/`event_id` within an export, neutralization of
  export-supplied strings at the point of display, and verification status
  carried positionally rather than as a sequence interval;
- consequently the reference verifier now answers **exit 4 (malformed
  input)** for two classes of document it used to assess: an export carrying
  a duplicate `sequence_number` or `event_id`, and one carrying a control,
  format or line/paragraph-separator character in a machine field.
  Provider-supplied display names (`tsa_name`) are held only to the
  control-character rule and are neutralized at display instead;
- implementations that render verdicts should re-test their output path
  against the rule 9 discipline — including the text of parser error
  messages, which typically quote the offending bytes verbatim.

These changes come from an independent audit of this release and from the
adversarial review of its remedies (2026-08-02), both run before
publication.

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
- Normative export rule (§8 rule 8 at the time of 1.3.0, renumbered to rule
  11 by the 1.4.0 export rules): the token is the authoritative
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
