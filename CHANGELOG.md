# Changelog

All notable changes to the Humarch public spec. SemVer (D33): additive = minor,
breaking = new major with a new `$id` path (and a new pre-image domain prefix
when hashing is touched).

## 1.7.0 — 2026-08-21

External binding of the verification recipe, reservation of the
`__tenant_default__` sentinel, declaration of a discarded retransmission, and
the determinism of §8 (additive, D33; SPEC.md §7, §8, §8.1, §1.0.1, §1.1):

- **Anchor binding (§7, new normative clause).** The §8 recipe verified the
  internal coherence of a document and never required a tie to anything
  outside it. A verified `.ots` attestation proves that *some* aggregate
  existed at a block time; nothing said it had to name *this* chain. So a
  genuine anchor lifted from a published export verified attached to a
  fabricated chain, at the cost of no keys at all. Verifiers MUST now check
  that `anchor_entries_for_aggregate` carries the pair for this export's
  `tenant_id` naming the **recomputed** head of the verified prefix — not the
  `last_event_hash` as it appears in the export, and not the sibling `entry`
  field, which no aggregate commits to — and MUST bind to the recomputed
  value. An anchor that verifies but does not bind contributes no anteriority.
  The clause is the twin of §7.1 step 2 and §7.2 step 2, written with the same
  structure and the same words: one rule, applied to each of the three proofs
  this format carries
- **Attribution (§8, new normative clause).** `signing_keys` travels inside
  the document, so a signature verifying under a key the document supplies
  proves internal consistency and nothing about who signed: an attacker
  generates a key pair, signs a fabricated chain, and ships the public key in
  the same file. The self-certifying key id of §6 does not close this — it
  proves the id matches the key, never that the key is the registry's.
  Verifiers MUST take the trusted `signing_key_id` set from a source
  independent of the export, and MUST NOT present a signature as attributed
  on the strength of a document-carried key. A signature valid under an
  untrusted key is a valid signature from an unknown issuer, reported as such
  and not as a failure. `KEYS.md` becomes a requirement, no longer a
  convenience
- **`__tenant_default__` is reserved (§1.1).** The literal is the format's own
  name for the encryption scope shared by a tenant's events with no
  `end_client`. Nothing stopped an end client from carrying it as its own
  `ref`, which filed that end client under the default pool: erasure of the
  pool then destroyed the real end client's key with it, irreversibly, on an
  append-only registry. Ingestion MUST reject an event whose
  `subject.end_client.ref` is exactly that literal, with `SCHEMA_VIOLATION`,
  and `event.schema.json` now carries the refusal so an implementation
  validating against the published schema inherits it. The reservation is
  scoped to `end_client`: `workflow.ref` and `tool.ref` are unrestricted,
  because neither names an encryption scope
- **`replay_divergence` (§1.0.1, D109).** The identity criterion of D24 is
  unchanged — same key + same `payload_hash` is still a replay, and the first
  event still stands. What changes is what the `202` **declares**: a
  retransmission carrying a different `actor`, `subject` or `event_type` was
  absorbed in silence, discarding a changed statement about who acted. The
  replay body now carries `replay_divergence: {fields, count}` over that
  closed set, compared by JCS canonical form, lexicographically ordered.
  Present **only** when something diverged, so a replay of an identical
  retransmission stays byte-identical to the pre-1.7 response; the verdict
  stays `202` and never becomes a `409`; error bodies never carry it
- **§8.1 verdict determinism (new).** Eleven classes where two verifiers built
  strictly from this document could reach different verdicts on the same
  export, plus the two the reference verifier had always refused without §8
  ever defining them (an event whose `tenant_id` differs from the export's;
  two anchors sharing an `anchor_date`). Each answer states what the reference
  already does, so no vector moves
- §8 rule 9: "a verifier MAY refuse" becomes MUST — one hostile document
  earned two lawful verdicts — and the machine-field list, previously
  exemplificative, is enumerated
- §8 rules 11–12: the 64 KiB token cap is normative **in its value**, not only
  in its existence; `vectors/seal/export-seal-oversize.json` pins an outcome
  that depends on it
- §9: the `SCHEMA_VIOLATION` `detail` carries **a** JSON Pointer to **a**
  violating field, not "the first" — draft 2020-12 leaves error order
  implementation-defined, so no validator can promise position (CWE-758)
- §7: where the digest sits in the `.ots` serialization (the 32 bytes after
  `magic ‖ 0x01 ‖ 0x08`), and §7.1: the `humarch-tsa/v1` trust-fixture format,
  both previously derivable only by reverse-engineering a vector
- §1.2.5 step 4 of the `message_id_sha256` algorithm was syntactically broken
  — unbalanced emphasis, an unclosed parenthesis, a truncated clause — inside
  a normative algorithm. Rewritten; the behaviour it now states is the one the
  vectors always pinned (no case folding)
- §1: the "violations are `SCHEMA_VIOLATION`" heading governed three bullets
  that are not of that class; §1.2.5: *element* and *property* are now used
  apart, on a document written to be reimplemented
- new vectors `vectors/replay/` (five cases) and two schema cases: **27**
  schema cases, 13 valid + 14 invalid. `v13`/`i14` are the two halves of the
  reservation — i14 that an `end_client` claiming the sentinel is refused, v13
  that `workflow` and `tool` are not, so widening the refusal is as much a
  test diff as dropping it
- `vectors/README.md` claimed all signatures used the RFC 8032 key "so that
  anyone can regenerate every value from scratch". That is false of the 15
  export vectors, signed with `ed25519:dc5578a147d359bf`, whose seed is not in
  the repository and will not be. They are verify-only, and the file now says
  so; the remedy is to tell the truth, not to publish the seed
- new `tests/clauses.ts`, `tests/prose.test.ts` and `tests/mutation.test.ts`:
  every normative obligation of the repository is registered as an **anchored
  clause**, and the mutation pass enumerates the RFC 2119 tokens of SPEC.md
  **from the document on every run**, weakens each one, and requires a clause
  to go red. It found the omissions this release fixes; a hand-maintained list
  would have been written before the clauses above and would have been born
  blind to them. `ERROR_CODES.md`, `CHANGELOG.md`, `README.md` and
  `vectors/README.md` were read by no test at all until now
- **Additive**: every pre-1.7 export verifies identically, every pre-1.7
  vector is byte-identical, and hashing, canonicalization and signing are
  untouched. The reservation of `__tenant_default__` is the one restriction:
  the literal never worked as an end-client identifier — it collided with the
  default pool by construction — so no correct producer loses anything

## 1.6.0 — 2026-08-06

Self-declaration of omitted proof artifacts (additive, D33; SPEC.md §8):

- new OPTIONAL top-level array `unavailable_artifacts` (§8 rule 14): the
  **single** mechanism by which an exporter declares the proof artifacts it
  omitted under rule 13, for all three at once — `{"kind": "ots_receipt" |
  "qualified_timestamp", "anchor_date"}` and `{"kind": "chain_seal",
  "sequence_number"}`. Elements carry no other member, and deliberately no
  free-text reason: an exporter-supplied string is hostile input at the
  point of display (rule 9), and both coordinates already exist in the
  format. Exports without the array are the pre-1.6 form and verify
  identically
- normative semantics: **a declaration is neither evidence nor an
  exemption.** It is an assertion by whoever produced the document about
  that producer's own operational state, and that producer may be the
  adversary — so an attacker who strips a genuine proof and adds the
  matching declaration MUST obtain exactly the outcome of the plain
  absence. The outcome, and the reference verifier's exit code, MUST be
  identical to those of the same document with the array removed; the
  absence of a declaration likewise asserts nothing
- form: a repeated coordinate, an unknown `kind`, a coordinate of the wrong
  shape or one that does not belong to its kind is malformed input (rule-8
  class); the ordering binds exporters only (rule-4 class)
- rule 13 emended, not contradicted: omission stays the behavior (never a
  metadata-only entry) and stays symmetric across the three artifacts; rule
  14 only lets the document say which omissions happened
- new vectors `vectors/unavailable/`: the declaring export and its
  declaration-free twin (same events, same verdict) plus the four malformed
  cases. All pre-1.6 vectors are byte-identical

## 1.5.1 — 2026-08-06

Clarification only (no format change, no new field, no vector change; §8):

- new §8 rule 13: an exporter that cannot resolve an archived proof object
  at export time omits the corresponding optional field or element — never
  a metadata-only entry — and this omission rule is **symmetric** across
  the three proof artifacts (`.ots` receipt, §7.1 qualified timestamp,
  §7.2 chain seal): none of them is dropped more silently than the others.
  Exports with an omitted artifact remain valid and verify as the
  corresponding earlier or artifact-less form. This documents behavior the
  reference exporter and verifier already had (rules 3, 11 and 12);
  nothing changes for implementers.

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
