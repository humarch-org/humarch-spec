# Humarch format specification (v1)

Normative specification of the Humarch evidence format: canonicalization,
hashing, chaining, signing, anchoring, and the verifiable export. Together
with `event.schema.json` and `vectors/`, this document is sufficient for an
independent third party to implement an adapter or a verifier with **no access
to the Humarch core** (brief §11).

Key words MUST / MUST NOT / SHOULD are to be interpreted as in RFC 2119.

## 1. Ingestion envelope

The body of `POST /ingest/{make|n8n|zapier|generic}` is a **normalized event
envelope** validated against `event.schema.json` (JSON Schema draft 2020-12,
D31). The envelope is **closed** (unknown top-level properties are rejected),
the `payload` is **open** except for one required field per event type (D28,
D30):

| `event_type` | required payload field |
|---|---|
| `agent_action` | `action` |
| `human_approval` | `decision` ∈ {`approved`,`rejected`} |
| `workflow_error` | `message` |
| `workflow_run` | `phase` ∈ {`start`,`end`}; `status` required when `phase = "end"` |
| `guardrail_event` | `outcome` |
| `correction` | `corrects` (UUID of the corrected event, same tenant) |
| `custom` | — (free payload; `actor`/`subject` still required) |

`actor` requires `type` ∈ {`agent`,`human`,`system`} and `id`; `label` is
always optional (D29). `subject` has 1–3 members among `workflow`,
`end_client`, `tool` (no others), each with a required `ref` and an optional
`label` (D29). `ref` is the **stable native identifier** of the source
platform, conserved verbatim by the registry; prefer codes over natural names
(GDPR minimization). `actor.type: "agent"` carries no determinism semantics:
autonomous agents and deterministic workflow modules are both `agent`,
distinguished only by `actor.id`.

Pipeline rules not expressible in the schema (violations are
`SCHEMA_VIOLATION`):

- No string may contain **U+0000**; unpaired UTF-16 surrogates are forbidden
  (I-JSON).
- Numbers are **IEEE 754 doubles**: precision beyond a double is lost at
  parse time, before hashing, by design.
- **Non-finite numbers do not exist in the format** (amendment 2026-07-18).
  JSON has no literal for `NaN`/`Infinity`, and RFC 8785 §3.2.2.3 requires a
  compliant JCS implementation to *terminate with an error* on them — so a
  conforming serializer can never emit one. A lenient parser, however, turns
  the out-of-range literal `1e999` into `Infinity`: verifiers MUST therefore
  reject any non-finite number, at any depth of `actor`/`subject`/`payload`,
  as **malformed input** (a form error, never a tampering verdict). The rule
  was implicit in the IEEE 754 bullet above; it is stated explicitly because
  a hand-crafted export could otherwise crash a verifier that canonicalizes
  before validating.
- Duplicate keys: last-wins (adapters SHOULD NOT produce them).
- `correction.corrects` MUST exist in the same tenant (checked at ingestion).
- `occurred_at` is informative and never bounded by a time window; the
  authoritative timestamp is the server-assigned `received_at`.
- Request body ≤ 256 KB.

The idempotency key travels **only** in the `x-idempotency-key` header, never
in the envelope (F7). Resolution precedence: explicit header → adapter-derived
(`adp:` prefix) → `raw:` + SHA-256(JCS(raw body)). Same key + same
`payload_hash` = replay (202, `idempotent_replay: true`); same key +
different content = `409 DUPLICATE_IDEMPOTENCY_KEY` (D24).

The success response is `202 {event_id, sequence_number, event_hash}`
(`event_hash` added in v1.4, additive). `event_hash` is an **echo field**:
the §5 hash of the event as stored, echoed on the first write and on an
idempotent replay alike (the replay echoes the hash of the originally stored
event, byte-identical by construction). A sender that logs the response
holds the exact slot `(event_id, sequence_number, event_hash)` its event
occupies in the tenant chain. The echo is not signed and is not a receipt —
by itself it carries the same weight as any other line in the sender's logs.
Its value is positional: the per-tenant sequence is dense, so any future
state of the registry in which that sequence number does not carry that
content is a demonstrable contradiction. Error bodies never carry
`event_hash`.

The ingestion API intentionally sends **no CORS headers**: every supported
source is server-side (E8).

### 1.1 Personal-data container `payload.personal` (v1.1, additive — B8 §8.6)

`payload.personal` (optional, object) contains **all and only** the end-client
personal data of natural persons that must be kept in identifiable form
(D47). Two forms, one `oneOf` in the schema:

- **Clear form (ingestion input):** a free-form object. The registry encrypts
  it per subject before storing (AES-256-GCM, D50); the plaintext is never
  stored or hashed.
- **Envelope form (stored/exported):**

  ```json
  {"enc":"aes-256-gcm","v":1,"subject":"<subject_ref>",
   "iv":"<base64>","ct":"<base64>","tag":"<base64>"}
  ```

  with `AAD = UTF8("humarch:pii:v1:" || subject_ref)` and
  `subject_ref = subject.end_client.ref` of the event (or
  `__tenant_default__` when `end_client` is absent, D48). The IV is random
  per encryption; the envelope is self-contained.

**Normative rule on non-personal fields (D47):** `label` and `ref` (in
`actor` and in every `subject` member) MUST NOT contain personal data of
natural persons — use codes, company names or internal agency identifiers. A
personal datum of an end client that must be conserved goes in
`payload.personal`, nowhere else.

**Note to verifiers:** encrypted fields appear as envelopes; integrity is
verified **without decrypting** — all hashes are computed on the stored form
(rule B8, Block 2 §2.0), so the envelope is just another JSON object under
JCS. Decryption is out of band, reserved to the data controller. An event
whose subject was crypto-shredded verifies **identically** to before the
shred (same bytes): chain verification is independent of key availability.
Vector V6 (`vectors/shredding/`); the DEK wrapping at rest is pinned by
vector W1 (`vectors/wrapping/`).

### 1.2 Payload conventions (v1.2 `tool_call`/`delegation`, v1.4 `external_refs`/`execution` — additive)

Optional payload conventions normalize how implementations record **tool
invocations** and **delegation between executions** (v1.2), and how they
declare **external references** and the **run that emits the event** (v1.4).
The payload stays open (D30): none of these fields is ever required, and
their absence is never a validation error. But **if** an implementation
records one of these facts in the payload, it MUST use these field names and
shapes — one public convention is what makes such records comparable across
sources and legible to third parties in audit and evidence use cases; fields
invented per client prove nothing to an auditor.

#### 1.2.1 `payload.tool_call` (object, optional)

Meaningful on `agent_action` (and admitted on `custom`):

```json
"tool_call": {
  "name": "send_email",
  "params": { "template": "order-confirmation", "recipient_ref": "crm-4821" },
  "result": "queued",
  "status": "ok"
}
```

| Member | Level | Meaning |
|---|---|---|
| `name` | REQUIRED, string | the concrete operation invoked |
| `params` | OPTIONAL, any | the call arguments, as passed by the caller |
| `result` | OPTIONAL, string or object | a synthetic outcome of the call |
| `status` | OPTIONAL, string | free string; `"ok"` and `"error"` are the recommended values |

`subject.tool` remains the identity of the **surface** (`gmail`, `shell`,
`stripe`); `tool_call.name` is the **specific function** invoked on that
surface. The two levels coexist and do not duplicate each other.

#### 1.2.2 `payload.delegation` (object, optional, admitted on every type)

```json
"delegation": {
  "parent": { "ref": "84210", "event_id": "7d8e9f0a-1b2c-4d3e-8f4a-5b6c7d8e9f0a" },
  "root":   { "ref": "84203" },
  "depth":  2
}
```

| Member | Level | Meaning |
|---|---|---|
| `parent` | REQUIRED when `delegation` is present | the delegating execution |
| `parent.ref` | REQUIRED, string | the **source-native run/execution id** of the delegator (an n8n or Make execution id, a custom agent's session id — realistic values are numeric strings like `"84210"` or `"3812746"`): what the delegator *knows at the moment it delegates* |
| `parent.event_id` | OPTIONAL, UUID | the registry `event_id` of the delegating event, for sources that capture the echo of the `202` ingestion response — a strengthening, never a precondition (the server assigns `event_id`; requiring it would make the convention unusable in real webhook flows) |
| `root` | OPTIONAL, same shape as `parent` | the top of the delegation chain |
| `depth` | OPTIONAL, integer ≥ 1 | position in the chain (a direct delegate of the root has `depth: 1`) |

The `{ref, …}` shape is deliberately consistent with the `SubjectRef` style
of the envelope.

**Declarative semantics (normative).** `delegation` is a **declarative,
informative reference**: ingestion does NOT check that the referenced parent
exists (unlike `correction.corrects`, which stays referentially checked — a
rare, deliberate, post-hoc act). Delegations are emitted *during* execution,
possibly in parallel and out of order; refusing an event because its parent
has not arrived yet would refuse evidence. The probative value lies
elsewhere: the reference is hashed, signed and chained at reception time, so
it cannot be invented retroactively. Consumers resolve the reference
downstream and MUST NOT treat an unresolved parent as tampering.

#### 1.2.3 Personal data in convention fields (the §1.1 rule, restated)

`tool_call.params` and `tool_call.result` are exactly where end-client
personal data would try to enter (email recipients, message bodies). The
§1.1 rule extends verbatim: personal data of natural persons goes **only**
in `payload.personal`, never in `params`/`result` in the clear. The
recommended pattern — pseudonymous references (or a content hash) in the
convention fields, the identifiable datum in the encrypted container:

```json
"payload": {
  "action": "send_email",
  "tool_call": {
    "name": "send_email",
    "params": { "template": "order-confirmation", "recipient_ref": "crm-4821" },
    "result": { "message_sha256": "5891b5b522d5df086d0ff0b110fbd9d21bb4fc7163af34d08286a2e846f6be03" },
    "status": "ok"
  },
  "personal": { "recipient_email": "client@example.com" }
}
```

This keeps the convention compatible with crypto-shredding (§1.1): after a
shred the `tool_call` facts remain legible and verifiable while the personal
datum is irrecoverable.

#### 1.2.4 Conformance level and crypto neutrality

- The conventions are **conditional MUSTs on the shape**, not obligations of
  presence. No new validation is added at ingestion in v1.2 or v1.4: a
  malformed `tool_call`, `delegation`, `external_refs` or `execution` is NOT
  a `SCHEMA_VIOLATION` (a future version MAY harden this, per D33; the
  trigger would be a real dispute over a malformed convention field).
- **Convention fields hash, chain and sign like any other payload content —
  no new verification surface.** The crypto vectors V0–V6/W1 are unaffected
  by construction (the payload was already open); schema cases v09/v10
  (v1.2) and v11/v12 (v1.4) in `vectors/schema/valid/` pin the canonical
  field names in the conformance contract.

#### 1.2.5 `payload.external_refs` (array of objects, optional, admitted on every type — v1.4)

An event MAY declare **external references**: pointers to evidence that lives
outside both the registry operator and the tenant — a file in the end
client's hands, an order in a third party's system, a message on a mail
provider's server. Because the referenced evidence is held by a
disinterested party, a declared reference can be checked by a third party
even in scenarios where operator and tenant would collude.

```json
"external_refs": [
  { "artifact_sha256": "5891b5b522d5df086d0ff0b110fbd9d21bb4fc7163af34d08286a2e846f6be03" },
  { "system": "shopify", "ref": "5723911058629" },
  { "message_id_sha256": "cd71135384f140d325708ac71da6a6705a603e362042abfcc956c9781a589e50" }
]
```

(the `message_id_sha256` above is the digest of the header
`<20260802094107.5A2C@mail.example.com>`, computed with the algorithm
below and pinned by `vectors/message-id/`.)

Each array member is an object in exactly one of these shapes (extra members
are allowed; the named member is the REQUIRED one):

| Shape | Meaning |
|---|---|
| `{ "artifact_sha256": "<64 lowercase hex>", … }` | SHA-256 fingerprint of a delivered or produced artifact — an attachment, a document, an API body |
| `{ "system": "<system name>", "ref": "<native id>", … }` | an identifier returned by a third-party system: an order id, a PSP transaction, a CRM record. The `{ref, …}` shape is deliberately consistent with `SubjectRef` and `delegation.parent` |
| `{ "message_id_sha256": "<64 lowercase hex>", … }` | SHA-256 digest of an email `Message-ID` (canonicalization below) |

Normative rules:

- **Hash stable content only** (`artifact_sha256`): the fingerprint is
  meaningful only for an object whose bytes do not change after the event —
  an attachment, a generated document, an API request/response body. An
  email **body** is NOT stable content: it mutates in transit (transfer
  encoding, footers, re-signing). For email, declare `message_id_sha256`.
- **`message_id_sha256` canonicalization (normative algorithm).** Two
  independent implementations MUST produce the same digest from the same
  message. Producers apply, in this order:

  0. **The input** is the **raw field body as transmitted**: the octets
     between the colon of the header field and the CRLF that terminates it,
     before any library-side normalization. Field names match
     case-insensitively (`Message-ID`, `MESSAGE-ID`, `message-id` are the
     same field). An implementation whose mail API cannot give it that —
     or cannot enumerate **every** instance of the field — MUST NOT declare
     `message_id_sha256`: a single-value accessor silently hides the
     duplicate case that step 1 exists to refuse.
  1. **Select** the message's `Message-ID` header fields. If there is **no**
     such field, or **more than one**, the field is NOT declared — omit
     `message_id_sha256` rather than choose (mail libraries differ in which
     duplicate they surface, and one of them concatenating or reordering
     would silently change the digest).
  2. **Unfold** the field body per RFC 5322 §2.2.3: remove every CRLF that
     is immediately followed by WSP (space or HTAB), keeping the WSP. The
     rule is CRLF-only, deliberately: a message stored with bare-LF line
     endings is no longer the message as transmitted, and a folded header
     read from such a copy will not parse in step 3 — the field is then
     omitted, which is the intended fail-closed outcome. Declaring a digest
     computed over a locally re-lined header would be worse: two honest
     implementations would disagree and neither would know it.
  3. **Parse** the unfolded body against the RFC 5322 §3.6.4 `msg-id`
     production — `[CFWS] "<" id-left "@" id-right ">" [CFWS]`, where
     `id-left` is `dot-atom-text` and `id-right` is `dot-atom-text` or a
     `no-fold-literal` (`"[" *dtext "]"`) — and take the
     `"<" id-left "@" id-right ">"` token, angle brackets included.
     Comments and folding whitespace (CFWS) are discarded, **including
     comments that themselves contain angle brackets**. The **obsolete**
     productions (`obs-id-left`, `obs-id-right`, obsolete CFWS) are NOT
     accepted, and neither is any body with characters left over after the
     token and its trailing CFWS: whatever does not match the production in
     full is not parsable, and the field is omitted. Under this rule the
     token is US-ASCII by construction.
  4. **Hash** exactly the bytes of that token, UTF-8 encoded (a no-op for
     case-folding** and no other normalization:
     `message_id_sha256 = hex(SHA-256(UTF8(msg-id)))`.

  Vectors `vectors/message-id/` pin this rule, the omission cases
  included.
- **The clear `Message-ID` SHOULD NOT be recorded.** A Message-ID is
  syntactically an email address, so it is a deterministic false positive
  for personal-data detection tooling — and some mailers embed the sender's
  real address in it, so it is sometimes actual personal data. The digest
  preserves third-party falsifiability: whoever holds the email recomputes
  and compares.
- **`filename` SHOULD NOT appear in `external_refs`** (or elsewhere in the
  clear): a filename is human-chosen text entering an append-only registry
  and may carry personal data invisible to syntactic detection. The
  recommended form is `artifact_sha256`; when the name itself must be
  conserved, it goes in `payload.personal` (the §1.2.3 pattern).
- **Declare identifiers as values, never as map keys.** Detection and
  reporting tooling masks long numeric object keys, which makes signal
  paths illegible; `{ "system": "...", "ref": "<id>" }` keeps the id a
  value.
- **Declared, never verified.** The declarative semantics of §1.2.2 extends
  verbatim: ingestion does not resolve, fetch or compare any external
  reference; consumers MUST NOT treat an unresolved or non-matching
  reference as tampering. Documentation, reports and verifier output MUST
  say the reference is **declared** — never "verified", "bound" or
  "proven". What the registry proves is that the declaration was recorded
  at reception time (hashed, signed, chained, anchored): an export can
  declare the fingerprint of any document, but it cannot declare it
  retroactively.
- **Honest detection note.** Bare numeric ids of 13–19 digits (e.g. some
  e-commerce order ids) pass payment-card checksum heuristics in roughly
  10% of cases: tenants using such ids in `system`/`ref` pairs should
  expect occasional false-positive personal-data signals. This is a
  declared limitation of syntactic detection, remedied by per-signal
  suppression on the operator side — never by weakening detection.

#### 1.2.6 `payload.execution` (object, optional, admitted on every type — v1.4)

```json
"execution": { "ref": "84211" }
```

| Member | Level | Meaning |
|---|---|---|
| `ref` | REQUIRED when `execution` is present, string | the **source-native run/execution id of the execution that emits THIS event** (Make `{{var.scenario.executionId}}`, n8n `$execution.id`, a custom agent's session id) |

The `{ref, …}` shape is again consistent with `SubjectRef`. Note the
three-way relation — the three identifiers are frequently confused:

- `execution.ref` — the run id of the event's **own** execution;
- `delegation.parent.ref` (§1.2.2) — the run id of the **parent** execution
  that delegated to this one;
- `x-idempotency-key` — a transport header (§1), never an event field.

`subject.workflow.ref` identifies the workflow **definition**;
`execution.ref` identifies one **run** of it. With both conventions present,
each event declares the run it belongs to and the run that spawned it —
enough for a consumer to reconstruct a declared execution tree downstream.
The declarative semantics of §1.2.2 applies verbatim: the run id is
declared, never verified at ingestion, and an unknown or unmatched
`execution.ref` is not tampering.

## 2. Canonicalization (D12)

`actor`, `subject` and `payload` are canonicalized with **JCS — RFC 8785**
(recursive property ordering by UTF-16 code units, ECMAScript primitive
serialization, shortest-round-trip numbers, minimal string escapes, UTF-8, no
whitespace).

**Golden rule:** always re-canonicalize **from parsed values**, never from
serialized text. An export may spell a number `1000000000000000000000`; JCS
brings it back to `1e+21` (vector V1b). Escape differences are not tampering
(V1c).

Component hashes, lowercase hex (D8):

```
payload_hash = hex( SHA-256( JCS(payload) ) )
actor_hash   = hex( SHA-256( JCS(actor) ) )
subject_hash = hex( SHA-256( JCS(subject) ) )
```

`actor_hash`/`subject_hash` are intermediate values (not stored columns).

## 3. Timestamps (§2.2.3)

Wherever a timestamp enters a hash pre-image or an export:

```
YYYY-MM-DDTHH:MM:SS.ssssssZ
```

UTC, `T` separator, **exactly 6 fractional digits**, `Z` suffix.

## 4. Genesis (D4)

The `prev_hash` of a tenant's first event (`sequence_number = 1`) is:

```
prev_hash = hex( SHA-256( UTF8("humarch:genesis:" || tenant_id) ) )
```

with `tenant_id` in canonical lowercase hyphenated UUID form. Vector V0.

## 5. `event_hash` pre-image (D11)

```
pre-image =
  "humarch:event:v1" \n
  event_id           \n
  tenant_id          \n
  sequence_number    \n      (decimal, no leading zeros)
  received_at        \n      (format §3)
  occurred_at        \n      (format §3)
  source             \n      (enum text value)
  event_type         \n      (enum text value)
  actor_hash         \n
  subject_hash       \n
  payload_hash       \n
  prev_hash          \n

event_hash = hex( SHA-256( UTF8(pre-image) ) )
```

UUIDs lowercase. **Every line ends with `\n` (0x0A), the last one included.**
The first line is a versioned domain prefix: a future breaking change would
use `humarch:event:v2`, keeping old events verifiable under their own rule
(D33). `raw_payload`, `idempotency_key` and `signing_key_id` are deliberately
excluded from the pre-image. Vectors V2 and V3.

## 6. Signature (D13) and key identity (D16)

```
signature = hex( Ed25519-sign( private_key, bytes_from_hex(event_hash) ) )
```

The signed message is the **32 raw bytes** of the digest, not the hex string.
Signature is 64 bytes → 128 hex chars.

```
signing_key_id = "ed25519:" + first 16 hex chars of SHA-256(raw 32-byte public key)
```

The key id is **self-certifying**: verify it against the declared public key
without trusting any registry. A key's validity for the events it signed is
permanent (referential, not temporal). Public keys: `KEYS.md`.

## 7. Daily anchor (D9) and OpenTimestamps

For day `D` (UTC, `YYYY-MM-DD`), over all tenants with an entry that day,
sorted ascending by `tenant_id` as a UUID string:

```
aggregate_hash = hex( SHA-256( UTF8(
    "humarch:anchor:" || D || "\n"
    || per tenant:  tenant_id || ":" || last_event_hash || "\n"
) ) )
```

Vector V4. The `aggregate_hash` is timestamped with **OpenTimestamps**
(Bitcoin). Attestation lifecycle: `pending` → `submitted` (receipt obtained
from calendar servers) → `confirmed` (Bitcoin attestation complete). The
`.ots` file is a detached timestamp of exactly `aggregate_hash`.

Anchor verification levels (D64) — the level used MUST be declared in output:

1. **trustless** — official `opentimestamps-client` + Bitcoin Core (the gold
   standard citable in court);
2. **trust-minimized** (verifier default) — block-header check via public
   explorers;
3. **convenience** — opentimestamps.org drag & drop (quick check, not proof).

A confirmed anchor proves existence **at or before** its Bitcoin block time
and covers events up to that anchor; later events are protected by chain and
signatures until the next anchor confirms. Verifiers MUST state this rather
than hide it.

### 7.1 Qualified timestamp (RFC 3161, optional — v1.3, additive)

A day's `aggregate_hash` MAY additionally carry an **RFC 3161 timestamp
token** (a DER `TimeStampToken`, profile ETSI EN 319 422) issued on the SAME
32-byte digest the OTS anchor commits to. When the issuer is a **qualified
trust service provider** accredited under Regulation (EU) 910/2014 (eIDAS),
the token is a qualified electronic timestamp and carries the **art. 42
presumption of the accuracy of the date and time it indicates and of the
integrity of the data bound to it**. The two proofs are independent by
design: they share the hash, not the failure modes.

Semantics (normative): **the presumption attaches to the data the token
marks — the daily aggregate hash.** Every event verifiably contained in that
aggregate (through the §7 recomputation and the §5 chain, both deterministic
and reproducible by anyone) inherits that anteriority through derivation.
Implementations and derived material MUST NOT state or imply that each event
carries its own qualified timestamp.

Verification (any RFC 3161 tooling works — the reference verifier is not
privileged):

1. the token parses as CMS `SignedData` carrying a `TSTInfo`;
2. `TSTInfo.messageImprint` (SHA-256) equals the aggregate hash **recomputed
   from `anchor_entries_for_aggregate` per §7** — NOT the `aggregate_hash`
   field as it appears in the export. That field is supplied by whoever
   produced the document: binding the token to it lets a genuine
   (hash, token) pair lifted from a published export vouch for a fabricated
   entry set. Verifiers MUST bind to the recomputed value;
3. the TSA's signature over the signed attributes verifies against the
   signer certificate embedded in the token (tokens are requested with
   `certReq` TRUE so exports verify offline);
4. the signer chains to a TSA the verifying party trusts — for the
   qualification claim, one accredited under the **EU Trusted List**.
   E.g. `openssl ts -verify -digest <recomputed aggregate> -token_in
   -in token.tst -CAfile <TSA CA chain>` — the digest passed on the command
   line is the value recomputed at step 2, never the one read from the file.

A token that fails 1–3 is **invalid**; a token that passes 1–3 from an
issuer outside the verifying party's trusted set is a **valid token from an
untrusted TSA and carries no presumption**. Either outcome is declared and
MUST NOT change the outcome of the §7/§5 verification (the field is
additive; absence is the pre-1.3 form and stays fully valid).

A genuine token proves existence of the aggregate **at its own `genTime`**.
When `genTime` falls outside the declared day's window (for example a later
re-timestamp under the lifecycle strategy below), verifiers SHOULD say so
explicitly rather than present the token as proof of the declared day; the
token itself remains valid.

Lifecycle note (declared, not a mechanism): a qualified timestamp remains
verifiable for as long as its certificate chain can be validated —
typically ~20 years under current QTSP practices. Before that horizon is
reached, the operator's declared strategy is to re-timestamp the aggregates
under a then-current qualified TSA (an additive operation on the same
hashes), exactly as key rotation is declared in §6.

### 7.2 On-demand chain seal (RFC 3161, optional — v1.5, additive)

A registry MAY additionally issue, on request, an **on-demand chain seal**:
an RFC 3161 timestamp token (same profile as §7.1) issued on the **32 bytes
of one `event_hash`** — the tenant chain's **head** at sealing time. The
seal closes the intra-day window the daily anchor leaves open: the daily
registry (§7) is unchanged and unaware of it, and the nightly anchor keeps
covering the same events (an older independent proof only ever adds value).

Semantics (normative): **the presumption attaches to the data the token
marks — the chain-head `event_hash` at sealing time.** Every event
preceding that head in the chain (through the §5 recomputation,
deterministic and reproducible by anyone) inherits that anteriority through
derivation. A seal covers a chain **prefix**; implementations and derived
material MUST NOT state or imply that each event carries its own qualified
timestamp, and MUST speak of "the seal of the chain up to sequence N",
never of per-event marks.

Verification (any RFC 3161 tooling works — the reference verifier is not
privileged):

1. the token parses as CMS `SignedData` carrying a `TSTInfo` (§7.1 step 1);
2. `TSTInfo.messageImprint` (SHA-256) equals the event hash **recomputed
   from the §5 pre-image at the declared `sequence_number`, within the
   verified prefix of the export (§8 rule 10)** — NOT the event's declared
   `event_hash` field, and NOT any value carried by the seal element
   itself. Those fields are supplied by whoever produced the document:
   binding the token to them lets a genuine (hash, token) pair lifted from
   a published export vouch for a fabricated chain. Verifiers MUST bind to
   the recomputed value, and MUST treat a seal whose declared sequence the
   export does not contain — or that falls beyond the verified prefix — as
   a declared `invalid` (the chain up to it is not proven, so the prefix
   inheritance claim does not hold);
3. the TSA's signature verifies against the embedded signer certificate
   (§7.1 step 3);
4. the signer chains to a TSA the verifying party trusts (§7.1 step 4).
   E.g. `openssl ts -verify -digest <recomputed event_hash> -token_in
   -in token.tst -CAfile <TSA CA chain>` — the digest passed on the command
   line is the value recomputed at step 2, never one read from the file.

Outcomes are exactly the §7.1 ones: invalid / valid-but-untrusted / valid,
each **declared and additive** — none changes the outcome of the §5/§7
verification, and an export without seals is the pre-1.5 form and stays
fully valid. A genuine seal proves existence of the sealed head **at its
own `genTime`**; a `genTime` earlier than the sealed event's `received_at`
is incoherent and verifiers SHOULD say so explicitly. The §7.1 lifecycle
note (~20-year horizon, additive re-timestamping) applies verbatim to
seals.

## 8. Export format `humarch-export/v1` (D27)

A single self-contained JSON document (allegeable as-is):

```
{
  "format": "humarch-export/v1",
  "generated_at": <timestamp §3>,
  "tenant_id": <uuid>,
  "range": { "from_sequence": N, "to_sequence": M },
  "genesis_note": <string>,
  "signing_keys": [ { signing_key_id, algorithm, public_key, created_at, retired_at } ],
  "events": [ <full event rows, ordered by sequence_number ascending> ],
  "anchors": [ {
      anchor_date, aggregate_hash, ots_status, ots_btc_block?,
      entry: { tenant_id, last_event_id, last_event_hash, last_sequence_number },
      anchor_entries_for_aggregate: [ { tenant_id, last_event_hash } ... ],
      ots_file_base64?,  (present when the .ots receipt exists)
      qualified_timestamp?: {   (v1.3, §7.1 — present when the day has its mark)
          token_base64,  (DER TimeStampToken)
          tsa_name, policy_oid, gen_time
      }
  } ],
  "chain_seals"?: [ {   (v1.5, §7.2 — ordered by sequence_number ascending)
      sequence_number,   (the sealed chain head)
      token_base64,      (DER TimeStampToken)
      tsa_name, policy_oid, gen_time
  } ]
}
```

Normative rules:

1. Timestamps in the §3 format — verifiers use them **verbatim** in the
   pre-image, no reformatting.
2. `anchor_entries_for_aggregate` contains the pairs of **all** tenants of
   that day (the D9 input); other tenants' tip hashes are digests and reveal
   nothing.
3. For `pending` anchors `ots_file_base64` is absent and `ots_status` says so.
4. Events ordered by `sequence_number`, anchors by `anchor_date` (verifiers
   MUST NOT rely on the order, exporters MUST produce it).
5. The export MUST include every anchor whose day intersects the event range,
   when such anchors exist.
6. `raw_payload` is excluded by default (GDPR minimization); verification
   never needs it (D11).
7. `payload.personal`, when present, travels as its stored **envelope**
   (§1.1); `raw_payload`, when included under an explicit audit flag, is
   likewise an envelope and stays opaque to anyone without the subject DEK
   (D51). Neither affects verification: hashes are computed on the stored
   form (B8 rule, §1.1).
8. **Within one export, `sequence_number` and `event_id` are unique** (the
   registry holds one event per `(tenant_id, sequence_number)` and
   `event_id` is a primary key). A repetition of either is **malformed
   input**, not a tampering verdict: verifiers MUST refuse such a document
   with their malformed-input outcome rather than verify it.
9. **Export-supplied strings are hostile input at the point of DISPLAY.**
   Every string an export carries — identifiers, statuses, timestamps,
   provider names — may have been chosen by an attacker. A verifier MUST
   NOT emit them to a terminal, a log or a report without neutralizing the
   characters that can drive or reorder a display: Unicode categories Cc
   (controls), Cf (format, the bidirectional overrides and isolates among
   them), Zl and Zp (line and paragraph separators). A bidi override inside
   an `event_type` renders as a reversed line and can spell out a verdict
   the verifier never reached. Machine fields (`event_id`, `tenant_id`,
   `event_type`, `source`, timestamps, hex digests) MUST NOT contain any of
   those characters and a verifier MAY refuse such a document as malformed
   input — the reference verifier does. Provider-supplied display names
   (`qualified_timestamp.tsa_name`) are held only to the control-character
   rule, because a legitimate name may carry a directional mark, and are
   neutralized at display instead. The same discipline applies to the text
   of parser and I/O error messages: a JSON parser typically quotes the
   offending bytes verbatim, so echoing its message re-opens the hole a
   verifier just closed.
10. **Verification status is a property of the verified PREFIX, never of a
   sequence interval.** A verifier walks the events ordered by
   `sequence_number` and stops at the first failure, so what it has
   verified is the leading run of events it actually processed. Deriving
   "this event is verified" from `sequence_number ≤ verified_through` is
   wrong wherever the numbering is not strictly increasing — with a
   duplicated number it credits an unverified event with the integrity of
   its twin. Consumers and derived tooling (search, indexing, reporting)
   MUST carry the verified/unverified distinction positionally, and MUST
   present anything outside that prefix as not covered by integrity.
11. `qualified_timestamp` (v1.3) is OPTIONAL and additive: exports without it
   are the pre-1.3 form and verify identically. `token_base64` is the
   authoritative artifact — `tsa_name`, `policy_oid` and `gen_time` are
   convenience metadata that verifiers MUST take from the token itself, and
   the presence of the field asserts nothing: qualification is a property of
   the issuing TSA, established in verification (§7.1). Verifiers MUST cap
   the token size they are willing to parse (the reference cap is 64 KiB)
   and MUST treat an unreadable token as a declared `invalid`, never as a
   verification failure of the export.
12. `chain_seals` (v1.5) is OPTIONAL and additive: exports without it are
   the pre-1.5 form and verify identically. Elements are ordered by
   `sequence_number` ascending and each sealed sequence appears **at most
   once** (one seal per head); a repetition **or a misordering** is
   **malformed input**, rule-8 class — unlike rule 4's event/anchor
   ordering (an exporter obligation), this one binds verifiers too, and
   the reference verifier refuses such a document. `token_base64` is the
   authoritative artifact — `tsa_name`,
   `policy_oid` and `gen_time` are convenience metadata that verifiers MUST
   take from the token itself; note the element deliberately carries **no
   event hash**: the binding target exists only as the recomputed value of
   §7.2 step 2. The presence of the field asserts nothing: qualification is
   a property of the issuing TSA, established in verification. Verifiers
   MUST cap the token size they are willing to parse (the reference cap is
   64 KiB) and MUST treat an unreadable token as a declared `invalid`,
   never as a verification failure of the export.

A verifier processes the export as in the reference implementation
(`humarch-verify`): recompute component hashes (JCS from parsed values),
recompute `event_hash` from the D11 pre-image, check the chain link and dense
sequence (down to genesis when the range starts at 1; a mid-chain start is a
**declared** entry point), check the self-certifying key id, verify the
Ed25519 signature, then recompute anchor aggregates and verify `.ots`
attestations at the chosen level. First failure reported with its exact
sequence number.

## 9. Error contract

See `ERROR_CODES.md`. Codes are **stable**: removing or changing semantics is
a breaking change; additions are minor. Clients MUST treat unknown codes as
non-retryable unless the HTTP class is 5xx or 429.

## 10. Versioning (D33)

SemVer; the schema `$id` is versioned per major (`/v1/`). Additive changes
(new event types, new optional fields, new error codes) are minor. Breaking
changes take a new `$id` path and — if hashing is touched — a new domain
prefix in the pre-image (`humarch:event:v2`), so that a 2030 verification of
2026 events knows exactly which rules apply. The export format key
(`humarch-export/v1`) follows the same principle.

## 11. Conformance

An implementation is conformant when it reproduces:

- the crypto vectors **V0–V5** (`vectors/`),
- the shredding vector **V6** (`vectors/shredding/`) and the DEK-wrapping
  vector **W1** (`vectors/wrapping/`), for implementations that handle
  `payload.personal` (v1.1),
- the **25 schema cases** (`vectors/schema/`) — v09/v10 pin the v1.2 payload
  conventions (`tool_call`, `delegation`), v11/v12 the v1.4 conventions
  (`external_refs`, `execution`),
- the **message-id vectors** (`vectors/message-id/`, v1.4) for
  implementations that declare `message_id_sha256`: the §1.2.5 algorithm on
  folded, commented and duplicated headers, omission cases included,
- the **qualified-timestamp vectors** (`vectors/qualified/`, v1.3) for
  implementations that read the §7.1 field: the valid-mark export, the
  no-mark export (byte-identical pre-1.3 behavior), the digest-mismatch and
  malformed-token exports (declared `invalid`), and the valid-but-untrusted
  TSA case (declared, no presumption),
- the pipeline rules of §1,

and, for verifiers, accepts/rejects the sample exports pointing at the exact
failing sequence. The server is authoritative: local validation in adapters is
recommended but never substitutive.
