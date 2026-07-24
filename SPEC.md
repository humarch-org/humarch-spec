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

### 1.2 Payload conventions: `tool_call` and `delegation` (v1.2, additive)

Two optional payload conventions normalize how implementations record **tool
invocations** and **delegation between executions**. The payload stays open
(D30): neither field is ever required, and their absence is never a
validation error. But **if** an implementation records a tool invocation or a
delegation relationship in the payload, it MUST use these field names and
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
  presence. No new validation is added at ingestion in v1.2: a malformed
  `tool_call` or `delegation` is NOT a `SCHEMA_VIOLATION` (a future version
  MAY harden this, per D33; the trigger would be a real dispute over a
  malformed convention field).
- **Convention fields hash, chain and sign like any other payload content —
  no new verification surface.** The crypto vectors V0–V6/W1 are unaffected
  by construction (the payload was already open); schema cases v09/v10
  (`vectors/schema/valid/`) pin the canonical field names in the conformance
  contract.

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
      ots_file_base64?   (present when the .ots receipt exists)
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
- the **23 schema cases** (`vectors/schema/`) — v09/v10 pin the §1.2 payload
  conventions (`tool_call`, `delegation`),
- the pipeline rules of §1,

and, for verifiers, accepts/rejects the sample exports pointing at the exact
failing sequence. The server is authoritative: local validation in adapters is
recommended but never substitutive.
