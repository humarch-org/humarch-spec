# Conformance vectors

These vectors are the **conformance contract** of the Humarch format (D73):
any writer, verifier or adapter implementation MUST reproduce them
byte-for-byte before being considered conformant.

| Directory | Vectors | What they pin down |
|---|---|---|
| `canonicalization/` | V1a–V1c | JCS (RFC 8785): recursive key ordering, ECMAScript numbers (`1e21` → `1e+21`), unicode, escape equivalence |
| `chain/` | V0, V2, V3 | per-tenant genesis (D4), component hashes, the 12-line `event_hash` pre-image (D11), Ed25519 signatures (D13) |
| `anchors/` | V4 | daily-anchor aggregate formula (D9) |
| `negative/` | V5a–V5c | tampering MUST be detected at the exact sequence; escape differences MUST NOT be flagged |
| `qualified/` | v1.3 exports + raw `.tst` tokens | the optional RFC 3161 qualified timestamp on the daily aggregate (§7.1): valid mark, digest mismatch, malformed token, valid-but-untrusted TSA, and the no-mark export that must behave exactly as pre-1.3 |
| `seal/` | v1.5 exports + raw `.tst` tokens | the optional on-demand chain seal on the chain-head `event_hash` (§7.2, §8 rule 12): valid seal, imprint mismatch, malformed token, over-cap token, sequence not present in the export, plus the `humarch-tsa/v1` trust fixture — binding is to the value recomputed within the verified prefix, and the no-seal export must behave exactly as pre-1.5 |
| `unavailable/` | v1.6 export pair + 4 malformed | the optional self-declaration of omitted proof artifacts (§8 rules 13–14): a document that omits all three artifacts and declares them, its twin that omits them silently — the two differ by `unavailable_artifacts` alone and MUST reach the same outcome, because a declaration is neither evidence nor an exemption — plus the repeated coordinate, the unknown `kind`, the coordinate of the wrong shape and the coordinate that does not belong to its kind, all four malformed input |
| `message-id/` | 14 cases | the §1.2.5 `message_id_sha256` algorithm: raw header field bodies (folded, commented, duplicated, unparsable) → the msg-id token and its digest, or `null` when the rule says the field must not be declared |
| `schema/` | 27 cases | ingestion envelope validation: 13 valid, 14 invalid, each invalid case pinning a JSON Pointer expected **among** the validator's errors (not "the first" — draft 2020-12 leaves the order implementation-defined, SPEC §9). v09/v10 pin the v1.2 payload conventions `tool_call`/`delegation`, v11/v12 the v1.4 conventions `external_refs`/`execution` (SPEC §1.2); v13/i14 are the two halves of the v1.7 reservation of `__tenant_default__` (SPEC §1.1) — i14 that an `end_client` claiming the sentinel is refused, v13 that `workflow` and `tool` are not, so widening the refusal is as much a test diff as dropping it |
| `shredding/` | V6 | `payload.personal` envelope (AES-256-GCM, AAD = `humarch:pii:v1:<subject>`): hashes on the stored form, verification without decryption, shred changes no byte (B8 §8.9) |
| `wrapping/` | W1 | DEK wrapping at rest (AES-256-CBC + HMAC-SHA256 Encrypt-then-MAC, HKDF-Expand subkeys, D55): round-trip, tamper ⇒ MAC failure before decryption, wrong KEK rejected (B8 §8.4.1) |

## The keys, and what you can regenerate

Two keys sign the material in this tree, and they answer different questions.
Which one signed a vector decides whether you can **regenerate** it or only
**verify** it.

The **regenerable** vectors — the crypto vectors of `chain/`, `anchors/`,
`negative/`, `canonicalization/`, `shredding/` and `wrapping/` — are signed
with the **RFC 8032 (TEST 1)** Ed25519 key, whose seed is right here, so
anyone can recompute every byte from scratch:

```
seed (private):  9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60
public_key:      d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a
signing_key_id:  ed25519:21fe31dfa154a261
```

The **export** vectors — the 15 `humarch-export/v1` documents under
`qualified/`, `seal/` and `unavailable/` — are signed with
`ed25519:dc5578a147d359bf`, whose seed is **not** in this repository and will
not be: they are **verify-only**. Their public key travels inside each
document, which is exactly the situation SPEC.md §8 describes — a signature
under a document-supplied key proves internal consistency, not attribution —
so treat them as what they are, fixtures for exercising a verifier, never as
attributed evidence. Everything about them except the signature is
recomputable: hashes, chain links, aggregates and the `.ots` and RFC 3161
artifacts all reproduce from the documents themselves.

Saying this plainly is the point. The earlier wording claimed *all*
signatures used the RFC 8032 key "so that anyone can regenerate every value
from scratch", which is false of those 15 files; a clean-room implementer who
took it at face value would conclude the suite was broken when the signature
would not reproduce.

The RFC 8032 key is public knowledge and MUST NEVER appear in a production
`signing_keys` registry (checked in CI and by the pgTAP suite).

## How to re-run

Reference libraries (any conformant JCS/Ed25519 stack works):

- JCS: `canonicalize` (npm, listed in RFC 8785 Appendix G) or `rfc8785` (PyPI)
- Ed25519 / SHA-256: the runtime's standard crypto (WebCrypto, `node:crypto`,
  libsodium, `cryptography`)

```sh
deno task test   # runs the schema cases and re-computes the crypto vectors
```

Golden rule: re-canonicalize **from parsed values**, never from the serialized
text (see `SPEC.md`).
