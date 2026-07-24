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
| `schema/` | 23 cases | ingestion envelope validation: 10 valid, 13 invalid with the JSON Pointer of the expected first error (v09/v10 pin the v1.2 payload conventions `tool_call`/`delegation`, SPEC §1.2) |
| `shredding/` | V6 | `payload.personal` envelope (AES-256-GCM, AAD = `humarch:pii:v1:<subject>`): hashes on the stored form, verification without decryption, shred changes no byte (B8 §8.9) |
| `wrapping/` | W1 | DEK wrapping at rest (AES-256-CBC + HMAC-SHA256 Encrypt-then-MAC, HKDF-Expand subkeys, D55): round-trip, tamper ⇒ MAC failure before decryption, wrong KEK rejected (B8 §8.4.1) |

## The test key

All signatures use the **RFC 8032 (TEST 1)** Ed25519 key, so that anyone can
regenerate every value from scratch:

```
seed (private):  9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60
public_key:      d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a
signing_key_id:  ed25519:21fe31dfa154a261
```

This key is public knowledge and MUST NEVER appear in a production
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
