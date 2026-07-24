# Signing keys (Ed25519)

Registry of the Humarch system signing keys, current and historical (D16/D17).
Each `signing_key_id` is self-certifying: `"ed25519:" + first 16 hex chars of
SHA-256(raw 32-byte public key)` — verify it yourself, no trust required.

A key's validity for the events it signed is **permanent**: `retired_at` only
means the key stops signing *new* events.

## Production keys

| signing_key_id | public_key (hex) | created_at | retired_at |
|---|---|---|---|
| *(none yet — the first production key is generated at first deployment, per the operational procedure)* | | | |

## Test key (vectors only — NEVER valid in production)

The conformance vectors use the **RFC 8032 (TEST 1)** key, publicly known by
construction:

| signing_key_id | public_key (hex) |
|---|---|
| `ed25519:21fe31dfa154a261` | `d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a` |

This key MUST NOT appear in any production `signing_keys` registry; Humarch CI
and the database test suite enforce the ban.
