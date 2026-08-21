# Error codes (public API contract)

Every error response of the ingestion API has this body (B4 §4.5):

```json
{
  "error_code": "SCHEMA_VIOLATION",
  "detail": "actor.type must be equal to one of the allowed values at /actor/type",
  "request_id": "8b6c9d2e-4f5a-4b1c-9d0e-7a8b9c0d1e2f"
}
```

- `error_code` — stable, documented string: the only field automation may
  parse.
- `detail` — human-readable English; for `SCHEMA_VIOLATION` it carries **a**
  JSON Pointer to **a** field that violates the schema. Not "the first": JSON
  Schema draft 2020-12 leaves error order implementation-defined, so no
  validator can promise position (SPEC.md §9). The `detail` never echoes the
  rejected value — an echo in a public error body is where a personal datum
  would leave the system.
- `request_id` — always present, also echoed in the `x-request-id` header of
  **every** response (including `202`).

## Registry (v1)

| `error_code` | HTTP | Meaning | Retry? |
|---|---|---|---|
| `UNAUTHORIZED` | 401 | Key missing, malformed, unknown or revoked | No (fix the key) |
| `TENANT_SUSPENDED` | 403 | Valid key, suspended tenant | No (contact the operator) |
| `UNKNOWN_SOURCE` | 404 | `{source}` path segment not recognized | No |
| `METHOD_NOT_ALLOWED` | 405 | Method other than POST | No |
| `DUPLICATE_IDEMPOTENCY_KEY` | 409 | Same key, different content (D24) | No (client bug) |
| `PAYLOAD_TOO_LARGE` | 413 | Body > 256 KB | No |
| `INVALID_PAYLOAD` | 400 | Body is not valid JSON or not an object | No |
| `SCHEMA_VIOLATION` | 422 | Valid JSON but not conformant to the spec (missing field, enum out of range, U+0000, impossible adapter mapping, `corrects` not found) | No |
| `RATE_LIMITED` | 429 | Per-tenant quota exhausted in the window | **Yes**, after `Retry-After` seconds |
| `INTERNAL_ERROR` | 500 | System fault (never the request's fault) | **Yes**, exponential backoff; idempotency makes the retry safe |
| `WRITE_CONTENTION` | 503 | Transient contention on the tenant's chain lock (added 2026-07-13, minor change per rule 1) | **Yes**, after `Retry-After` seconds; idempotency makes the retry safe |

## Binding rules

1. Codes are **stable**: removing one or changing its semantics is a breaking
   change of this spec; adding codes is a minor change. Clients MUST treat
   unknown codes as non-retryable unless the HTTP class is 5xx or 429.
2. `detail` is for humans and is **not parseable**: automation looks only at
   `error_code` and the headers.
3. The success response is `202 {event_id, sequence_number, event_hash}`
   (`event_hash` added in v1.4 as an additive **echo field** — the stored
   event's hash, present on first write and on replay alike; clients that do
   not read it are unaffected, error bodies never carry it); an idempotent
   replay adds `idempotent_replay: true` (D24/E6).
4. On `401` the `detail` is identical for missing/malformed/unknown/revoked
   keys ("authentication failed"): no enumeration oracle.
