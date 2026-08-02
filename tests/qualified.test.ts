// Qualified-timestamp vectors (SPEC §7.1/§8 rule 11, v1.3) — the spec-side
// gate stays implementation-independent: no ASN.1 parser here. What a third
// party can check from the published JSON alone, it checks: the field shape,
// the size cap, and the fact that the RFC 3161 messageImprint — the raw
// digest bytes — rides verbatim inside the DER token, so the valid vector's
// token visibly commits to its anchor's aggregate_hash and the mismatch
// vector's visibly does not. Cryptographic verification of the tokens is the
// reference verifier's gate (humarch-verify, two TSA implementations).
import { assert, assertEquals } from "jsr:@std/assert@1";

const vec = (p: string) =>
  JSON.parse(Deno.readTextFileSync(new URL(`../vectors/qualified/${p}`, import.meta.url)));
const raw = (p: string) => Deno.readFileSync(new URL(`../vectors/qualified/${p}`, import.meta.url));
const toHex = (b: Uint8Array) => Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");
const b64ToBytes = (s: string) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));
const MAX_TST_BYTES = 64 * 1024; // §8 rule 11 reference cap

Deno.test("qualified vectors: field shape and size cap", () => {
  for (
    const name of [
      "export-qualified.json",
      "export-qualified-today.json",
      "export-qualified-mismatch.json",
    ]
  ) {
    const qt = vec(name).anchors[0].qualified_timestamp;
    assertEquals(typeof qt.token_base64, "string");
    assertEquals(typeof qt.tsa_name, "string");
    assertEquals(typeof qt.policy_oid, "string");
    assertEquals(typeof qt.gen_time, "string");
    assert(b64ToBytes(qt.token_base64).byteLength <= MAX_TST_BYTES, `${name}: token within cap`);
  }
});

Deno.test("qualified vectors: the valid token commits to the anchor's aggregate", () => {
  // Same-day mark: the token was issued on THIS day's aggregate (the
  // export-qualified.json pair is the later re-timestamp case, SPEC 7.1).
  const today = vec("export-qualified-today.json").anchors[0];
  assert(
    toHex(b64ToBytes(today.qualified_timestamp.token_base64)).includes(today.aggregate_hash),
    "the same-day token commits to the recomputed aggregate",
  );
  const exp = vec("export-qualified.json");
  const anchor = exp.anchors[0];
  const tokenHex = toHex(b64ToBytes(anchor.qualified_timestamp.token_base64));
  assert(
    tokenHex.includes(anchor.aggregate_hash),
    "the messageImprint digest must ride verbatim inside the DER token",
  );
  // The raw .tst artifacts are the same bytes the export carries.
  assertEquals(tokenHex, toHex(raw("real-local.tst")));
});

Deno.test("qualified vectors: the mismatch token visibly does NOT commit to this aggregate", () => {
  const exp = vec("export-qualified-mismatch.json");
  const anchor = exp.anchors[0];
  const tokenHex = toHex(b64ToBytes(anchor.qualified_timestamp.token_base64));
  assert(!tokenHex.includes(anchor.aggregate_hash), "a token for another digest must not match");
});

Deno.test("qualified vectors: the malformed token is not a DER SEQUENCE", () => {
  const qt = vec("export-qualified-malformed.json").anchors[0].qualified_timestamp;
  const bytes = b64ToBytes(qt.token_base64);
  assert(bytes[0] !== 0x30, "deliberately not a TimeStampToken");
});

Deno.test("SPEC §7.1: the binding step names the RECOMPUTED aggregate", () => {
  // The spec IS the contract third parties implement against. An
  // implementer who binds the token to the `aggregate_hash` field carried by
  // the export — producer-supplied data — builds a verifier that a stolen
  // (hash, token) pair defeats. The wording is load-bearing, so it is
  // pinned here (external audit, 2026-07-29).
  // Line endings vary by checkout (CRLF on Windows): normalize, then read a
  // window from the step's opening rather than matching its punctuation.
  const spec = Deno.readTextFileSync(new URL("../SPEC.md", import.meta.url))
    .replace(/\r\n/g, "\n");
  const at = spec.indexOf("2. `TSTInfo.messageImprint`");
  assert(at >= 0, "§7.1 step 2 must exist");
  // Collapse the wrapping: a normative phrase must be found whether or not
  // the paragraph happens to break in the middle of it.
  const step2 = spec.slice(at, spec.indexOf("\n3. ", at)).replace(/\s+/g, " ");
  assert(step2.length > 0, "§7.1 step 2 must be followed by step 3");
  assert(
    /recomputed/i.test(step2),
    "§7.1 step 2 must bind the token to the RECOMPUTED aggregate",
  );
  assert(
    /NOT the `aggregate_hash` field/i.test(step2),
    "§7.1 step 2 must rule out the declared field explicitly",
  );
});

Deno.test("qualified vectors: tsa-trust document shape (humarch-tsa/v1)", () => {
  const doc = vec("tsa-trust-local.json");
  assertEquals(doc.format, "humarch-tsa/v1");
  assert(Array.isArray(doc.tsas) && doc.tsas.length > 0);
  for (const t of doc.tsas) {
    assert(Array.isArray(t.sha256_cert_fingerprints) && t.sha256_cert_fingerprints.length > 0);
    for (const f of t.sha256_cert_fingerprints) assert(/^[0-9a-f]{64}$/.test(f));
  }
});
