// Qualified-timestamp vectors (SPEC §7.1/§8 rule 8, v1.3) — the spec-side
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
const MAX_TST_BYTES = 64 * 1024; // §8 rule 8 reference cap

Deno.test("qualified vectors: field shape and size cap", () => {
  for (const name of ["export-qualified.json", "export-qualified-mismatch.json"]) {
    const qt = vec(name).anchors[0].qualified_timestamp;
    assertEquals(typeof qt.token_base64, "string");
    assertEquals(typeof qt.tsa_name, "string");
    assertEquals(typeof qt.policy_oid, "string");
    assertEquals(typeof qt.gen_time, "string");
    assert(b64ToBytes(qt.token_base64).byteLength <= MAX_TST_BYTES, `${name}: token within cap`);
  }
});

Deno.test("qualified vectors: the valid token commits to the anchor's aggregate", () => {
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

Deno.test("qualified vectors: tsa-trust document shape (humarch-tsa/v1)", () => {
  const doc = vec("tsa-trust-local.json");
  assertEquals(doc.format, "humarch-tsa/v1");
  assert(Array.isArray(doc.tsas) && doc.tsas.length > 0);
  for (const t of doc.tsas) {
    assert(Array.isArray(t.sha256_cert_fingerprints) && t.sha256_cert_fingerprints.length > 0);
    for (const f of t.sha256_cert_fingerprints) assert(/^[0-9a-f]{64}$/.test(f));
  }
});
