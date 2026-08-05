// Chain-seal vectors (SPEC §7.2/§8 rule 12, v1.5) — the spec-side gate stays
// implementation-independent: no ASN.1 parser here. What a third party can
// check from the published JSON alone, it checks: the field shape and
// ordering, the size cap, and the fact that the RFC 3161 messageImprint —
// the raw digest bytes — rides verbatim inside the DER token, so the valid
// vector's token visibly commits to the sealed head's event hash and the
// mismatch vector's visibly does not. Cryptographic verification of the
// tokens is the reference verifier's gate (humarch-verify).
import { assert, assertEquals } from "jsr:@std/assert@1";

const vec = (p: string) =>
  JSON.parse(Deno.readTextFileSync(new URL(`../vectors/seal/${p}`, import.meta.url)));
const raw = (p: string) => Deno.readFileSync(new URL(`../vectors/seal/${p}`, import.meta.url));
const toHex = (b: Uint8Array) => Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");
const b64ToBytes = (s: string) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));
const MAX_TST_BYTES = 64 * 1024; // §8 rule 12 reference cap

Deno.test("seal vectors: field shape, ordering, one seal per head", () => {
  for (
    const name of [
      "export-seal.json",
      "export-seal-mismatch.json",
      "export-seal-unknown-sequence.json",
    ]
  ) {
    const seals = vec(name).chain_seals;
    assert(Array.isArray(seals) && seals.length > 0, `${name}: chain_seals is a non-empty array`);
    let prev = 0;
    const seen = new Set<number>();
    for (const s of seals) {
      assert(Number.isInteger(s.sequence_number) && s.sequence_number >= 1);
      assert(!seen.has(s.sequence_number), `${name}: one seal per head (rule 12)`);
      seen.add(s.sequence_number);
      assert(s.sequence_number >= prev, `${name}: ordered by sequence (rule 12)`);
      prev = s.sequence_number;
      assertEquals(typeof s.token_base64, "string");
      assertEquals(typeof s.tsa_name, "string");
      assertEquals(typeof s.policy_oid, "string");
      assertEquals(typeof s.gen_time, "string");
      assert(!("event_hash" in s), "the element carries NO event hash (rule 12): the binding target exists only recomputed");
      assert(b64ToBytes(s.token_base64).byteLength <= MAX_TST_BYTES, `${name}: token within cap`);
    }
  }
});

Deno.test("seal vectors: the valid token commits to the sealed head's event hash", () => {
  const exp = vec("export-seal.json");
  const seal = exp.chain_seals[0];
  const head = exp.events.find(
    (e: { sequence_number: number }) => e.sequence_number === seal.sequence_number,
  );
  assert(head, "the sealed sequence is present in the export");
  const tokenHex = toHex(b64ToBytes(seal.token_base64));
  assert(
    tokenHex.includes(head.event_hash),
    "the messageImprint digest must ride verbatim inside the DER token",
  );
  // The raw .tst artifact is the same bytes the export carries.
  assertEquals(tokenHex, toHex(raw("seal-local.tst")));
});

Deno.test("seal vectors: the mismatch token visibly does NOT commit to the declared head", () => {
  const exp = vec("export-seal-mismatch.json");
  const seal = exp.chain_seals[0];
  const head = exp.events.find(
    (e: { sequence_number: number }) => e.sequence_number === seal.sequence_number,
  );
  const tokenHex = toHex(b64ToBytes(seal.token_base64));
  assert(!tokenHex.includes(head.event_hash), "a token for another hash must not match");
  assertEquals(tokenHex, toHex(raw("seal-mismatch-local.tst")));
});

Deno.test("seal vectors: malformed and over-cap tokens", () => {
  const malformed = vec("export-seal-malformed.json").chain_seals[0];
  // A truncated token: starts like a SEQUENCE but cannot parse whole — the
  // spec-side check is only that it differs from the valid artifact and the
  // reference verifier declares it invalid (its gate).
  assert(
    toHex(b64ToBytes(malformed.token_base64)) !== toHex(raw("seal-local.tst")),
    "deliberately not the valid token",
  );
  const oversize = vec("export-seal-oversize.json").chain_seals[0];
  assert(
    b64ToBytes(oversize.token_base64).byteLength > MAX_TST_BYTES,
    "the oversize vector exceeds the rule-12 reference cap",
  );
});

Deno.test("seal vectors: the unknown-sequence vector declares a head the export does not contain", () => {
  const exp = vec("export-seal-unknown-sequence.json");
  const seal = exp.chain_seals[0];
  assert(
    !exp.events.some(
      (e: { sequence_number: number }) => e.sequence_number === seal.sequence_number,
    ),
    "the sealed sequence must be absent from the export (declared-invalid case)",
  );
});

Deno.test("SPEC §7.2: the binding step names the RECOMPUTED head within the verified prefix", () => {
  // The spec IS the contract third parties implement against (external
  // audit trap 10, 2026-07-29): an implementer who binds the token to the
  // declared `event_hash` field builds a verifier a stolen (hash, token)
  // pair defeats. The wording is load-bearing, so it is pinned here.
  const spec = Deno.readTextFileSync(new URL("../SPEC.md", import.meta.url))
    .replace(/\r\n/g, "\n");
  const at72 = spec.indexOf("### 7.2 On-demand chain seal");
  assert(at72 >= 0, "§7.2 must exist");
  const s72 = spec.slice(at72, spec.indexOf("## 8.", at72));
  const step2At = s72.indexOf("2. `TSTInfo.messageImprint`");
  assert(step2At >= 0, "§7.2 step 2 must exist");
  const step2 = s72.slice(step2At, s72.indexOf("\n3. ", step2At)).replace(/\s+/g, " ");
  assert(/recomputed/i.test(step2), "§7.2 step 2 must bind the token to the RECOMPUTED value");
  assert(
    /NOT the event's declared `event_hash` field/i.test(step2),
    "§7.2 step 2 must rule out the declared field explicitly",
  );
  assert(/verified prefix/i.test(step2), "§7.2 step 2 must scope the binding to the verified prefix");
  // The prefix semantics is normative and the per-event formulation banned.
  assert(
    /MUST NOT state or imply that each event carries its own qualified timestamp/.test(
      s72.replace(/\s+/g, " "),
    ),
    "§7.2 must ban the per-event formulation",
  );
  // Rule 12 must assign BOTH repetition and misordering to the malformed
  // class (lens-3 review: the reference verifier exits 4 on either, and a
  // third party following the spec alone must not accept what the
  // reference refuses).
  const at12 = spec.indexOf("12. `chain_seals`");
  assert(at12 >= 0, "§8 rule 12 must exist");
  const rule12 = spec.slice(at12, spec.indexOf("\nA verifier processes", at12)).replace(/\s+/g, " ");
  assert(
    /repetition \*\*or a misordering\*\* is \*\*malformed input\*\*/.test(rule12),
    "rule 12 must declare repetition AND misordering malformed",
  );
});

Deno.test("seal vectors: tsa-trust document shape (humarch-tsa/v1)", () => {
  const doc = vec("tsa-trust-seal.json");
  assertEquals(doc.format, "humarch-tsa/v1");
  assert(Array.isArray(doc.tsas) && doc.tsas.length >= 2, "both fixture TSAs are pinned");
  for (const t of doc.tsas) {
    assert(Array.isArray(t.sha256_cert_fingerprints) && t.sha256_cert_fingerprints.length > 0);
    for (const f of t.sha256_cert_fingerprints) assert(/^[0-9a-f]{64}$/.test(f));
  }
});
