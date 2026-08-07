// Unavailable-artifact vectors (SPEC §8 rules 13-14, v1.6) — the spec-side
// gate stays implementation-independent: no crypto here. What a third party
// can check from the published JSON alone, it checks: the element shapes, the
// exporter ordering, and above all the PAIR — the declaring export and its
// silent twin differ by `unavailable_artifacts` and by nothing else, which is
// the whole normative point (a declaration is neither evidence nor an
// exemption, so the outcome must not move). The cryptographic proof that the
// outcome really does not move is the reference verifier's gate
// (humarch-verify: same verdict, same exit code, on both files).
import { assert, assertEquals } from "jsr:@std/assert@1";

const vec = (p: string) =>
  JSON.parse(Deno.readTextFileSync(new URL(`../vectors/unavailable/${p}`, import.meta.url)));

const DECLARING = "export-unavailable.json";
const TWIN = "export-no-declaration.json";
const MALFORMED = [
  "export-unavailable-duplicate.json",
  "export-unavailable-unknown-kind.json",
  "export-unavailable-bad-coordinate.json",
  "export-unavailable-kind-mismatch.json",
];

const KINDS = ["ots_receipt", "qualified_timestamp", "chain_seal"];
const DATE_YMD = /^\d{4}-\d{2}-\d{2}$/;

Deno.test("unavailable vectors: the declaring export omits all three artifacts and names them", () => {
  const exp = vec(DECLARING);
  // The document is the realistic rule-13 case: nothing resolved, so nothing
  // rides. A metadata-only entry would claim a proof without carrying it.
  const anchor = exp.anchors[0];
  assert(!("ots_file_base64" in anchor), "the omitted receipt leaves no trace in the anchor");
  assert(!("qualified_timestamp" in anchor), "the omitted mark leaves no trace in the anchor");
  assert(!("chain_seals" in exp), "the omitted seal leaves no element behind");
  assert(anchor.ots_status !== "pending", "a pending anchor never had a receipt to omit");

  const decl = exp.unavailable_artifacts;
  assert(Array.isArray(decl) && decl.length === 3, "all three kinds are exercised");
  assertEquals(
    decl.map((d: { kind: string }) => d.kind),
    KINDS,
    "ordered by kind as rule 14 lists",
  );
  for (const d of decl) {
    assert(KINDS.includes(d.kind), `unknown kind ${d.kind}`);
    const members = Object.keys(d).sort();
    const coordinate = d.kind === "chain_seal" ? "sequence_number" : "anchor_date";
    assertEquals(members, ["kind", coordinate].sort(), "no member beyond kind and its coordinate");
    if (coordinate === "anchor_date") {
      assert(DATE_YMD.test(d.anchor_date), "the anchor coordinate is a strict YYYY-MM-DD");
      assert(
        exp.anchors.some((a: { anchor_date: string }) => a.anchor_date === d.anchor_date),
        "the declared anchor is one this export carries",
      );
    } else {
      assert(Number.isInteger(d.sequence_number) && d.sequence_number >= 1);
    }
  }
  // The one member the format deliberately does NOT have: free text. An
  // exporter-supplied string is hostile input at the point of display
  // (rule 9), and no reason a producer gives about itself is verifiable.
  for (const d of decl) {
    for (const forbidden of ["reason", "note", "message", "detail", "error"]) {
      assert(!(forbidden in d), `no free-text ${forbidden} member exists in this format`);
    }
  }
});

Deno.test("unavailable vectors: the pair differs by the declaration and by NOTHING else", () => {
  // This is the vector that makes the semantics falsifiable. If the two
  // documents differed anywhere else, "same outcome with and without the
  // array" would be an untested claim.
  const declaring = vec(DECLARING);
  const twin = vec(TWIN);
  assert("unavailable_artifacts" in declaring, "the declaring twin declares");
  assert(!("unavailable_artifacts" in twin), "the silent twin does not");
  delete declaring.unavailable_artifacts;
  assertEquals(
    JSON.stringify(declaring),
    JSON.stringify(twin),
    "the two documents are otherwise identical",
  );
});

Deno.test("unavailable vectors: the four malformed cases are each malformed in their declared way", () => {
  const seen = new Set<string>();
  for (const name of MALFORMED) {
    const decl = vec(name).unavailable_artifacts;
    assert(Array.isArray(decl) && decl.length > 0, `${name}: carries the array`);
    seen.add(name);
  }
  assertEquals(seen.size, 4, "all four cases exist");

  // (a) the same (kind, coordinate) pair twice: an artifact cannot be
  // missing twice, and a repetition is the decoy-riding pattern rule 8
  // refuses on event ids and rule 12 on sealed sequences.
  const dup = vec(MALFORMED[0]).unavailable_artifacts;
  const keys = dup.map((d: Record<string, unknown>) =>
    `${d.kind}|${d.anchor_date ?? d.sequence_number}`
  );
  assert(new Set(keys).size < keys.length, "the duplicate vector really repeats a coordinate");

  // (b) an unknown kind: the enumeration is closed, so a fourth kind is a
  // form error, never a member to ignore.
  const unknown = vec(MALFORMED[1]).unavailable_artifacts;
  assert(
    unknown.some((d: { kind: string }) => !KINDS.includes(d.kind)),
    "the unknown-kind vector really carries a kind outside the enumeration",
  );

  // (c) a coordinate of the wrong shape. Date.parse is lenient — the string
  // below parses, to a DIFFERENT day (the W2 class) — so the coordinate is
  // only ever the strict YYYY-MM-DD the format declares.
  const bad = vec(MALFORMED[2]).unavailable_artifacts;
  assert(
    bad.some((d: { anchor_date?: string }) =>
      typeof d.anchor_date === "string" && !DATE_YMD.test(d.anchor_date)
    ),
    "the bad-coordinate vector really carries a non-date",
  );

  // (d) a coordinate that does not belong to its kind: a seal has no anchor
  // date. Both members are individually well-formed, which is exactly why
  // the pairing has to be checked.
  const mismatch = vec(MALFORMED[3]).unavailable_artifacts;
  assert(
    mismatch.some((d: Record<string, unknown>) =>
      d.kind === "chain_seal" && !("sequence_number" in d) && "anchor_date" in d
    ),
    "the kind-mismatch vector really pairs a seal with an anchor coordinate",
  );
});

Deno.test("SPEC §8 rule 14 (1.6.0): a declaration is neither evidence nor an exemption", () => {
  // The spec IS the contract third parties implement against (external audit
  // trap 10, 2026-07-29): an implementer who reads a declaration as an
  // excuse builds a verifier that an attacker defeats by stripping a genuine
  // proof and declaring it gone. The wording is load-bearing, so it is
  // pinned here, exactly as §7.2's binding step is.
  const spec = Deno.readTextFileSync(new URL("../SPEC.md", import.meta.url))
    .replace(/\r\n/g, "\n");
  const at14 = spec.indexOf("14. **`unavailable_artifacts`");
  assert(at14 >= 0, "§8 rule 14 must exist");
  const rule14 = spec.slice(at14, spec.indexOf("\nA verifier processes", at14))
    .replace(/\s+/g, " ");

  // These assertions pin SCOPE, not vocabulary. An unanchored substring test
  // ("does the phrase appear somewhere?") survives edits that move the phrase
  // onto a different subject — which is exactly how a normative sentence gets
  // hollowed out while its test stays green (adversarial review, 2026-08-06:
  // three material weakenings passed the first version of this test). Each
  // regex below therefore carries the clause it governs.
  assert(
    /neither evidence nor an exemption/.test(rule14),
    "rule 14 must say what a declaration is NOT, in those terms",
  );
  assert(
    /assertion by whoever produced the document about that producer's own operational state, and whoever produced the document may be the adversary/
      .test(rule14),
    "rule 14 must name who is speaking, and that it may be the attacker",
  );
  assert(
    /attacker who strips a genuine proof and adds the matching declaration MUST obtain \*\*exactly\*\* the outcome of the plain absence/
      .test(rule14),
    "rule 14 must state the exit-neutrality requirement as an adversarial one",
  );
  assert(
    /the verification outcome — and, for the reference verifier, the exit\s+code — MUST be identical to the outcome for the same document with this\s+array removed/
      .test(rule14),
    "rule 14 must give the neutrality a testable formulation naming the exit code",
  );
  // The carve-out (same review, finding 1): without it the neutrality MUST is
  // literally false of the reference verifier, which exits 4 on a malformed
  // array — and an implementer following the letter would ACCEPT duplicate
  // declarations to keep the exit codes equal.
  assert(
    /for a \*\*well-formed\*\* array/.test(rule14),
    "the neutrality requirement must be scoped to a well-formed array",
  );
  assert(
    /A malformed array is\s+malformed input under the paragraph above, and refusing to read such a\s+document is that refusal and not a verdict about its proofs/.test(rule14),
    "rule 14 must say that refusing a malformed array is not a verdict about the proofs",
  );
  assert(
    /governs what a declaration may do to a verification, never\s+whether a document parses/.test(rule14),
    "rule 14 must draw the boundary between neutrality and parsing",
  );
  assert(
    /MUST NOT treat a declared artifact\s+as present, as proven to have existed, or as softening any conclusion\s+the document earns without the array/.test(rule14),
    "the three forbidden readings must stay attached to the same MUST NOT",
  );
  // Self-contradiction (same review, finding 4): a document that carries an
  // artifact it also declares unavailable must not let a reader re-read a
  // verification failure as an availability problem.
  assert(
    /contradicts itself\*\* by carrying an artifact it also declares\s+unavailable, which changes no outcome/.test(rule14),
    "rule 14 must cover the self-contradicting document explicitly",
  );
  assert(
    /the ABSENCE of a\s+declaration asserts nothing, since an exporter of an earlier version —\s+or one that never attempted the resolution — omits silently/.test(rule14),
    "rule 14 must close the converse reading with its reason",
  );
  // The whole rendering contract lives in one sentence: pin it entire.
  assert(
    /A verifier MAY present the declared list, and the reference\s+verifier does, as \*\*declared facts naming who is speaking\*\*, never as a\s+finding of its own\./.test(rule14),
    "rule 14 must keep the presentation contract intact",
  );
  // The mechanism is ONE, not three ad-hoc fields, and it is additive.
  assert(/single, OPTIONAL mechanism/.test(rule14), "one mechanism for all three artifacts");
  assert(/pre-1\.6 form and verify identically/.test(rule14), "the array is additive");
  // No free-text member, with the reason given (rule 9 is the reason), and
  // the forward-compatibility rule for members this version does not know.
  assert(
    /carrying no other\s+member, and in particular no free-text reason: an exporter-supplied\s+string is hostile input at the point of display \(rule 9\)/.test(rule14),
    "rule 14 must rule out free text AND say why, in the same breath",
  );
  assert(
    /a verifier MUST ignore a member it does not know\s+rather than refuse it/.test(rule14) &&
      /MUST NOT display one/.test(rule14),
    "rule 14 must say what a verifier does with an unknown member: ignore, never display",
  );
  // Form class, explicitly: rule-8 for the content, rule-4 for the ordering.
  // Both halves name their own subject, so neither can be swapped onto the
  // other (the third weakening the review found).
  assert(
    /A repetition, an unknown\s+`kind`, a coordinate of the wrong shape, or a coordinate that does not\s+belong to its kind is \*\*malformed input\*\*, rule-8 class/.test(rule14),
    "the four form errors must stay enumerated as malformed input",
  );
  assert(
    /the ordering,\s+like rule 4's, binds exporters only/.test(rule14),
    "and the ordering — that one, not the repetition — binds exporters only",
  );
});

Deno.test("SPEC §8 rule 13: emended by rule 14, not contradicted", () => {
  // The light form of audit finding F3 (1.5.1) stays the behavior: omission,
  // never a metadata-only entry, symmetric across the three artifacts. Rule
  // 14 only lets the document SAY which omissions happened — if a later
  // reading ever turned rule 13 into "declare instead of omitting", the
  // format would start claiming proofs it does not carry.
  const spec = Deno.readTextFileSync(new URL("../SPEC.md", import.meta.url))
    .replace(/\r\n/g, "\n");
  const at13 = spec.indexOf("13. **Omission of unavailable proof artifacts");
  assert(at13 >= 0, "§8 rule 13 must exist");
  const rule13 = spec.slice(at13, spec.indexOf("\n14. ", at13)).replace(/\s+/g, " ");

  assert(/MUST omit/.test(rule13), "the omission is still a MUST");
  assert(/metadata-only entry/.test(rule13), "metadata-only entries are still ruled out");
  assert(/SAME for all three/.test(rule13), "the symmetry is still explicit");
  assert(
    /Rule 14 gives exporters the one mechanism to say so/.test(rule13),
    "rule 13 must point at the declaration mechanism",
  );
  assert(
    /emends this rule without contradicting it/.test(rule13),
    "rule 13 must say the relationship in so many words",
  );
  assert(
    /the omission remains the behavior/.test(rule13),
    "rule 13 must keep omission as the behavior",
  );
});

Deno.test("SPEC §8: the sketch and the conformance list carry the v1.6 array", () => {
  const spec = Deno.readTextFileSync(new URL("../SPEC.md", import.meta.url))
    .replace(/\r\n/g, "\n");
  // "Normative rules:" also appears in §1 — anchor the end INSIDE §8.
  const at8 = spec.indexOf("## 8. Export format");
  assert(at8 >= 0, "§8 must exist");
  const sketch = spec.slice(at8, spec.indexOf("Normative rules:", at8));
  assert(/"unavailable_artifacts"\?:/.test(sketch), "the sketch declares the array OPTIONAL");
  for (const kind of KINDS) {
    assert(sketch.includes(`"${kind}"`), `the sketch shows the ${kind} shape`);
  }
  const conformance = spec.slice(spec.indexOf("## 11. Conformance"));
  assert(
    /unavailable-artifact vectors.*`vectors\/unavailable\/`/s.test(conformance),
    "the conformance list names the new vectors",
  );
});
