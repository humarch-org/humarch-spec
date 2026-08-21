// The normative-clause registry of this repository.
//
// WHY THIS FILE EXISTS
// --------------------
// Before it, the prose tests of this repo pinned *phrases*, not *clauses*: an
// unanchored substring test ("does this sentence appear somewhere?") survives
// an edit that moves the sentence onto a different subject, or that keeps the
// sentence and guts the obligation inside it. An adversarial pass over
// SPEC.md weakened six material clauses — among them the recomputed-binding
// steps of §7.1 and §7.2, the two clauses that stand between a reader and a
// genuine (hash, token) pair lifted from a published export — and the whole
// suite stayed green. Four documents that are part of the public contract
// (ERROR_CODES.md, CHANGELOG.md, README.md, vectors/README.md) were read by
// no test at all.
//
// So every normative obligation of this repository is registered here as a
// CLAUSE: a set of patterns that must all match inside a slice of a named
// document, where the slice is delimited by anchors that name the subject the
// clause governs. `tests/prose.test.ts` runs the registry against the real
// documents. `tests/mutation.test.ts` enumerates the normative tokens of
// SPEC.md *from the document itself*, weakens them one at a time, and proves
// that each one makes at least one clause here fail.
//
// HOW TO ADD A CLAUSE
// -------------------
// Anchor it. `from`/`to` are normalized substrings (see `normalize`) that
// bracket the sentence's subject — a rule number, a section heading, a table
// caption. A pattern that matches anywhere in the document is not a clause,
// it is a phrase, and it is exactly what this file exists to replace.
//
// A clause carries `tokens`: the normative words it is responsible for. The
// mutation pass does not read that field to decide anything — it derives
// coverage by mutating and observing — but it is the reviewer's map, and a
// clause that claims a token it does not actually protect is caught the
// moment the mutation pass runs.

export type DocName =
  | "SPEC.md"
  | "ERROR_CODES.md"
  | "README.md"
  | "CHANGELOG.md"
  | "KEYS.md"
  | "vectors/README.md";

export interface Clause {
  /** Stable id: document area + subject. Cited in failures. */
  id: string;
  doc: DocName;
  /** Normalized substring opening the slice this clause governs. */
  from: string;
  /** Normalized substring closing it. Omitted = to the end of the document. */
  to?: string;
  /** Every pattern must match inside the slice, or the clause fails. */
  must: RegExp[];
  /** The normative words this clause is answerable for. Documentation. */
  tokens: string;
  /** Why the obligation is load-bearing — what breaks if it is weakened. */
  why: string;
}

/** Collapse every run of whitespace, so patterns need not encode line breaks. */
export function normalize(text: string): string {
  return text
    .replace(/\r\n/g, "\n")
    // Markdown blockquote markers are layout, not text: without dropping them
    // a quoted paragraph collapses to "PyPI — > any package", and a clause
    // pattern written against the sentence fails for a reason that has
    // nothing to do with the sentence.
    .replace(/^[ \t]*>[ \t]?/gm, "")
    .replace(/\s+/g, " ");
}

export function readDoc(doc: DocName): string {
  return Deno.readTextFileSync(new URL(`../${doc}`, import.meta.url));
}

export interface ClauseFailure {
  clause: string;
  reason: string;
}

/**
 * Check one clause against an already-normalized document body. Returns the
 * failures; an empty array means the clause holds.
 *
 * A missing anchor is a failure, deliberately: a clause whose subject cannot
 * be located has not been proven present, and treating that as a pass is the
 * vacuous-green failure mode this registry exists to remove.
 */
export function checkClause(
  clause: Clause,
  normalizedDoc: string,
): ClauseFailure[] {
  const start = normalizedDoc.indexOf(clause.from);
  if (start < 0) {
    return [{
      clause: clause.id,
      reason: `opening anchor not found: ${JSON.stringify(clause.from)}`,
    }];
  }
  let end = normalizedDoc.length;
  if (clause.to !== undefined) {
    const at = normalizedDoc.indexOf(clause.to, start + clause.from.length);
    if (at < 0) {
      return [{
        clause: clause.id,
        reason: `closing anchor not found: ${JSON.stringify(clause.to)}`,
      }];
    }
    end = at;
  }
  const slice = normalizedDoc.slice(start, end);
  const failures: ClauseFailure[] = [];
  for (const pattern of clause.must) {
    if (!pattern.test(slice)) {
      failures.push({
        clause: clause.id,
        reason: `pattern did not match inside the slice: ${pattern.source}`,
      });
    }
  }
  return failures;
}

// ---------------------------------------------------------------------------
// SPEC.md — §0 conventions
// ---------------------------------------------------------------------------

const SPEC_CLAUSES: Clause[] = [
  {
    id: "spec/rfc2119",
    doc: "SPEC.md",
    from: "# Humarch format specification",
    to: "## 1. Ingestion envelope",
    must: [
      /Key words MUST \/ MUST NOT \/ SHOULD are to be interpreted as in RFC 2119\./,
    ],
    tokens: "the RFC 2119 declaration itself",
    why:
      "every other clause in this document borrows its force from this line. " +
      "Remove it and the obligations below become style preferences.",
  },

  // -------------------------------------------------------------------------
  // SPEC.md §1 — ingestion envelope
  // -------------------------------------------------------------------------
  {
    id: "spec/1/non-finite",
    doc: "SPEC.md",
    from: "**Non-finite numbers do not exist in the format**",
    to: "- Duplicate keys: last-wins",
    must: [
      /verifiers MUST therefore reject any non-finite number, at any depth of `actor`\/`subject`\/`payload`, as \*\*malformed input\*\*/,
      /\(a form error, never a tampering verdict\)/,
    ],
    tokens: "MUST (reject non-finite)",
    why:
      "a lenient parser turns `1e999` into Infinity. Without the refusal a " +
      "hand-crafted export crashes a verifier that canonicalizes before it " +
      "validates, and the crash is not a verdict.",
  },
  {
    id: "spec/1/corrects-same-tenant",
    doc: "SPEC.md",
    from: "- `correction.corrects` MUST exist",
    to: "- `occurred_at` is informative",
    must: [
      /`correction\.corrects` MUST exist in the same tenant \(checked at ingestion\)/,
    ],
    tokens: "MUST (corrects exists)",
    why:
      "the one referentially checked reference in the format. Weaken it and a " +
      "correction can point at nothing, or across tenants.",
  },
  {
    id: "spec/1.0.1/replay-divergence",
    doc: "SPEC.md",
    from: "### 1.0.1 Declaring a discarded retransmission",
    to: "### 1.1 Personal-data container",
    must: [
      // The identity criterion is NOT what changed. An implementer who reads
      // this as a widening of D24 turns a legitimate retry into a 409.
      /The identity criterion of D24 is unchanged/,
      /the registry then discards a changed statement about \*\*who acted\*\*, silently|The registry then discards a changed statement about \*\*who acted\*\*, silently/,
      // Presence only on divergence: this is the byte-identity promise the
      // whole minor rests on.
      /`replay_divergence` is present \*\*only when there is divergence\*\*/,
      /A replay of an identical retransmission is byte-identical to the pre-1\.7 response/,
      // The set is CLOSED, and it is not an extension point.
      /`fields` is a non-empty, \*\*lexicographically ordered\*\* subset of the \*\*closed\*\* set `\["actor", "event_type", "subject"\]`/,
      /A receiver MUST treat an unexpected name as a defect of the sender's implementation, not as an extension point\./,
      /Comparison is on the \*\*JCS canonical form\*\* of the normalized value/,
      /`count` equals `fields\.length`\./,
      /it never becomes a `409`/,
      /Error bodies never carry it/,
      // The one thing a consumer must not conclude from the field.
      /Consumers MUST NOT read `replay_divergence` as a statement that anything was stored/,
      /it describes what the registry \*\*refused to store\*\*/,
    ],
    tokens: "MUST (unexpected name is a defect) + MUST NOT (nothing was stored)",
    why:
      "D109 makes a silent discard visible without touching D24. Both halves " +
      "are load-bearing: an open field set would let a sender invent " +
      "attribution names, and a consumer reading the field as a write would " +
      "believe the registry stored the value it just refused.",
  },
  {
    id: "spec/1.1/no-personal-data-in-ref",
    doc: "SPEC.md",
    from: "**Normative rule on non-personal fields (D47):**",
    to: "**Note to verifiers:**",
    must: [
      /`label` and `ref` \(in `actor` and in every `subject` member\) MUST NOT contain personal data of natural persons/,
      /A personal datum of an end client that must be conserved goes in `payload\.personal`, nowhere else\./,
    ],
    tokens: "MUST NOT (personal data outside payload.personal)",
    why:
      "the whole crypto-shredding design assumes identifiable data lives in " +
      "exactly one container. A personal datum in `ref` is unshreddable: it " +
      "is inside the hash chain, and the chain is append-only.",
  },
  {
    id: "spec/1.2/conditional-must-on-shape",
    doc: "SPEC.md",
    from: "Optional payload conventions normalize how implementations record",
    to: "#### 1.2.1",
    must: [
      /\*\*if\*\* an implementation records one of these facts in the payload, it MUST use these field names and shapes/,
      /fields invented per client prove nothing to an auditor/,
    ],
    tokens: "MUST (convention field names and shapes)",
    why:
      "the conventions buy comparability across sources. Made optional in " +
      "shape as well as in presence, they buy nothing.",
  },
  {
    id: "spec/1.2.1/tool-call-name",
    doc: "SPEC.md",
    from: "#### 1.2.1 `payload.tool_call`",
    to: "#### 1.2.2",
    must: [
      /\| `name` \| REQUIRED, string \| the concrete operation invoked \|/,
    ],
    tokens: "REQUIRED (tool_call.name)",
    why:
      "a `tool_call` without the name of the call records that something was " +
      "invoked and refuses to say what.",
  },
  {
    id: "spec/1.2.2/delegation-parent",
    doc: "SPEC.md",
    from: "#### 1.2.2 `payload.delegation`",
    to: "**Declarative semantics (normative).**",
    must: [
      /\| `parent` \| REQUIRED when `delegation` is present \| the delegating execution \|/,
      /\| `parent\.ref` \| REQUIRED, string \| the \*\*source-native run\/execution id\*\*/,
      /\| `parent\.event_id` \| OPTIONAL, UUID \|/,
    ],
    tokens: "REQUIRED (delegation.parent, delegation.parent.ref)",
    why:
      "a delegation that need not name its delegator is not a delegation. " +
      "The third row is pinned with it because the asymmetry is the point: " +
      "`parent.event_id` is a strengthening, never a precondition.",
  },
  {
    id: "spec/1.2.2/declared-not-verified",
    doc: "SPEC.md",
    from: "**Declarative semantics (normative).**",
    to: "#### 1.2.3",
    must: [
      /Consumers resolve the reference downstream and MUST NOT treat an unresolved parent as tampering\./,
      /ingestion does NOT check that the referenced parent exists/,
    ],
    tokens: "MUST NOT (unresolved parent is not tampering)",
    why:
      "delegations are emitted during execution, out of order. A consumer " +
      "that reads an unresolved parent as tampering turns normal concurrency " +
      "into a fabricated integrity failure.",
  },
  {
    id: "spec/1.2.4/conformance-level",
    doc: "SPEC.md",
    from: "#### 1.2.4 Conformance level and crypto neutrality",
    to: "#### 1.2.5",
    must: [
      /The conventions are \*\*conditional MUSTs on the shape\*\*, not obligations of presence\./,
      /a malformed `tool_call`, `delegation`, `external_refs` or `execution` is NOT a `SCHEMA_VIOLATION`/,
    ],
    tokens: "MUST (the 'conditional MUSTs' characterization)",
    why:
      "this sentence is what stops an implementer from adding ingestion-time " +
      "validation that would reject evidence over a convention field.",
  },
  {
    id: "spec/1.2.5/external-ref-shapes",
    doc: "SPEC.md",
    from: "Each array **element** is an object in exactly one of these shapes",
    to: "Normative rules:",
    must: [
      /Within an element, extra \*\*properties\*\* are allowed and the named property is the REQUIRED one\./,
      /This document uses \*element\* for a position in an array and \*property\* for a name\/value pair in an object, throughout\./,
    ],
    tokens: "REQUIRED (the named property of an external_refs element)",
    why:
      "an element whose named property is optional is an empty object, and " +
      "an empty object declares no external evidence at all.",
  },
  {
    id: "spec/1.2.5/message-id-interop",
    doc: "SPEC.md",
    from: "**`message_id_sha256` canonicalization (normative algorithm).**",
    to: "0. **The input**",
    must: [
      /Two independent implementations MUST produce the same digest from the same message\./,
    ],
    tokens: "MUST (algorithm interoperability)",
    why:
      "the digest is only falsifiable by a third party if the third party " +
      "recomputes the same bytes. This sentence is the reason the algorithm " +
      "below is specified to the octet.",
  },
  {
    id: "spec/1.2.5/message-id-enumerate",
    doc: "SPEC.md",
    from: "0. **The input** is the **raw field body as transmitted**",
    to: "1. **Select** the message's",
    must: [
      /cannot enumerate \*\*every\*\* instance of the field — MUST NOT declare `message_id_sha256`/,
      /a single-value accessor silently hides the duplicate case that step 1 exists to refuse/,
    ],
    tokens: "MUST NOT (declare without enumerating every instance)",
    why:
      "step 1 refuses the duplicate case. An API that surfaces one of two " +
      "Message-IDs defeats step 1 without anyone noticing, so the refusal has " +
      "to bite at the input, not at the selection.",
  },
  {
    id: "spec/1.2.5/declared-never-verified",
    doc: "SPEC.md",
    from: "- **Declared, never verified.**",
    to: "- **Honest detection note.**",
    must: [
      /consumers MUST NOT treat an unresolved or non-matching reference as tampering/,
      /Documentation, reports and verifier output MUST say the reference is \*\*declared\*\* — never "verified", "bound" or "proven"/,
      /it cannot declare it retroactively/,
    ],
    tokens: "MUST NOT (not tampering) + MUST (say 'declared')",
    why:
      "an external reference is a claim the registry never checked. A report " +
      "that calls it 'verified' launders a claim into a proof — the exact " +
      "overclaim this format is built to avoid.",
  },
  {
    id: "spec/1.2.6/execution-ref",
    doc: "SPEC.md",
    from: "#### 1.2.6 `payload.execution`",
    to: "The `{ref, …}` shape is again consistent",
    must: [
      /\| `ref` \| REQUIRED when `execution` is present, string \|/,
    ],
    tokens: "REQUIRED (execution.ref)",
    why: "an `execution` with no run id names no run.",
  },

  // -------------------------------------------------------------------------
  // SPEC.md §7 — anchoring
  // -------------------------------------------------------------------------
  {
    id: "spec/7/anchor-level-declared",
    doc: "SPEC.md",
    from: "Anchor verification levels (D64)",
    to: "1. **trustless**",
    must: [
      /the level used MUST be declared in output/,
    ],
    tokens: "MUST (declare the anchor verification level)",
    why:
      "trustless, trust-minimized and convenience are three different " +
      "strengths of claim. A verdict that does not say which one it used is " +
      "not citable.",
  },
  {
    id: "spec/7/anchor-coverage-honesty",
    doc: "SPEC.md",
    from: "A confirmed anchor proves existence **at or before**",
    to: "### 7.1 Qualified timestamp",
    must: [
      /covers events up to that anchor; later events are protected by chain and signatures until the next anchor confirms/,
      /Verifiers MUST state this rather than hide it\./,
    ],
    tokens: "MUST (state the coverage boundary)",
    why:
      "the window between the last confirmed anchor and now is the honest " +
      "limit of the time claim. A verifier that hides it overclaims.",
  },
  {
    id: "spec/7/anchor-binds-this-chain",
    doc: "SPEC.md",
    from: "**Binding the anchor to this chain (normative).**",
    to: "### 7.1 Qualified timestamp",
    must: [
      // The tie has to be the committed entry set, not the convenience field.
      /The tie is the pair for this export's `tenant_id` inside `anchor_entries_for_aggregate` — the entry set the `aggregate_hash` was recomputed from/,
      // The bind target is the RECOMPUTED head of the verified prefix.
      /Verifiers MUST check that this pair is present and that its `last_event_hash` names the \*\*recomputed\*\* head of the verified chain prefix/,
      /NOT the `last_event_hash` as it appears in the export, and NOT the sibling `entry` field, which no aggregate commits to/,
      /supplied by whoever produced the document/,
      /lets a genuine \(aggregate, `\.ots`\) pair lifted from a published export vouch for a fabricated chain, at the cost of no keys at all/,
      /Verifiers MUST bind to the recomputed value\./,
      // The consequence of failing the bind must be stated, not left open.
      /An anchor that verifies but does not bind proves nothing about this chain, and verifiers MUST NOT let it contribute anteriority/,
      // Rule 8 is a precondition of binding at all: the head is resolved by a
      // sequence number, so a document that repeats one must not be bound.
      /a verifier that has not refused the repetition of rule 8 MUST NOT bind at all/,
    ],
    tokens: "MUST (bind the anchor to the recomputed chain head)",
    why:
      "without it the §8 recipe checks only the internal coherence of a " +
      "document the attacker wrote. A genuine anchor lifted from a published " +
      "export verifies attached to a chain that never existed — cost of " +
      "attack: zero keys and one public sample export.",
  },
  {
    id: "spec/7.1/no-per-event-mark",
    doc: "SPEC.md",
    from: "**the presumption attaches to the data the token marks — the daily aggregate hash.**",
    to: "Verification (any RFC 3161 tooling works",
    must: [
      /inherits that anteriority through derivation/,
      /Implementations and derived material MUST NOT state or imply that each event carries its own qualified timestamp\./,
    ],
    tokens: "MUST NOT (per-event qualified timestamp)",
    why:
      "the art. 42 presumption attaches to the marked data. Claiming it " +
      "per event inflates a real legal effect into one the token does not " +
      "carry.",
  },
  {
    id: "spec/7.1/bind-recomputed-aggregate",
    doc: "SPEC.md",
    from: "2. `TSTInfo.messageImprint` (SHA-256) equals the aggregate hash",
    to: "3. the TSA's signature over the signed attributes",
    must: [
      /\*\*recomputed from `anchor_entries_for_aggregate` per §7\*\* — NOT the `aggregate_hash` field as it appears in the export/,
      /supplied by whoever produced the document/,
      /lets a genuine \(hash, token\) pair lifted from a published export vouch for a fabricated entry set/,
      /Verifiers MUST bind to the recomputed value/,
    ],
    tokens: "MUST (bind the RFC 3161 token to the recomputed aggregate)",
    why:
      "binding to the declared field lets the attacker choose both sides of " +
      "the comparison. This is the §7.1 twin of the §7 and §7.2 clauses.",
  },
  {
    id: "spec/7.1/outcome-additive",
    doc: "SPEC.md",
    from: "A token that fails 1–3 is **invalid**",
    to: "A genuine token proves existence of the aggregate",
    must: [
      /valid token from an untrusted TSA and carries no presumption/,
      /Either outcome is declared and MUST NOT change the outcome of the §7\/§5 verification/,
      /absence is the pre-1\.3 form and stays fully valid/,
    ],
    tokens: "MUST NOT (a token outcome changes the chain verdict)",
    why:
      "the two proofs share the hash, not the failure modes. A broken " +
      "optional mark that could fail the chain verdict would hand an " +
      "attacker a denial-of-verification lever.",
  },
  {
    id: "spec/7.2/seal-prefix-only",
    doc: "SPEC.md",
    from: "**the presumption attaches to the data the token marks — the chain-head `event_hash` at sealing time.**",
    to: "Verification (any RFC 3161 tooling works",
    must: [
      /A seal covers a chain \*\*prefix\*\*/,
      /implementations and derived material MUST NOT state or imply that each event carries its own qualified timestamp, and MUST speak of "the seal of the chain up to sequence N", never of per-event marks/,
    ],
    tokens: "MUST NOT + MUST (seal speaks of a prefix, not of events)",
    why: "the §7.1 twin, for the on-demand seal.",
  },
  {
    id: "spec/7.2/bind-recomputed-event-hash",
    doc: "SPEC.md",
    from: "2. `TSTInfo.messageImprint` (SHA-256) equals the event hash",
    to: "3. the TSA's signature verifies against the embedded signer certificate",
    must: [
      /\*\*recomputed from the §5 pre-image at the declared `sequence_number`, within the verified prefix of the export \(§8 rule 10\)\*\*/,
      /NOT the event's declared `event_hash` field, and NOT any value carried by the seal element itself/,
      /supplied by whoever produced the document/,
      /lets a genuine \(hash, token\) pair lifted from a published export vouch for a fabricated chain/,
      /Verifiers MUST bind to the recomputed value, and MUST treat a seal whose declared sequence the export does not contain — or that falls beyond the verified prefix — as a declared `invalid`/,
    ],
    tokens: "MUST (bind the seal to the recomputed event hash) ×2",
    why:
      "the §7.2 twin. The second MUST is separate work: a seal pointing " +
      "outside the verified prefix inherits nothing, because the prefix " +
      "inheritance claim is what makes a head seal cover the events below it.",
  },

  // -------------------------------------------------------------------------
  // SPEC.md §8 — export format
  // -------------------------------------------------------------------------
  {
    id: "spec/8/rule4-ordering",
    doc: "SPEC.md",
    from: "4. Events ordered by `sequence_number`, anchors by `anchor_date`",
    to: "5. The export MUST include every anchor",
    must: [
      /verifiers MUST NOT rely on the order, exporters MUST produce it/,
    ],
    tokens: "MUST NOT (verifier relies on order) + MUST (exporter produces it)",
    why:
      "the asymmetry is the clause: an exporter obligation a verifier may " +
      "not lean on. Collapse either half and a verifier starts trusting an " +
      "attacker-chosen array order.",
  },
  {
    id: "spec/8/rule5-anchor-completeness",
    doc: "SPEC.md",
    from: "5. The export MUST include every anchor",
    to: "6. `raw_payload` is excluded by default",
    must: [
      /The export MUST include every anchor whose day intersects the event range, when such anchors exist\./,
    ],
    tokens: "MUST (include every intersecting anchor)",
    why:
      "an exporter free to drop anchors can drop the one that contradicts " +
      "the story it wants the document to tell.",
  },
  {
    id: "spec/8/rule8-uniqueness",
    doc: "SPEC.md",
    from: "8. **Within one export, `sequence_number` and `event_id` are unique**",
    to: "9. **Export-supplied strings are hostile input",
    must: [
      /A repetition of either is \*\*malformed input\*\*, not a tampering verdict/,
      /verifiers MUST refuse such a document with their malformed-input outcome rather than verify it/,
    ],
    tokens: "MUST (refuse a repeated sequence_number or event_id)",
    why:
      "rule 10 derives verification status positionally. A duplicated " +
      "sequence number is precisely the input that makes a positional claim " +
      "credit an unverified event with its twin's integrity.",
  },
  {
    id: "spec/8/rule9-hostile-display",
    doc: "SPEC.md",
    from: "9. **Export-supplied strings are hostile input at the point of DISPLAY.**",
    to: "10. **Verification status is a property of the verified PREFIX",
    must: [
      /A verifier MUST NOT emit them to a terminal, a log or a report without neutralizing the characters that can drive or reorder a display/,
      /Unicode categories Cc \(controls\), Cf \(format, the bidirectional overrides and isolates among them\), Zl and Zp/,
      /Machine fields MUST NOT contain any of those characters, and a verifier MUST refuse such a document with its malformed-input outcome\./,
      // BT-46: the permission that let one hostile document earn two lawful
      // verdicts, and the list that was exemplificative rather than closed.
      /The permission this rule used to grant \("MAY refuse"\) let two conformant verifiers reach two different verdicts on the same hostile document/,
      /The machine fields are exactly: `tenant_id` at the top level/,
      /Free-text members carried inside an event .{0,120}?are NOT machine fields/,
      /The same discipline applies to the text of parser and I\/O error messages/,
    ],
    tokens: "MUST NOT (emit unneutralized) + MUST NOT (controls in machine fields)",
    why:
      "a bidi override inside an `event_type` renders as a reversed line and " +
      "can spell out a verdict the verifier never reached. The error-message " +
      "sentence is pinned with it because an error path is a renderer too.",
  },
  {
    id: "spec/8/rule10-prefix",
    doc: "SPEC.md",
    from: "10. **Verification status is a property of the verified PREFIX, never of a sequence interval.**",
    to: "11. `qualified_timestamp` (v1.3) is OPTIONAL",
    must: [
      /stops at the first failure/,
      /Deriving "this event is verified" from `sequence_number ≤ verified_through` is wrong/,
      /MUST carry the verified\/unverified distinction positionally, and MUST present anything outside that prefix as not covered by integrity/,
    ],
    tokens: "MUST ×2 (positional verification status)",
    why:
      "everything downstream — search, indexing, reporting — inherits this. " +
      "An interval claim over a non-monotone numbering is false.",
  },
  {
    id: "spec/8/rule11-qualified-timestamp",
    doc: "SPEC.md",
    from: "11. `qualified_timestamp` (v1.3) is OPTIONAL and additive",
    to: "12. `chain_seals` (v1.5) is OPTIONAL",
    must: [
      /`token_base64` is the authoritative artifact/,
      /convenience metadata that verifiers MUST take from the token itself/,
      /the presence of the field asserts nothing: qualification is a property of the issuing TSA, established in verification/,
      /Verifiers MUST cap the token size they are willing to parse at \*\*64 KiB\*\* of DER/,
      /MUST treat an unreadable token — including one over that cap — as a declared `invalid`, never as a verification failure of the export/,
      // BT-45: the value is normative, because a shipped vector depends on it.
      /The cap is normative in its value, not only in its existence/,
      /`export-seal-oversize` in `vectors\/seal\/` pins an outcome that depends on it/,
    ],
    tokens: "MUST ×3 (metadata from the token, cap, unreadable = declared invalid)",
    why:
      "`tsa_name` and `gen_time` are attacker-chosen strings sitting next to " +
      "the artifact that actually carries them. The cap is the parse-bomb " +
      "defence; the last MUST keeps a bad optional mark from failing a good " +
      "export.",
  },
  {
    id: "spec/8/rule12-chain-seals",
    doc: "SPEC.md",
    from: "12. `chain_seals` (v1.5) is OPTIONAL and additive",
    to: "13. **Omission of unavailable proof artifacts",
    must: [
      /each sealed sequence appears \*\*at most once\*\*/,
      /a repetition \*\*or a misordering\*\* is \*\*malformed input\*\*, rule-8 class/,
      /unlike rule 4's event\/anchor ordering \(an exporter obligation\), this one binds verifiers too/,
      /convenience metadata that verifiers MUST take from the token itself/,
      /the element deliberately carries \*\*no event hash\*\*: the binding target exists only as the recomputed value of §7\.2 step 2/,
      /Verifiers MUST cap the token size they are willing to parse at \*\*64 KiB\*\* of DER \(rule 11, same value and same reason\)/,
      /MUST treat an unreadable token — including one over that cap — as a declared `invalid`, never as a verification failure of the export/,
    ],
    tokens: "MUST ×3 (as rule 11, for seals)",
    why:
      "the rule-12 ordering binds verifiers, unlike rule 4's — the one place " +
      "in §8 where the asymmetry runs the other way, and the reason the " +
      "element carries no hash of its own.",
  },
  {
    id: "spec/8/rule13-omission",
    doc: "SPEC.md",
    from: "13. **Omission of unavailable proof artifacts is defined exporter behavior, and it is symmetric.**",
    to: "14. **`unavailable_artifacts` (v1.6)",
    must: [
      /MUST omit the corresponding optional field or element rather than emit a metadata-only entry \(metadata alone would claim a proof without carrying it\)/,
      /the omission rule is the SAME for all three artifacts — none of them is dropped more silently than the others/,
      /a reader cannot tell "this proof never existed" from "it existed and did not resolve"/,
    ],
    tokens: "MUST (omit rather than emit metadata-only)",
    why:
      "a metadata-only entry claims a proof it does not carry, and the " +
      "symmetry across the three artifact kinds is what stops one of them " +
      "becoming the quiet one.",
  },
  {
    id: "spec/8/rule14-declaration",
    doc: "SPEC.md",
    from: "14. **`unavailable_artifacts` (v1.6) is the single, OPTIONAL mechanism",
    to: "A verifier processes the export as in the reference implementation",
    must: [
      /carrying no other member, and in particular no free-text reason/,
      /a verifier MUST ignore a member it does not know rather than refuse it/,
      /MUST NOT display one, for the same rule-9 reason/,
      /Exporters MUST NOT repeat a `\(kind, coordinate\)` pair/,
      /\*\*A declaration is neither evidence nor an exemption\.\*\*/,
      /whoever produced the document may be the adversary/,
      /An attacker who strips a genuine proof and adds the matching declaration MUST obtain \*\*exactly\*\* the outcome of the plain absence/,
      /for a \*\*well-formed\*\* array/,
      /MUST be identical to the outcome for the same document with this array removed/,
      /Verifiers MUST NOT treat a declared artifact as present, as proven to have existed, or as softening any conclusion the document earns without the array/,
      /the ABSENCE of a declaration asserts nothing/,
    ],
    tokens: "MUST ×3 + MUST NOT ×3 (rule 14 in full)",
    why:
      "an implementer who reads a declaration as an excuse builds a verifier " +
      "an attacker defeats by stripping a genuine proof and declaring it " +
      "gone. Exit-neutrality is the whole mechanism.",
  },
  {
    id: "spec/8/recipe",
    doc: "SPEC.md",
    from: "A verifier processes the export as in the reference implementation",
    to: "## 9. Error contract",
    must: [
      /recompute component hashes \(JCS from parsed values\)/,
      /recompute `event_hash` from the D11 pre-image/,
      /check the chain link and dense sequence/,
      /check the self-certifying key id/,
      /recompute anchor aggregates, verify `\.ots` attestations at the chosen level/,
      // The two external bindings. Internal coherence alone is not verification.
      /take the set of trusted issuers from OUTSIDE this document and verify the Ed25519 signature against it/,
      /and bind that anchor to the recomputed chain head per §7/,
      /a recipe without them accepts a fabricated chain carrying a stolen anchor, signed by a key the document supplied/,
      /First failure reported with its exact sequence number\./,
    ],
    tokens: "the §8 recipe (BT-01 (a) and (b))",
    why:
      "the recipe is what a third-party implementer follows. Before v1.7 it " +
      "asked only for internal coherence, so a verifier built strictly from " +
      "it accepted a fabricated chain carrying a stolen anchor, signed by a " +
      "key the document itself supplied.",
  },
  {
    id: "spec/8.1/verdict-determinism",
    doc: "SPEC.md",
    from: "### 8.1 Verdict determinism",
    to: "**Attribution: the trusted issuer set comes from outside",
    must: [
      // The premise. Without it §8.1 reads as trivia rather than as the
      // answer to "why did two conformant verifiers disagree?".
      /two implementations built strictly from this document could reach \*\*different verdicts on the same export\*\*/,
      /The answers state what the reference already does, so no vector moves\./,
      // 1 — recomputed vs declared aggregate
      /The value recomputed from `anchor_entries_for_aggregate` per §7 is authoritative/,
      /A mismatch is an \*\*anchor failure\*\*/,
      // 2 — range is declarative
      /Verifiers MUST derive what is verified from the events they actually processed \(rule 10\), and MUST NOT report coverage on the strength of `range`/,
      // 3 — anchors[].entry
      /no aggregate, no `\.ots` and no token commits to it\. Verifiers MUST NOT use it for the §7 binding or for any other verification decision, and MUST read `anchor_entries_for_aggregate` instead/,
      // 4 — a non-covering anchor is lawful, and its DATE decides nothing
      // about whether it binds: measured on the shipped vector, whose
      // anchor names an unrelated day and binds anyway.
      /Such an anchor is neither malformed input nor a failure\./,
      /the day it names decides nothing about whether it binds/i,
      /Verifiers MUST NOT use `anchor_date` as a proxy for coverage in either direction/,
      // 5 — the ots_status vocabulary
      /Exactly three values are defined — `pending`, `submitted`, `confirmed`/,
      /A verifier MUST NOT credit any other value as `confirmed`, and MUST NOT derive anteriority from an anchor that is not `confirmed`, Bitcoin verified and time consistent/,
      // 6 — caps are declared, never silent
      /A verifier MUST bound the work an export can make it do, and MUST report a document that exceeds a bound with its malformed-input outcome rather than truncate the check/,
      /A silent cap turns a size into a verdict/,
      // 7 — duplicate keys
      /an object with a repeated member is read as though only the last occurrence were present/,
      // 8 — non-finite everywhere
      /a verifier MUST reject a non-finite number \*\*at any position in the document\*\* as malformed input/,
      /`sequence_number: 1e999` was outside the letter of the old wording/,
      // 9 — verbatim vs comparison
      /a verifier parses a copy for the comparison and still hashes the original bytes/,
      // 10 — the export object is OPEN
      /A top-level member this version does not define MUST be ignored, never refused/,
      /Closedness belongs to the ingestion envelope \(§1\)/,
      // 11 — a declaration naming an absent coordinate
      /appears nowhere in the export is NOT malformed input/,
      // 12 and 13 — the two the reference always enforced and §8 never said
      /MUST be refused rather than verified under a label the attacker chose/,
      /\*\*Two anchors sharing an `anchor_date`\*\* are malformed input, rule-8 class/,
      /admitting it lets a decoy anchor ride in on a real one's date/,
    ],
    tokens: "MUST ×6 + MUST NOT ×4 across the thirteen classes",
    why:
      "each of these was a place where the reference verifier was silently " +
      "arbitrating on every implementer's behalf. For an artifact produced " +
      "in evidence, the same document has to earn the same verdict — a split " +
      "between two conformant verifiers is worth more to an opponent than " +
      "either verdict is to its holder.",
  },
  {
    id: "spec/8/attribution-out-of-band",
    doc: "SPEC.md",
    from: "**Attribution: the trusted issuer set comes from outside (normative).**",
    to: "A verifier processes the export as in the reference implementation",
    must: [
      /`signing_keys` travels \*\*inside\*\* the document/,
      /a signature that verifies under a key the document itself supplies proves .{0,120}?nothing about who signed/,
      /an attacker generates a key pair, signs a fabricated chain, and ships the public key in the same file/,
      /Verifiers MUST obtain the set of trusted `signing_key_id` values from a source independent of the export/,
      /MUST NOT present a signature as attributed.{0,140}?on the strength of a key carried by the document alone/,
      // The third obligation: an untrusted key is an unknown issuer, not a
      // failure. Collapsing the two would make a real export look tampered.
      /A signature valid under an untrusted key is a \*\*valid signature from an unknown issuer\*\*, and verifiers MUST report it as such rather than as a failure/,
      /`KEYS\.md` in this repository/,
    ],
    tokens: "MUST + MUST NOT (out-of-band issuer set)",
    why:
      "self-certifying key ids prove the id matches the key, never that the " +
      "key is the registry's. Attribution is the one property that cannot " +
      "come from inside the artifact being attributed.",
  },
  {
    id: "spec/8/subject-ref-reserved",
    doc: "SPEC.md",
    from: "**Reserved `subject_ref` sentinel (normative).**",
    to: "**Normative rule on non-personal fields (D47):**",
    must: [
      /The literal `__tenant_default__` is \*\*reserved\*\*/,
      /the encryption scope shared by a tenant's events with no `end_client`/,
      /Ingestion MUST reject an event whose `subject\.end_client\.ref` is exactly `__tenant_default__`, with `SCHEMA_VIOLATION`/,
      /`event\.schema\.json` carries the refusal/,
      // The scope of the reservation is as load-bearing as its existence.
      /The reservation is on `end_client` only — `workflow\.ref` and `tool\.ref` may carry any value/,
      // The consequence: why a reservation and not a nicety.
      /Erasure of the default pool then destroys that end client's key with it: one real end client, irreversibly unreadable/,
      /the registry is append-only, so nothing can be rewritten afterwards/,
    ],
    tokens: "MUST (reject the reserved sentinel at ingestion)",
    why:
      "the sentinel names the default encryption scope. An end client free " +
      "to carry it as its own `ref` shares a DEK with the default pool and " +
      "is destroyed, irreversibly, by that pool's erasure.",
  },

  // -------------------------------------------------------------------------
  // SPEC.md §9–§11
  // -------------------------------------------------------------------------
  {
    id: "spec/9/unknown-codes",
    doc: "SPEC.md",
    from: "## 9. Error contract",
    to: "## 10. Versioning",
    must: [
      /Codes are \*\*stable\*\*: removing or changing semantics is a breaking change; additions are minor\./,
      /Clients MUST treat unknown codes as non-retryable unless the HTTP class is 5xx or 429\./,
    ],
    tokens: "MUST (unknown codes are non-retryable)",
    why:
      "a client that retries an unknown 4xx hammers the registry over a " +
      "condition no retry can fix.",
  },
  {
    id: "spec/9/schema-violation-pointer",
    doc: "SPEC.md",
    from: "**On the JSON Pointer in a `SCHEMA_VIOLATION` `detail` (v1.7).**",
    to: "## 10. Versioning",
    must: [
      /JSON Schema draft 2020-12 does not define the order in which a validator reports errors/,
      /"the pointer of the first failing field" is a property of a validator, not of `event\.schema\.json`/,
      /the `detail` of a `SCHEMA_VIOLATION` MUST carry \*\*a\*\* JSON Pointer to \*\*a\*\* field whose value violates the schema/,
      /assert membership, not position/,
    ],
    tokens: "MUST (a pointer to a violating field)",
    why:
      "the old contract was a property of one validator (CWE-758). An " +
      "implementer who pins position finds validators disagreeing with " +
      "neither of them violating this spec.",
  },
  {
    id: "spec/10/versioning",
    doc: "SPEC.md",
    from: "## 10. Versioning (D33)",
    to: "## 11. Conformance",
    must: [
      /SemVer; the schema `\$id` is versioned per major/,
      /Breaking changes take a new `\$id` path and — if hashing is touched — a new domain prefix in the pre-image \(`humarch:event:v2`\)/,
      /a 2030 verification of 2026 events knows exactly which rules apply/,
    ],
    tokens: "(no MUST — pinned because the minor/major boundary is contractual)",
    why:
      "every additive change in this document leans on this rule. It carries " +
      "no RFC 2119 token and had no test.",
  },
  {
    id: "spec/11/conformance-list",
    doc: "SPEC.md",
    from: "## 11. Conformance",
    must: [
      /the crypto vectors \*\*V0–V5\*\*/,
      /the shredding vector \*\*V6\*\*.{0,200}?the DEK-wrapping vector \*\*W1\*\*/,
      /the \*\*27 schema cases\*\*/,
      /which differ by that array alone and MUST reach the same outcome/,
      /a verifier MUST refuse as malformed input/,
      /the identical retransmission whose `202` MUST stay byte-identical to the pre-1\.7 form/,
      /the different-payload case that stays a `409` carrying no declaration/,
      /The server is authoritative: local validation in adapters is recommended but never substitutive\./,
    ],
    tokens: "MUST ×2 (the unavailable-vector conformance obligations)",
    why:
      "the conformance list is the acceptance test of the whole document. " +
      "The count of schema cases is pinned here and in vectors/README.md.",
  },
];

// ---------------------------------------------------------------------------
// ERROR_CODES.md — zero test coverage before v1.7.0
// ---------------------------------------------------------------------------

const ERROR_CODE_CLAUSES: Clause[] = [
  {
    id: "errors/body-shape",
    doc: "ERROR_CODES.md",
    from: "Every error response of the ingestion API has this body",
    to: "## Registry (v1)",
    must: [
      /`error_code` — stable, documented string: the only field automation may parse\./,
      /`detail` — human-readable English; for `SCHEMA_VIOLATION` it carries \*\*a\*\* JSON Pointer to \*\*a\*\* field that violates the schema\./,
      // BT-44: not "the first". Draft 2020-12 leaves the order to the
      // validator, so no implementation can promise position.
      /Not "the first": JSON Schema draft 2020-12 leaves error order implementation-defined/,
      /The `detail` never echoes the rejected value/,
      /`request_id` — always present, also echoed in the `x-request-id` header of \*\*every\*\* response \(including `202`\)\./,
    ],
    tokens: "(the error-body contract)",
    why:
      "this is the shape every integrator parses. It had no test at all " +
      "before v1.7.0.",
  },
  {
    id: "errors/registry-rows",
    doc: "ERROR_CODES.md",
    from: "## Registry (v1)",
    to: "## Binding rules",
    must: [
      /\| `UNAUTHORIZED` \| 401 \|.*?\| No \(fix the key\) \|/,
      /\| `TENANT_SUSPENDED` \| 403 \|/,
      /\| `UNKNOWN_SOURCE` \| 404 \|/,
      /\| `METHOD_NOT_ALLOWED` \| 405 \|/,
      /\| `DUPLICATE_IDEMPOTENCY_KEY` \| 409 \|.*?\(D24\)/,
      /\| `PAYLOAD_TOO_LARGE` \| 413 \| Body > 256 KB \|/,
      /\| `INVALID_PAYLOAD` \| 400 \| Body is not valid JSON or not an object \|/,
      /\| `SCHEMA_VIOLATION` \| 422 \|/,
      /\| `RATE_LIMITED` \| 429 \|.*?\*\*Yes\*\*, after `Retry-After` seconds \|/,
      /\| `INTERNAL_ERROR` \| 500 \|.*?\*\*Yes\*\*, exponential backoff/,
      /\| `WRITE_CONTENTION` \| 503 \|.*?\*\*Yes\*\*, after `Retry-After` seconds/,
    ],
    tokens: "(the eleven codes and their retry semantics)",
    why:
      "§9 of SPEC.md delegates the whole error contract here, including the " +
      "retry column an automation reads. Nothing verified that the table " +
      "still said what §9 promises.",
  },
  {
    id: "errors/binding-rules",
    doc: "ERROR_CODES.md",
    from: "## Binding rules",
    must: [
      /Codes are \*\*stable\*\*: removing one or changing its semantics is a breaking change of this spec; adding codes is a minor change\./,
      /Clients MUST treat unknown codes as non-retryable unless the HTTP class is 5xx or 429\./,
      /`detail` is for humans and is \*\*not parseable\*\*/,
      /The success response is `202 \{event_id, sequence_number, event_hash\}`/,
      /an idempotent replay adds `idempotent_replay: true`/,
      /On `401` the `detail` is identical for missing\/malformed\/unknown\/revoked keys \("authentication failed"\): no enumeration oracle\./,
    ],
    tokens: "MUST (unknown codes non-retryable) — the §9 twin",
    why:
      "the same obligation as spec/9/unknown-codes, written in the document " +
      "§9 points at. Weakening either copy alone must be caught; before " +
      "v1.7.0 weakening this one was caught by nothing.",
  },
  {
    id: "errors/no-value-echo",
    doc: "ERROR_CODES.md",
    from: "Every error response of the ingestion API has this body",
    to: "## Registry (v1)",
    must: [
      // The example must not promise an echo of the rejected value: the
      // implementation cannot produce one (ajv emits "must be equal to one of
      // the allowed values"), and a documented shape no implementation emits
      // is a false contract. It must also not become the place personal data
      // enters a public error body.
      /"detail": "actor\.type must be equal to one of the allowed values at \/actor\/type"/,
    ],
    tokens: "(the documented `detail` example)",
    why:
      "the published example promised `(got: \"robot\")`. No implementation " +
      "emits that, and an echo of the rejected value in a public error body " +
      "is where a personal datum would leave the system.",
  },
];

// ---------------------------------------------------------------------------
// README.md — zero test coverage before v1.7.0
// ---------------------------------------------------------------------------

const README_CLAUSES: Clause[] = [
  {
    id: "readme/scope-of-proof",
    doc: "README.md",
    from: "Scope of the proof, stated plainly",
    must: [
      /verification proves the events were recorded by the holder of the trusted keys, unaltered, in this order, at the anchored time — \*\*as received, not as true\*\*/,
      /The truth of what a payload asserts stays outside any cryptographic proof/,
      /attribution proves the key, not the truth/,
    ],
    tokens: "(the headline honesty claim of the repository)",
    why:
      "the single sentence that keeps this project from being sold as a " +
      "truth oracle. It is the most-quoted line in the repo and no test " +
      "read it.",
  },
  {
    id: "readme/distribution-channel",
    doc: "README.md",
    from: "Official distribution channel",
    to: "Humarch is a passive evidence registry",
    must: [
      /\*\*github\.com\/humarch-org\*\*/,
      /Humarch is \*\*not\*\* published on npm or PyPI — any package with this name on a registry is not ours\./,
    ],
    tokens: "(the supply-chain disclaimer)",
    why:
      "a typosquatted package on npm is the cheapest attack on a verifier " +
      "audience. The disclaimer is the defence, and it was untested.",
  },
  {
    id: "readme/reimplementation-is-the-test",
    doc: "README.md",
    from: "## Verify an export",
    to: "## Send events",
    must: [
      /reimplement the verifier in any language from `SPEC\.md` \+ `vectors\/` alone — that is the acceptance test of this spec/,
    ],
    tokens: "(the clean-room criterion)",
    why:
      "this promise is why §8 must be complete enough to implement against. " +
      "It is the sentence BT-01 and BT-43 were measured against.",
  },
];

// ---------------------------------------------------------------------------
// vectors/README.md — zero test coverage before v1.7.0
// ---------------------------------------------------------------------------

const VECTORS_README_CLAUSES: Clause[] = [
  {
    id: "vectors/conformance-contract",
    doc: "vectors/README.md",
    from: "These vectors are the **conformance contract**",
    to: "| Directory | Vectors |",
    must: [
      /any writer, verifier or adapter implementation MUST reproduce them byte-for-byte before being considered conformant/,
    ],
    tokens: "MUST (byte-for-byte reproduction)",
    why: "non-negotiable 5 of the project, stated in the public tree.",
  },
  {
    id: "vectors/negative-row",
    doc: "vectors/README.md",
    from: "| `negative/` |",
    to: "| `qualified/` |",
    must: [
      // Both halves are obligations, and they pull in opposite directions:
      // one says what MUST be caught, the other what MUST NOT be flagged.
      // Dropping either turns V5 from a contract into an illustration —
      // and a verifier that flags escape differences reports tampering on
      // an honest re-serialization (SPEC §2, vector V1c).
      /tampering MUST be detected at the exact sequence; escape differences MUST NOT be flagged/,
    ],
    tokens: "MUST (detect at the exact sequence) + MUST NOT (flag escapes)",
    why:
      "V5 is the vector that says a verifier must be both sensitive and " +
      "specific. The false-positive half is the one an implementer drops " +
      "first, and it is the half that decides whether a real export survives " +
      "a round trip through another JSON library.",
  },
  {
    id: "vectors/unavailable-row",
    doc: "vectors/README.md",
    from: "| `unavailable/` |",
    to: "| `message-id/` |",
    must: [
      /the two differ by `unavailable_artifacts` alone and MUST reach the same outcome, because a declaration is neither evidence nor an exemption/,
      /all four malformed input/,
    ],
    tokens: "MUST (the declaring export and its twin reach the same outcome)",
    why:
      "the twin pair IS the exit-neutrality proof of §8 rule 14. Stated here " +
      "as a conformance obligation, it is what an implementer reads before " +
      "running the vectors.",
  },
  {
    id: "vectors/test-key-honesty",
    doc: "vectors/README.md",
    from: "## The keys, and what you can regenerate",
    to: "## How to re-run",
    must: [
      // BT-12: the old text claimed ALL signatures used the RFC 8032 key, so
      // that "anyone can regenerate every value from scratch". False for the
      // 15 export vectors, which are verify-only.
      /The \*\*regenerable\*\* vectors .{0,220}?are signed with the \*\*RFC 8032 \(TEST 1\)\*\* Ed25519 key, whose seed is right here/,
      /seed \(private\): 9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60/,
      /signing_key_id: ed25519:21fe31dfa154a261/,
      /The \*\*export\*\* vectors — the 15 `humarch-export\/v1` documents .{0,90}?— are signed with `ed25519:dc5578a147d359bf`, whose seed is \*\*not\*\* in this repository and will not be: they are \*\*verify-only\*\*/,
      // The honest note about what the earlier wording did to a clean-room
      // implementer. Deleting it is how the claim quietly comes back.
      /which is false of those 15 files/,
      /The RFC 8032 key is public knowledge and MUST NEVER appear in a production `signing_keys` registry/,
    ],
    tokens: "MUST NEVER (test key in production)",
    why:
      "the regeneration claim was false of 15 of the export vectors. A " +
      "clean-room implementer who takes it at face value concludes the suite " +
      "is broken when the signature does not reproduce.",
  },
];

// ---------------------------------------------------------------------------
// CHANGELOG.md — zero test coverage before v1.7.0
// ---------------------------------------------------------------------------

const CHANGELOG_CLAUSES: Clause[] = [
  {
    id: "changelog/semver-discipline",
    doc: "CHANGELOG.md",
    from: "# Changelog",
    to: "## 1.7.0",
    must: [
      /All notable changes to the Humarch public spec\./,
      /SemVer \(D33\): additive = minor, breaking = new major with a new `\$id` path/,
      /a new pre-image domain prefix when hashing is touched/,
    ],
    tokens: "(the versioning discipline of the file)",
    why: "the header states the contract the entries below are written under.",
  },
  {
    id: "changelog/current-release",
    doc: "CHANGELOG.md",
    from: "## 1.7.0",
    to: "## 1.6.0",
    must: [
      // The release that carries the two blocking clauses must say what it did.
      /\*\*Anchor binding \(§7, new normative clause\)\.\*\*/,
      /\*\*Attribution \(§8, new normative clause\)\.\*\*/,
      /\*\*`__tenant_default__` is reserved \(§1\.1\)\.\*\*/,
      /\*\*`replay_divergence` \(§1\.0\.1, D109\)\.\*\*/,
      /\*\*§8\.1 verdict determinism \(new\)\.\*\*/,
      // The additivity statement, and the one restriction, named as such.
      /\*\*Additive\*\*: every pre-1\.7 export verifies identically, every pre-1\.7 vector is byte-identical/,
      /The reservation of `__tenant_default__` is the one restriction/,
    ],
    tokens: "(the 1.7.0 entry)",
    why:
      "CHANGELOG.md is part of the contract: it is how a deployed verifier " +
      "learns what a minor added. It had no test.",
  },
];

export const CLAUSES: Clause[] = [
  ...SPEC_CLAUSES,
  ...ERROR_CODE_CLAUSES,
  ...README_CLAUSES,
  ...VECTORS_README_CLAUSES,
  ...CHANGELOG_CLAUSES,
];
