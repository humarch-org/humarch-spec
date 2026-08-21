// The mutation pass over SPEC.md.
//
// WHAT IT PROVES
// --------------
// That every normative token in SPEC.md is load-bearing on a test. It takes
// the document, finds each RFC 2119 obligation, weakens exactly one of them
// at a time (MUST -> SHOULD, MUST NOT -> MAY, REQUIRED -> OPTIONAL), and
// requires that at least one clause of tests/clauses.ts goes red for that
// mutant. A token no clause reacts to is a token an editor can quietly
// dissolve, which is how six material weakenings once passed a full green
// suite: MUST -> SHOULD on both recomputed-binding steps of §7.1 and §7.2,
// an emptied §7.1 step 2 that kept its sentence, an inverted verifier binding
// in §8 rule 12, a metadata-only permission in rule 13, and MUST NOT repeat
// -> MAY repeat in rule 14.
//
// WHY IT ENUMERATES FROM THE DOCUMENT
// -----------------------------------
// The obligations are extracted from SPEC.md ON EVERY RUN, never from a list
// maintained by hand. A hand-maintained list would have been written the day
// this file was, so any clause added afterwards — starting with the two
// clauses of v1.7.0, written hours later — would have been born unmutated,
// and the check would carry the very defect it exists to remove. The cost of
// enumerating is that adding a normative sentence to SPEC.md turns this test
// red until a clause in tests/clauses.ts answers for it. That cost is the
// feature.

import { assertEquals } from "jsr:@std/assert@1";
import { checkClause, CLAUSES, normalize, readDoc } from "./clauses.ts";

/** How each obligation is weakened. Longest alternative first. */
const WEAKENING: Array<[string, string]> = [
  ["MUST NOT", "MAY"],
  ["SHALL NOT", "MAY"],
  ["MUST NEVER", "SHOULD NOT"],
  ["MUST", "SHOULD"],
  ["SHALL", "SHOULD"],
  ["REQUIRED", "OPTIONAL"],
];

const TOKEN_RE = new RegExp(
  WEAKENING.map(([t]) => t).join("|"),
  "g",
);

interface Obligation {
  index: number;
  line: number;
  token: string;
  weakened: string;
  start: number;
  context: string;
}

/** Extract every RFC 2119 obligation of a document, in document order. */
export function obligations(text: string): Obligation[] {
  const found: Obligation[] = [];
  TOKEN_RE.lastIndex = 0;
  for (const match of text.matchAll(TOKEN_RE)) {
    const start = match.index!;
    const token = match[0];
    const weakened = WEAKENING.find(([t]) => t === token)![1];
    found.push({
      index: found.length + 1,
      line: text.slice(0, start).split("\n").length,
      token,
      weakened,
      start,
      context: normalize(
        text.slice(Math.max(0, start - 60), start + token.length + 60),
      ),
    });
  }
  return found;
}

const SPEC_RAW = readDoc("SPEC.md").replace(/\r\n/g, "\n");
const SPEC_CLAUSES = CLAUSES.filter((c) => c.doc === "SPEC.md");

/**
 * Every document the registry covers, not only SPEC.md. Scoping the pass to
 * one file would be the same "remedy the instance, never the class" habit the
 * pass exists to break: ERROR_CODES.md carries the retry obligation §9
 * delegates to it, and vectors/README.md carries the ban on the test key ever
 * appearing in a production registry. Both were readable by no test at all
 * until v1.7.0.
 */
const DOCUMENTS = [...new Set(CLAUSES.map((c) => c.doc))];

/**
 * CHANGELOG.md is covered by clauses (it is part of the contract: it is how a
 * deployed verifier learns what a minor added) but it is NOT mutated.
 *
 * Its RFC 2119 words are QUOTATIONS. "verifiers MUST reject them" in the 1.1.0
 * entry is a report of what 1.1.0 did, and the obligation it reports is live
 * in SPEC.md, where the pass covers it. Mutating a historical entry proves
 * nothing about the format and would force a verbatim pin on every past
 * release — freezing the record, and doing it with exactly the hand-written
 * constants this file exists to avoid. The live obligations of the other four
 * documents ARE mutated, including the two in the vectors table.
 */
const NOT_MUTATED: readonly string[] = ["CHANGELOG.md"];

Deno.test("mutation pass: the enumerator reads SPEC.md, not a stored list", () => {
  const all = obligations(SPEC_RAW);
  // A floor, not a pin. Pinning the exact count would be a hand-written
  // constant blessing today's document — the failure mode this whole file is
  // an answer to. The floor only catches an enumerator that silently stopped
  // matching (a bad regex, a file read that returned nothing).
  if (all.length < 20) {
    throw new Error(
      `the enumerator found only ${all.length} obligation(s) in SPEC.md; ` +
        `it is broken, not the document`,
    );
  }
  // Cross-check the enumerator against an independent count, so a regex that
  // silently drops a whole token class is caught.
  const naive = (SPEC_RAW.match(/\bMUST\b|\bSHALL\b|\bREQUIRED\b/g) ?? [])
    .length;
  if (naive > all.length) {
    throw new Error(
      `a naive scan finds ${naive} normative words but the enumerator ` +
        `returned ${all.length}: the enumerator is dropping obligations`,
    );
  }
});

Deno.test("mutation pass: every normative token in SPEC.md is load-bearing", () => {
  const all = obligations(SPEC_RAW);
  const survivors: string[] = [];
  const caughtBy = new Map<string, number>();

  for (const ob of all) {
    const mutant = normalize(
      SPEC_RAW.slice(0, ob.start) + ob.weakened +
        SPEC_RAW.slice(ob.start + ob.token.length),
    );

    const reddened: string[] = [];
    for (const clause of SPEC_CLAUSES) {
      if (checkClause(clause, mutant).length > 0) reddened.push(clause.id);
    }

    if (reddened.length === 0) {
      survivors.push(
        `#${ob.index} SPEC.md:${ob.line} "${ob.token}" -> "${ob.weakened}"\n` +
          `      ...${ob.context}...`,
      );
    } else {
      for (const id of reddened) {
        caughtBy.set(id, (caughtBy.get(id) ?? 0) + 1);
      }
    }
  }

  console.log(
    `  mutation pass: ${all.length} obligations in SPEC.md, ` +
      `${all.length - survivors.length} caught, ${survivors.length} survived ` +
      `(${SPEC_CLAUSES.length} clauses, ${caughtBy.size} of them load-bearing)`,
  );

  assertEquals(
    survivors,
    [],
    `${survivors.length} normative token(s) of SPEC.md can be weakened with ` +
      `the whole suite staying green. Each one needs a clause in ` +
      `tests/clauses.ts that answers for it:\n\n` +
      survivors.map((s) => `  - ${s}`).join("\n\n"),
  );
});

Deno.test("mutation pass: every normative token in EVERY covered document is load-bearing", () => {
  const survivors: string[] = [];
  let total = 0;

  for (const name of DOCUMENTS) {
    if (NOT_MUTATED.includes(name)) continue;
    const raw = readDoc(name).replace(/\r\n/g, "\n");
    const clauses = CLAUSES.filter((c) => c.doc === name);
    for (const ob of obligations(raw)) {
      total++;
      const mutant = normalize(
        raw.slice(0, ob.start) + ob.weakened +
          raw.slice(ob.start + ob.token.length),
      );
      const reddened = clauses.filter((c) =>
        checkClause(c, mutant).length > 0
      );
      if (reddened.length === 0) {
        survivors.push(
          `${name}:${ob.line} "${ob.token}" -> "${ob.weakened}"\n` +
            `      ...${ob.context}...`,
        );
      }
    }
  }

  console.log(
    `  mutation pass (all documents): ${total} obligations across ` +
      `${DOCUMENTS.length} documents, ${total - survivors.length} caught, ` +
      `${survivors.length} survived`,
  );

  assertEquals(
    survivors,
    [],
    `${survivors.length} normative token(s) can be weakened with the whole ` +
      `suite staying green:\n\n` +
      survivors.map((s) => `  - ${s}`).join("\n\n"),
  );
});

Deno.test("mutation pass: no clause in the registry is inert", () => {
  // A clause that never reacts to any mutation is not necessarily wrong — it
  // may pin a sentence that carries no RFC 2119 token (§10 versioning, the
  // README scope-of-proof line). But an inert clause in a *document-scoped*
  // pass is worth naming, because the usual cause is a pattern so loose it
  // matches the weakened text too.
  const all = obligations(SPEC_RAW);
  const reactive = new Set<string>();
  for (const ob of all) {
    const mutant = normalize(
      SPEC_RAW.slice(0, ob.start) + ob.weakened +
        SPEC_RAW.slice(ob.start + ob.token.length),
    );
    for (const clause of SPEC_CLAUSES) {
      if (checkClause(clause, mutant).length > 0) reactive.add(clause.id);
    }
  }
  const inert = SPEC_CLAUSES
    .filter((c) => !reactive.has(c.id))
    .map((c) => c.id);

  // Clauses that pin sentences carrying no RFC 2119 token of their own. They
  // are not decoration: §10 is the rule every additive change in this document
  // leans on, and the §8 recipe is the paragraph a clean-room implementer
  // actually follows — it names the steps, and the obligations it defers to
  // live in §7, §7.1, §7.2 and the attribution clause, each with its own entry
  // here. A clause landing on this list by accident is the loose-pattern bug
  // the assertion below exists to catch, so keep it short and justify additions.
  const declaredInert = ["spec/10/versioning", "spec/8/recipe"];
  const unexpected = inert.filter((id) => !declaredInert.includes(id));
  assertEquals(
    unexpected,
    [],
    `clause(s) that no mutation of SPEC.md can redden — usually a pattern ` +
      `loose enough to match the weakened text as well:\n` +
      unexpected.map((id) => `  - ${id}`).join("\n"),
  );
  const wronglyDeclared = declaredInert.filter((id) => reactive.has(id));
  assertEquals(
    wronglyDeclared,
    [],
    `clause(s) declared inert that actually react; remove them from the list`,
  );
});
