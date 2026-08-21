// Runs the normative-clause registry (tests/clauses.ts) against the real
// documents of this repository.
//
// This is the test half of the pair. The other half, tests/mutation.test.ts,
// proves that the registry is COMPLETE — that no normative token of SPEC.md
// can be weakened without one of these clauses going red. Neither test is
// useful without the other: this one can pass on a registry that covers three
// clauses out of forty, and that one can pass on a registry of assertions
// nobody ever ran against the real file.

import { assertEquals } from "jsr:@std/assert@1";
import {
  type Clause,
  checkClause,
  CLAUSES,
  type DocName,
  normalize,
  readDoc,
} from "./clauses.ts";

const docCache = new Map<DocName, string>();
function doc(name: DocName): string {
  let text = docCache.get(name);
  if (text === undefined) {
    text = normalize(readDoc(name));
    docCache.set(name, text);
  }
  return text;
}

Deno.test("clause registry: every id is unique", () => {
  const seen = new Set<string>();
  const duplicates: string[] = [];
  for (const clause of CLAUSES) {
    if (seen.has(clause.id)) duplicates.push(clause.id);
    seen.add(clause.id);
  }
  assertEquals(duplicates, [], "duplicate clause ids");
});

Deno.test("clause registry: every clause holds in its document", () => {
  const failures: string[] = [];
  for (const clause of CLAUSES) {
    for (const failure of checkClause(clause, doc(clause.doc))) {
      failures.push(`[${clause.doc}] ${failure.clause}: ${failure.reason}`);
    }
  }
  assertEquals(
    failures,
    [],
    `${failures.length} normative clause(s) no longer hold:\n` +
      failures.map((f) => `  - ${f}`).join("\n"),
  );
});

// Coverage of the four documents that had none. Named individually so a
// deletion shows up as a missing document rather than as a smaller number.
for (
  const [name, minimum] of [
    ["SPEC.md", 20],
    ["ERROR_CODES.md", 3],
    ["README.md", 3],
    ["vectors/README.md", 2],
    ["CHANGELOG.md", 2],
  ] as Array<[DocName, number]>
) {
  Deno.test(`clause registry: ${name} is covered`, () => {
    const forDoc = CLAUSES.filter((c: Clause) => c.doc === name);
    if (forDoc.length < minimum) {
      throw new Error(
        `${name} carries only ${forDoc.length} clause(s), expected at least ` +
          `${minimum}. Four documents of this repository (ERROR_CODES.md, ` +
          `CHANGELOG.md, README.md, vectors/README.md) were read by no test ` +
          `at all before v1.7.0; this floor keeps that from happening again.`,
      );
    }
    // A clause that names a document it does not live in would silently
    // inflate the count above.
    for (const clause of forDoc) {
      assertEquals(
        checkClause(clause, doc(name)),
        [],
        `${clause.id} does not hold in ${name}`,
      );
    }
  });
}
