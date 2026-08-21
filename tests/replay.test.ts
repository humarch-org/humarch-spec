// The v1.7 replay-divergence vectors (SPEC §1.0.1, D109).
//
// Like tests/vectors.test.ts, this file plays the "independent third party"
// reading SPEC.md: it re-implements the rule inline from the prose, against
// the published cases, and must agree with the registry that emits it. The
// rule is small on purpose — a closed set of three names, compared by JCS
// canonical form — because the whole point of D109 is to make a discard
// visible without touching the identity criterion of D24.

import { assertEquals } from "jsr:@std/assert@1";
import canonicalizeImport from "npm:canonicalize@2.0.0";

const canonicalize = canonicalizeImport as unknown as (
  input: unknown,
) => string | undefined;

interface ReplayCase {
  id: string;
  description: string;
  idempotency_key: string;
  first: Record<string, unknown>;
  second: Record<string, unknown>;
  expect_status: number;
  expect_error_code?: string;
  expect_idempotent_replay: boolean | null;
  expect_replay_divergence: { fields: string[]; count: number } | null;
}

const CASES: ReplayCase[] = JSON.parse(
  Deno.readTextFileSync(new URL("../vectors/replay/cases.json", import.meta.url)),
);

/** SPEC §1.0.1 point 2: the set is CLOSED, and this is the whole of it. */
const ATTRIBUTION_FIELDS = ["actor", "event_type", "subject"] as const;

/**
 * SPEC §1.0.1 points 2–4. Returns null when nothing diverged — the case the
 * field must stay absent for.
 */
function replayDivergence(
  first: Record<string, unknown>,
  second: Record<string, unknown>,
): { fields: string[]; count: number } | null {
  const fields = ATTRIBUTION_FIELDS
    // Point 3: compare the JCS canonical form, never the text. For the enum
    // `event_type` this degenerates to a direct comparison, which is what the
    // spec says it should.
    .filter((f) => canonicalize(first[f]) !== canonicalize(second[f]))
    // Point 2: lexicographic order. ATTRIBUTION_FIELDS is already in it, but
    // sorting explicitly means a future reordering of the constant cannot
    // silently change the wire format.
    .toSorted();
  return fields.length === 0 ? null : { fields, count: fields.length };
}

Deno.test("replay vectors: the case file is the five shapes D109 specifies", () => {
  assertEquals(
    CASES.map((c) => c.id),
    [
      "r01-identical-replay",
      "r02-actor-diverges",
      "r03-actor-and-event-type-diverge",
      "r04-subject-diverges",
      "r05-payload-diverges-stays-409",
    ],
  );
});

for (const c of CASES) {
  Deno.test(`replay: ${c.id}`, () => {
    // Point 5/6: a different payload is not a replay at all. The identity
    // criterion of D24 decides that, and no declaration rides on the error.
    const samePayload = canonicalize(c.first.payload) ===
      canonicalize(c.second.payload);
    if (!samePayload) {
      assertEquals(c.expect_status, 409, "a divergent payload stays a 409");
      assertEquals(c.expect_error_code, "DUPLICATE_IDEMPOTENCY_KEY");
      assertEquals(
        c.expect_replay_divergence,
        null,
        "error bodies never carry replay_divergence",
      );
      assertEquals(c.expect_idempotent_replay, null);
      return;
    }

    assertEquals(c.expect_status, 202, "a replay keeps its 202 (point 5)");
    assertEquals(c.expect_idempotent_replay, true);
    assertEquals(
      replayDivergence(c.first, c.second),
      c.expect_replay_divergence,
      c.description,
    );
  });
}

Deno.test("replay: the field set is closed — a payload difference alone never names a field", () => {
  // The trap this guards: implementing the comparison over "everything except
  // the payload" rather than over the three named fields. Both behave the same
  // on the five cases above, and differ the first time a sender adds
  // occurred_at or raw_payload to a retransmission — transport metadata, which
  // SPEC §1.0.1 point 2 says is not attribution.
  const base = {
    event_type: "agent_action",
    actor: { type: "agent", id: "asst_4kx" },
    subject: { end_client: { ref: "acme-ltd" } },
    payload: { action: "send_email" },
  };
  assertEquals(
    replayDivergence(base, { ...base, occurred_at: "2026-08-21T09:00:00.000000Z" }),
    null,
  );
  assertEquals(replayDivergence(base, { ...base, raw_payload: { a: 1 } }), null);
});

Deno.test("replay: comparison is by canonical form, not by text", () => {
  // SPEC §1.0.1 point 3. Two spellings of the same value are the same value;
  // an implementation comparing serialized text would report a divergence
  // that did not happen, and a sender would chase a discard that never
  // occurred.
  const a = {
    actor: { type: "agent", id: "asst_4kx" },
    subject: { end_client: { ref: "acme-ltd" }, tool: { ref: "gmail" } },
    event_type: "agent_action",
  };
  const b = {
    actor: { id: "asst_4kx", type: "agent" },
    subject: { tool: { ref: "gmail" }, end_client: { ref: "acme-ltd" } },
    event_type: "agent_action",
  };
  assertEquals(replayDivergence(a, b), null);
});

Deno.test("replay: fields is lexicographically ordered whatever the input order", () => {
  const first = {
    event_type: "agent_action",
    actor: { type: "agent", id: "a" },
    subject: { end_client: { ref: "x" } },
  };
  const second = {
    event_type: "custom",
    actor: { type: "human", id: "b" },
    subject: { end_client: { ref: "y" } },
  };
  const d = replayDivergence(first, second)!;
  assertEquals(d.fields, ["actor", "event_type", "subject"]);
  assertEquals(d.count, 3);
  assertEquals(d.fields, d.fields.toSorted(), "already ordered");
});
