// The 27 schema cases (B5 §5.2.1; v1.2 amendment D91, v1.4 amendment D100,
// v1.7 reserved sentinel) are the validation contract: 13 valid, 14 invalid
// each failing with the expected JSON Pointer among its errors. v09/v10 pin
// the v1.2 payload conventions (tool_call, delegation), v11/v12 the v1.4
// conventions (external_refs, execution): valid by construction (the payload
// is open, D30) — the cases freeze the canonical field names so a drift
// becomes a test diff. v13/i14 are the two halves of the v1.7 reservation of
// __tenant_default__ (SPEC.md §1.1): i14 pins that an end_client claiming the
// sentinel is refused, v13 pins that workflow and tool are NOT, so widening
// the refusal is as much a test diff as dropping it.
import { assert, assertEquals } from "jsr:@std/assert@1";
import Ajv2020Import from "npm:ajv@8.18.0/dist/2020.js";
import addFormatsImport from "npm:ajv-formats@3.0.1";

// CJS interop: Deno's type-checker sees namespaces instead of the callables.
const Ajv2020 = Ajv2020Import as unknown as new (opts?: Record<string, unknown>) => {
  compile: (schema: unknown) => ((data: unknown) => boolean) & {
    errors?: { instancePath: string; message?: string }[] | null;
  };
};
const addFormats = addFormatsImport as unknown as (ajv: unknown) => void;

const read = (p: string) =>
  JSON.parse(Deno.readTextFileSync(new URL(`../${p}`, import.meta.url)));

const schema = read("event.schema.json");
const ajv = new Ajv2020({ allErrors: true, strict: false });
addFormats(ajv);
const validate = ajv.compile(schema);

const caseFiles = (dir: string): string[] =>
  [...Deno.readDirSync(new URL(`../vectors/schema/${dir}`, import.meta.url))]
    .filter((e) => e.isFile && e.name.endsWith(".json"))
    .map((e) => e.name)
    .sort();

const validNames = caseFiles("valid");
const invalidNames = caseFiles("invalid");

Deno.test("the case count is the contract: 13 valid + 14 invalid = 27", () => {
  assertEquals(validNames.length, 13);
  assertEquals(invalidNames.length, 14);
});

for (const name of validNames) {
  Deno.test(`valid: ${name}`, () => {
    const c = read(`vectors/schema/valid/${name}`);
    const ok = validate(c.envelope);
    assert(ok, `expected valid, got: ${JSON.stringify(validate.errors)}`);
  });
}

for (const name of invalidNames) {
  Deno.test(`invalid: ${name}`, () => {
    const c = read(`vectors/schema/invalid/${name}`);
    const ok = validate(c.envelope);
    assertEquals(ok, false, "expected the envelope to be rejected");
    const pointers = (validate.errors ?? []).map((e) => e.instancePath);
    assert(
      pointers.includes(c.expect_pointer),
      `expected an error at ${JSON.stringify(c.expect_pointer)}, got: ${JSON.stringify(pointers)}`,
    );
  });
}

// ---------------------------------------------------------------------------
// payload.personal oneOf (v1.1 amendment, B8 §8.6). B5 norms no additional
// NUMBERED cases for the container — the numbered cases above stay the
// canonical contract; these cover the amendment without renumbering it.
// ---------------------------------------------------------------------------
const base = (payload: Record<string, unknown>) => ({
  event_type: "agent_action",
  actor: { type: "agent", id: "asst_4kx" },
  subject: { end_client: { ref: "acme-ltd" } },
  payload: { action: "send_email", ...payload },
});
const v6envelope = read("vectors/shredding/v6.json").event.payload.personal;

Deno.test("personal: clear object (ingestion input) is valid", () => {
  assert(validate(base({ personal: { to: "client@example.com" } })));
});

Deno.test("personal: stored envelope (V6) is valid", () => {
  assert(
    validate(base({ personal: v6envelope })),
    JSON.stringify(validate.errors),
  );
});

Deno.test("personal: non-object is rejected at /payload/personal", () => {
  assertEquals(validate(base({ personal: "John Doe" })), false);
  const pointers = (validate.errors ?? []).map((e) => e.instancePath);
  assert(pointers.includes("/payload/personal"), JSON.stringify(pointers));
});

Deno.test("personal: partial envelope shape degrades to the clear branch", () => {
  // The oneOf discriminates on the six required envelope members: an object
  // missing any of them is indistinguishable from a clear object and is
  // accepted as such (at ingestion it would simply be encrypted wholesale).
  const { tag: _tag, ...missingTag } = v6envelope;
  assert(validate(base({ personal: missingTag })));
});

Deno.test("personal: envelope with a wrong enc value matches neither branch", () => {
  assertEquals(validate(base({ personal: { ...v6envelope, enc: "aes-128-gcm" } })), false);
});
