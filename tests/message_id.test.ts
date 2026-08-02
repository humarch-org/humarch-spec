// message_id_sha256 conformance (SPEC §1.2.5, v1.4.0). The canonicalization
// of a Message-ID is the one place in the conventions where two honest
// implementations could disagree and produce different digests for the same
// message — the external audit of 2026-08-02 (finding 3) showed the earlier
// one-line rule admitted at least two readings of a folded header. The
// vectors are the contract; the extractor below is the executable reading of
// the normative steps (select → unfold → parse msg-id → hash), and exists so
// that a drift in either direction becomes a test diff.
import { assert, assertEquals } from "jsr:@std/assert@1";

const CR = String.fromCharCode(13);
const LF = String.fromCharCode(10);
const HTAB = String.fromCharCode(9);
const CRLF = CR + LF;

const ATEXT = /[A-Za-z0-9!#$%&'*+\-/=?^_`{|}~]/;
// dtext (RFC 5322 §3.4.1): %d33-90 / %d94-126 — printable ASCII minus
// "[" (91), "\" (92) and "]" (93).
const DTEXT = /[\x21-\x5A\x5E-\x7E]/;

/** Step 2 — RFC 5322 §2.2.3: drop every CRLF immediately followed by WSP. */
function unfold(body: string): string {
  return body.replace(new RegExp(CRLF + "(?=[ " + HTAB + "])", "g"), "");
}

/** Skip CFWS (whitespace and nested comments); -1 on an unterminated comment. */
function skipCfws(s: string, i: number): number {
  for (;;) {
    while (i < s.length && (s[i] === " " || s[i] === HTAB)) i++;
    if (s[i] !== "(") return i;
    let depth = 0;
    while (i < s.length) {
      const c = s[i];
      if (c === "\\") {
        i += 2;
        continue;
      }
      if (c === "(") depth++;
      else if (c === ")") {
        depth--;
        i++;
        if (depth === 0) break;
        else continue;
      }
      i++;
    }
    if (depth !== 0) return -1;
  }
}

function dotAtomText(s: string, i: number): number {
  for (;;) {
    let atoms = 0;
    while (i < s.length && ATEXT.test(s[i])) {
      i++;
      atoms++;
    }
    if (atoms === 0) return -1;
    if (s[i] === ".") {
      i++;
      continue;
    }
    return i;
  }
}

/**
 * Steps 1–3: the msg-id token of one header field body, or null when the body
 * does not match the RFC 5322 §3.6.4 production in full (obsolete forms,
 * trailing garbage, unterminated comment). Comments are discarded even when
 * they contain angle brackets — the trap that makes a naive "first < to
 * last >" extraction hash a token that never existed.
 */
function msgIdToken(rawBody: string): string | null {
  const s = unfold(rawBody);
  let i = skipCfws(s, 0);
  if (i < 0) return null;
  const start = i;
  if (s[i] !== "<") return null;
  i++;
  const left = dotAtomText(s, i);
  if (left < 0) return null;
  i = left;
  if (s[i] !== "@") return null;
  i++;
  if (s[i] === "[") { // no-fold-literal = "[" *dtext "]"
    i++;
    // dtext is %d33-90 / %d94-126: printable ASCII except "[", "\" and "]".
    // Validating it (rather than scanning to the next "]") keeps the token
    // US-ASCII by construction and refuses `<a@[192.0.2.10 ]>`, whose space
    // the production does not admit — adversarial review, 2026-08-02.
    while (i < s.length && DTEXT.test(s[i])) i++;
    if (s[i] !== "]") return null;
    i++;
  } else {
    const right = dotAtomText(s, i);
    if (right < 0) return null;
    i = right;
  }
  if (s[i] !== ">") return null;
  i++;
  const token = s.slice(start, i);
  const rest = skipCfws(s, i);
  if (rest < 0 || rest !== s.length) return null;
  return token;
}

/** Steps 1 and 4: the declared value of message_id_sha256, or null. */
async function messageIdSha256(headers: string[]): Promise<string | null> {
  if (headers.length !== 1) return null; // absent or duplicated ⇒ not declared
  const token = msgIdToken(headers[0]);
  if (token === null) return null;
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(token));
  return Array.from(new Uint8Array(digest), (b) => b.toString(16).padStart(2, "0")).join("");
}

interface Case {
  description: string;
  headers: string[];
  expect_msg_id: string | null;
  expect_message_id_sha256: string | null;
}

const cases: Case[] = JSON.parse(
  Deno.readTextFileSync(new URL("../vectors/message-id/cases.json", import.meta.url)),
);

Deno.test("message-id vectors: the case file is the contract (14 cases, 7 of them omissions)", () => {
  assertEquals(cases.length, 14);
  assertEquals(cases.filter((c) => c.expect_message_id_sha256 === null).length, 7);
  // The omissions are the load-bearing half: zero headers, several headers,
  // and every body the production does not accept in full.
  assertEquals(cases.filter((c) => c.headers.length === 0).length, 1);
  assertEquals(cases.filter((c) => c.headers.length > 1).length, 1);
});

Deno.test("message-id: every declared token is US-ASCII (step 3 admits nothing else)", () => {
  for (const c of cases) {
    if (c.expect_msg_id === null) continue;
    assertEquals(
      /^[\x20-\x7E]+$/.test(c.expect_msg_id),
      true,
      "non-ASCII token in vector: " + c.description,
    );
  }
});

for (const c of cases) {
  Deno.test("message_id_sha256 vector — " + c.description, async () => {
    if (c.headers.length === 1) {
      assertEquals(msgIdToken(c.headers[0]), c.expect_msg_id, "extracted token");
    }
    assertEquals(await messageIdSha256(c.headers), c.expect_message_id_sha256);
  });
}

Deno.test("message_id_sha256: folding, outer whitespace and bracket-bearing comments collapse to ONE digest", async () => {
  // The ambiguity the audit found: a folded header used to admit two
  // readings. Every spelling of the same message MUST hash identically, and
  // a comment carrying angle brackets must never be mistaken for the id.
  const spellings = [
    "<20260802094107.5A2C@mail.example.com>",
    " <20260802094107.5A2C@mail.example.com>" + HTAB,
    "(audit)" + CRLF + HTAB + "<20260802094107.5A2C@mail.example.com>",
    "(<not@a.real.id>) <20260802094107.5A2C@mail.example.com>",
  ];
  const digests = new Set<string | null>();
  for (const s of spellings) digests.add(await messageIdSha256([s]));
  assertEquals(digests.size, 1, "one message, one digest");
  const only = [...digests][0];
  assert(only !== null && /^[0-9a-f]{64}$/.test(only));

  // Case is content, not noise: the same id lowercased is a different message.
  assert(
    (await messageIdSha256(["<20260802094107.5a2c@mail.example.com>"])) !== only,
    "no case-folding",
  );
});

Deno.test("message_id_sha256: schema case v11 declares the digest of a documented header", async () => {
  const v11 = JSON.parse(
    Deno.readTextFileSync(
      new URL("../vectors/schema/valid/v11-external-refs.json", import.meta.url),
    ),
  );
  const declared = (v11.envelope.payload.external_refs as Record<string, string>[])
    .find((r) => "message_id_sha256" in r)?.message_id_sha256;
  assertEquals(
    declared,
    await messageIdSha256(["<20260802094107.5A2C@mail.example.com>"]),
    "a schema case must not carry an unanchored digest",
  );
});
