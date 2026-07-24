// Independent re-execution of the crypto vectors (B2 §2.8) from the published
// JSON files. This test deliberately re-implements the few formulas inline —
// it plays the role of the "independent third party" reading SPEC.md, and
// must agree with the reference implementation in humarch-verify.
import { assertEquals } from "jsr:@std/assert@1";
import canonicalizeImport from "npm:canonicalize@2.0.0";

const canonicalize = canonicalizeImport as unknown as (input: unknown) => string | undefined;
const enc = new TextEncoder();
const toHex = (b: Uint8Array) => Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");
const fromHex = (s: string) => Uint8Array.from(s.match(/.{1,2}/g) ?? [], (h) => parseInt(h, 16));
const sha256 = async (b: Uint8Array) =>
  toHex(new Uint8Array(await crypto.subtle.digest("SHA-256", b as BufferSource)));
const jcsHash = (o: unknown) => sha256(enc.encode(canonicalize(o) as string));

const vec = (p: string) =>
  JSON.parse(Deno.readTextFileSync(new URL(`../vectors/${p}`, import.meta.url)));

Deno.test("V0 — genesis", async () => {
  const v = vec("chain/v0.json");
  assertEquals(await sha256(enc.encode("humarch:genesis:" + v.tenant_id)), v.genesis);
});

for (const name of ["v1a", "v1b"]) {
  Deno.test(`${name.toUpperCase()} — canonicalization`, async () => {
    const v = vec(`canonicalization/${name}.json`);
    assertEquals(canonicalize(v.input), v.canonical);
    assertEquals(await jcsHash(v.input), v.sha256);
  });
}

Deno.test("V1c — escape equivalence", async () => {
  const v = vec("canonicalization/v1c.json");
  assertEquals(canonicalize(v.input_literal), v.canonical);
  assertEquals(canonicalize(JSON.parse(v.input_escaped_text)), v.canonical);
  assertEquals(await jcsHash(v.input_literal), v.sha256);
});

async function checkEvent(v: { event: Record<string, unknown>; actor_hash: string; subject_hash: string }, publicKey: string) {
  const e = v.event as Record<string, string | number | object>;
  assertEquals(await jcsHash(e.actor), v.actor_hash);
  assertEquals(await jcsHash(e.subject), v.subject_hash);
  assertEquals(await jcsHash(e.payload), e.payload_hash);
  const pre = "humarch:event:v1\n" + e.event_id + "\n" + e.tenant_id + "\n" +
    String(e.sequence_number) + "\n" + e.received_at + "\n" + e.occurred_at + "\n" +
    e.source + "\n" + e.event_type + "\n" +
    v.actor_hash + "\n" + v.subject_hash + "\n" + e.payload_hash + "\n" + e.prev_hash + "\n";
  assertEquals(await sha256(enc.encode(pre)), e.event_hash);
  // self-certifying key id (D16)
  assertEquals("ed25519:" + (await sha256(fromHex(publicKey))).slice(0, 16), e.signing_key_id);
  // Ed25519 over the raw digest bytes (D13)
  const key = await crypto.subtle.importKey(
    "raw", fromHex(publicKey) as BufferSource, { name: "Ed25519" }, false, ["verify"],
  );
  assertEquals(
    await crypto.subtle.verify(
      { name: "Ed25519" }, key,
      fromHex(e.signature as string) as BufferSource,
      fromHex(e.event_hash as string) as BufferSource,
    ),
    true,
  );
}

Deno.test("V2 — full event reproduction", async () => {
  const v = vec("chain/v2.json");
  await checkEvent(v, v.signing_key.public_key);
});

Deno.test("V3 — chained event reproduction", async () => {
  const v2 = vec("chain/v2.json");
  const v3 = vec("chain/v3.json");
  assertEquals(v3.event.prev_hash, v2.event.event_hash);
  await checkEvent(v3, v2.signing_key.public_key);
});

Deno.test("V4 — anchor aggregate (D9)", async () => {
  const v = vec("anchors/v4.json");
  const lines = [...v.entries]
    .sort((x, y) => (x.tenant_id < y.tenant_id ? -1 : 1))
    .map((e) => `${e.tenant_id}:${e.last_event_hash}\n`).join("");
  assertEquals(
    await sha256(enc.encode(`humarch:anchor:${v.anchor_date}\n` + lines)),
    v.aggregate_hash,
  );
});

Deno.test("V5a — the altered payload hashes to the published mismatch value", async () => {
  const v5 = vec("negative/v5.json");
  assertEquals(await jcsHash(v5.v5a.altered_payload), v5.v5a.altered_payload_hash);
});

// ---------------------------------------------------------------------------
// V6 — crypto-shredding (B8 §8.9). DEK/IV fixed only for the vector.
// ---------------------------------------------------------------------------
const b64 = (b: Uint8Array) => btoa(String.fromCharCode(...b));

Deno.test("V6 — envelope reproduction (AES-256-GCM, AAD = domain:subject)", async () => {
  const v = vec("shredding/v6.json");
  const e = v.encryption;
  assertEquals(canonicalize(e.personal_clear), e.personal_jcs);
  const key = await crypto.subtle.importKey(
    "raw", fromHex(e.dek) as BufferSource, { name: "AES-GCM" }, false, ["encrypt"],
  );
  const sealed = new Uint8Array(await crypto.subtle.encrypt(
    {
      name: "AES-GCM",
      iv: fromHex(e.iv) as BufferSource,
      additionalData: enc.encode(e.aad) as BufferSource,
    },
    key,
    enc.encode(e.personal_jcs) as BufferSource,
  ));
  const envlp = v.event.payload.personal;
  assertEquals(b64(fromHex(e.iv)), envlp.iv);
  assertEquals(b64(sealed.slice(0, -16)), envlp.ct);
  assertEquals(b64(sealed.slice(-16)), envlp.tag);
});

Deno.test("V6a — full event reproduction on the stored form, no DEK needed", async () => {
  const v = vec("shredding/v6.json");
  // checkEvent recomputes every hash from the stored (encrypted) form and
  // verifies the signature: exactly what a third party does without keys.
  await checkEvent(v, v.signing_key.public_key);
});

Deno.test("V6c — without the right DEK, decryption fails (irrecoverable after shred)", async () => {
  const v = vec("shredding/v6.json");
  const e = v.encryption;
  const envlp = v.event.payload.personal;
  const wrongDek = fromHex(e.dek.replace(/^00/, "ff"));
  const key = await crypto.subtle.importKey(
    "raw", wrongDek as BufferSource, { name: "AES-GCM" }, false, ["decrypt"],
  );
  const fromB64 = (s: string) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));
  const ctAndTag = new Uint8Array([...fromB64(envlp.ct), ...fromB64(envlp.tag)]);
  let failed = false;
  try {
    await crypto.subtle.decrypt(
      {
        name: "AES-GCM",
        iv: fromB64(envlp.iv) as BufferSource,
        additionalData: enc.encode(e.aad) as BufferSource,
      },
      key,
      ctAndTag as BufferSource,
    );
  } catch {
    failed = true; // WebCrypto's InvalidTag surfaces as OperationError
  }
  assertEquals(failed, true);
});

// ---------------------------------------------------------------------------
// W1 — DEK wrapping at rest (B8 §8.4.1, D55). Recomputed with WebCrypto
// (AES-CBC + HMAC-SHA256): the same standard primitives pgcrypto builds on.
// ---------------------------------------------------------------------------
const hmacSha256 = async (keyBytes: Uint8Array, data: Uint8Array) => {
  const k = await crypto.subtle.importKey(
    "raw", keyBytes as BufferSource, { name: "HMAC", hash: "SHA-256" }, false, ["sign"],
  );
  return new Uint8Array(await crypto.subtle.sign("HMAC", k, data as BufferSource));
};
const hkdfExpand = (kek: Uint8Array, label: string) =>
  hmacSha256(kek, new Uint8Array([...enc.encode(label), 0x01]));

Deno.test("W1 — subkeys, ciphertext, MAC and wrapped_dek reproduction", async () => {
  const w = vec("wrapping/w1.json");
  const kek = fromHex(w.kek);
  assertEquals(toHex(await hkdfExpand(kek, w.subkeys.enc_label)), w.subkeys.enc_key);
  assertEquals(toHex(await hkdfExpand(kek, w.subkeys.mac_label)), w.subkeys.mac_key);
  assertEquals(toHex(await hkdfExpand(kek, w.subkeys.cmp_label)), w.subkeys.cmp_key);
  const cbcKey = await crypto.subtle.importKey(
    "raw", fromHex(w.subkeys.enc_key) as BufferSource, { name: "AES-CBC" }, false, ["encrypt"],
  );
  const ct = new Uint8Array(await crypto.subtle.encrypt(
    { name: "AES-CBC", iv: fromHex(w.iv) as BufferSource },
    cbcKey,
    fromHex(w.dek) as BufferSource,
  ));
  assertEquals(toHex(ct), w.ct); // PKCS#7 padding included
  const ivct = fromHex(w.iv + w.ct);
  assertEquals(toHex(await hmacSha256(fromHex(w.subkeys.mac_key), ivct)), w.mac);
  assertEquals(w.iv + w.ct + w.mac, w.wrapped_dek);
});

Deno.test("W1a/W1b/W1c — round-trip; tamper and wrong KEK fail the MAC before decryption", async () => {
  const w = vec("wrapping/w1.json");
  const wrapped = fromHex(w.wrapped_dek);
  const iv = wrapped.slice(0, 16);
  const ct = wrapped.slice(16, wrapped.length - 32);
  const mac = wrapped.slice(wrapped.length - 32);
  const ivct = wrapped.slice(0, wrapped.length - 32);
  // W1a — Encrypt-then-MAC verify, then decrypt: the original DEK comes back.
  assertEquals(toHex(await hmacSha256(fromHex(w.subkeys.mac_key), ivct)), toHex(mac));
  const cbcKey = await crypto.subtle.importKey(
    "raw", fromHex(w.subkeys.enc_key) as BufferSource, { name: "AES-CBC" }, false, ["decrypt"],
  );
  const dek = new Uint8Array(await crypto.subtle.decrypt(
    { name: "AES-CBC", iv: iv as BufferSource }, cbcKey, ct as BufferSource,
  ));
  assertEquals(toHex(dek), w.dek);
  // W1b — any flipped byte invalidates the MAC (checked BEFORE decryption).
  for (const at of [0, 16, wrapped.length - 1]) {
    const tampered = wrapped.slice();
    tampered[at] ^= 0x01;
    const tMac = toHex(await hmacSha256(
      fromHex(w.subkeys.mac_key),
      tampered.slice(0, wrapped.length - 32),
    ));
    const declared = toHex(tampered.slice(wrapped.length - 32));
    assertEquals(tMac === declared, false, `byte ${at}: MAC must not verify`);
  }
  // W1c — a different KEK derives a different mac_key: the MAC never verifies.
  const wrongKek = fromHex(w.kek.replace(/^20/, "ff"));
  const wrongMacKey = await hkdfExpand(wrongKek, w.subkeys.mac_label);
  assertEquals(toHex(await hmacSha256(wrongMacKey, ivct)) === toHex(mac), false);
});
