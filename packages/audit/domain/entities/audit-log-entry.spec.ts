import { describe, expect, it } from "vitest";

import { utf8ByteLength } from "../value-objects/audit-metadata.js";

import { AuditLogEntry, GENESIS_HASH, verifyChain } from "./audit-log-entry.js";

function chainOf(length: number): AuditLogEntry[] {
  const entries: AuditLogEntry[] = [];
  let previous: AuditLogEntry | undefined;

  for (let index = 0; index < length; index += 1) {
    const entry = AuditLogEntry.append({
      action: "user.login_succeeded",
      actorId: `actor-${String(index)}`,
      previous,
      occurredAt: new Date(1_700_000_000_000 + index * 1000),
    });
    entries.push(entry);
    previous = entry;
  }

  return entries;
}

describe("AuditLogEntry", () => {
  it("starts a chain from the genesis hash", () => {
    const first = AuditLogEntry.append({ action: "user.registered" });

    expect(first.sequence).toBe(1);
    expect(first.previousHash).toBe(GENESIS_HASH);
  });

  it("links each entry to its predecessor", () => {
    const [first, second] = chainOf(2);

    expect(second?.sequence).toBe(2);
    expect(second?.previousHash).toBe(first?.hash);
  });

  it("produces a 64-character hex digest", () => {
    expect(AuditLogEntry.append({ action: "user.registered" }).hash).toMatch(/^[0-9a-f]{64}$/);
  });

  it("verifies its own hash against its content", () => {
    expect(AuditLogEntry.append({ action: "user.registered" }).hasValidHash).toBe(true);
  });

  it("gives different hashes to entries differing only in one field", () => {
    const occurredAt = new Date(1_700_000_000_000);
    const a = AuditLogEntry.append({ action: "user.login_succeeded", actorId: "x", occurredAt });
    const b = AuditLogEntry.append({ action: "user.login_failed", actorId: "x", occurredAt });

    expect(a.hash).not.toBe(b.hash);
  });

  it("hashes metadata independently of key insertion order", () => {
    // The digest has to be reproducible by someone re-deriving it years later
    // from the stored columns, possibly in another language. If it depended on
    // JavaScript's property order, that reproduction would fail for reasons
    // nobody could diagnose.
    const occurredAt = new Date(1_700_000_000_000);
    const a = AuditLogEntry.append({
      action: "user.registered",
      metadata: { alpha: "1", beta: "2" },
      occurredAt,
    });
    const b = AuditLogEntry.append({
      action: "user.registered",
      metadata: { beta: "2", alpha: "1" },
      occurredAt,
    });

    expect(a.hash).toBe(b.hash);
  });

  it("does not let different field values collide through concatenation", () => {
    // Fields are newline-separated rather than concatenated, so no combination
    // of values can spell the same canonical string as a different one. The
    // classic bug this avoids: actor "ab" + subject "c" hashing identically to
    // actor "a" + subject "bc".
    const occurredAt = new Date(1_700_000_000_000);
    const a = AuditLogEntry.append({
      action: "user.registered",
      actorId: "ab",
      subjectId: "c",
      occurredAt,
    });
    const b = AuditLogEntry.append({
      action: "user.registered",
      actorId: "a",
      subjectId: "bc",
      occurredAt,
    });

    expect(a.hash).not.toBe(b.hash);
  });
});

describe("verifyChain", () => {
  it("accepts an intact chain", () => {
    expect(verifyChain(chainOf(5))).toBeUndefined();
  });

  it("accepts an empty chain", () => {
    expect(verifyChain([])).toBeUndefined();
  });

  it("detects an altered entry", () => {
    // The attack the whole design exists for: someone with write access edits
    // the row recording what they did. The stored hash no longer matches the
    // content, because the check recomputes rather than trusting.
    const entries = chainOf(5);
    const target = entries[2];
    if (target === undefined) throw new Error("fixture setup failed");

    entries[2] = AuditLogEntry.reconstitute({
      id: target.id,
      sequence: target.sequence,
      action: "user.registered",
      actorId: target.actorId,
      subjectId: target.subjectId,
      metadata: target.metadata,
      occurredAt: target.occurredAt,
      previousHash: target.previousHash,
      // The original hash, kept — which is exactly what an attacker editing
      // one column would leave behind.
      hash: target.hash,
    });

    expect(verifyChain(entries)).toEqual({ sequence: 3, reason: "content_altered" });
  });

  it("detects a deleted entry", () => {
    // Removal does not break any single entry's own hash — each remaining one
    // is internally fine. What breaks is the link, because entry 4 still
    // commits to the hash of the entry that is now missing.
    const entries = chainOf(5);
    entries.splice(2, 1);

    expect(verifyChain(entries)).toEqual({ sequence: 4, reason: "link_broken" });
  });

  it("detects a truncated chain that was renumbered", () => {
    // A more careful attacker removes the last entries rather than one in the
    // middle, leaving a chain that links correctly. That is genuinely
    // undetectable from the chain alone — which is precisely why the head gets
    // anchored externally. Here the counter is what gives it away.
    const entries = chainOf(5).slice(1);

    expect(verifyChain(entries)).toEqual({ sequence: 2, reason: "link_broken" });
  });

  it("reports only the first break", () => {
    // Everything after a break is unreliable as a consequence of it, and
    // listing the cascade would bury the one fact that matters.
    const entries = chainOf(6);
    entries.splice(1, 1);

    const result = verifyChain(entries);
    expect(result?.sequence).toBe(3);
  });

  it("accepts a chain rewritten wholesale, which is the documented limit", () => {
    // Worth an explicit test because it is the property most often claimed and
    // least often true. An attacker with full write access can rebuild the
    // chain from any point; the result verifies perfectly. Hash chaining makes
    // tampering *evident to someone holding an earlier hash* — it does not
    // make it impossible. That gap is what anchoring to Stellar closes.
    const rewritten = chainOf(3);

    expect(verifyChain(rewritten)).toBeUndefined();
  });

  describe("canonical form", () => {
    // The hash is only a commitment to *this entry* if nothing inside a field
    // can be read as framing. These are the collisions the newline-joined
    // pre-image allowed; each pair is two different facts.
    const shape = {
      action: "user.login_succeeded" as const,
      occurredAt: new Date(1_700_000_000_000),
    };

    it("does not let a newline move the boundary between actorId and subjectId", () => {
      const split = AuditLogEntry.append({
        ...shape,
        actorId: "a\nb",
        subjectId: "c",
      });
      const joined = AuditLogEntry.append({
        ...shape,
        actorId: "a",
        subjectId: "b\nc",
      });

      expect(split.hash).not.toBe(joined.hash);
    });

    it("does not let a separator inside a metadata value shift a pair boundary", () => {
      // Same trick, one layer down: with a naive `key=value` join, two pairs and
      // one pair whose value contains the framing come out identically.
      const twoPairs = AuditLogEntry.append({
        ...shape,
        actorId: "actor",
        metadata: { a: "b", c: "d" },
      });
      const onePair = AuditLogEntry.append({
        ...shape,
        actorId: "actor",
        metadata: { a: "b;c=d" },
      });

      expect(twoPairs.hash).not.toBe(onePair.hash);
    });

    it("does not let the action absorb the following fields", () => {
      const a = AuditLogEntry.append({
        action: `user.login_succeeded\nactor-1` as AuditLogEntry["action"],
        actorId: "x",
        occurredAt: shape.occurredAt,
      });
      const b = AuditLogEntry.append({
        ...shape,
        actorId: "actor-1\nx",
      });

      expect(a.hash).not.toBe(b.hash);
    });

    it("hashes the same content regardless of metadata insertion order", () => {
      const sorted = AuditLogEntry.append({
        ...shape,
        metadata: { a: "1", b: "2" },
      });
      const reversed = AuditLogEntry.append({
        ...shape,
        metadata: { b: "2", a: "1" },
      });

      expect(sorted.hash).toBe(reversed.hash);
    });

    it("keeps a metadata-free entry distinct from one with an empty-string value", () => {
      const absent = AuditLogEntry.append({ ...shape, metadata: {} });
      const present = AuditLogEntry.append({ ...shape, metadata: { k: "" } });

      expect(absent.hash).not.toBe(present.hash);
    });

    it("is stable for multi-byte content, which a character count would not be", () => {
      // The declared lengths are UTF-8 byte lengths, so the pre-image can be
      // re-derived from the stored columns by something that is not this
      // runtime. A JavaScript `.length` counts UTF-16 code units, and the two
      // disagree on anything outside ASCII — an emoji is 2 units and 4 bytes.
      const entry = AuditLogEntry.append({
        ...shape,
        metadata: { note: "café 👍" },
      });

      expect(entry.hasValidHash).toBe(true);
      expect(utf8ByteLength("café 👍")).toBe(10);
    });
  });

  describe("toLogFields", () => {
    it("renders one entry as text that cannot end a record early", () => {
      const entry = AuditLogEntry.append({
        action: "user.login_failed",
        actorId: "attacker\n[2026-10-02] INFO audit: admin login granted",
        metadata: { reason: "bad password\r\nsecond line" },
      });

      const fields = entry.toLogFields();

      for (const value of Object.values(fields)) {
        // eslint-disable-next-line no-control-regex -- asserting their absence is the test.
        expect(value).not.toMatch(/[\r\n\u0000-\u0008\u000b\u000c\u000e-\u001f]/u);
      }
      expect(fields.actorId).toContain("\\n");
      // The content itself is unchanged in storage, so the digest still matches.
      expect(entry.hasValidHash).toBe(true);
    });

    it("keeps the metadata field parseable as the JSON it claims to be", () => {
      // A double escape pass is the mistake to guard against: running the text
      // escaper over a JSON document escapes the backslashes the document uses
      // for its own escaping, and the result is neither JSON nor the value.
      const metadata = {
        quote: 'a"b',
        backslash: "a\\b",
        newline: "a\nb",
        control: "\u0007\u0085\u2028\u2029",
        unicode: "café 👍",
      };
      const entry = AuditLogEntry.append({
        action: "user.login_failed",
        metadata,
      });

      const field = entry.toLogFields().metadata ?? "";

      // eslint-disable-next-line no-control-regex -- asserting their absence is the test.
      expect(field).not.toMatch(/[\u0000-\u001f\u0085\u2028\u2029]/u);
      expect(JSON.parse(field)).toEqual(metadata);
    });
  });
});
