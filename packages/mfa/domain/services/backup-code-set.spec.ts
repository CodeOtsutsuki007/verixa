import { describe, expect, it } from "vitest";

import { BackupCodeSet } from "./backup-code-set.js";

describe("BackupCodeSet", () => {
  it("generates the specified number of backup codes", async () => {
    const result = await BackupCodeSet.generate(10);
    expect(result.rawCodes).toHaveLength(10);
    expect(result.hashedCodes).toHaveLength(10);
  });

  it("generates unique codes within a set", async () => {
    const result = await BackupCodeSet.generate(20);
    const uniqueRaw = new Set(result.rawCodes);
    const uniqueHashes = new Set(result.hashedCodes);

    expect(uniqueRaw.size).toBe(20);
    expect(uniqueHashes.size).toBe(20);
  });

  it("formats codes as human-readable strings", async () => {
    const result = await BackupCodeSet.generate(1);
    const code = result.rawCodes[0]!;

    // Format XXXXX-XXXXX
    expect(code).toMatch(
      /^[23456789ABCDEFGHJKLMNPQRSTUVWXYZ]{5}-[23456789ABCDEFGHJKLMNPQRSTUVWXYZ]{5}$/,
    );
  });

  it("returns hashed codes that do not contain the plaintext", async () => {
    const result = await BackupCodeSet.generate(1);
    const raw = result.rawCodes[0]!;
    const hash = result.hashedCodes[0]!;

    expect(hash).not.toContain(raw);
    expect(hash.startsWith("$argon2id$")).toBe(true);
  });

  it("can verify a raw code against its hash", async () => {
    const result = await BackupCodeSet.generate(1);
    const raw = result.rawCodes[0]!;
    const hash = result.hashedCodes[0]!;

    const isValid = await BackupCodeSet.verify(raw, hash);
    expect(isValid).toBe(true);
  });

  it("rejects an invalid code", async () => {
    const result = await BackupCodeSet.generate(1);
    const hash = result.hashedCodes[0]!;

    const isValid = await BackupCodeSet.verify("AAAAA-BBBBB", hash);
    expect(isValid).toBe(false);
  });

  it("normalizes input during verification", async () => {
    const result = await BackupCodeSet.generate(1);
    const raw = result.rawCodes[0]!;
    const hash = result.hashedCodes[0]!;

    // Remove dash and lowercase
    const malformedRaw = raw.replace("-", "").toLowerCase();

    const isValid = await BackupCodeSet.verify(malformedRaw, hash);
    expect(isValid).toBe(true);
  });
});
