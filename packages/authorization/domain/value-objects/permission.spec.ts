import { Result, ValidationError } from "@verixa/shared-kernel";
import { describe, expect, it } from "vitest";

import { Permission } from "./permission.js";

describe("Permission value object", () => {
  it("creates a valid permission from a resource:action string", () => {
    const result = Permission.create("users:read");
    expect(Result.isOk(result)).toBe(true);
    if (!Result.isOk(result)) return;

    const perm = result.value;
    expect(perm.value).toBe("users:read");
    expect(perm.resource).toBe("users");
    expect(perm.action).toBe("read");
    expect(perm.toString()).toBe("users:read");
  });

  it("normalizes permission strings by trimming and lowercasing", () => {
    const result = Permission.create("  USERS:WRITE  ");
    expect(Result.isOk(result)).toBe(true);
    if (!Result.isOk(result)) return;

    expect(result.value.value).toBe("users:write");
    expect(result.value.resource).toBe("users");
    expect(result.value.action).toBe("write");
  });

  it("supports wildcard actions such as orgs:*", () => {
    const result = Permission.create("orgs:*");
    expect(Result.isOk(result)).toBe(true);
    if (!Result.isOk(result)) return;

    expect(result.value.action).toBe("*");
    expect(result.value.matches(Permission.from("orgs:create"))).toBe(true);
    expect(result.value.matches(Permission.from("orgs:delete"))).toBe(true);
    expect(result.value.matches(Permission.from("users:read"))).toBe(false);
  });

  it("rejects non-string input", () => {
    // @ts-expect-error testing invalid type input
    const result = Permission.create(12345);
    expect(Result.isErr(result)).toBe(true);
    if (!Result.isErr(result)) return;
    expect(result.error).toBeInstanceOf(ValidationError);
  });

  it("rejects empty or whitespace-only strings", () => {
    const emptyResult = Permission.create("");
    expect(Result.isErr(emptyResult)).toBe(true);
    if (!Result.isErr(emptyResult)) return;
    expect(emptyResult.error.message).toContain("required");

    const whitespaceResult = Permission.create("   ");
    expect(Result.isErr(whitespaceResult)).toBe(true);
  });

  it("rejects strings missing a colon separator", () => {
    const result = Permission.create("usersread");
    expect(Result.isErr(result)).toBe(true);
    if (!Result.isErr(result)) return;
    expect(result.error.message).toContain('must be formatted as "resource:action"');
  });

  it("rejects strings with multiple colons", () => {
    const result = Permission.create("users:read:extra");
    expect(Result.isErr(result)).toBe(true);
    if (!Result.isErr(result)) return;
    expect(result.error.message).toContain("with exactly one colon");
  });

  it("rejects missing resource segment", () => {
    const result = Permission.create(":read");
    expect(Result.isErr(result)).toBe(true);
    if (!Result.isErr(result)) return;
    expect(result.error.message).toContain("missing a resource component");
  });

  it("rejects missing action segment", () => {
    const result = Permission.create("users:");
    expect(Result.isErr(result)).toBe(true);
    if (!Result.isErr(result)) return;
    expect(result.error.message).toContain("missing an action component");
  });

  it("rejects invalid characters", () => {
    const result = Permission.create("users:read$write");
    expect(Result.isErr(result)).toBe(true);
    if (!Result.isErr(result)) return;
    expect(result.error.message).toContain("invalid characters");
  });

  it("provides value equality via equals()", () => {
    const p1 = Permission.from("roles:manage");
    const p2 = Permission.from("  ROLES:MANAGE  ");
    const p3 = Permission.from("roles:view");

    expect(p1.equals(p2)).toBe(true);
    expect(p1.equals(p3)).toBe(false);
  });

  it("throws ValidationError when using Permission.from() on invalid string", () => {
    expect(() => Permission.from("invalid-format")).toThrow(ValidationError);
  });
});
