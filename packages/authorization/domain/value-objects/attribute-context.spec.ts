import { describe, expect, it } from "vitest";

import { AttributeContext } from "./attribute-context.js";

describe("AttributeContext", () => {
  const date = new Date("2026-09-30T12:00:00.000Z");
  const context = new AttributeContext({
    subject: { id: "user-1", age: 30, active: true, roles: ["reader"], createdAt: date },
    resource: { owner: { id: "user-1" } },
    action: { name: "read" },
    environment: { ip: "192.0.2.1" },
  });

  it("provides typed lookups across all four attribute bags", () => {
    expect(context.getString("subject", "id")).toBe("user-1");
    expect(context.getNumber("subject", "age")).toBe(30);
    expect(context.getBoolean("subject", "active")).toBe(true);
    expect(context.getArray("subject", "roles")).toEqual(["reader"]);
    expect(context.getDate("subject", "createdAt")?.toISOString()).toBe(date.toISOString());
    expect(context.getString("resource", "owner.id")).toBe("user-1");
    expect(context.getString("action", "name")).toBe("read");
    expect(context.getString("environment", "ip")).toBe("192.0.2.1");
  });

  it("returns undefined for missing paths and type mismatches", () => {
    expect(context.getString("subject", "missing")).toBeUndefined();
    expect(context.getString("subject", "age")).toBeUndefined();
    expect(context.get("resource", "owner.missing")).toBeUndefined();
    expect(context.get("environment", "ip.invalid.path")).toBeUndefined();
  });

  it("copies and freezes input so callers cannot mutate the context", () => {
    const source = { subject: { roles: ["reader"] } };
    const immutable = new AttributeContext(source);
    source.subject.roles.push("admin");

    expect(immutable.getArray("subject", "roles")).toEqual(["reader"]);
    expect(Object.isFrozen(immutable)).toBe(true);
    expect(Object.isFrozen(immutable.subject)).toBe(true);
    expect(Object.isFrozen(immutable.getArray("subject", "roles"))).toBe(true);
  it("supports typed lookups across all four attribute categories", () => {
    const context = AttributeContext.create({
      subject: { id: "user-1", role: "admin" },
      resource: { ownerId: "user-2", sensitivity: "high" },
      action: { name: "read" },
      environment: { requestedAt: new Date("2026-01-01T00:00:00Z") },
    });

    expect(context.get("subject", "id")).toBe("user-1");
    expect(context.get("resource", "ownerId")).toBe("user-2");
    expect(context.get("action", "name")).toBe("read");
    expect(context.get("environment", "requestedAt")).toEqual(new Date("2026-01-01T00:00:00Z"));
  });

  it("supports string, number, boolean, date, and array attribute values", () => {
    const context = AttributeContext.create({
      resource: {
        name: "doc-1",
        views: 42,
        locked: false,
        availableFrom: new Date("2026-01-01T00:00:00Z"),
        tags: ["a", "b"],
      },
    });

    expect(context.get("resource", "name")).toBe("doc-1");
    expect(context.get("resource", "views")).toBe(42);
    expect(context.get("resource", "locked")).toBe(false);
    expect(context.get("resource", "availableFrom")).toBeInstanceOf(Date);
    expect(context.get("resource", "tags")).toEqual(["a", "b"]);
  });

  it("returns undefined, not throwing, for a missing attribute", () => {
    const context = AttributeContext.create({ subject: { id: "user-1" } });
    expect(context.get("subject", "role")).toBeUndefined();
  });

  it("defaults every unsupplied category to an empty bag", () => {
    const context = AttributeContext.create({});
    expect(context.get("subject", "id")).toBeUndefined();
    expect(context.get("resource", "id")).toBeUndefined();
    expect(context.get("action", "name")).toBeUndefined();
    expect(context.get("environment", "now")).toBeUndefined();
  });

  describe("resolve", () => {
    it("resolves a dotted path to the matching category and key", () => {
      const context = AttributeContext.create({ resource: { ownerId: "user-2" } });
      expect(context.resolve("resource.ownerId")).toBe("user-2");
    });

    it("resolves a key that itself contains dots by treating only the first segment as the category", () => {
      const context = AttributeContext.create({ resource: { "metadata.key": "value" } });
      expect(context.resolve("resource.metadata.key")).toBe("value");
    });

    it("returns undefined for an unrecognized category", () => {
      const context = AttributeContext.create({ resource: { ownerId: "user-2" } });
      expect(context.resolve("nonexistentCategory.ownerId")).toBeUndefined();
    });

    it("returns undefined for a path with no category separator", () => {
      const context = AttributeContext.create({ resource: { ownerId: "user-2" } });
      expect(context.resolve("ownerId")).toBeUndefined();
    });

    it("returns undefined for a missing key within a recognized category", () => {
      const context = AttributeContext.create({ resource: { ownerId: "user-2" } });
      expect(context.resolve("resource.sensitivity")).toBeUndefined();
    });
  });
});
