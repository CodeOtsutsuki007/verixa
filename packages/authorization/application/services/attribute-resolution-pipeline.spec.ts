import { describe, expect, it, vi } from "vitest";

import { AttributeContext } from "../../domain/value-objects/attribute-context.js";
import type { AttributeProvider } from "../ports/attribute-provider.js";
import {
  AttributeProviderResolutionError,
  AttributeResolutionPipeline,
} from "./attribute-resolution-pipeline.js";

const request = { subjectId: "user-1", resourceRef: "doc-1", action: "read" };

function provider(
  name: string,
  context: AttributeContext | (() => Promise<AttributeContext>),
  failureMode: AttributeProvider["failureMode"] = "fail-closed",
): AttributeProvider {
  return {
    name,
    failureMode,
    resolve: vi.fn(async () => (typeof context === "function" ? context() : context)),
  };
}

describe("AttributeResolutionPipeline", () => {
  it("merges in order, with later providers overriding leaves", async () => {
    const pipeline = new AttributeResolutionPipeline([
      provider("claims", new AttributeContext({ subject: { id: "unverified", roles: ["reader"] }, resource: { owner: { id: "user-1" } } })),
      provider("identity", new AttributeContext({ subject: { id: "user-1", active: true }, resource: { owner: { verified: true } } })),
    ]);

    const { context } = await pipeline.resolve(request);
    expect(context.getString("subject", "id")).toBe("user-1");
    expect(context.getBoolean("subject", "active")).toBe(true);
    expect(context.getArray("subject", "roles")).toEqual(["reader"]);
    expect(context.getString("resource", "owner.id")).toBe("user-1");
    expect(context.getBoolean("resource", "owner.verified")).toBe(true);
  });

  it("isolates and reports fail-open provider errors", async () => {
    const pipeline = new AttributeResolutionPipeline([
      provider("optional-enrichment", async () => {
        throw new Error("service unavailable");
      }, "fail-open"),
      provider("identity", new AttributeContext({ subject: { id: "user-1" } })),
    ]);

    const result = await pipeline.resolve(request);
    expect(result.context.getString("subject", "id")).toBe("user-1");
    expect(result.failures.map(({ provider: name }) => name)).toEqual(["optional-enrichment"]);
  });

  it("fails closed when a required provider fails", async () => {
    const pipeline = new AttributeResolutionPipeline([
      provider("required-identity", async () => {
        throw new Error("database unavailable");
      }),
    ]);

    await expect(pipeline.resolve(request)).rejects.toBeInstanceOf(AttributeProviderResolutionError);
    await expect(pipeline.resolve(request)).rejects.toThrow('Required attribute provider "required-identity" failed.');
  });

  it("validates provider names and rejects duplicates", () => {
    expect(() => new AttributeResolutionPipeline([provider("", new AttributeContext())])).toThrow();
    expect(() =>
      new AttributeResolutionPipeline([
        provider("identity", new AttributeContext()),
        provider("identity", new AttributeContext()),
      ]),
    ).toThrow("Duplicate attribute provider: identity");
  });
});
