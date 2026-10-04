import { describe, expect, it } from "vitest";

import type {
  ResourceAttributeResolver,
  ResourceAttributes,
} from "../ports/resource-attribute-resolver.js";

import {
  ResourceAttributeResolverRegistry,
  UnknownResourceTypeError,
} from "./resource-attribute-resolver-registry.js";

function stubResolver(attributes: ResourceAttributes): ResourceAttributeResolver {
  return { resolve: () => Promise.resolve(attributes) };
}

describe("ResourceAttributeResolverRegistry", () => {
  it("resolves attributes using the resolver registered for the resource type", async () => {
    const registry = new ResourceAttributeResolverRegistry();
    registry.register("document", stubResolver({ ownerId: "user-1", sensitivity: "high" }));

    const attributes = await registry.resolve("document", "doc-1");

    expect(attributes).toEqual({ ownerId: "user-1", sensitivity: "high" });
  });

  it("passes the resource id through to the registered resolver", async () => {
    const registry = new ResourceAttributeResolverRegistry();
    let receivedResourceId: string | undefined;
    registry.register("document", {
      resolve: (resourceId) => {
        receivedResourceId = resourceId;
        return Promise.resolve({});
      },
    });

    await registry.resolve("document", "doc-42");

    expect(receivedResourceId).toBe("doc-42");
  });

  it("supports multiple independently registered resource types", async () => {
    const registry = new ResourceAttributeResolverRegistry();
    registry.register("document", stubResolver({ ownerId: "user-1" }));
    registry.register("verificationCase", stubResolver({ status: "pending" }));

    await expect(registry.resolve("document", "doc-1")).resolves.toEqual({ ownerId: "user-1" });
    await expect(registry.resolve("verificationCase", "case-1")).resolves.toEqual({
      status: "pending",
    });
  });

  it("throws UnknownResourceTypeError for a resource type nothing registered", async () => {
    const registry = new ResourceAttributeResolverRegistry();

    await expect(registry.resolve("invoice", "invoice-1")).rejects.toThrow(
      UnknownResourceTypeError,
    );
  });

  it("names the unresolved resource type on the thrown error", async () => {
    const registry = new ResourceAttributeResolverRegistry();

    await expect(registry.resolve("invoice", "invoice-1")).rejects.toMatchObject({
      resourceType: "invoice",
    });
  });

  it("reports whether a resource type has a registered resolver via has()", () => {
    const registry = new ResourceAttributeResolverRegistry();
    registry.register("document", stubResolver({}));

    expect(registry.has("document")).toBe(true);
    expect(registry.has("invoice")).toBe(false);
  });

  it("registering again for the same resource type overrides the previous resolver", async () => {
    const registry = new ResourceAttributeResolverRegistry();
    registry.register("document", stubResolver({ ownerId: "user-1" }));
    registry.register("document", stubResolver({ ownerId: "user-2" }));

    await expect(registry.resolve("document", "doc-1")).resolves.toEqual({ ownerId: "user-2" });
  });
});
