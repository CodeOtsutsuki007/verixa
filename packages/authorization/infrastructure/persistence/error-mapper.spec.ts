import { Prisma, PrismaClientKnownRequestError } from "@verixa/database";
import { ConflictError, NotFoundError } from "@verixa/shared-kernel";
import { describe, expect, it } from "vitest";

import { mapPrismaError, withMappedErrors } from "./error-mapper.js";

function prismaError(code: string): Error {
  return new Prisma.PrismaClientKnownRequestError("database error", {
    code,
    clientVersion: "test",
  });
}

describe("policy Prisma error mapping", () => {
  it("maps unique-key conflicts to a domain conflict", () => {
    expect(() => mapPrismaError(prismaError("P2002"), "Policy")).toThrow(ConflictError);
  });

  it("maps a missing related record to a domain not-found error", () => {
    expect(() => mapPrismaError(prismaError("P2003"), "Policy")).toThrow(NotFoundError);
  });

  it("leaves unknown failures unchanged", async () => {
    const original = new Error("connection reset");
    await expect(withMappedErrors("Policy", () => Promise.reject(original))).rejects.toBe(original);
  });

  it("recognizes real Prisma request errors", () => {
    expect(prismaError("P2002")).toBeInstanceOf(PrismaClientKnownRequestError);
  });
});
