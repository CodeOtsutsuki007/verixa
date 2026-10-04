import { describe, expect, it } from "vitest";

import { PasswordReusedError } from "./password-reused-error.js";

describe("PasswordReusedError", () => {
  it("names the history depth so the message tells the user what to do", () => {
    // The depth is in the message because "that password was recently used"
    // leaves someone guessing how far back "recently" goes, and they will
    // guess wrong twice before succeeding.
    const error = new PasswordReusedError(3);

    expect(error.message).toContain("last 3 passwords");
  });

  it("defaults to a depth of five", () => {
    expect(new PasswordReusedError().message).toContain("last 5 passwords");
  });

  it("is catchable as its own type across the module boundary", () => {
    // `Object.setPrototypeOf` in the constructor exists for this. Extending a
    // built-in like `Error` breaks the prototype chain when the class is
    // down-levelled, and `instanceof` then returns false for a genuine
    // instance — so the use cases that catch this would miss it entirely and
    // the error would surface as an unhandled 500.
    const error: unknown = new PasswordReusedError();

    expect(error).toBeInstanceOf(PasswordReusedError);
    expect(error).toBeInstanceOf(Error);
  });

  it("carries a name distinct from Error", () => {
    // Logged output says PasswordReusedError rather than Error, which is the
    // difference between a searchable log line and a useless one.
    expect(new PasswordReusedError().name).toBe("PasswordReusedError");
  });
});
