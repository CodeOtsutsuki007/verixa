import { Result } from "@verixa/shared-kernel";
import { describe, expect, it } from "vitest";

import {
  TERMINAL_STATUSES,
  VerificationStatus,
  type VerificationStatusValue,
} from "./verification-status.js";

const ALL_STATUSES: readonly VerificationStatusValue[] = [
  "pending_evidence",
  "submitted",
  "in_review",
  "needs_more_info",
  "approved",
  "rejected",
];

/** The complete transition table, restated here so the test fails if the domain's changes. */
const LEGAL_TRANSITIONS: readonly (readonly [VerificationStatusValue, VerificationStatusValue])[] =
  [
    ["pending_evidence", "submitted"],
    ["submitted", "in_review"],
    ["in_review", "approved"],
    ["in_review", "rejected"],
    ["in_review", "needs_more_info"],
    ["needs_more_info", "pending_evidence"],
  ];

function status(value: VerificationStatusValue): VerificationStatus {
  return VerificationStatus.reconstitute(value);
}

describe("VerificationStatus", () => {
  it("rejects a value the domain does not define", () => {
    const created = VerificationStatus.create("half_approved");

    expect(Result.isErr(created)).toBe(true);
    if (Result.isErr(created)) {
      expect(created.error.fieldErrors["status"]).toEqual(["unsupported"]);
    }
  });

  it("accepts each value the domain defines", () => {
    for (const value of ALL_STATUSES) {
      expect(Result.isOk(VerificationStatus.create(value))).toBe(true);
    }
  });

  it.each(LEGAL_TRANSITIONS)("allows the legal transition %s -> %s", (from, to) => {
    expect(status(from).canTransitionTo(status(to))).toBe(true);
  });

  it("rejects every transition that is not in the table", () => {
    // The exhaustive assertion: 36 ordered pairs, of which exactly the six
    // above are legal. Enumerating the illegal ones too is what makes this a
    // state-machine test rather than a happy-path test — a stray transition
    // added to the table fails here, and so does one accidentally removed.
    const legal = new Set(LEGAL_TRANSITIONS.map(([from, to]) => `${from}->${to}`));

    for (const from of ALL_STATUSES) {
      for (const to of ALL_STATUSES) {
        expect(status(from).canTransitionTo(status(to)), `${from} -> ${to}`).toBe(
          legal.has(`${from}->${to}`),
        );
      }
    }
  });

  it("rejects any transition out of a terminal status", () => {
    for (const terminal of TERMINAL_STATUSES) {
      for (const to of ALL_STATUSES) {
        expect(status(terminal).canTransitionTo(status(to))).toBe(false);
      }
    }
  });

  it("reports terminality consistently with the transition table", () => {
    for (const value of ALL_STATUSES) {
      const isTerminal = status(value).isTerminal;
      expect(isTerminal).toBe(TERMINAL_STATUSES.includes(value));
      // Derived rather than declared: a terminal status is exactly one with no
      // outgoing edges, so the two readouts cannot drift apart.
      const hasNoOutgoing = ALL_STATUSES.every((to) => !status(value).canTransitionTo(status(to)));
      expect(isTerminal).toBe(hasNoOutgoing);
    }
  });

  it("compares and prints by value", () => {
    expect(status("in_review").equals(VerificationStatus.reconstitute("in_review"))).toBe(true);
    expect(status("in_review").equals(status("approved"))).toBe(false);
    expect(status("needs_more_info").toString()).toBe("needs_more_info");
  });
});
