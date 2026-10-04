import { Keypair } from "@stellar/stellar-sdk";
import { Result } from "@verixa/shared-kernel";
import { describe, expect, it, vi } from "vitest";

import {
  ANCHOR_TRANSACTION_FEE_STROOPS,
  BalanceUnavailableError,
  type AnchorAccountBalance,
  type AnchorAccountBalanceReader,
  type AnchorBalanceMetric,
  type AnchorFundingAlert,
  xlmToStroops,
} from "../application/ports/account-balance.js";
import { AnchorError } from "../application/ports/hash-anchor.js";

import {
  AnchorBalanceMonitor,
  DEFAULT_BALANCE_THRESHOLD_XLM,
  isUnderfundedLedgerError,
  loggingFundingAlerter,
} from "./balance-monitor.js";
import { StellarHashAnchor } from "./stellar/stellar-hash-anchor.js";

const PUBLIC_KEY = "GANCHORAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABCDEFG";

function outcomeBalance(stroops: number): AnchorAccountBalance {
  return {
    publicKey: PUBLIC_KEY,
    network: "stellar:testnet",
    availableStroops: stroops,
    queriedAt: new Date("2026-10-02T00:00:00.000Z"),
  };
}

type Outcome = { readonly balanceStroops: number } | { readonly unavailable: true };

/**
 * A reader replaying scripted outcomes, one per call, repeating the last one.
 *
 * Scripted rather than a single fixed value because most of what this monitor
 * does interesting is a *sequence*: drain, alert, top up, recover.
 */
function scriptedReader(outcomes: readonly Outcome[]) {
  let reads = 0;

  const reader: AnchorAccountBalanceReader & { reads: number } = {
    get reads(): number {
      return reads;
    },
    read() {
      const outcome = outcomes[Math.min(reads, outcomes.length - 1)]!;
      reads += 1;

      if ("unavailable" in outcome) {
        return Promise.resolve(Result.err(new BalanceUnavailableError("Horizon is unreachable.")));
      }

      return Promise.resolve(Result.ok(outcomeBalance(outcome.balanceStroops)));
    },
  };

  return reader;
}

function harness(
  outcomes: readonly Outcome[],
  options: { thresholdXlm?: number; feeStroops?: number } = {},
) {
  const alerts: AnchorFundingAlert[] = [];
  const metrics: AnchorBalanceMetric[] = [];
  const reader = scriptedReader(outcomes);

  const monitor = new AnchorBalanceMonitor({
    reader,
    publicKey: PUBLIC_KEY,
    thresholdXlm: options.thresholdXlm,
    transactionFeeStroops: options.feeStroops,
    alerter: { alert: (alert) => void alerts.push(alert) },
    metricSink: { emit: (metric) => void metrics.push(metric) },
    now: () => new Date("2026-10-02T00:00:00.000Z"),
  });

  return { monitor, alerts, metrics, reader };
}

const FUNDED = 500_000_000; // 50 XLM
const BELOW_THRESHOLD = 5_000_000; // 0.5 XLM

describe("AnchorBalanceMonitor", () => {
  it("emits a metric on every check and stays quiet while funded", async () => {
    const { monitor, metrics, alerts } = harness([{ balanceStroops: FUNDED }]);

    await monitor.check();
    await monitor.check();

    expect(metrics).toHaveLength(2);
    expect(metrics[0]?.name).toBe("verixa_stellar_anchor_balance_xlm");
    expect(metrics[0]?.valueXlm).toBe(50);
    expect(metrics[0]?.fundable).toBe(true);
    expect(alerts).toHaveLength(0);
  });

  it("alerts once while the balance stays below the threshold", async () => {
    const { monitor, alerts } = harness([{ balanceStroops: BELOW_THRESHOLD }], {
      thresholdXlm: 1,
    });

    expect((await monitor.check()).kind).toBe("below_threshold");
    expect((await monitor.check()).kind).toBe("below_threshold");

    // Two checks, one page. A page for every poll of an unchanged condition is
    // how an alert ends up muted, and a muted alert is the silent failure this
    // subsystem exists to prevent.
    expect(alerts).toHaveLength(1);
    expect(alerts[0]?.availableXlm).toBe(0.5);
    expect(alerts[0]?.thresholdXlm).toBe(1);
  });

  it("defaults the alert threshold to one XLM", () => {
    const { monitor } = harness([{ balanceStroops: FUNDED }]);

    expect(monitor.thresholdXlm).toBe(DEFAULT_BALANCE_THRESHOLD_XLM);
  });

  it("classifies a balance below the transaction fee as unfundable", async () => {
    const { monitor, alerts, metrics } = harness([
      { balanceStroops: ANCHOR_TRANSACTION_FEE_STROOPS - 1 },
    ]);

    expect((await monitor.check()).kind).toBe("unfundable");
    expect(alerts[0]?.kind).toBe("unfundable");
    expect(metrics[0]?.fundable).toBe(false);
  });

  it("treats an unreadable balance as alarming rather than healthy", async () => {
    const { monitor, alerts, metrics } = harness([{ unavailable: true }]);

    expect((await monitor.check()).kind).toBe("unknown");
    expect(alerts).toHaveLength(1);
    expect(alerts[0]?.kind).toBe("balance_unreadable");
    expect(alerts[0]?.availableXlm).toBeUndefined();
    // The metric still goes out, marked not fundable, so a dashboard shows a
    // hole instead of a reassuring flat line.
    expect(metrics[0]?.fundable).toBe(false);
  });

  it("alerts again when the account recovers", async () => {
    const { monitor, alerts } = harness([
      { balanceStroops: BELOW_THRESHOLD },
      { balanceStroops: FUNDED },
    ]);

    await monitor.check();
    expect((await monitor.check()).kind).toBe("funded");
    expect(alerts.map((alert) => alert.kind)).toEqual(["below_threshold", "recovered"]);
  });

  describe("beforeAnchor", () => {
    it("clears a funded account", async () => {
      const { monitor } = harness([{ balanceStroops: FUNDED }]);

      expect(Result.isOk(await monitor.beforeAnchor())).toBe(true);
    });

    it("refuses an account that cannot pay the fee, quoting both numbers", async () => {
      const { monitor } = harness([{ balanceStroops: 50 }], { feeStroops: 100 });

      const cleared = await monitor.beforeAnchor();

      expect(Result.isErr(cleared)).toBe(true);
      if (Result.isOk(cleared)) throw new Error("expected the guard to refuse");
      expect(cleared.error.message).toContain("Not submitting an anchoring transaction");
      expect(cleared.error.message).toContain("0.0000050");
    });

    it("refuses when the funding state cannot be established at all", async () => {
      // An answer of "probably fine" here would make the check decorative
      // during exactly the outages when it matters.
      const { monitor, alerts } = harness([{ unavailable: true }]);

      expect(Result.isErr(await monitor.beforeAnchor())).toBe(true);
      expect(alerts[0]?.kind).toBe("balance_unreadable");
    });
  });

  describe("reportUnderfundedRejection", () => {
    it("raises the ledger's rejection even after a matching alert", async () => {
      const { monitor, alerts } = harness([{ balanceStroops: BELOW_THRESHOLD }]);

      await monitor.check();
      await monitor.reportUnderfundedRejection("op_underfunded");

      expect(alerts.map((alert) => alert.kind)).toEqual([
        "below_threshold",
        "unfundable_anchor_attempt",
      ]);
    });

    it("outranks a low reading until the balance clears the threshold again", async () => {
      const { monitor, alerts } = harness([
        { balanceStroops: BELOW_THRESHOLD },
        { balanceStroops: FUNDED },
      ]);

      await monitor.reportUnderfundedRejection("op_underfunded");
      // 0.5 XLM is above the 100-stroop fee, but the ledger has just said it
      // would not be paid. The rejection outranks the arithmetic until a
      // reading clears the threshold, which is the only evidence that could
      // overturn it.
      expect((await monitor.check()).kind).toBe("unfundable");
      expect((await monitor.check()).kind).toBe("funded");
      expect(alerts.at(-1)?.kind).toBe("recovered");
    });
  });

  describe("start", () => {
    it("polls on the interval until stopped", async () => {
      vi.useFakeTimers();
      try {
        const { monitor, reader } = harness([{ balanceStroops: FUNDED }]);

        const stop = monitor.start(60_000);
        await vi.advanceTimersByTimeAsync(120_000);
        stop();
        await vi.advanceTimersByTimeAsync(180_000);

        expect(reader.reads).toBe(2);
      } finally {
        vi.useRealTimers();
      }
    });

    it("reports a throwing check instead of dying with the timer", async () => {
      vi.useFakeTimers();
      try {
        let reads = 0;
        const failing: AnchorAccountBalanceReader = {
          read: () => {
            reads += 1;
            return Promise.reject(new Error("reader exploded"));
          },
        };
        const failures: unknown[] = [];
        const monitor = new AnchorBalanceMonitor({
          reader: failing,
          publicKey: PUBLIC_KEY,
          alerter: { alert: () => undefined },
        });

        const stop = monitor.start(60_000, (error) => void failures.push(error));
        await vi.advanceTimersByTimeAsync(60_000);
        stop();

        expect(reads).toBe(1);
        expect(failures).toHaveLength(1);
      } finally {
        vi.useRealTimers();
      }
    });
  });
});

describe("StellarHashAnchor funding guard", () => {
  it("does not submit a transaction the guard declines", async () => {
    // Refusing *before* submission is the difference between a guard and a
    // report: no fee is spent, and no half-committed hash is left behind.
    const { monitor, reader } = harness([{ balanceStroops: 50 }], { feeStroops: 100 });
    const declining = new StellarHashAnchor({
      secretKey: Keypair.random().secret(),
      network: "testnet",
      fundingGuard: monitor,
    });

    const result = await declining.anchor("a".repeat(64));

    expect(Result.isErr(result)).toBe(true);
    if (Result.isOk(result)) throw new Error("expected anchoring to be refused");
    expect(result.error.message).toContain("Not submitting an anchoring transaction");
    // One read: the guard's check. Reaching for the account to build a
    // transaction would mean the guard had been bypassed.
    expect(reader.reads).toBe(1);
  });

  it("does not misreport a transport failure as a funding failure", async () => {
    // Both arrive through the same catch, and they need opposite answers: a
    // funding failure goes to the funding alarm, a transport failure is
    // ordinary retryable noise. Confusing them either pages someone for
    // nothing or hides an account that has run dry.
    const reported: string[] = [];
    const anchor = new StellarHashAnchor({
      secretKey: Keypair.random().secret(),
      network: "testnet",
      horizonUrl: "https://verixa-anchor-unreachable.invalid",
      fundingGuard: {
        beforeAnchor: () => Promise.resolve(Result.ok(undefined)),
        reportUnderfundedRejection: (detail) => void reported.push(detail),
      },
    });

    const result = await anchor.anchor("b".repeat(64));

    expect(Result.isErr(result)).toBe(true);
    expect(reported).toHaveLength(0);
  });

  it("hands the guard's refusal back unchanged", async () => {
    const guardError = new AnchorError("the guard's own words");
    const anchor = new StellarHashAnchor({
      secretKey: Keypair.random().secret(),
      network: "testnet",
      fundingGuard: {
        beforeAnchor: () => Promise.resolve(Result.err(guardError)),
        reportUnderfundedRejection: () => undefined,
      },
    });

    const result = await anchor.anchor("c".repeat(64));

    // Re-wrapping it would produce a second, vaguer error on top of the one
    // that already explains the situation.
    if (Result.isOk(result)) throw new Error("expected the anchor to be refused");
    expect(result.error).toBe(guardError);
  });
});

describe("isUnderfundedLedgerError", () => {
  it("recognises ledger responses that mean the account cannot pay", () => {
    expect(isUnderfundedLedgerError(new Error("bad not enough money: op_underfunded"))).toBe(true);
    expect(
      isUnderfundedLedgerError(new Error("ExceedsAvailableBalance insufficient balance")),
    ).toBe(true);
    expect(isUnderfundedLedgerError(new Error("The Source Account Does Not Have Enough XLM"))).toBe(
      true,
    );
    expect(isUnderfundedLedgerError(new Error("transaction failed: no such account"))).toBe(true);
  });

  it("does not read a transport fault as a funding fault", () => {
    // The two need opposite answers — one needs XLM, the other needs a retry.
    expect(isUnderfundedLedgerError(new Error("timeout of 60000ms exceeded"))).toBe(false);
    expect(isUnderfundedLedgerError("connect ECONNREFUSED 127.0.0.1:1")).toBe(false);
  });
});

describe("loggingFundingAlerter", () => {
  it("writes each alert as one structured record", () => {
    const records: Record<string, unknown>[] = [];
    const alerter = loggingFundingAlerter({ error: (object) => void records.push(object) });

    void alerter.alert({
      kind: "below_threshold",
      network: "stellar:testnet",
      publicKey: PUBLIC_KEY,
      availableXlm: 0.5,
      thresholdXlm: 1,
      message: "balance below threshold",
      observedAt: new Date("2026-10-02T00:00:00.000Z"),
    });

    expect(records).toHaveLength(1);
    expect(records[0]).toMatchObject({
      type: "anchor_funding_alert",
      kind: "below_threshold",
      availableXlm: 0.5,
      publicKey: PUBLIC_KEY,
    });
  });
});

describe("xlmToStroops", () => {
  it("converts Stellar amount strings without float drift", () => {
    // Funding decisions are compared against these values, and `0.1 * 1e7`
    // landing a stroop off is a wrong answer exactly at the boundary that
    // matters — near zero.
    expect(xlmToStroops("0.0000001")).toBe(1);
    expect(xlmToStroops("7")).toBe(70_000_000);
    expect(xlmToStroops("3.1415926")).toBe(31_415_926);
    expect(xlmToStroops("100.0000000")).toBe(1_000_000_000);
  });

  it("refuses anything that is not a plain decimal amount", () => {
    // A failed parse must not be reportable as a zero balance, or a malformed
    // Horizon response pages someone with nothing to fix.
    expect(xlmToStroops("")).toBeUndefined();
    expect(xlmToStroops("1e7")).toBeUndefined();
    expect(xlmToStroops("-1")).toBeUndefined();
    expect(xlmToStroops("0.12345678")).toBeUndefined();
    expect(xlmToStroops("abc")).toBeUndefined();
  });
});
