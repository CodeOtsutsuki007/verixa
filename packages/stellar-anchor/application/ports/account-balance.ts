import { DomainError, type Result } from "@verixa/shared-kernel";

import type { AnchorError } from "./hash-anchor.js";

/**
 * Stroops in one XLM. Stellar amounts are integers at this scale, never
 * floats — see {@link xlmToStroops} for why the conversion is done in
 * strings rather than arithmetic.
 */
export const STROOPS_PER_XLM = 10_000_000;

/**
 * The ledger's base transaction fee, and therefore the cost of one anchoring
 * transaction: a self-payment plus a memo, nothing else.
 */
export const ANCHOR_TRANSACTION_FEE_STROOPS = 100;

/**
 * A balance read from the ledger.
 *
 * Amounts are carried in stroops rather than XLM floats. `0.0000001` parses
 * to a double that is not exactly one ten-millionth, and comparing floats for
 * "can this account pay a fee" is how a monitoring tool ends up wrong in the
 * one region — near zero — where being wrong matters.
 */
export interface AnchorAccountBalance {
  /** Account the balance belongs to, in `G...` form. */
  readonly publicKey: string;
  /** Ledger the reading came from, e.g. `stellar:testnet`. */
  readonly network: string;
  readonly availableStroops: number;
  readonly queriedAt: Date;
}

/**
 * The balance could not be read — Horizon unreachable, the account unknown,
 * or the response shaped unexpectedly.
 *
 * `503` rather than `502` because from the caller's point of view the funding
 * check is part of Verixa's own availability: an operator cannot anchor, and
 * the reason surfaced upward is that Verixa could not establish its funding
 * state.
 */
export class BalanceUnavailableError extends DomainError {
  readonly code = "ANCHOR_BALANCE_UNAVAILABLE";
  readonly httpStatusHint = 503;
}

/**
 * Reads an account's spendable balance from the ledger.
 *
 * Deliberately free of any reference to Stellar, Horizon, or an SDK type —
 * the same discipline `HashAnchor` follows, so a deployment reading balances
 * from a different RPC endpoint, a different ledger, or a cached metric
 * supplies the same interface.
 *
 * Implementations must return an error rather than a zero balance when the
 * reading fails. The two look identical in a `number`, and confusing them
 * turns an outage into a false alarm — or, worse, an outage reported as
 * "account empty" and pages someone who has nothing to fix.
 */
export interface AnchorAccountBalanceReader {
  read(publicKey: string): Promise<Result<AnchorAccountBalance, BalanceUnavailableError>>;
}

/**
 * A funding observation, pushed to whatever the deployment uses for
 * dashboards and alert rules.
 *
 * Metrics rather than only alerts, because an alert tells you the moment a
 * threshold was crossed while a gauge tells you the slope. Anchoring runs on
 * a schedule, so the balance falls in a predictable stairway; the number that
 * actually wants watching is how fast the stairs are being climbed, which is
 * how an operator learns their anchoring interval is wrong before the account
 * is empty rather than after.
 */
export interface AnchorBalanceMetric {
  readonly name: "verixa_stellar_anchor_balance_xlm";
  /** Floating-point is fine *here*: this is a display value, not a comparison. */
  readonly valueXlm: number;
  readonly availableStroops: number;
  readonly thresholdStroops: number;
  /** Whether an anchoring transaction could be paid for right now. */
  readonly fundable: boolean;
  readonly network: string;
  readonly publicKey: string;
  readonly observedAt: Date;
}

/** Sink for {@link AnchorBalanceMetric}. */
export interface AnchorBalanceMetricSink {
  emit(metric: AnchorBalanceMetric): void;
}

/**
 * Why the monitor is shouting.
 *
 * - `below_threshold` — funded, but under the configured alert level.
 * - `unfundable` — the account cannot pay for the next anchoring transaction.
 * - `balance_unreadable` — the monitor could not establish the balance at all.
 * - `unfundable_anchor_attempt` — an anchor was attempted and refused for
 *   want of funds, reported by the ledger itself rather than inferred.
 * - `recovered` — the balance is back above the threshold after an alert.
 */
export type AnchorFundingAlertKind =
  | "below_threshold"
  | "unfundable"
  | "balance_unreadable"
  | "unfundable_anchor_attempt"
  | "recovered";

/** A funding alert, already shaped for a structured sink — no message formatting here. */
export interface AnchorFundingAlert {
  readonly kind: AnchorFundingAlertKind;
  readonly network: string;
  readonly publicKey: string;
  /** Absent when the balance could not be read — there is no number to report. */
  readonly availableXlm: number | undefined;
  readonly thresholdXlm: number;
  readonly message: string;
  readonly observedAt: Date;
}

/**
 * Where funding alerts go: PagerDuty, e-mail, a webhook, a log stream.
 *
 * Allowed to be async, and the monitor awaits it. Not because the monitor
 * needs the result but because a delivery that fails should be visible to the
 * caller's error path instead of becoming an unhandled rejection in a
 * fire-and-forget promise, which is the most reliable way for an alerting
 * system to appear healthy while silently losing every alert.
 */
export interface AnchorFundingAlerter {
  alert(alert: AnchorFundingAlert): Promise<void> | void;
}

/**
 * The check an anchor performs before submitting, and the report it files
 * when the ledger refuses for want of funds.
 *
 * Separated from the monitor's own interface so an adapter depends on a
 * capability rather than on a class: a deployment can supply a guard that
 * consults a cached metric, or a no-op, without the anchoring code knowing
 * which.
 */
export interface AnchorFundingGuard {
  /**
   * Whether the next anchoring transaction can be paid for.
   *
   * An `err` means the adapter must not submit. Implementations are expected
   * to have raised their own alarm by the time they return one — a guard that
   * silently declines is the silent degradation this whole subsystem exists
   * to prevent.
   */
  beforeAnchor(): Promise<Result<void, AnchorError>>;

  /**
   * Reports a ledger rejection caused by insufficient funds.
   *
   * The guard is told about it rather than left to infer it: the ledger knows
   * the account was underfunded before the monitor's last poll, so without
   * this the event would go unnoticed for up to one polling interval.
   */
  reportUnderfundedRejection(detail: string): Promise<void> | void;
}

/** A metric sink that discards everything — the default for a monitor nobody is watching. */
export const NullAnchorBalanceMetricSink: AnchorBalanceMetricSink = {
  emit: () => undefined,
};

/**
 * Converts a Stellar amount string ("100.0000000") to stroops.
 *
 * Done in string arithmetic on purpose. `Number.parseFloat` then
 * multiplication lands one stroop either side of the true value for some
 * inputs, and this number is what funding decisions are compared against.
 * Returns `undefined` for anything that is not a plain decimal amount, which
 * callers treat as a failed reading rather than as zero.
 */
export function xlmToStroops(amount: string): number | undefined {
  const match = /^(\d+)(?:\.(\d{1,7}))?$/u.exec(amount.trim());
  if (match === null) return undefined;

  const whole = Number(match[1]);
  const fraction = (match[2] ?? "").padEnd(7, "0");
  if (!Number.isSafeInteger(whole)) return undefined;

  return whole * STROOPS_PER_XLM + Number(fraction);
}

/** Converts stroops to XLM for display. Not used for comparisons. */
export function stroopsToXlm(stroops: number): number {
  return stroops / STROOPS_PER_XLM;
}
