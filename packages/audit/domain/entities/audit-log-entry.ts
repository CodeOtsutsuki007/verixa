import { createHash } from "node:crypto";

import { createId, type Id } from "@verixa/shared-kernel";

import {
  AuditMetadata,
  escapeForText,
  escapeJsonLineTerminators,
  utf8ByteLength,
} from "../value-objects/audit-metadata.js";

export type AuditLogEntryId = Id<"AuditLogEntryId">;

/**
 * The label prefixed to every canonical form.
 *
 * Changing how an entry is serialized changes its digest, and a chain written
 * under one rule and verified under another reports `content_altered` on every
 * entry after the change — an integrity alarm with no tampering behind it.
 * Naming the form in the form means that if this ever has to change again, the
 * version that produced a given hash travels with the hash.
 */
const CANONICAL_FORM_VERSION = "verixa-audit-v2";

/**
 * What happened. A closed set rather than a free string, so a query for
 * "every failed login last week" cannot miss entries because someone wrote
 * `login_failed` in one place and `LOGIN_FAILURE` in another.
 */
export type AuditAction =
  | "user.registered"
  | "user.email_verified"
  | "user.password_changed"
  | "user.status_changed"
  | "user.profile_updated"
  | "organization.invitation_created"
  | "user.login_succeeded"
  | "user.login_failed"
  | "user.locked_out"
  | "user.password_reset_requested"
  | "user.password_reset_completed"
  // Reads of the audit log itself — see `domain/policies/audit-access-policy.ts`.
  | "audit.queried"
  | "audit.exported"
  | "audit.access_denied";

/**
 * The genesis link.
 *
 * The first entry in a chain has no predecessor, and needs *something* in the
 * position where a previous hash would go — otherwise the first entry's hash
 * is computed over a different shape than every other entry's, and the
 * verification loop needs a special case. Sixty-four zeroes is the
 * conventional choice and keeps the shape uniform.
 */
export const GENESIS_HASH = "0".repeat(64);

interface AuditLogEntryProps {
  readonly id: AuditLogEntryId;
  readonly sequence: number;
  readonly action: AuditAction;
  readonly actorId: string | undefined;
  readonly subjectId: string | undefined;
  readonly metadata: Readonly<Record<string, string>>;
  readonly occurredAt: Date;
  readonly previousHash: string;
  readonly hash: string;
}

/**
 * One tamper-evident record of something that happened.
 *
 * ## Why entries are chained rather than merely timestamped
 *
 * An audit log that is just rows in a table proves nothing against the one
 * adversary it most needs to resist: someone with write access to that table.
 * They can delete the row recording what they did, or edit it, and no
 * evidence of the change remains.
 *
 * Each entry therefore commits to its predecessor: `hash = SHA256(previous
 * hash ‖ this entry's content)`. Removing or altering any entry breaks every
 * hash after it, so tampering is no longer a matter of editing one row — it
 * requires rewriting the entire log from that point forward.
 *
 * ## What chaining alone does *not* give you
 *
 * Exactly that: it requires rewriting the log, and an attacker with full
 * database access can do precisely that. A rewritten chain is internally
 * consistent and indistinguishable from an honest one.
 *
 * Chaining makes the log tamper-**evident** to anyone holding an earlier copy
 * of a hash. It does not make it tamper-**proof**. Closing that gap needs a
 * commitment stored somewhere the operator cannot rewrite, which is what
 * anchoring the chain head to Stellar is for — see
 * `docs/adr/0003-stellar-audit-anchoring.md`. The two mechanisms are
 * complementary and neither is sufficient alone, which is worth stating
 * plainly because "we hash-chain our audit log" is frequently claimed as
 * though it were the whole answer.
 *
 * ## No update or delete
 *
 * There is deliberately no method to modify an entry. Append-only is the
 * property being protected, and an aggregate that could edit itself would
 * make the chain a formality.
 */
export class AuditLogEntry {
  readonly id: AuditLogEntryId;
  readonly sequence: number;
  readonly action: AuditAction;
  readonly actorId: string | undefined;
  readonly subjectId: string | undefined;
  readonly metadata: Readonly<Record<string, string>>;
  readonly occurredAt: Date;
  readonly previousHash: string;
  readonly hash: string;

  private constructor(props: AuditLogEntryProps) {
    this.id = props.id;
    this.sequence = props.sequence;
    this.action = props.action;
    this.actorId = props.actorId;
    this.subjectId = props.subjectId;
    this.metadata = props.metadata;
    this.occurredAt = props.occurredAt;
    this.previousHash = props.previousHash;
    this.hash = props.hash;
  }

  /**
   * The canonical byte representation an entry's hash is computed over.
   *
   * Field order is fixed, metadata keys are sorted, and **every field carries
   * its own byte length**. That last part is the one to read carefully.
   *
   * This used to join the fields with newlines, on the reasoning that an
   * explicit separator makes concatenation unambiguous. It does not, when the
   * separator can appear *inside* a field: `actorId` and `subjectId` are
   * routinely supplied from outside the process, and an entry with actor
   * `"a\nb"` and subject `"c"` serialized identically to a different entry with
   * actor `"a"` and subject `"b\nc"`. Two different facts, one digest — which
   * inverts the property the chain exists to provide. The same bug class
   * reappears wherever a value is embedded in a syntax by concatenation, so it
   * is treated as a threat in its own right in
   * `docs/security/threat-model-audit.md`.
   *
   * A length prefix declares how many bytes belong to the field, so nothing
   * inside it can be read as framing. The form is versioned and mechanical
   * rather than pretty, because the digest has to be re-derivable years later
   * from the stored columns by somebody not running this code — hence UTF-8
   * *byte* lengths rather than JavaScript character counts, which disagree
   * about anything outside ASCII.
   */
  private static canonicalize(props: Omit<AuditLogEntryProps, "hash" | "id">): string {
    const fields = [
      String(props.sequence),
      props.action,
      props.actorId ?? "",
      props.subjectId ?? "",
      props.occurredAt.toISOString(),
      props.previousHash,
      AuditMetadata.of(props.metadata).canonicalForm,
    ];

    const framed = fields.map((field) => `${String(utf8ByteLength(field))}:${field}`).join("|");

    return `${CANONICAL_FORM_VERSION} ${String(fields.length)} ${framed}`;
  }

  /** SHA-256 over {@link canonicalize}, hex-encoded. */
  private static computeHash(props: Omit<AuditLogEntryProps, "hash" | "id">): string {
    return createHash("sha256").update(AuditLogEntry.canonicalize(props), "utf8").digest("hex");
  }

  /**
   * Appends an entry after `previous`, or starts a chain when it is
   * `undefined`.
   *
   * Taking the predecessor rather than a bare hash is what makes a broken
   * chain hard to construct by accident: the caller has to have actually read
   * the tail of the log.
   */
  static append(params: {
    action: AuditAction;
    actorId?: string | undefined;
    subjectId?: string | undefined;
    metadata?: Readonly<Record<string, string>> | undefined;
    previous?: AuditLogEntry | undefined;
    occurredAt?: Date | undefined;
  }): AuditLogEntry {
    const body = {
      sequence: params.previous === undefined ? 1 : params.previous.sequence + 1,
      action: params.action,
      actorId: params.actorId,
      subjectId: params.subjectId,
      metadata: params.metadata ?? {},
      occurredAt: params.occurredAt ?? new Date(),
      previousHash: params.previous?.hash ?? GENESIS_HASH,
    };

    return new AuditLogEntry({
      id: createId<"AuditLogEntryId">(),
      ...body,
      hash: AuditLogEntry.computeHash(body),
    });
  }

  /** Rebuilds from already-trusted data (a database row). */
  static reconstitute(props: AuditLogEntryProps): AuditLogEntry {
    return new AuditLogEntry(props);
  }

  /**
   * Whether this entry's stored hash matches its content.
   *
   * Recomputed rather than trusted, which is the entire point: a stored hash
   * that is simply read back proves nothing, because an attacker editing the
   * row would edit the hash too. The check only means something when the
   * digest is derived again from the content.
   */
  /**
   * The hash this entry's *content* produces, recomputed from scratch.
   *
   * Distinct from {@link hash}, which is whatever the row happens to store.
   * The two agree only while the record is intact, so anything comparing an
   * entry against an external commitment must use this one -- comparing the
   * stored hash to a ledger means comparing a tampered row's own claim about
   * itself, which always agrees.
   */
  get recomputedHash(): string {
    return AuditLogEntry.computeHash({
      sequence: this.sequence,
      action: this.action,
      actorId: this.actorId,
      subjectId: this.subjectId,
      metadata: this.metadata,
      occurredAt: this.occurredAt,
      previousHash: this.previousHash,
    });
  }

  get hasValidHash(): boolean {
    return this.hash === this.recomputedHash;
  }

  /**
   * A one-record-per-entry projection of this entry, safe to write into any
   * line-oriented sink.
   *
   * No field can contain a character a reader would take for a line break, so
   * the number of lines in the output equals the number of entries — the
   * property an auditor counting rows is silently relying on, and the reason
   * this projection, rather than the raw values, is what `ExportAuditEvents`
   * builds its CSV rows from.
   *
   * Note what this does *not* do: it does not change what is stored or hashed.
   * The escaping is a property of this rendering, not of the data, so the same
   * entry can be logged, exported as CSV, and exported as JSON without any of
   * the three agreeing on how to write a newline — and without any of them
   * rewriting the record.
   */
  toLogFields(): Readonly<Record<string, string>> {
    // `sequence`, `occurredAt`, and the two hashes are structurally safe — a
    // number, an ISO timestamp, and hex. Everything that came from outside the
    // process is escaped, and the metadata bag goes through the JSON-specific
    // treatment instead of `escapeForText` (see `escapeJsonLineTerminators`).
    return {
      sequence: String(this.sequence),
      action: escapeForText(this.action),
      actorId: escapeForText(this.actorId ?? ""),
      subjectId: escapeForText(this.subjectId ?? ""),
      occurredAt: this.occurredAt.toISOString(),
      previousHash: this.previousHash,
      hash: this.hash,
      metadata: escapeJsonLineTerminators(JSON.stringify(this.metadata) ?? "{}"),
    };
  }
}

/** Why a chain failed verification. */
export interface ChainBreak {
  readonly sequence: number;
  readonly reason: "content_altered" | "link_broken" | "sequence_gap";
}

/**
 * Verifies a contiguous run of entries, seeded with the entry that precedes
 * the run.
 *
 * The seed is what makes verification work on a *window* of a log rather than
 * only from its genesis: a caller that pages through a million-entry log never
 * holds the whole chain in memory, but each page still has to know what its
 * first entry was supposed to link to. Pass `undefined` for the run that starts
 * the chain.
 */
export function verifyChainFrom(
  previous: AuditLogEntry | undefined,
  entries: readonly AuditLogEntry[],
): ChainBreak | undefined {
  let predecessor = previous;

  for (const entry of entries) {
    if (!entry.hasValidHash) {
      return { sequence: entry.sequence, reason: "content_altered" };
    }

    const expectedPreviousHash = predecessor?.hash ?? GENESIS_HASH;
    if (entry.previousHash !== expectedPreviousHash) {
      return { sequence: entry.sequence, reason: "link_broken" };
    }

    const expectedSequence = predecessor === undefined ? 1 : predecessor.sequence + 1;
    if (entry.sequence !== expectedSequence) {
      return { sequence: entry.sequence, reason: "sequence_gap" };
    }

    predecessor = entry;
  }

  return undefined;
}

/**
 * Verifies a chain, in order, and reports the first break.
 *
 * Returns the *first* break rather than all of them because everything after
 * a break is unreliable anyway — once an entry is altered, every subsequent
 * link mismatches as a consequence, and listing them all would bury the one
 * fact that matters under noise it caused.
 *
 * Checks three distinct failures, and they mean different things:
 * - `content_altered` — an entry's own hash no longer matches its content.
 * - `link_broken` — the entry is intact but does not follow its predecessor,
 *   which is what a *deletion* looks like.
 * - `sequence_gap` — numbering skips, which catches a removal that also fixed
 *   up the hashes but not the counter.
 */
export function verifyChain(entries: readonly AuditLogEntry[]): ChainBreak | undefined {
  return verifyChainFrom(undefined, entries);
}
