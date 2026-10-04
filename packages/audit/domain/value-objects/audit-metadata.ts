import { Result, ValidationError } from "@verixa/shared-kernel";

/**
 * Why a metadata bag was replaced rather than recorded as supplied.
 *
 * The key is unlikely to collide with real metadata, and its value is one of a
 * closed set of reasons, so a query for "entries whose metadata was rejected"
 * finds them all. See `RecordAuditEvent`, which keeps the entry and swaps the
 * bag rather than dropping the record.
 */
export const METADATA_REJECTED_KEY = "metadataRejected";

/** Why {@link AuditMetadata.create} refused a bag. */
export type AuditMetadataRejectionReason =
  | "too_many_fields"
  | "empty_key"
  | "key_too_long"
  | "non_string_value"
  | "value_too_long"
  | "unclassified";

/**
 * The bound a rejection was about, recovered from a `ValidationError` returned
 * by {@link AuditMetadata.create}.
 *
 * The reasons live in `fieldErrors.metadata`, which is a `string[]` — so this
 * is the one place that turns that untyped code back into the closed set, and
 * `unclassified` is what a caller gets if the error came from somewhere else
 * entirely. Preferable to the alternative: letting a caller string-match on
 * `error.message`, which is written for humans and changes when the wording
 * does.
 */
export function rejectionReasonOf(error: ValidationError): AuditMetadataRejectionReason {
  const [reason] = error.fieldErrors.metadata ?? [];

  switch (reason) {
    case "too_many_fields":
    case "empty_key":
    case "key_too_long":
    case "non_string_value":
    case "value_too_long":
      return reason;
    default:
      return "unclassified";
  }
}

/**
 * Bounds on a metadata bag, and the reason each one is where it is.
 *
 * These are not a size policy for the sake of tidiness. Every limit here is
 * what makes an assertion about *output* possible: a CSV cell, a log record,
 * and a hash pre-image all have to be finished sometime, and "unbounded string
 * you plan to embed in all three" is how the guarantees in this file stop
 * holding.
 */
export const MAX_METADATA_ENTRIES = 32;
export const MAX_METADATA_KEY_LENGTH = 64;
export const MAX_METADATA_VALUE_LENGTH = 1024;

/**
 * Metadata that has been checked for the properties the audit trail needs from
 * it: bounded, string-valued, and safe to hand to *any* textual sink.
 *
 * ## The attack this exists to stop
 *
 * Metadata is the only part of an audit entry that an outside party usually
 * controls. It arrives from request bodies, from failure reasons, from
 * third-party provider messages, and from whatever a caller decided to record —
 * and then it is written to a database, hashed into a chain, rendered as CSV
 * for a regulator, and echoed into the application log. Each of those is a
 * place where a crafted value can say more than the record does.
 *
 * Concretely, without handling:
 *
 * - **Log forgery.** A value containing `\n` ends a pino line early if the
 *   value is interpolated into a message, so the attacker's text starts a new
 *   one — `... failed\n[2026-10-02] INFO audit: admin login granted` — and
 *   anyone grepping the log later cannot tell the injected line from a real
 *   one.
 * - **CSV structural damage.** A comma or quote breaks one record into two
 *   cells; a `\r\n` inside a quoted field is a whole fabricated row in the
 *   compliance export somebody will hand to an auditor.
 * - **Spreadsheet execution.** A cell starting with `=`, `+`, `-` or `@` is not
 *   text when Excel opens it, it is a formula, and the classic payload is
 *   `=cmd|'/c calc'!A1`. The attacker does not need to reach the server; they
 *   need to reach whoever reads the export.
 * - **Digest ambiguity.** The chain hash is computed over a serialization of
 *   the entry. If a metadata value can contain the field separator, two
 *   different entries can produce the same pre-image and so the same hash,
 *   which lets one recorded fact be presented as another.
 *
 * ## The shape of the fix
 *
 * Never concatenate attacker-chosen text into a *syntax*. Storage is a JSON
 * document, export is a JSON document per line, CSV cells are quoted and
 * escaped, and the hash pre-image is length-prefixed. Values are preserved
 * verbatim where they are stored, and neutralized at each textual boundary
 * where they could be misread.
 *
 * The rejected alternative was to strip or escape control characters on the way
 * *in*. It looks simpler and it is worse in two ways: it silently rewrites the
 * evidence (the value that gets hashed and exported is no longer the value that
 * was supplied, which is exactly what an audit log must not do to facts), and
 * it teaches the next reader that safety is a property of the stored data
 * rather than of each encoder — so the next output path, added by someone who
 * did not read this file, forgets to sanitize and is unsafe.
 */
export class AuditMetadata {
  readonly #values: Readonly<Record<string, string>>;

  private constructor(values: Readonly<Record<string, string>>) {
    this.#values = Object.freeze({ ...values });
  }

  /**
   * Validates metadata arriving from outside the domain.
   *
   * Values must already be strings. Coercing numbers and booleans would make
   * `true` and `"true"` indistinguishable in a query, and silently accepting a
   * nested object means `JSON.stringify`-shaped data ends up inside a column
   * that every other reader expects to be flat.
   */
  static create(input: Readonly<Record<string, unknown>>): Result<AuditMetadata, ValidationError> {
    const keys = Object.keys(input);

    if (keys.length > MAX_METADATA_ENTRIES) {
      // The offending key list is deliberately not attached: an oversized bag is
      // exactly the input whose size this bound exists to contain, and the
      // caller already holds it.
      return Result.err(
        new ValidationError(
          `Audit metadata may not exceed ${String(MAX_METADATA_ENTRIES)} fields.`,
          { metadata: ["too_many_fields"] },
        ),
      );
    }

    const values: Record<string, string> = {};

    for (const key of keys) {
      if (key.length === 0) {
        return Result.err(
          new ValidationError("Audit metadata keys may not be empty.", {
            metadata: ["empty_key"],
          }),
        );
      }

      if (key.length > MAX_METADATA_KEY_LENGTH) {
        return Result.err(
          new ValidationError(
            `Audit metadata key ${describeKey(key)} exceeds ${String(MAX_METADATA_KEY_LENGTH)} characters.`,
            { metadata: ["key_too_long"] },
          ),
        );
      }

      const value = input[key];

      if (typeof value !== "string") {
        return Result.err(
          new ValidationError(
            `Audit metadata value for ${describeKey(key)} must be a string; received ${describeType(value)}.`,
            { metadata: ["non_string_value"] },
          ),
        );
      }

      if (value.length > MAX_METADATA_VALUE_LENGTH) {
        return Result.err(
          new ValidationError(
            `Audit metadata value for ${describeKey(key)} exceeds ${String(MAX_METADATA_VALUE_LENGTH)} characters.`,
            { metadata: ["value_too_long"] },
          ),
        );
      }

      values[key] = value;
    }

    return Result.ok(new AuditMetadata(values));
  }

  /**
   * Wraps metadata that has already been validated, or that came back from
   * trusted storage.
   *
   * The counterpart to {@link create} that `AuditEvent.reconstitute` has for the
   * same reason: re-validating a row that was validated on the way in would
   * mean a rule change silently makes historical records unreadable, and
   * verification would fail on tampering it imagined.
   */
  static of(values: Readonly<Record<string, string>>): AuditMetadata {
    return new AuditMetadata(values);
  }

  /** The empty bag. */
  static empty(): AuditMetadata {
    return new AuditMetadata({});
  }

  /**
   * The bag recorded in place of metadata that failed {@link create}.
   *
   * Recording the reason rather than nothing keeps the fact that somebody tried
   * to attach unusable metadata — which is itself the interesting event — and
   * the replacement is still a valid bag, so nothing downstream has to
   * special-case it.
   */
  static rejected(reason: AuditMetadataRejectionReason): AuditMetadata {
    return new AuditMetadata({ [METADATA_REJECTED_KEY]: reason });
  }

  /** The values as recorded, unmodified. */
  get values(): Readonly<Record<string, string>> {
    return this.#values;
  }

  /**
   * The hash pre-image for this bag.
   *
   * Self-delimiting by construction: a field count, then each pair as
   * `byteLength:key=byteLength:value`. Lengths make any character inside a key
   * or value part of that field's *content* rather than of the framing, so a
   * newline, a comma, or an `=` cannot move a boundary and cannot make two
   * different bags serialize identically.
   *
   * Lengths are in UTF-8 bytes, not JavaScript characters, because the digest
   * has to be re-derivable from the stored columns by somebody who is not
   * running this code — see `AuditLogEntry.canonicalize`.
   *
   * Keys are sorted, so insertion order cannot change the hash.
   */
  get canonicalForm(): string {
    const keys = Object.keys(this.#values).sort();
    const segments: string[] = [String(keys.length)];

    for (const key of keys) {
      const value = this.#values[key] ?? "";
      segments.push(`${utf8ByteLength(key)}:${key}=${utf8ByteLength(value)}:${value}`);
    }

    return segments.join(";");
  }

  /**
   * The bag shaped for a textual sink: one whose output cannot start, continue,
   * or end a record in a log file, a CSV, or a terminal.
   *
   * Control characters — including the `\n` and `\r` that forge log lines and
   * CSV rows, and the `\t` that spreadsheet tools treat as a cell separator —
   * become visible escapes. `util.inspect` calls this what it is: the value is
   * still readable in a log line, and a reader can tell an injected newline
   * from the newline that ends a record.
   *
   * This is the representation for anything that embeds metadata in *text*.
   * Structured output (JSON export, the stored column, pino fields) uses
   * {@link values} directly, because those encoders escape what they encode.
   */
  toLogFields(): Readonly<Record<string, string>> {
    return Object.fromEntries(
      Object.entries(this.#values).map(([key, value]) => [
        escapeForText(key),
        escapeForText(value),
      ]),
    );
  }

  /** JSON as it is stored and as JSON-lines export emits it. */
  toJSON(): Readonly<Record<string, string>> {
    return this.#values;
  }
}

const BYTE_ENCODER = new TextEncoder();

/**
 * UTF-8 byte length, which is what a length prefix in a hash pre-image has to
 * mean. Character counts differ between languages — a JavaScript `.length` is
 * UTF-16 code units, so an emoji counts twice here and once elsewhere, and a
 * pre-image that only reproduces in one runtime is not an auditable one.
 */
export function utf8ByteLength(value: string): number {
  return BYTE_ENCODER.encode(value).length;
}

function describeType(value: unknown): string {
  if (value === null) return "null";
  if (Array.isArray(value)) return "array";
  return typeof value;
}

/**
 * A rejected key's name, spelled for an error message.
 *
 * A key is attacker-chosen text like a value is, so naming it here is a
 * deliberate trade-off: the message is useless to the caller if it cannot say
 * *which* field was rejected, and a key is normally a short identifier. What
 * makes it safe to put one in a sentence is that it is truncated and escaped
 * first — otherwise a key containing a newline would let the input start a
 * fresh line in the very log record that reports the rejection.
 *
 * Truncation is by code point, not by UTF-16 unit, so cutting an emoji in half
 * cannot leave a lone surrogate that encodes differently depending on the sink.
 */
function describeKey(key: string): string {
  const codePoints = Array.from(key);
  const preview = codePoints.length > 24 ? `${codePoints.slice(0, 24).join("")}…` : key;
  return `"${escapeForText(preview)}"`;
}

/**
 * Escapes characters that a textual sink would read as structure.
 *
 * One pass, and backslash is one of the things it escapes: a literal `\n` in
 * someone's input would otherwise come out looking exactly like an escaped
 * newline, and the transformation would stop being one-to-one. That it is
 * one-to-one matters — a reader of the log is entitled to reconstruct what was
 * actually supplied.
 */
// eslint-disable-next-line no-control-regex -- the control ranges are the whole point: this is precisely the set of characters a line-oriented or comma-separated sink reads as structure.
const TEXT_UNSAFE = /[\\\u0000-\u001f\u007f-\u009f]/gu;

export function escapeForText(value: string): string {
  return value.replace(TEXT_UNSAFE, (character) => {
    switch (character) {
      case "\\":
        return "\\\\";
      case "\n":
        return "\\n";
      case "\r":
        return "\\r";
      case "\t":
        return "\\t";
      default: {
        const code = character.codePointAt(0) ?? 0;
        return `\\u${code.toString(16).padStart(4, "0")}`;
      }
    }
  });
}

/**
 * Line terminators a JSON encoder leaves raw.
 *
 * `JSON.stringify` escapes everything below U+0020, which covers `\n` and `\r`,
 * but it leaves NEL (U+0085) and the two Unicode line separators (U+2028,
 * U+2029) as they are. JavaScript's line splitting does not treat those as
 * breaks, so a Node process reading an export is untroubled — but Python's
 * `str.splitlines` treats all three as line endings, and an audit export gets
 * read by whatever tool the auditor brought with them.
 *
 * The replacement writes the six-character `\u00nn` form, which is *inside* the
 * JSON document, so a reader that parses the document still gets the original
 * character back. That is what makes this safe to apply to a JSON string at all
 * — unlike {@link escapeForText}, which would escape the backslashes JSON used
 * for its own escapes and leave behind something that is no longer JSON.
 */
const RAW_LINE_TERMINATORS = /[\u0085\u2028\u2029]/gu;

export function escapeJsonLineTerminators(value: string): string {
  return value.replace(RAW_LINE_TERMINATORS, (character) => {
    const code = character.codePointAt(0) ?? 0;
    return `\\u${code.toString(16).padStart(4, "0")}`;
  });
}

/**
 * Neutralizes a value destined for a spreadsheet cell.
 *
 * Quoting alone does not help: Excel evaluates a *quoted* cell that begins with
 * `=` when it is opened from CSV, so the defense has to change the content. A
 * leading apostrophe is the conventional marker, and it is what Excel itself
 * writes when it exports a text cell that starts with a formula character.
 */
export function neutralizeFormulaPrefix(value: string): string {
  return /^[=+\-@\t\r]/u.test(value) ? `'${value}` : value;
}
