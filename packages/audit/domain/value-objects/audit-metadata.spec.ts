import { Result, ValidationError } from "@verixa/shared-kernel";
import { describe, expect, it } from "vitest";

import {
  AuditMetadata,
  escapeForText,
  escapeJsonLineTerminators,
  MAX_METADATA_ENTRIES,
  MAX_METADATA_KEY_LENGTH,
  MAX_METADATA_VALUE_LENGTH,
  METADATA_REJECTED_KEY,
  neutralizeFormulaPrefix,
  rejectionReasonOf,
  utf8ByteLength,
} from "./audit-metadata.js";

/** A value carrying one of everything a textual sink reads as framing. */
const ADVERSARIAL = 'x\ny\rz,a"b;c=d|e\tf\\g\u0000h\u001bi\u007fj\u0085l àé👍';

function valuesOf(input: Record<string, string>): AuditMetadata {
  const created = AuditMetadata.create(input);

  if (Result.isErr(created)) throw new Error(`unexpected rejection: ${created.error.message}`);

  return created.value;
}

function reasonOf(input: Record<string, string>): string {
  const created = AuditMetadata.create(input);

  if (Result.isOk(created)) throw new Error("unexpected acceptance");

  return rejectionReasonOf(created.error);
}

describe("utf8ByteLength", () => {
  it("counts bytes, not code units", () => {
    expect(utf8ByteLength("abc")).toBe(3);
    expect(utf8ByteLength("é")).toBe(2);
    expect(utf8ByteLength("👍")).toBe(4);
    expect(utf8ByteLength("")).toBe(0);
  });
});

describe("escapeForText", () => {
  it("leaves nothing in the value that a line-oriented reader would act on", () => {
    const escaped = escapeForText(ADVERSARIAL);

    // eslint-disable-next-line no-control-regex -- asserting their absence is the test.
    expect(escaped).not.toMatch(/[\u0000-\u001f\u007f-\u009f]/u);
    expect(escaped.includes("\n")).toBe(false);
    expect(escaped.includes("\r")).toBe(false);
    expect(escaped).toContain("\\n");
    expect(escaped).toContain("\\r");
    expect(escaped).toContain("\\t");
    expect(escaped).toContain("\\u0000");
    expect(escaped).toContain("\\u001b");
    expect(escaped).toContain("\\u007f");
  });

  it("does not touch characters that are only unsafe to a particular parser", () => {
    // Commas, quotes, semicolons, pipes and non-ASCII text are content. The
    // encoders that care about them quote or escape at their own boundary.
    const escaped = escapeForText('a,b"c;d|e àé👍');

    expect(escaped).toBe('a,b"c;d|e àé👍');
  });

  it("is one-to-one, so a reader can reconstruct what was supplied", () => {
    // The whole point of escaping *and* escaping the escape character: a real
    // newline and the two characters `\` `n` must not come out the same, or the
    // log reader cannot tell an injected line break from text that was typed.
    expect(escapeForText("a\nb")).not.toBe(escapeForText("a\\nb"));
    expect(escapeForText("a\\\\b")).not.toBe(escapeForText("a\\b"));
  });
});

describe("neutralizeFormulaPrefix", () => {
  it.each(["=cmd|'/c calc'!A1", "+1", "-1", "@SUM(A1)", "\t=1", "\r=1"])(
    "prefixes a cell a spreadsheet would evaluate: %s",
    (value) => {
      const neutralized = neutralizeFormulaPrefix(value);

      expect(neutralized.startsWith("'")).toBe(true);
      expect(/^[=+\-@\t\r]/u.test(neutralized)).toBe(false);
    },
  );

  it("leaves ordinary text alone", () => {
    expect(neutralizeFormulaPrefix("actor-1")).toBe("actor-1");
    expect(neutralizeFormulaPrefix("a=b")).toBe("a=b");
    expect(neutralizeFormulaPrefix("")).toBe("");
  });

  it("keeps the composition with escaping safe in either order of attack", () => {
    // A payload that hides its formula character behind a control character is
    // defused twice over: escaping turns the leading tab into the two
    // characters `\t`, so nothing is left to trigger the formula check, and a
    // payload that arrives with the formula character first is prefixed.
    for (const payload of ["=cmd|'/c calc'!A1", "\t=1+1", "\r@SUM(A1)", "-1+2"]) {
      const cell = neutralizeFormulaPrefix(escapeForText(payload));

      expect(/^[=+\-@]/u.test(cell)).toBe(false);
      expect(cell).not.toBe(payload);
    }
  });
});

describe("escapeJsonLineTerminators", () => {
  it("turns the terminators JSON leaves raw into their own escape form", () => {
    const escaped = escapeJsonLineTerminators('{"k":"a\u0085b\u2028c\u2029d"}');

    expect(escaped).toBe('{"k":"a\\u0085b\\u2028c\\u2029d"}');
    expect(escaped).not.toMatch(/[\u0085\u2028\u2029]/u);
  });

  it("is lossless when the document is parsed back", () => {
    const metadata = { k: "a\u0085b\u2028c\u2029d", j: 'plain"value' };
    const document = escapeJsonLineTerminators(JSON.stringify(metadata));

    expect(JSON.parse(document)).toEqual(metadata);
  });
});

describe("AuditMetadata.create", () => {
  it("preserves adversarial content verbatim", () => {
    // Nothing is sanitized on the way in. The value that is hashed and the
    // value that is stored have to be the value that was supplied, or the chain
    // commits to something other than what happened.
    const metadata = valuesOf({ reason: ADVERSARIAL });

    expect(metadata.values.reason).toBe(ADVERSARIAL);
  });

  it("accepts an empty bag and a bounded one", () => {
    expect(AuditMetadata.empty().values).toEqual({});
    expect(Object.keys(valuesOf({ a: "b" }).values)).toEqual(["a"]);
  });

  it("refuses more fields than the bound allows", () => {
    const input: Record<string, string> = {};
    for (let index = 0; index <= MAX_METADATA_ENTRIES; index += 1) {
      input[`k${String(index)}`] = "v";
    }

    expect(reasonOf(input)).toBe("too_many_fields");
  });

  it("refuses an empty key, an over-long key, and an over-long value", () => {
    expect(reasonOf({ "": "v" })).toBe("empty_key");
    expect(reasonOf({ ["k".repeat(MAX_METADATA_KEY_LENGTH + 1)]: "v" })).toBe("key_too_long");
    expect(reasonOf({ k: "v".repeat(MAX_METADATA_VALUE_LENGTH + 1) })).toBe("value_too_long");
  });

  it("refuses values that are not strings", () => {
    const created = AuditMetadata.create({ n: 1 });

    expect(Result.isErr(created)).toBe(true);
    if (Result.isErr(created)) {
      expect(rejectionReasonOf(created.error)).toBe("non_string_value");
      // The message is for humans; the type name is what tells a caller which
      // assumption it broke.
      expect(created.error.message).toContain("number");
    }
  });

  it("names a value's shape rather than echoing the value in the error", () => {
    // The rejection path must not become a way to get unsanitized input into a
    // log line, so the message quotes the type, not the content.
    const created = AuditMetadata.create({ k: { nested: "value\nwith newline" } });

    if (Result.isErr(created)) {
      expect(created.error.message).not.toContain("with newline");
    } else {
      throw new Error("expected rejection");
    }
  });

  it("cannot be made to forge a line by the name of the rejected key", () => {
    // Naming which field broke the bound is worth reflecting a *sanitized* key
    // for, but a key is attacker-chosen text like a value is: unescaped, a
    // newline in it would start a fresh record in the log line reporting the
    // rejection.
    const hostile = `reason\n${"P".repeat(MAX_METADATA_KEY_LENGTH)} admin login granted`;
    const created = AuditMetadata.create({ [hostile]: "v" });

    if (Result.isErr(created)) {
      expect(rejectionReasonOf(created.error)).toBe("key_too_long");
      expect(created.error.message).not.toMatch(/[\n\r\t]/u);
      expect(created.error.message).toContain("\\n");
      // And it is truncated, so an unbounded key cannot make an unbounded message.
      expect(created.error.message).not.toContain("admin login granted");
    } else {
      throw new Error("expected rejection");
    }
  });
});

describe("AuditMetadata.canonicalForm", () => {
  it("is unaffected by insertion order", () => {
    expect(valuesOf({ a: "1", b: "2" }).canonicalForm).toBe(
      valuesOf({ b: "2", a: "1" }).canonicalForm,
    );
  });

  it("cannot be re-shaped by a separator inside a value", () => {
    // `;`, `=` and `:` are all framing characters in the pre-image. Without the
    // declared byte lengths, the pair on the left and the pair on the right
    // would serialize identically — two different records, one digest.
    const twoPairs = valuesOf({ a: "b", c: "d" }).canonicalForm;
    const onePair = valuesOf({ a: "b;c=d" }).canonicalForm;

    expect(twoPairs).not.toBe(onePair);

    const withColon = valuesOf({ "a:b": "c" }).canonicalForm;
    const withLength = valuesOf({ a: "b:c" }).canonicalForm;
    expect(withColon).not.toBe(withLength);
  });

  it("distinguishes an absent key from one whose value is empty", () => {
    expect(AuditMetadata.empty().canonicalForm).not.toBe(valuesOf({ k: "" }).canonicalForm);
  });

  it("declares lengths in bytes", () => {
    expect(valuesOf({ k: "é" }).canonicalForm).toBe("1;1:k=2:é");
    expect(valuesOf({ k: "👍" }).canonicalForm).toBe("1;1:k=4:👍");
  });
});

describe("AuditMetadata projections", () => {
  it("toLogFields escapes every key and value for a textual sink", () => {
    const fields = valuesOf({ "a\nb": "c\r\nd" }).toLogFields();

    expect(Object.keys(fields)).toEqual(["a\\nb"]);
    expect(fields["a\\nb"]).toBe("c\\r\\nd");
  });

  it("toJSON keeps the recorded values exactly", () => {
    expect(valuesOf({ reason: ADVERSARIAL }).toJSON().reason).toBe(ADVERSARIAL);
  });

  it("rejected records why the supplied bag was unusable", () => {
    const metadata = AuditMetadata.rejected("value_too_long");

    expect(metadata.values).toEqual({ [METADATA_REJECTED_KEY]: "value_too_long" });
    // A replacement bag is still a valid bag: nothing downstream has to know it
    // was synthesized.
    expect(metadata.canonicalForm).toBe("1;16:metadataRejected=14:value_too_long");
  });

  it("classifies a rejection that came from somewhere else", () => {
    // A `ValidationError` from another value object has no metadata reason, and
    // inventing one would be worse than admitting the classification failed.
    expect(rejectionReasonOf(new ValidationError("unrelated.", { other: ["nope"] }))).toBe(
      "unclassified",
    );
  });
});
