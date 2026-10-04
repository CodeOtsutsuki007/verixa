import { describe, expect, it } from "vitest";

import { CborReader, decodeCbor, encodeCbor } from "./cbor.js";

describe("CBOR Encoder and Decoder", () => {
  it("encodes and decodes unsigned integers of all sizes", () => {
    const values = [0, 1, 23, 24, 255, 256, 65535, 65536, 4294967295];
    for (const v of values) {
      const encoded = encodeCbor(v);
      const decoded = decodeCbor<number>(encoded);
      expect(decoded).toBe(v);
    }
  });

  it("encodes and decodes negative integers", () => {
    const values = [-1, -10, -24, -25, -1000];
    for (const v of values) {
      const encoded = encodeCbor(v);
      const decoded = decodeCbor<number>(encoded);
      expect(decoded).toBe(v);
    }
  });

  it("encodes and decodes text strings", () => {
    const strs = ["", "hello", "verixa.example", "🌟 WebAuthn FIDO2"];
    for (const s of strs) {
      const encoded = encodeCbor(s);
      const decoded = decodeCbor<string>(encoded);
      expect(decoded).toBe(s);
    }
  });

  it("encodes and decodes byte strings", () => {
    const bytes = new Uint8Array([0xde, 0xad, 0xbe, 0xef, 0x01, 0x02]);
    const encoded = encodeCbor(bytes);
    const decoded = decodeCbor<Uint8Array>(encoded);
    expect(decoded).toEqual(bytes);
  });

  it("encodes and decodes arrays", () => {
    const arr = [1, "two", false, null, [3, 4]];
    const encoded = encodeCbor(arr);
    const decoded = decodeCbor<unknown[]>(encoded);
    expect(decoded).toEqual(arr);
  });

  it("encodes and decodes Map and Object", () => {
    const map = new Map<unknown, unknown>([
      ["fmt", "none"],
      [1, 2],
    ]);
    const encoded = encodeCbor(map);
    const decoded = decodeCbor<Map<unknown, unknown>>(encoded);
    expect(decoded.get("fmt")).toBe("none");
    expect(decoded.get(1)).toBe(2);

    const obj = { a: "apple", b: 123 };
    const encObj = encodeCbor(obj);
    const decObj = decodeCbor<Map<string, unknown>>(encObj);
    expect(decObj.get("a")).toBe("apple");
    expect(decObj.get("b")).toBe(123);
  });

  it("encodes and decodes booleans and null", () => {
    expect(decodeCbor(encodeCbor(true))).toBe(true);
    expect(decodeCbor(encodeCbor(false))).toBe(false);
    expect(decodeCbor(encodeCbor(null))).toBe(null);
  });

  it("throws on floats in minimal encoder", () => {
    expect(() => encodeCbor(3.14)).toThrow("Floats not supported");
  });

  it("throws on unsupported types in encoder", () => {
    expect(() => encodeCbor(() => {})).toThrow("Unsupported type");
  });

  it("throws on EOF in CborReader", () => {
    const reader = new CborReader(new Uint8Array([]));
    expect(() => reader.read()).toThrow("Unexpected end of CBOR input");
  });

  it("throws on unexpected EOF for byte/text strings", () => {
    // 0x58 (byte string with 1-byte length), length 10, but only 2 bytes provided
    const truncatedByteString = new Uint8Array([0x58, 10, 0x01, 0x02]);
    expect(() => decodeCbor(truncatedByteString)).toThrow("past end of buffer");

    // 0x78 (text string with 1-byte length), length 10, but only 2 bytes provided
    const truncatedTextString = new Uint8Array([0x78, 10, 0x61, 0x62]);
    expect(() => decodeCbor(truncatedTextString)).toThrow("past end of buffer");
  });

  it("handles 64-bit uint in decoder", () => {
    // 0x1b (major type 0, additional info 27) followed by 8 bytes
    const view = new DataView(new ArrayBuffer(9));
    view.setUint8(0, 0x1b);
    view.setBigUint64(1, 1000000n, false);
    const decoded = decodeCbor(new Uint8Array(view.buffer));
    expect(decoded).toBe(1000000);
  });
});
