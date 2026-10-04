/**
 * Minimal RFC 8949 CBOR encoder and decoder for WebAuthn data structures.
 *
 * Implements canonical deterministic encoding and decoding for:
 * - integers (positive and negative)
 * - byte strings (Uint8Array)
 * - text strings (UTF-8)
 * - arrays
 * - maps (including string and integer keys)
 * - booleans and null
 */

export class CborReader {
  private offset = 0;

  constructor(private readonly data: Uint8Array) {}

  get isEOF(): boolean {
    return this.offset >= this.data.length;
  }

  get remaining(): number {
    return this.data.length - this.offset;
  }

  read(): unknown {
    if (this.isEOF) {
      throw new Error("Unexpected end of CBOR input");
    }

    const initialByte = this.data[this.offset];
    if (initialByte === undefined) {
      throw new Error("Unexpected end of CBOR input");
    }
    this.offset++;

    const majorType = initialByte >> 5;
    const additionalInfo = initialByte & 0x1f;

    const value = this.readLengthOrValue(additionalInfo);

    switch (majorType) {
      case 0: // unsigned integer
        return value;

      case 1: // negative integer: -1 - value
        return -1 - Number(value);

      case 2: {
        // byte string
        const len = Number(value);
        if (this.offset + len > this.data.length) {
          throw new Error("CBOR byte string extends past end of buffer");
        }
        const slice = this.data.subarray(this.offset, this.offset + len);
        this.offset += len;
        return slice;
      }

      case 3: {
        // text string
        const len = Number(value);
        if (this.offset + len > this.data.length) {
          throw new Error("CBOR text string extends past end of buffer");
        }
        const slice = this.data.subarray(this.offset, this.offset + len);
        this.offset += len;
        return new TextDecoder("utf-8").decode(slice);
      }

      case 4: {
        // array
        const len = Number(value);
        const arr: unknown[] = [];
        for (let i = 0; i < len; i++) {
          arr.push(this.read());
        }
        return arr;
      }

      case 5: {
        // map
        const len = Number(value);
        const map = new Map<unknown, unknown>();
        for (let i = 0; i < len; i++) {
          const key = this.read();
          const val = this.read();
          map.set(key, val);
        }
        return map;
      }

      case 6: {
        // semantic tag
        return this.read();
      }

      case 7: {
        // simple values
        if (additionalInfo === 20) return false;
        if (additionalInfo === 21) return true;
        if (additionalInfo === 22) return null;
        if (additionalInfo === 23) return undefined;
        return value;
      }

      default:
        throw new Error(`Unsupported CBOR major type: ${majorType}`);
    }
  }

  private readLengthOrValue(additionalInfo: number): number | bigint {
    if (additionalInfo < 24) {
      return additionalInfo;
    }
    if (additionalInfo === 24) {
      const b = this.data[this.offset];
      if (b === undefined) throw new Error("Unexpected EOF reading 1-byte value");
      this.offset++;
      return b;
    }
    if (additionalInfo === 25) {
      const b0 = this.data[this.offset];
      const b1 = this.data[this.offset + 1];
      if (b0 === undefined || b1 === undefined)
        throw new Error("Unexpected EOF reading 2-byte value");
      const val = (b0 << 8) | b1;
      this.offset += 2;
      return val;
    }
    if (additionalInfo === 26) {
      if (this.offset + 4 > this.data.length)
        throw new Error("Unexpected EOF reading 4-byte value");
      const view = new DataView(this.data.buffer, this.data.byteOffset + this.offset, 4);
      const val = view.getUint32(0, false);
      this.offset += 4;
      return val;
    }
    if (additionalInfo === 27) {
      if (this.offset + 8 > this.data.length)
        throw new Error("Unexpected EOF reading 8-byte value");
      const view = new DataView(this.data.buffer, this.data.byteOffset + this.offset, 8);
      const val = view.getBigUint64(0, false);
      this.offset += 8;
      if (val <= BigInt(Number.MAX_SAFE_INTEGER)) {
        return Number(val);
      }
      return val;
    }
    throw new Error(`Unsupported CBOR additional info: ${additionalInfo}`);
  }
}

export function decodeCbor<T = unknown>(buffer: Uint8Array): T {
  const reader = new CborReader(buffer);
  return reader.read() as T;
}

export function encodeCbor(value: unknown): Uint8Array {
  const parts: Uint8Array[] = [];

  function write(val: unknown): void {
    if (val === false) {
      parts.push(new Uint8Array([0xf4]));
    } else if (val === true) {
      parts.push(new Uint8Array([0xf5]));
    } else if (val === null) {
      parts.push(new Uint8Array([0xf6]));
    } else if (val === undefined) {
      parts.push(new Uint8Array([0xf7]));
    } else if (typeof val === "number") {
      if (Number.isInteger(val)) {
        if (val >= 0) {
          writeUint(0, val);
        } else {
          writeUint(1, -1 - val);
        }
      } else {
        throw new Error("Floats not supported in minimal CBOR encoder");
      }
    } else if (typeof val === "string") {
      const bytes = new TextEncoder().encode(val);
      writeUint(3, bytes.length);
      parts.push(bytes);
    } else if (val instanceof Uint8Array) {
      writeUint(2, val.length);
      parts.push(val);
    } else if (Array.isArray(val)) {
      writeUint(4, val.length);
      for (const item of val) {
        write(item);
      }
    } else if (val instanceof Map) {
      writeUint(5, val.size);
      for (const [k, v] of val.entries()) {
        write(k);
        write(v);
      }
    } else if (typeof val === "object") {
      const entries = Object.entries(val as Record<string, unknown>);
      writeUint(5, entries.length);
      for (const [k, v] of entries) {
        write(k);
        write(v);
      }
    } else {
      throw new Error(`Unsupported type for CBOR encoding: ${typeof val}`);
    }
  }

  function writeUint(majorType: number, num: number): void {
    const typeShift = majorType << 5;
    if (num < 24) {
      parts.push(new Uint8Array([typeShift | num]));
    } else if (num < 256) {
      parts.push(new Uint8Array([typeShift | 24, num]));
    } else if (num < 65536) {
      const b = new Uint8Array(3);
      b[0] = typeShift | 25;
      b[1] = (num >> 8) & 0xff;
      b[2] = num & 0xff;
      parts.push(b);
    } else {
      const b = new Uint8Array(5);
      b[0] = typeShift | 26;
      b[1] = (num >> 24) & 0xff;
      b[2] = (num >> 16) & 0xff;
      b[3] = (num >> 8) & 0xff;
      b[4] = num & 0xff;
      parts.push(b);
    }
  }

  write(value);

  const totalLen = parts.reduce((acc, p) => acc + p.length, 0);
  const result = new Uint8Array(totalLen);
  let offset = 0;
  for (const part of parts) {
    result.set(part, offset);
    offset += part.length;
  }
  return result;
}
