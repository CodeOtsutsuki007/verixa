export const base32 = {
  encode(buffer: Buffer): string {
    const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let bits = 0;
    let value = 0;
    let output = "";

    for (let i = 0; i < buffer.length; i++) {
      value = (value << 8) | buffer[i]!;
      bits += 8;
      while (bits >= 5) {
        output += alphabet[(value >>> (bits - 5)) & 31];
        bits -= 5;
      }
    }
    if (bits > 0) {
      output += alphabet[(value << (5 - bits)) & 31];
    }
    return output;
  },

  decode(input: string): Buffer {
    const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    const cleaned = input.toUpperCase().replace(/=+$/, "");
    let bits = 0;
    let value = 0;
    let index = 0;
    const output = Buffer.alloc(Math.floor((cleaned.length * 5) / 8));

    for (let i = 0; i < cleaned.length; i++) {
      const char = cleaned[i]!;
      const charVal = alphabet.indexOf(char);
      if (charVal === -1) {
        throw new Error(`Invalid base32 character: ${char}`);
      }
      value = (value << 5) | charVal;
      bits += 5;
      if (bits >= 8) {
        output[index++] = (value >>> (bits - 8)) & 255;
        bits -= 8;
      }
    }
    return output;
  },
};
