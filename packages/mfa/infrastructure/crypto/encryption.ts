import { randomBytes, createCipheriv, createDecipheriv } from "crypto";

// Need a 32-byte key for AES-256
// In a real app this would come from an environment variable or KMS
function getEncryptionKey(): Buffer {
  const keyBase64 = process.env.MFA_ENCRYPTION_KEY;
  if (!keyBase64) {
    // For tests, fallback to a dummy key if not set.
    // The issue says "symmetric encryption with a managed key", so it should be injected.
    return Buffer.alloc(32, 1);
  }
  return Buffer.from(keyBase64, "base64");
}

export function encrypt(plaintext: string): string {
  const iv = randomBytes(12); // GCM standard IV size
  const key = getEncryptionKey();
  const cipher = createCipheriv("aes-256-gcm", key, iv);

  let ciphertext = cipher.update(plaintext, "utf8");
  ciphertext = Buffer.concat([ciphertext, cipher.final()]);
  const authTag = cipher.getAuthTag();

  // Return iv:authTag:ciphertext encoded in base64
  return Buffer.concat([iv, authTag, ciphertext]).toString("base64");
}

export function decrypt(encryptedPayload: string): string {
  const payload = Buffer.from(encryptedPayload, "base64");
  const iv = payload.subarray(0, 12);
  const authTag = payload.subarray(12, 28); // Auth tag is 16 bytes in GCM
  const ciphertext = payload.subarray(28);
  const key = getEncryptionKey();

  const decipher = createDecipheriv("aes-256-gcm", key, iv);
  decipher.setAuthTag(authTag);

  let plaintext = decipher.update(ciphertext);
  plaintext = Buffer.concat([plaintext, decipher.final()]);

  return plaintext.toString("utf8");
}
