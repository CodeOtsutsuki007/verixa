import type { PrismaClient } from "@prisma/client";
import type { WebAuthnCredentialRepository } from "../../application/ports/webauthn-credential-repository.js";
import type { UserId } from "../../domain/entities/mfa-method.js";
import type { WebAuthnCredential, WebAuthnCredentialId } from "../../domain/entities/webauthn-credential.js";
import { mapPrismaError } from "./error-mapper.js";
import { WebAuthnCredentialMapper } from "./webauthn-credential-mapper.js";

export class PrismaWebAuthnCredentialRepository implements WebAuthnCredentialRepository {
  constructor(private readonly prisma: PrismaClient) {}

  async findById(id: WebAuthnCredentialId): Promise<WebAuthnCredential | undefined> {
    try {
      const row = await this.prisma.webAuthnCredential.findUnique({
        where: { id },
      });
      return row ? WebAuthnCredentialMapper.toDomain(row) : undefined;
    } catch (error) {
      throw mapPrismaError(error);
    }
  }

  async findByCredentialId(credentialId: string): Promise<WebAuthnCredential | undefined> {
    try {
      const row = await this.prisma.webAuthnCredential.findUnique({
        where: { credentialId },
      });
      return row ? WebAuthnCredentialMapper.toDomain(row) : undefined;
    } catch (error) {
      throw mapPrismaError(error);
    }
  }

  async findByUserId(userId: UserId): Promise<readonly WebAuthnCredential[]> {
    try {
      const rows = await this.prisma.webAuthnCredential.findMany({
        where: { userId },
      });
      return rows.map((row) => WebAuthnCredentialMapper.toDomain(row));
    } catch (error) {
      throw mapPrismaError(error);
    }
  }

  async save(credential: WebAuthnCredential): Promise<void> {
    try {
      const data = WebAuthnCredentialMapper.toPersistence(credential);
      await this.prisma.webAuthnCredential.upsert({
        where: { id: credential.id },
        create: data,
        update: {
          publicKey: data.publicKey,
          signCounter: data.signCounter,
          transports: data.transports,
          attestationType: data.attestationType,
          lastUsedAt: data.lastUsedAt,
        },
      });
    } catch (error) {
      throw mapPrismaError(error);
    }
  }

  async delete(id: WebAuthnCredentialId): Promise<void> {
    try {
      await this.prisma.webAuthnCredential.delete({
        where: { id },
      });
    } catch (error) {
      // If not found or already deleted, treat as idempotent success or map if needed
      try {
        throw mapPrismaError(error);
      } catch (err: any) {
        if (err.code === "NOT_FOUND") {
          return;
        }
        throw err;
      }
    }
  }
}
