import type { MfaMethodRepository } from "../../application/ports/mfa-method-repository.js";
import { MfaMethod, type MfaMethodId, type UserId } from "../../domain/entities/mfa-method.js";

export class InMemoryMfaMethodRepository implements MfaMethodRepository {
  private readonly methods = new Map<MfaMethodId, MfaMethod>();

  async save(method: MfaMethod): Promise<void> {
    this.methods.set(method.id, method);
  }

  async findById(id: MfaMethodId): Promise<MfaMethod | undefined> {
    return this.methods.get(id);
  }

  async findActiveByUserId(userId: UserId): Promise<MfaMethod[]> {
    return Array.from(this.methods.values()).filter(
      (m) => m.userId === userId && m.status === "active",
    );
  }

  async findPendingByUserId(userId: UserId): Promise<MfaMethod[]> {
    return Array.from(this.methods.values()).filter(
      (m) => m.userId === userId && m.status === "pending",
    );
  }

  async findAllByUserId(userId: UserId): Promise<MfaMethod[]> {
    return Array.from(this.methods.values()).filter((m) => m.userId === userId);
  }

  async delete(id: MfaMethodId): Promise<void> {
    this.methods.delete(id);
  }

  // Test helper
  async findAll(): Promise<MfaMethod[]> {
    return Array.from(this.methods.values());
  }
}
