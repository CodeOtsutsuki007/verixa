import type { Id } from "@verixa/shared-kernel";
import type { MfaMethod, MfaMethodId } from "../../domain/entities/mfa-method.js";
import type { MfaMethodRepository } from "../../application/ports/mfa-method-repository.js";

/**
 * An in-memory fake satisfying the MfaMethodRepository port.
 * Allows MFA use cases to be tested without a database.
 */
export class InMemoryMfaMethodRepository implements MfaMethodRepository {
  private readonly methodsById = new Map<MfaMethodId, MfaMethod>();

  save(method: MfaMethod): Promise<void> {
    this.methodsById.set(method.id, method);
    return Promise.resolve();
  }

  findById(id: MfaMethodId): Promise<MfaMethod | undefined> {
    return Promise.resolve(this.methodsById.get(id));
  }

  findActiveByUserId(userId: Id<"UserId">): Promise<MfaMethod[]> {
    const activeMethods = Array.from(this.methodsById.values()).filter(
      (m) => m.userId === userId && m.status === "active",
    );
    return Promise.resolve(activeMethods);
  }

  findPendingByUserId(userId: Id<"UserId">): Promise<MfaMethod[]> {
    const pendingMethods = Array.from(this.methodsById.values()).filter(
      (m) => m.userId === userId && m.status === "pending",
    );
    return Promise.resolve(pendingMethods);
  }

  findAllByUserId(userId: Id<"UserId">): Promise<MfaMethod[]> {
    const methods = Array.from(this.methodsById.values()).filter((m) => m.userId === userId);
    return Promise.resolve(methods);
  }

  delete(id: MfaMethodId): Promise<void> {
    this.methodsById.delete(id);
    return Promise.resolve();
  }
}
