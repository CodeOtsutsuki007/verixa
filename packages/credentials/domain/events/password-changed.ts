import { BaseDomainEvent } from "@verixa/shared-kernel";

import type { CredentialUserId } from "../entities/credential.js";

/** Emitted after a successful password change by an authenticated user. */
export class PasswordChanged extends BaseDomainEvent {
  readonly eventName = "credentials.password.changed";

  constructor(userId: CredentialUserId) {
    super(userId);
  }
}
