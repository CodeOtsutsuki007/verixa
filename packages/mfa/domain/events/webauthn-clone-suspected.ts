import { BaseDomainEvent } from "@verixa/shared-kernel";

export interface WebAuthnCloneSuspectedProps {
  readonly credentialId: string;
  readonly userId: string;
  readonly previousCounter: number;
  readonly presentedCounter: number;
}

/**
 * Recorded when an authenticator assertion presents a non-increasing signature
 * counter, indicating that the credential may have been duplicated / cloned.
 */
export class WebAuthnCloneSuspected extends BaseDomainEvent {
  readonly eventName = "mfa.webauthn.clone_suspected";
  readonly credentialId: string;
  readonly userId: string;
  readonly previousCounter: number;
  readonly presentedCounter: number;

  constructor(props: WebAuthnCloneSuspectedProps) {
    super(props.credentialId);
    this.credentialId = props.credentialId;
    this.userId = props.userId;
    this.previousCounter = props.previousCounter;
    this.presentedCounter = props.presentedCounter;
  }
}
