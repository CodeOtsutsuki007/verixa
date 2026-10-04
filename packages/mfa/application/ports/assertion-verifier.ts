import type { Result } from "@verixa/shared-kernel";

export interface VerifiedAssertion {
  readonly credentialId: string;
  readonly signCounter: number;
  readonly userPresent: boolean;
  readonly userVerified: boolean;
  readonly rpId: string;
  readonly origin: string;
}

export interface VerifyAssertionOptions {
  readonly credentialId: string;
  readonly clientDataJSON: string | Uint8Array;
  readonly authenticatorData: string | Uint8Array;
  readonly signature: string | Uint8Array;
  readonly credentialPublicKey: string;
  readonly expectedChallenge: string;
  readonly expectedOrigin: string;
  readonly expectedRpId: string;
  readonly userHandle?: string | Uint8Array | undefined;
}

export interface AssertionVerifier {
  verify(options: VerifyAssertionOptions): Promise<Result<VerifiedAssertion, Error>>;
}
