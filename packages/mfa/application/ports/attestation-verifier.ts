import type { Result } from "@verixa/shared-kernel";

export interface VerifiedAttestation {
  readonly credentialId: string;
  readonly credentialPublicKey: string;
  readonly signCounter: number;
  readonly aaguid?: string;
  readonly attestationType: string;
  readonly rpId: string;
  readonly origin: string;
}

export interface VerifyAttestationOptions {
  readonly clientDataJSON: string | Uint8Array;
  readonly attestationObject: string | Uint8Array;
  readonly expectedChallenge: string;
  readonly expectedOrigin: string;
  readonly expectedRpId: string;
}

export interface AttestationVerifier {
  verify(options: VerifyAttestationOptions): Promise<Result<VerifiedAttestation, Error>>;
}
