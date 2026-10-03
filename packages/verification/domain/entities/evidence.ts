import { createId, type Id, Result, ValidationError } from "@verixa/shared-kernel";

import { EvidenceType, type EvidenceTypeValue } from "../value-objects/evidence-type.js";
import type { VerificationType } from "../value-objects/verification-type.js";

import type { VerificationRequestId } from "./verification-request.js";

export type EvidenceId = Id<"EvidenceId">;

interface EvidenceProps {
  readonly id: EvidenceId;
  readonly requestId: VerificationRequestId;
  readonly type: EvidenceType;
  /** Opaque pointer to where the bytes live. Never the bytes themselves. */
  readonly storageRef: string;
  /** Hex-encoded SHA-256 of the stored bytes, for tamper detection and deduplication. */
  readonly checksum: string;
  readonly uploadedAt: Date;
}

const SHA256_HEX_PATTERN = /^[0-9a-f]{64}$/u;

/**
 * A chunk on disk cannot meaningfully be longer than this, and a bounded
 * length is what keeps a caller from smuggling file contents into the column
 * that is supposed to hold a pointer to them. A real storage reference — an
 * S3 key, a local path, a UUID — is nowhere near 1024 characters.
 */
const MAX_STORAGE_REF_LENGTH = 1024;

/**
 * One piece of evidence attached to a `VerificationRequest`: a government ID
 * scan, a selfie, a utility bill.
 *
 * The entity deliberately holds a **pointer** (`storageRef` + `checksum`),
 * not the bytes. The domain layer must never hold binary blobs or know whether
 * the bytes are in S3, on a local disk, or somewhere else — that boundary is
 * what lets `EvidenceStorage` (Issue 166) change without a domain change, and
 * what keeps a domain entity small enough to log. See
 * `docs/security/evidence-handling.md`.
 *
 * Evidence is its own aggregate rather than a field on the request for the
 * same reason a `Credential` is not a field on `User`: it has its own
 * lifecycle, its own access rules, and the audit trail needs to name one
 * specific artifact ("the front of the ID, uploaded at 14:02"), not "the
 * request was edited".
 */
export class Evidence {
  readonly id: EvidenceId;
  readonly requestId: VerificationRequestId;
  readonly type: EvidenceType;
  readonly storageRef: string;
  readonly checksum: string;
  readonly uploadedAt: Date;

  private constructor(props: EvidenceProps) {
    this.id = props.id;
    this.requestId = props.requestId;
    this.type = props.type;
    this.storageRef = props.storageRef;
    this.checksum = props.checksum;
    this.uploadedAt = props.uploadedAt;
  }

  /**
   * Attaches a new piece of evidence to a request.
   *
   * The `verificationType` is a parameter even though the request carries one
   * because the domain cannot reach through to the request from here without
   * making evidence persistence-aware; the calling use case (Issue 168) has
   * both objects loaded and passing the type in keeps this a pure function of
   * its inputs.
   */
  static attach(params: {
    requestId: VerificationRequestId;
    verificationType: VerificationType;
    evidenceType: string;
    storageRef: string;
    checksum: string;
  }): Result<Evidence, ValidationError> {
    const type = EvidenceType.create(params.evidenceType);
    if (Result.isErr(type)) {
      return type;
    }

    if (!type.value.isValidFor(params.verificationType.value)) {
      return Result.err(
        new ValidationError(
          `Evidence type "${type.value.value}" is not valid for a "${params.verificationType.value}" request.`,
          { evidenceType: ["invalid_for_verification_type"] },
        ),
      );
    }

    const fieldErrors: Record<string, string[]> = {};

    const storageRef = params.storageRef.trim();
    if (storageRef.length === 0) {
      fieldErrors["storageRef"] = ["required"];
    } else if (storageRef.length > MAX_STORAGE_REF_LENGTH || storageRef.startsWith("data:")) {
      // `data:` is a self-contained payload — exactly the raw-bytes-in-the-domain
      // mistake this field exists to prevent.
      fieldErrors["storageRef"] = ["not_a_reference"];
    }

    if (!SHA256_HEX_PATTERN.test(params.checksum)) {
      fieldErrors["checksum"] = ["invalid_sha256"];
    }

    if (Object.keys(fieldErrors).length > 0) {
      return Result.err(new ValidationError("Evidence is invalid.", fieldErrors));
    }

    return Result.ok(
      new Evidence({
        id: createId<"EvidenceId">(),
        requestId: params.requestId,
        type: type.value,
        storageRef,
        checksum: params.checksum,
        uploadedAt: new Date(),
      }),
    );
  }

  /** Rebuilds from already-trusted data (e.g. a database row). */
  static reconstitute(props: EvidenceProps): Evidence {
    return new Evidence(props);
  }

  /** Whether this evidence belongs to `requestId` — the check a reviewer's view is scoped by. */
  belongsTo(requestId: VerificationRequestId): boolean {
    return this.requestId === requestId;
  }

  get typeValue(): EvidenceTypeValue {
    return this.type.value;
  }
}

/** Whether `value` is a 64-character lowercase hex SHA-256 digest. */
export function isValidSha256Hex(value: string): boolean {
  return SHA256_HEX_PATTERN.test(value);
}
