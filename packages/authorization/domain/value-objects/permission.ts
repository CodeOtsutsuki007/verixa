import { Result, ValidationError } from "@verixa/shared-kernel";

const PERMISSION_PATTERN = /^[a-z0-9_-]+:[a-z0-9_*-]+$/u;

/**
 * An immutable domain value object representing a permission formatted as `resource:action`.
 *
 * Examples: `users:read`, `roles:write`, `audit:export`, `orgs:*`.
 *
 * Uses structural value equality (two Permission instances with the same normalized
 * string value are considered equal).
 */
export class Permission {
  readonly value: string;
  readonly resource: string;
  readonly action: string;

  private constructor(value: string, resource: string, action: string) {
    this.value = value;
    this.resource = resource;
    this.action = action;
  }

  /**
   * The canonical permission key (e.g. `users:read`), identical to `value`.
   */
  get key(): string {
    return this.value;
  }

  /**
   * Normalizes (trims, lowercases) and validates a raw permission string.
   *
   * Rejects malformed strings (missing colon, empty segments, invalid characters, whitespace).
   */
  static create(raw: string): Result<Permission, ValidationError> {
    if (typeof raw !== "string") {
      return Result.err(
        new ValidationError("Permission identifier must be a string.", {
          permission: ["invalid_type"],
        }),
      );
    }

    const normalized = raw.trim().toLowerCase();

    if (normalized.length === 0) {
      return Result.err(
        new ValidationError("Permission identifier is required.", {
          permission: ["required"],
        }),
      );
    }

    const parts = normalized.split(":");
    if (parts.length !== 2) {
      return Result.err(
        new ValidationError(
          `Permission identifier "${raw}" must be formatted as "resource:action" with exactly one colon.`,
          { permission: ["invalid_format"] },
        ),
      );
    }

    const [resource, action] = parts;
    if (!resource || resource.trim().length === 0) {
      return Result.err(
        new ValidationError(
          `Permission identifier "${raw}" is missing a resource component before the colon.`,
          { permission: ["empty_resource"] },
        ),
      );
    }

    if (!action || action.trim().length === 0) {
      return Result.err(
        new ValidationError(
          `Permission identifier "${raw}" is missing an action component after the colon.`,
          { permission: ["empty_action"] },
        ),
      );
    }

    if (!PERMISSION_PATTERN.test(normalized)) {
      return Result.err(
        new ValidationError(
          `Permission identifier "${raw}" contains invalid characters. Allowed: lowercase alphanumeric, hyphen, underscore, and wildcard "*".`,
          { permission: ["invalid_characters"] },
        ),
      );
    }

    return Result.ok(new Permission(normalized, resource, action));
  }

  /**
   * Convenience factory that returns a Permission or throws a {@link ValidationError}.
   */
  static from(raw: string): Permission {
    const result = Permission.create(raw);
    if (Result.isErr(result)) {
      throw result.error;
    }
    return result.value;
  }

  /**
   * Compares two Permission instances for value equality.
   */
  equals(other: Permission): boolean {
    return this.value === other.value;
  }

  /**
   * Returns true if this permission matches a required permission, taking into
   * account action wildcards (e.g. `users:*` matches `users:read`).
   */
  matches(required: Permission): boolean {
    if (this.value === required.value) {
      return true;
    }
    if (this.resource === required.resource && this.action === "*") {
      return true;
    }
    return false;
  }

  toString(): string {
    return this.value;
  }
}
