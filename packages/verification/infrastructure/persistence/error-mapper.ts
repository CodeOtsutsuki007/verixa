import { PrismaClientKnownRequestError } from "@verixa/database";
import { ConflictError, NotFoundError } from "@verixa/shared-kernel";

/**
 * Translates Prisma errors into the domain error hierarchy — the same
 * anti-corruption layer every repository adapter in this codebase uses (see
 * `packages/identity/infrastructure/persistence/error-mapper.ts`). Prisma's
 * vocabulary stops here so no use case ever branches on "P2002".
 *
 * Duplicated rather than imported from `@verixa/identity`: reaching into
 * another context's infrastructure from this one would be a deep import of
 * exactly the kind the package boundary rule forbids (see
 * `docs/guides/domain-modeling.md`), and the mapping is a boundary concern of
 * whichever adapter owns it.
 */

/** Unique constraint violation. */
const UNIQUE_VIOLATION = "P2002";
/** An operation (update/delete) targeted a row that does not exist. */
const RECORD_NOT_FOUND = "P2025";
/** Foreign key constraint violation. */
const FOREIGN_KEY_VIOLATION = "P2003";

function isKnownRequestError(error: unknown): error is PrismaClientKnownRequestError {
  return error instanceof PrismaClientKnownRequestError;
}

function violatedFields(error: PrismaClientKnownRequestError): string[] {
  const target: unknown = error.meta?.["target"];
  if (Array.isArray(target)) {
    return target.filter((value): value is string => typeof value === "string");
  }
  return typeof target === "string" ? [target] : [];
}

/**
 * Maps a Prisma error to a domain error, or rethrows if it has no domain
 * meaning. Only failures a caller can act on are translated; an unreachable
 * database stays an exception, because there is no sensible `err` branch for
 * it (see `docs/guides/error-handling.md`).
 */
export function mapPrismaError(error: unknown, entity: string): never {
  if (isKnownRequestError(error)) {
    switch (error.code) {
      case UNIQUE_VIOLATION: {
        const fields = violatedFields(error);
        const detail = fields.length > 0 ? ` (${fields.join(", ")})` : "";
        throw new ConflictError(`${entity} already exists with the same unique value${detail}.`);
      }

      case FOREIGN_KEY_VIOLATION: {
        throw new NotFoundError(
          `${entity} references a record that does not exist. A foreign key constraint failed.`,
        );
      }

      case RECORD_NOT_FOUND: {
        throw new NotFoundError(`${entity} was not found.`);
      }

      default:
        break;
    }
  }

  throw error;
}

/** Runs a repository write, translating any Prisma error on the way out. */
export async function withMappedErrors<T>(entity: string, work: () => Promise<T>): Promise<T> {
  try {
    return await work();
  } catch (error) {
    return mapPrismaError(error, entity);
  }
}
