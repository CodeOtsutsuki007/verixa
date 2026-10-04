import { PrismaClientKnownRequestError } from "@verixa/database";
import { ConflictError, NotFoundError } from "@verixa/shared-kernel";

function isKnownRequestError(error: unknown): error is PrismaClientKnownRequestError {
  return error instanceof PrismaClientKnownRequestError;
}

/** Keep Prisma's error codes inside the persistence adapter, following Issue 056. */
export function mapPrismaError(error: unknown, entity: string): never {
  if (isKnownRequestError(error)) {
    switch (error.code) {
      case "P2002":
        throw new ConflictError(`${entity} already exists with the same unique value.`);
      case "P2003":
      case "P2025":
        throw new NotFoundError(`${entity} references a record that does not exist.`);
      default:
        break;
    }
  }
  throw error;
}

export async function withMappedErrors<T>(entity: string, work: () => Promise<T>): Promise<T> {
  try {
    return await work();
  } catch (error) {
    return mapPrismaError(error, entity);
  }
}
