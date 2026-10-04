import {
  AttributeContext,
  type AttributeBag,
  type AttributeBagName,
} from "../../domain/value-objects/attribute-context.js";
import type { AttributeProvider, AttributeResolutionRequest } from "../ports/attribute-provider.js";

export interface AttributeProviderFailure {
  readonly provider: string;
  readonly error: unknown;
}

export interface AttributeResolutionResult {
  readonly context: AttributeContext;
  readonly failures: readonly AttributeProviderFailure[];
}

/** Required provider failure rejects resolution with its source identified. */
export class AttributeProviderResolutionError extends Error {
  constructor(
    readonly provider: string,
    options?: ErrorOptions,
  ) {
    super(`Required attribute provider "${provider}" failed.`, options);
    this.name = "AttributeProviderResolutionError";
  }
}

/**
 * Resolves providers in registration order. Each later provider overlays
 * earlier values recursively, allowing trusted identity/resource lookups to
 * replace request claims without discarding unrelated claims. Optional
 * fail-open errors are reported to the caller; required errors fail closed.
 */
export class AttributeResolutionPipeline {
  constructor(private readonly providers: readonly AttributeProvider[]) {
    const names = new Set<string>();
    for (const provider of providers) {
      if (!provider.name.trim()) throw new TypeError("Attribute providers need a non-empty name.");
      if (names.has(provider.name))
        throw new TypeError(`Duplicate attribute provider: ${provider.name}`);
      names.add(provider.name);
    }
  }

  async resolve(request: AttributeResolutionRequest): Promise<AttributeResolutionResult> {
    let bags: Record<AttributeBagName, AttributeBag> = {
      subject: {},
      resource: {},
      action: {},
      environment: {},
    };
    const failures: AttributeProviderFailure[] = [];

    for (const provider of this.providers) {
      let context: AttributeContext;
      try {
        context = await provider.resolve(request);
      } catch (error) {
        if (provider.failureMode === "fail-closed") {
          throw new AttributeProviderResolutionError(provider.name, { cause: error });
        }
        failures.push({ provider: provider.name, error });
        continue;
      }

      const next = context.toBags();
      bags = {
        subject: mergeRecords(bags.subject, next.subject),
        resource: mergeRecords(bags.resource, next.resource),
        action: mergeRecords(bags.action, next.action),
        environment: mergeRecords(bags.environment, next.environment),
      };
    }

    return { context: AttributeContext.create(bags), failures: Object.freeze(failures) };
  }
}

function mergeRecords(earlier: AttributeBag, later: AttributeBag): AttributeBag {
  const merged: Record<string, unknown> = { ...earlier };
  for (const [key, value] of Object.entries(later)) {
    const oldValue = merged[key];
    if (isRecord(oldValue) && isRecord(value)) {
      merged[key] = mergeRecords(oldValue as AttributeBag, value);
    } else {
      merged[key] = value;
    }
  }
  return merged as AttributeBag;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return (
    typeof value === "object" && value !== null && !Array.isArray(value) && !(value instanceof Date)
  );
}
