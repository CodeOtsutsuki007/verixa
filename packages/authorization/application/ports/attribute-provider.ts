import type { AttributeContext } from "../../domain/value-objects/attribute-context.js";

/** Stable input shared by all attribute sources for one authorization request. */
export interface AttributeResolutionRequest {
  readonly subjectId: string;
  readonly resourceRef: string;
  readonly action: string;
}

/**
 * Application boundary for one source of ABAC attributes. Providers must
 * return only facts they are entitled to assert; the pipeline determines
 * precedence and isolates optional failures.
 */
export interface AttributeProvider {
  readonly name: string;
  /**
   * `fail-open` is for optional enrichment whose absence cannot grant access.
   * `fail-closed` is for a source required by an authorization invariant; its
   * failure rejects resolution so the caller can deny the request.
   */
  readonly failureMode: "fail-open" | "fail-closed";
  resolve(request: AttributeResolutionRequest): Promise<AttributeContext>;
}
