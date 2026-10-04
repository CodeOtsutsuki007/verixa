import {
  AttributeContext,
  type AttributeBag,
} from "../../domain/value-objects/attribute-context.js";
import type { AuthorizationDecision } from "../dto/authorization-decision.js";
import type {
  AuthorizationResult,
  AuthorizationService,
} from "../services/authorization-service.js";
import type { ResourceAttributeResolverRegistry } from "../services/resource-attribute-resolver-registry.js";

export interface AuthorizeActionCommand {
  readonly subjectId: string;
  readonly action: string;
  readonly resourceType: string;
  readonly resourceId: string;
  readonly subjectAttributes?: AttributeBag;
  readonly resourceAttributes?: AttributeBag;
  readonly environmentAttributes?: AttributeBag;
}

/**
 * The Policy Decision Point (PDP): the single call site other contexts and
 * route handlers use to ask "can this subject do this action on this
 * resource," wrapping `AuthorizationService` (Issue 152) the way Issue 153
 * specifies. Has no HTTP/Fastify dependency — like every use case, it can be
 * called identically from a route handler, a CLI command, or a test (see
 * `docs/guides/use-cases.md`).
 *
 * When constructed with a `resourceAttributeResolvers` registry (Issue 151),
 * `execute` resolves the resource's own attributes automatically via
 * `resourceId`, so callers don't have to fetch and pass them by hand on
 * every check; `resourceAttributes` on the command can still supply
 * additional attributes, or override a resolved one (e.g. a caller that
 * already has the resource loaded and wants to skip a redundant fetch).
 * Passing no registry (or one with nothing registered for this resource
 * type) simply means no resource attributes are resolved automatically —
 * not an error, since not every check needs any.
 */
export class AuthorizeAction {
  constructor(
    private readonly authorizationService: AuthorizationService,
    private readonly resourceAttributeResolvers?: ResourceAttributeResolverRegistry,
  ) {}

  async execute(command: AuthorizeActionCommand): Promise<AuthorizationDecision> {
    let resolvedResourceAttributes: AttributeBag = {};

    if (this.resourceAttributeResolvers?.has(command.resourceType) === true) {
      try {
        resolvedResourceAttributes = await this.resourceAttributeResolvers.resolve(
          command.resourceType,
          command.resourceId,
        );
      } catch (error) {
        // A resource-attribute resolution failure means the request cannot
        // be evaluated against whatever policies target this resource type
        // — failing open here would silently skip exactly the attributes an
        // ABAC policy might be relying on to deny. Denying is the only safe
        // outcome, and it is reported as a distinct reason (this is the
        // "policy-error path" Issue 153's tests cover) rather than left
        // indistinguishable from an ordinary policy-driven denial.
        return {
          granted: false,
          reason: `Denied: could not resolve "${command.resourceType}" resource attributes (${
            error instanceof Error ? error.message : String(error)
          }).`,
          matchedPolicyIds: [],
          evaluatedAt: new Date(),
        };
      }
    }

    const context = AttributeContext.create({
      subject: { id: command.subjectId, ...command.subjectAttributes },
      resource: {
        id: command.resourceId,
        ...resolvedResourceAttributes,
        ...command.resourceAttributes,
      },
      action: { name: command.action },
      environment: command.environmentAttributes ?? {},
    });

    const result = await this.authorizationService.authorize({
      subjectId: command.subjectId,
      action: command.action,
      resourceType: command.resourceType,
      context,
    });

    return {
      granted: result.effect === "PERMIT",
      reason: AuthorizeAction.describeReason(result),
      matchedPolicyIds: result.matchedPolicyIds,
      evaluatedAt: new Date(),
    };
  }

  private static describeReason(result: AuthorizationResult): string {
    if (result.effect === "DENY") {
      if (result.abacDecision === "DENY") {
        return `Denied: an applicable policy denies this action (matched: ${result.matchedPolicyIds.join(", ")}).`;
      }
      if (result.rbacDecision === "DENY") {
        return "Denied: role/permission grant denies this action.";
      }
      return "Denied: no role grant or policy permits this action (fail-closed default).";
    }

    if (result.rbacDecision === "PERMIT") {
      return "Granted: role/permission grant permits this action.";
    }
    return `Granted: an applicable policy permits this action (matched: ${result.matchedPolicyIds.join(", ")}).`;
  }
}
