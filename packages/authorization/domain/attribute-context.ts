/**
 * Attribute vocabulary shared by every Phase 08 authorization entry point.
 *
 * The engine never reads attributes off entities directly: callers assemble an
 * {@link AttributeContext} from whatever sources they trust (the session, the
 * resource's owning service, the environment) and pass it in. That keeps a
 * policy decision reproducible from its inputs and keeps the domain layer free
 * of provider/network knowledge.
 *
 * The four bags are the categories NIST SP 800-162 uses for ABAC (subject,
 * resource, action, environment). Verixa keeps all four defined from the start
 * even though the composition service in this issue only forwards the context:
 * a condition like `environment.now between ...` is written against this shape,
 * so the shape is the interface the DSL has to target.
 */

/** A flat, provider-supplied attribute bag. Values are `unknown` on purpose: the policy engine is what gives them type meaning. */
export interface AttributeBag {
  readonly [attribute: string]: unknown;
}

/** The subject a decision is being rendered for. */
export interface SubjectRef {
  readonly subjectId: string;
  readonly tenantId: string;
}

/** The resource a decision is being rendered for. */
export interface ResourceRef {
  readonly resourceType: string;
  readonly resourceId?: string;
}

/**
 * Every attribute the evaluation may consult, grouped by the axis it comes from.
 *
 * A missing attribute is deliberately representable: an absent key and a
 * present `undefined` both mean "not resolved", and the condition evaluator
 * treats both as `false` rather than failing open (threat model: attribute
 * provider failure is fail-closed).
 */
export interface AttributeContext {
  /** Attributes of the acting principal — roles held, clearance, organization. */
  readonly subject: AttributeBag;
  /** Attributes of the target — owner, status, sensitivity label. */
  readonly resource: AttributeBag;
  /** Attributes of the operation attempted — `name`, `sensitivity`, `mutates`. */
  readonly action: AttributeBag;
  /** Attributes of the request itself — time, IP, request id. */
  readonly environment: AttributeBag;
}

/** A complete authorization question: who, doing what, to what, with which attributes. */
export interface AuthorizationRequest {
  readonly subject: SubjectRef;
  readonly action: string;
  readonly resource: ResourceRef;
  readonly context?: AttributeContext;
}

/** The attribute context used when a caller supplies none: all four axes empty. */
export function emptyAttributeContext(): AttributeContext {
  return { subject: {}, resource: {}, action: {}, environment: {} };
}
