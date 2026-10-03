/**
 * An attribute value a resolver may return. Restricted to JSON-serializable
 * primitives and arrays of them for the same reason `ComparisonLiteral` is
 * (see `domain/value-objects/condition.ts`) — resource attributes ultimately
 * feed comparisons in a `Condition` tree, so their shape has to line up with
 * what a comparison can hold.
 */
export type ResourceAttributeValue = string | number | boolean | readonly (string | number)[];

/** The attributes a resolver fetched for one resource instance (owner, org, sensitivity label, status, ...). */
export type ResourceAttributes = Readonly<Record<string, ResourceAttributeValue>>;

/**
 * The port a bounded context implements to let ABAC policies condition on
 * *its* resources — a `document`'s owner and sensitivity label, a
 * `verificationCase`'s status and org — without `packages/authorization`
 * depending on that context's schema.
 *
 * Per `ARCHITECTURE.md` §4's dependency rules, the relationship is
 * inverted from what you might expect: `packages/verification` (say) would
 * implement this port and register an instance of it with the
 * {@link import("../services/resource-attribute-resolver-registry.js").ResourceAttributeResolverRegistry},
 * rather than `packages/authorization` importing anything from
 * `packages/verification` to look attributes up itself.
 *
 * `resolve` takes only a bare `resourceId` — not a typed reference into the
 * owning context's entities — for the same decoupling reason: this port
 * must not mention any type that lives outside `packages/authorization`.
 */
export interface ResourceAttributeResolver {
  resolve(resourceId: string): Promise<ResourceAttributes>;
}
