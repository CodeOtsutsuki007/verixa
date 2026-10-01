import type {
  ResourceAttributeResolver,
  ResourceAttributes,
} from "../ports/resource-attribute-resolver.js";

/**
 * Thrown when {@link ResourceAttributeResolverRegistry.resolve} is asked to
 * resolve a resource type nothing has registered a resolver for.
 *
 * A distinct, named error rather than returning `undefined` silently — per
 * Issue 151's acceptance criteria — because a missing resolver here is a
 * wiring bug (a context added a new resource type to policy targets without
 * registering how to fetch its attributes), and a policy silently evaluating
 * against an empty attribute set instead of failing loudly is exactly the
 * kind of "correct code implementing an incorrect policy" risk
 * `docs/security/threat-model-abac.md` (Issue 159) will need to call out.
 */
export class UnknownResourceTypeError extends Error {
  readonly resourceType: string;

  constructor(resourceType: string) {
    super(`No resource-attribute resolver is registered for resource type "${resourceType}".`);
    this.name = "UnknownResourceTypeError";
    this.resourceType = resourceType;
  }
}

/**
 * Maps resource types (`"document"`, `"verificationCase"`, ...) to the
 * {@link ResourceAttributeResolver} that knows how to fetch that resource's
 * attributes from its own bounded context.
 *
 * This is the seam described in `ARCHITECTURE.md` §4: other contexts
 * register a resolver with this registry (typically from their own
 * composition-root wiring, Issue 157), and `packages/authorization` never
 * imports anything from those contexts to do the lookup itself. Registering
 * a resolver for a new resource type is therefore a one-line addition at the
 * registration call site — it requires no change here or in the evaluation
 * engine, which is Issue 151's acceptance criterion.
 */
export class ResourceAttributeResolverRegistry {
  private readonly resolversByResourceType = new Map<string, ResourceAttributeResolver>();

  /**
   * Registers `resolver` for `resourceType`, replacing any resolver already
   * registered for it. Overwriting rather than throwing on a duplicate
   * registration is deliberate: composition-root wiring (Issue 157) runs
   * once at process startup in a fixed, known order, so a second
   * registration for the same resource type is far more likely to be an
   * intentional override (e.g. test setup replacing a real resolver with a
   * fake) than a bug worth failing startup over.
   */
  register(resourceType: string, resolver: ResourceAttributeResolver): void {
    this.resolversByResourceType.set(resourceType, resolver);
  }

  /** Whether a resolver is currently registered for `resourceType`. */
  has(resourceType: string): boolean {
    return this.resolversByResourceType.has(resourceType);
  }

  /**
   * Resolves `resourceId`'s attributes using the resolver registered for
   * `resourceType`.
   *
   * @throws {UnknownResourceTypeError} if no resolver is registered for
   * `resourceType`.
   */
  async resolve(resourceType: string, resourceId: string): Promise<ResourceAttributes> {
    const resolver = this.resolversByResourceType.get(resourceType);
    if (resolver === undefined) {
      throw new UnknownResourceTypeError(resourceType);
    }
    return resolver.resolve(resourceId);
  }
}
