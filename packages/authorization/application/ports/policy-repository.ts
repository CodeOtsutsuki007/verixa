import type { Policy, PolicyId } from "../../domain/entities/policy.js";

/**
 * The persistence contract the application layer needs for {@link Policy} —
 * the **port** half of ports & adapters (see
 * `packages/identity/application/ports/user-repository.ts` for the pattern
 * this follows, and `docs/guides/domain-modeling.md` for the rationale). No
 * Prisma, SQL, or any other implementation detail appears here; the
 * concrete adapter (Issue 150, Prisma-backed) implements this interface
 * without this package ever depending on it.
 *
 * Method contracts:
 *
 * - `save` persists exactly the `Policy` instance it is given, at whatever
 *   version that instance carries. Unlike `UserRepository.save`, this is
 *   **not** a create-or-update-in-place upsert: `Policy` is immutable and
 *   `publishNewVersion` always produces a brand-new instance rather than
 *   mutating an existing one (see `policy.ts`), so every `save` call adds a
 *   version rather than replacing one. Saving the exact same `(id,
 *   version)` pair twice is idempotent — it must not create a duplicate
 *   history entry — but saving is otherwise append-only: there is
 *   deliberately no `delete` or `update` here, because rewriting or
 *   discarding a published version is exactly what Issue 150's "append-only
 *   history" requirement forbids.
 *
 * - `findById` returns the **latest** version of the policy with that id,
 *   or `undefined` if no policy with that id has ever been saved. Callers
 *   that need a specific historical version, or the full history, use
 *   {@link listVersionsFor} instead.
 *
 * - `findApplicableTo` returns the latest version of every policy whose
 *   {@link import("../../domain/entities/policy.js").PolicyTarget} matches
 *   the given resource type and includes the given action. This is the
 *   lookup the evaluation engine (Issue 146) and `AuthorizationService`
 *   (Issue 152) use at request time, so it must stay a cheap, targeted
 *   query rather than "load everything and filter in the application
 *   layer" once a real adapter is backing it.
 *
 * - `listVersionsFor` returns every version ever saved for a given policy
 *   id, ordered by `version` ascending (oldest first) — the append-only
 *   version history Issue 150 persists durably. Returns an empty array,
 *   never `undefined`, when the id is unknown: "no history" and "unknown
 *   id" are the same observable fact from this method's point of view, and
 *   an empty list is a normal case for its caller to iterate over without
 *   an extra existence check.
 */
export interface PolicyRepository {
  save(policy: Policy): Promise<void>;
  findById(id: PolicyId): Promise<Policy | undefined>;
  findApplicableTo(resourceType: string, action: string): Promise<Policy[]>;
  listVersionsFor(policyId: PolicyId): Promise<Policy[]>;
}
