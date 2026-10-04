import type { PolicyRepository } from "../../application/ports/policy-repository.js";
import type { Policy, PolicyId } from "../../domain/entities/policy.js";

/**
 * An in-memory fake satisfying {@link PolicyRepository}, following the
 * Issue 031 pattern: lets policy-dependent use cases (Issue 153) be written
 * and tested before a real, database-backed adapter (Issue 150) exists.
 *
 * Versions are stored keyed by policy id, each id mapping to the ordered
 * list of every version ever saved for it — mirroring the append-only
 * history the port's contract requires a real adapter to maintain.
 */
export class InMemoryPolicyRepository implements PolicyRepository {
  private readonly versionsById = new Map<PolicyId, Policy[]>();

  save(policy: Policy): Promise<void> {
    const versions = this.versionsById.get(policy.id) ?? [];
    const alreadySaved = versions.some((existing) => existing.version === policy.version);
    if (!alreadySaved) {
      versions.push(policy);
      versions.sort((a, b) => a.version - b.version);
      this.versionsById.set(policy.id, versions);
    }
    return Promise.resolve();
  }

  findById(id: PolicyId): Promise<Policy | undefined> {
    const versions = this.versionsById.get(id);
    return Promise.resolve(versions?.at(-1));
  }

  findApplicableTo(resourceType: string, action: string): Promise<Policy[]> {
    const latestVersions = Array.from(this.versionsById.values())
      .map((versions) => versions.at(-1))
      .filter((policy): policy is Policy => policy !== undefined);

    const applicable = latestVersions.filter(
      (policy) =>
        policy.status === "published" &&
        policy.target.resourceType === resourceType &&
        policy.target.actions.includes(action),
    );

    return Promise.resolve(applicable);
  }

  listVersionsFor(policyId: PolicyId): Promise<Policy[]> {
    return Promise.resolve([...(this.versionsById.get(policyId) ?? [])]);
  }
}
