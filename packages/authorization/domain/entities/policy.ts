import { createId, type Id, Result, ValidationError } from "@verixa/shared-kernel";

import type { Rule } from "../value-objects/rule.js";

export type PolicyId = Id<"PolicyId">;
export type PolicyStatus = "draft" | "published" | "archived";

/**
 * Which resource type and actions a {@link Policy} applies to.
 *
 * Kept as a plain selector rather than a `Condition` itself: "does this
 * policy even apply here" (a cheap lookup key used by
 * `findApplicableTo(resourceType, action)`, Issue 149) is a different
 * question from "does it grant or deny" (the rule tree's job), and folding
 * them together would force every applicability check through full
 * condition evaluation.
 */
export interface PolicyTarget {
  readonly resourceType: string;
  readonly actions: readonly string[];
}

interface PolicyProps {
  readonly id: PolicyId;
  readonly name: string;
  readonly target: PolicyTarget;
  readonly rules: readonly Rule[];
  readonly version: number;
  readonly createdAt: Date;
  readonly status: PolicyStatus;
  readonly dslSource: string | undefined;
}

/**
 * The aggregate root of the ABAC model: a named, versioned set of
 * {@link Rule}s scoped to a {@link PolicyTarget}.
 *
 * Immutable, like `User` and `AuditLogEntry` before it (see
 * `docs/guides/domain-modeling.md`) — there is no method that mutates a
 * `Policy` in place. Publishing a new version (Issue 150) means creating a
 * *new* `Policy` instance with `version` incremented, never editing an
 * existing one, which is what makes append-only version history
 * (Issue 150's acceptance criterion) a property of how the aggregate is
 * used rather than something the persistence layer has to enforce on top of
 * a mutable model.
 */
export class Policy {
  readonly id: PolicyId;
  readonly name: string;
  readonly target: PolicyTarget;
  readonly rules: readonly Rule[];
  readonly version: number;
  readonly createdAt: Date;
  readonly status: PolicyStatus;
  readonly dslSource: string | undefined;

  private constructor(props: PolicyProps) {
    this.id = props.id;
    this.name = props.name;
    this.target = props.target;
    this.rules = props.rules;
    this.version = props.version;
    this.createdAt = props.createdAt;
    this.status = props.status;
    this.dslSource = props.dslSource;
  }

  /**
   * Creates version 1 of a brand-new policy.
   *
   * Validates the invariants a later DSL parser (Issue 143) and repository
   * (Issue 150) both need to be able to rely on already holding: a policy
   * with no rules can never produce a decision, and a nameless policy is
   * unidentifiable in an audit trail or an admin UI — both are input
   * mistakes an author can make, not aggregate-internal bugs, so they come
   * back as a `Result` rather than throwing (see `docs/guides/error-handling.md`).
   */
  static create(params: {
    name: string;
    target: PolicyTarget;
    rules: readonly Rule[];
    status?: PolicyStatus;
    dslSource?: string;
  }): Result<Policy, ValidationError> {
    const fieldErrors: Record<string, string[]> = {};

    if (params.name.trim().length === 0) {
      fieldErrors.name = ["required"];
    }
    if (params.rules.length === 0) {
      fieldErrors.rules = ["at_least_one_rule_required"];
    }
    if (params.target.actions.length === 0) {
      fieldErrors.target = ["at_least_one_action_required"];
    }

    if (Object.keys(fieldErrors).length > 0) {
      return Result.err(new ValidationError("Policy is invalid.", fieldErrors));
    }

    return Result.ok(
      new Policy({
        id: createId<"PolicyId">(),
        name: params.name,
        target: params.target,
        rules: Object.freeze([...params.rules]),
        version: 1,
        createdAt: new Date(),
        status: params.status ?? "published",
        dslSource: params.dslSource,
      }),
    );
  }

  /**
   * Rebuilds a `Policy` from already-trusted data (a database row, once
   * Issue 150 lands). Skips {@link create}'s validation for the same reason
   * `User.reconstitute` does — the data already represents a previously
   * valid state, so re-validating it as if it were new authoring input would
   * be redundant.
   */
  static reconstitute(props: PolicyProps): Policy {
    return new Policy(props);
  }

  /**
   * Produces the next version of this policy with a new rule set, leaving
   * this instance (and therefore every prior version already persisted)
   * unchanged. `name` and `target` carry over — republishing under a new
   * name or against a different target is a new policy, not a new version
   * of this one.
   */
  publishNewVersion(
    rules: readonly Rule[],
    dslSource: string | undefined = this.dslSource,
  ): Result<Policy, ValidationError> {
    if (rules.length === 0) {
      return Result.err(
        new ValidationError("Policy is invalid.", { rules: ["at_least_one_rule_required"] }),
      );
    }

    return Result.ok(
      new Policy({
        ...this,
        rules: Object.freeze([...rules]),
        version: this.version + 1,
        createdAt: new Date(),
        status: "published",
        dslSource,
      }),
    );
  }
}
