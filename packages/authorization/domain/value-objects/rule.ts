import { Condition } from "./condition.js";
import type { Effect } from "./effect.js";

interface RuleProps {
  readonly effect: Effect;
  readonly condition: Condition;
  readonly description: string | undefined;
}

/**
 * One `if <condition> then <effect>` clause inside a {@link Policy}.
 *
 * Immutable value object (no identity of its own — two rules with the same
 * effect and condition are the same rule) constructed only through
 * {@link Rule.create}, which is the single place the "must have a condition"
 * invariant is enforced. There is no `reconstitute`: unlike an aggregate
 * such as `Policy`, a `Rule` has no independent existence a repository would
 * load on its own — it only ever arrives already embedded in a `Policy`,
 * which reconstitutes itself and its rules together in one factory.
 */
export class Rule {
  readonly effect: Effect;
  readonly condition: Condition;
  readonly description: string | undefined;

  private constructor(props: RuleProps) {
    this.effect = props.effect;
    this.condition = props.condition;
    this.description = props.description;
  }

  /**
   * Every acceptance criterion for Issue 141 requires a rule to carry a
   * condition — "at least one condition or an explicit 'always' marker" — so
   * `condition` is required here, not optional. Pass
   * {@link Condition.always} for a rule meant to match unconditionally
   * (e.g. a catch-all `DENY` at the end of a policy); there is deliberately
   * no way to construct a `Rule` with `condition: undefined`, which is what
   * makes "always" an explicit choice rather than an accidental omission.
   */
  static create(params: {
    effect: Effect;
    condition: Condition;
    description?: string | undefined;
  }): Rule {
    return new Rule({
      effect: params.effect,
      condition: params.condition,
      description: params.description,
    });
  }

  /** Structural equality: same effect and same condition tree, regardless of `description`. */
  equals(other: Rule): boolean {
    return this.effect === other.effect && Condition.equals(this.condition, other.condition);
  }
}
