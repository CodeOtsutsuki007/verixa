/**
 * The outcome a matching {@link Rule} contributes to a decision.
 *
 * A closed two-value set rather than a boolean, because a rule that doesn't
 * match is a third state (`NOT_APPLICABLE`, see `combining-algorithms.ts` in
 * a later issue) distinct from both — collapsing that into `boolean` would
 * make "this rule denies" and "this rule doesn't apply" indistinguishable at
 * the type level, which is exactly the ambiguity XACML's PERMIT/DENY/
 * NOT_APPLICABLE split exists to avoid.
 */
export type Effect = "PERMIT" | "DENY";
