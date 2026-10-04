import { asId, createId, type Id } from "@verixa/shared-kernel";

/**
 * The identifier of a single authenticated session.
 *
 * A session is the thing a login *creates* and a logout *destroys*: one
 * device, one sign-in, one lifetime. Access tokens carry this id in their
 * `sid` claim (Issue 084) and the revocation deny-list (Issue 088) is keyed
 * by it, so revoking a session and rejecting its still-unexpired access tokens
 * are the same operation addressed by the same id.
 *
 * The full `Session` aggregate — expiry policy, `lastSeenAt`, device metadata —
 * arrives with Issue 081. This id is split out ahead of it because the two
 * pieces of infrastructure that land first (the token signer and the deny-list)
 * both need to *name* a session without yet needing the whole entity. Branding
 * the id (rather than passing a bare `string`) is what stops a `UserId` or a
 * raw request parameter being handed to `revoke()` by mistake — the compiler
 * refuses it, so the guarantee costs nothing at runtime.
 */
export type SessionId = Id<"SessionId">;

/** Generates a new random {@link SessionId}. */
export function createSessionId(): SessionId {
  return createId<"SessionId">();
}

/**
 * Brands a session id string that already came from a trusted source — a
 * token's verified `sid` claim, or a row read back from the session store.
 * Performs no format validation; never call it on untrusted input.
 */
export function asSessionId(value: string): SessionId {
  return asId<"SessionId">(value);
}
