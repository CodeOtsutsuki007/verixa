# Tutorial: Building Production-Grade Session Management

This guide walks through how Verixa implements authentication sessions in Phase 05 (`packages/sessions`). Instead of relying on a black-box library, we build the core primitives—JWT access tokens, opaque refresh tokens, Redis-backed revocation, and reuse detection—from scratch.

The goal isn't just to write code, but to understand _why_ these specific patterns exist and the security tradeoffs they represent.

## 1. The Stateful vs. Stateless Dilemma

When designing an API authentication system, the first question is always where to store session state.

### The Stateful Approach (Database/Redis Sessions)

You generate a random session ID, store it in a database or Redis, and send it to the client as a cookie. On every request, the server looks up the ID to verify the session is active and fetch the user's details.

**The tradeoff:** This provides immediate revocation—if you delete the session from Redis, the user is instantly logged out. The downside is latency and load: every API request requires a database round-trip before it can even begin processing the business logic.

### The Stateless Approach (JWTs)

You issue a JSON Web Token (JWT) containing the user's ID and sign it with a secret key. When the client sends the JWT, the server verifies the signature computationally without talking to a database.

**The tradeoff:** This is fast and infinitely scalable, but **stateless tokens cannot be revoked**. If a JWT is valid for an hour, and an administrator suspends the user ten minutes in, that JWT remains mathematically valid for another 50 minutes.

### The Verixa Solution: Short-Lived Access, Stateful Refresh

We combine both approaches to get the best of both worlds:

1. **Access Tokens (JWTs):** Issued for a very short duration (e.g., 5-15 minutes). They are verified statelessly by the API gateway or services.
2. **Refresh Tokens (Opaque Strings):** Issued with a longer duration (e.g., 30 days) and stored in the database. When the access token expires, the client uses the refresh token to get a new one.

This means revocation (like a password reset or manual logout) takes effect within minutes (when the current access token expires), rather than days, without paying the database tax on every single request.

## 2. JWT Access Tokens: RS256 over HS256

Verixa uses **asymmetric signatures (RS256/ES256)** instead of symmetric ones (HS256) for JWTs.

With HS256, the same secret key is used to both create and verify the token. This means any service that needs to verify a user's identity must hold the secret that can also _forge_ identities.

With RS256, the central identity provider (our `TokenSigner` port) holds the **private key** and signs the token. The API gateway and downstream microservices only hold the **public key**. They can verify the token is legitimate, but a breach in a downstream service doesn't give the attacker the ability to mint new tokens.

_Reference: See `JwtTokenSigner` in `packages/sessions/infrastructure/jwt-token-signer.ts`._

## 3. Refresh Token Rotation

When a client uses a refresh token to get a new access token, what happens to the old refresh token?

A common mistake is to let the refresh token live forever. If an attacker steals it, they can silently mint access tokens indefinitely.

To solve this, Verixa implements **Refresh Token Rotation**:

- Every time a refresh token is used, it is invalidated.
- The server issues a brand-new refresh token alongside the new access token.

This limits the lifespan of a stolen token, but introduces a new problem: what if the network drops the response? The client never receives the new token, but the server has already invalidated the old one, logging the user out accidentally.

## 4. Token Theft Detection (Token Families)

To make rotation robust against network failures and active attackers, we implement **Token Families** and **Reuse Detection**.

Every refresh token belongs to a "family" (representing a single logical login session on a specific device).
When a refresh token is used, we mark it as `revoked` but keep it in the database.

If someone attempts to use a `revoked` refresh token, we know one of two things happened:

1. The client is retrying a dropped request.
2. An attacker stole the token and is trying to use it.

Because we cannot distinguish between the two, we take the safest route: **we revoke the entire token family**. If an attacker uses a stolen token, they instantly terminate the victim's session. The victim will have to log in again, but the attacker loses their access.

_Reference: See `RefreshTokenReuseDetected` in `packages/sessions/domain/events/refresh-token-reuse-detected.ts` and the `RefreshAccessToken` use case._

## 5. Explicit Revocation (The Redis Deny-List)

While waiting 15 minutes for an access token to expire is acceptable for normal operations, certain security events demand **instant** revocation:

- A user changes their password.
- An administrator disables an account.
- The user clicks "Log out everywhere".

For these scenarios, we use a Redis-backed `RevocationList`. When a session is explicitly revoked, its unique ID (`jti` claim in the JWT) is added to Redis with a TTL matching the remainder of the JWT's lifespan.

The API gateway checks this Redis list before accepting a JWT. This reintroduces a small stateful check, but Redis lookups are sub-millisecond, and we only store revoked tokens, keeping the dataset tiny.

_Reference: See `RedisRevocationList` in `packages/sessions/infrastructure/redis-revocation-list.ts` and the `LogoutEverywhere` use case._

## Summary

By carefully combining stateless JWTs, stateful refresh tokens, rigorous rotation, and a fast deny-list, we build a session architecture that is highly scalable under normal load but immediately responsive to security threats.
