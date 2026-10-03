#!/bin/bash
set -e

cd "c:\Users\Nuelthewave\Desktop\Kayvera PR\verixa"

git add .

git commit -m "feat(084): JWT access token design & signing service

- Add TokenSigner port (packages/sessions/application/ports/token-signer.ts) with careful contract documentation covering sign/verify guarantees, error handling, and claim set design
- Define AccessTokenClaims with sub, sid, orgId, iat, exp, kid claims — minimal set for stateless verification without stale authorization data
- Implement JwtTokenSigner using RS256 (asymmetric) with jose library for node crypto compatibility
- Add custom error types (InvalidSignatureError, ExpiredTokenError, MalformedTokenError, SigningError) for precise error handling
- Include comprehensive unit tests covering: sign/verify round-trip, tamper detection (payload & signature), expiry rejection, malformed token handling, key caching, concurrent operations
- Add token-design.md security documentation covering: design rationale, RS256 vs HS256 tradeoff for multi-service verification, threat model with mitigations, key rotation strategy
- Update packages/sessions/package.json to add jose@^5.9.6 dependency

Resolves GitHub issue #24 (Roadmap 084)"

git push -u origin feat/084-jwt-access-token-signer

echo "✓ Commit and push complete for Issue 084"
