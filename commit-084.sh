#!/bin/bash
cd "c:\Users\Nuelthewave\Desktop\Kayvera PR\verixa"
git add -A
git commit -m "feat(084): JWT access token design & signing service

- Add AccessTokenClaims interface with claims: sub, sid, orgId, iat, exp, kid
- Create TokenSigner port with sign() and verify() methods
- Implement JwtTokenSigner using RS256 (jose library) for asymmetric signing
- Add custom error types: InvalidSignatureError, ExpiredTokenError, MalformedTokenError
- Include comprehensive unit tests for sign/verify round-trip, tamper detection, expiry
- Add token-design.md security documentation with threat model
- Update packages/sessions/package.json to add jose@^5.9.6 dependency

Resolves Issue 084 (Phase 05 - Sessions & Tokens)"
