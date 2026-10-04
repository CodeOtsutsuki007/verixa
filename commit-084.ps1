#!/usr/bin/env pwsh
$dir = "c:\Users\Nuelthewave\Desktop\Kayvera PR\verixa"
Set-Location -LiteralPath $dir

& git add .

$commitMessage = @"
feat(084): JWT access token design & signing service

- Add TokenSigner port with careful contract documentation
- Define AccessTokenClaims with sub, sid, orgId, iat, exp, kid
- Implement JwtTokenSigner using RS256 (asymmetric) with jose
- Add custom error types (InvalidSignatureError, ExpiredTokenError, MalformedTokenError, SigningError)
- Include comprehensive unit tests for sign/verify, tamper detection, expiry, key caching
- Add token-design.md security documentation covering RS256 vs HS256 tradeoff
- Update packages/sessions/package.json to add jose@^5.9.6

Resolves GitHub issue #24 (Roadmap 084)
"@

& git commit -m $commitMessage
& git push -u origin feat/084-jwt-access-token-signer

Write-Host "✓ Issue 084 committed and pushed"
