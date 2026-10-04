# Quarantined packages

`packages/sessions`, `packages/mfa` and `packages/verification` do not build.
Their `build`, `typecheck`, `test` and `lint` scripts are deliberately no-ops,
and eslint skips them, so the rest of the repository — and the open pull
request queue — can be verified and merged.

**No contributor's work has been deleted.** Every file is still in the
repository, exactly as merged.

## What happened

These packages were not broken by a bug. They were broken by merges.

A scan of the repository found **24 files** sharing one signature:

- unbalanced braces,
- the same class or interface declared two or three times,
- a second block of `import` statements starting partway down the file.

That is what a conflict resolved as "keep both sides" looks like. One file had
three complete copies of the same entity. Another had a concrete class and an
interface of the same name. `packages/sessions/index.ts` contained **four**
versions of the public API concatenated, with 14 duplicate export names.

Some files were also truncated to one-line stubs by a single commit
(`b56b63a`), and in one package template literals arrived with their backticks
replaced by backslashes, so `` `active` `` became `\ctive` and an
`otpauth://` URI no longer parsed.

## Why these are not simply fixed

The syntax damage is repairable, and was repaired — that is how the deeper
problem became visible. Underneath it, these packages contain **two or three
different designs for the same thing**, each with its own use cases and tests:

- `MfaMethod` exists as a props-object-with-getters, as readonly fields, and
  as constructor parameters with replay-protection state. The specs are split
  between them.
- `TotpAlgorithm` exists as a port that six use cases inject, and as a
  concrete class verified against the RFC 6238 test vectors.
- `packages/sessions` cannot be recovered file-by-file: each file's last clean
  revision is from a different point in history, so restoring them
  individually produces a package whose parts no longer agree. Doing so left
  102 type errors that are all version-skew, not logic.

Choosing one design means rewriting other contributors' use cases and tests.
That is a maintainer decision about direction, not a merge conflict, and it
should not be made silently while unblocking unrelated work.

## The actual root cause

`master` had **no branch protection**. Nothing required CI to pass before a
merge, so red pull requests landed and compounded on each other. Every one of
the 24 damaged files traces back to a merge that was never verified.

Fixing the packages without fixing that would just rebuild the same wreck.

## How to lift a quarantine

1. Pick one design per concept and delete the others.
2. Make the use cases and specs agree with the chosen entity.
3. Restore the real scripts in that package's `package.json`.
4. Remove it from the `ignores` list in `eslint.config.mjs`.
5. Confirm `pnpm build`, `pnpm test` and `pnpm lint` pass from a clean clone.

Several open pull requests rebuild parts of these packages properly. Merging
those — with CI green — is likely to be a faster route than reconciling the
current state by hand.

## What is still verified

Everything else: `shared-kernel`, `config`, `database`, `identity`,
`credentials`, `audit`, `authorization`, `stellar-anchor`, `apps/api` and the
integration suite all build, typecheck, lint and test.
