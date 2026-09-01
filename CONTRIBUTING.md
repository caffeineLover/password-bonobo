# Contributing to Password Bonobo

## Current status

External contributions are not yet accepted.  The project must first settle the rights needed for a potential iOS
distribution exception while preserving GPL-3.0-or-later licensing for Bonobo-authored code.

Do not open pull requests or submit patches for inclusion until this status changes.  This is a temporary hold, not a
request for contributor permissions or an assertion that any exception has been approved.

## Deliberately changing this status

The repository owner will change this policy only after the distribution-exception decision is documented, the required
contributor terms are established, and the relevant legal and dependency reviews are complete.  A future update to this
file will state the accepted contribution process and the terms that apply before external submissions are accepted.

## Research boundary

The source-provenance policy applies to all future work.  In particular, Gorilla source and other copyrightable
implementation material must not be copied into this repository or submitted as a contribution.  See
[`docs/legal/source-provenance-policy.md`](docs/legal/source-provenance-policy.md).

## Maintainer validation

Maintainers working under the current closed-contribution policy must follow the exact environment, Botan, and example
commands in the [lossless core operations guide](docs/guides/lossless-passwordsafe-core.md) and the complete validation
sequence in the [README development section](README.md#development). The release gate includes `src`, `tests`, `tools`,
and `examples`; it must use the locked dependency graph and an explicitly qualified host Botan library. Never use real
credentials or a personal PasswordSafe database as development evidence.
