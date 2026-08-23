# Source Provenance Policy

## 1. Purpose and scope

This policy protects Password Bonobo's original implementation work and records how compatibility research becomes
reviewable, neutral project knowledge.  It applies to Bonobo-authored source, tests, fixtures, documentation,
dependencies, assets, and research records.  It does not grant permission to reuse material owned by another party.

Before commit, every future file must be classified and receive accurate per-file or appropriately bounded REUSE
annotation metadata.  Third-party notices must be preserved and cannot be supplemented with ungranted Bonobo ownership
or licensing claims.

## 2. Allowed authoritative inputs

Product implementation and tests may use these authoritative inputs:

- Approved Bonobo specifications and decisions.
- Official PasswordSafe format documentation and other official format documentation applicable to the work.
- The approved neutral behavior dossier, which describes observable behavior without reproducing implementation text.
- Bonobo synthetic tests and fixtures that passed the intake process in this policy.

These inputs are the handoff boundary for implementation.  A developer must not translate external implementation
material into Bonobo code, tests, comments, identifiers, or document structure.

## 3. External research boundary and read-only checkout rules

Password Gorilla may be studied only in an external, pinned, read-only research checkout outside this repository.
Gorilla source is evidence about behavior, not implementation material for Bonobo.  Researchers may inspect the pinned
checkout for neutral observations, but must not modify it, add Bonobo annotations to it, copy it into this repository,
or include it in a product build.

Research findings enter Bonobo through cited, neutral observations in the compatibility dossier.  Product development
uses the approved Bonobo documents, official format documentation, and synthetic tests rather than the external source.

## 4. Prohibited copying categories

Do not copy or adapt external source, comments, identifiers, file organization, control flow, UI assets, translations,
test fixtures, screenshots, or other copyrightable implementation expression.  Do not quote external source fragments
in product code or compatibility documents.  Upstream vault files remain external research-only and may never enter
tracked fixture paths.

## 5. Evidence citation format

Each compatibility evidence record must identify, in neutral prose:

- Revision: the pinned upstream revision.
- Location: repository-relative path and either a line range or a test name.
- Evidence kind: for example, source inspection, test observation, documentation, or change history.
- Neutral observation: the observable behavior or unresolved question, without copied source text.

Use the cited material only to support the observation.  A citation is not permission to reproduce or implement the
source expression it references.

## 6. Fixture intake

Before a fixture is accepted, record proof that every credential and vault content is synthetic or fabricated, together
with its origin and license.  Approval, license review, and sensitive-data scanning are additional mandatory gates;
none can substitute for synthetic provenance proof.  The intake record must state the reviewer or approving authority
only when that role and decision have been formally defined; it must not invent one.  Real, personal, or upstream vault
files and fixtures containing real credentials, tokens, or provider metadata are prohibited from tracked fixture paths.

## 7. Dependency and asset ledger

Every dependency and nontrivial asset must have a ledger entry before use.  The entry must identify its origin, version
or immutable revision, license or terms, intended use, distribution implications, provenance evidence, and required
review status.  The ledger must flag dependencies and assets that are incompatible with an iOS distribution decision or
with the project's no-copy boundary.

The canonical [dependency and asset provenance ledger](dependency-asset-provenance-ledger.md) covers resolved and
declared Python packages, GitHub Actions, document tools, and tracked repository assets.  Run
`uv run python -m tools.check_provenance` after any dependency declaration, lock, action pin, document tool, or asset
change; a passing freshness check records coverage, not legal approval for a row whose review remains pending.

## 8. Upstream revision updates

Updating an external research revision requires a separate review, a newly pinned immutable revision, a provenance
entry, and a neutral dossier delta.  Keep the checkout external and read-only throughout the update.  Do not replace an
existing observation merely because a later upstream revision differs; record the scope of the revised evidence and
revisit affected compatibility claims.

## 9. Suspected copied-expression incident response

If copied expression is suspected, stop distributing and modifying the affected material, preserve the relevant
provenance records, and restrict discussion to information safe to share.  Escalate the concern to the repository owner
for review.  Do not resolve the incident by rewriting history, deleting evidence, or publishing the suspected material.
Resume work only after the affected material, evidence, and required corrective action have been reviewed.
