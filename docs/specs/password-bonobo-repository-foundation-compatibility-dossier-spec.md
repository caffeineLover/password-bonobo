# Password Bonobo Repository Foundation and Compatibility Dossier Specification

Date: 2026-08-22

Status: Approved program design; implementation plan pending execution

Parent design: [Password Bonobo Python Reimplementation](./password-bonobo-python-reimplementation-design.md)

## 1. Purpose

This subproject establishes the Password Bonobo repository, its enforceable engineering policy, and a neutral
compatibility record for the selected Password Gorilla baseline.  It creates the boundary that later subprojects will
use to implement original Python code without consulting or translating Gorilla source during product development.

This subproject produces infrastructure, documentation, and an empty typed Python package boundary.  It does not
implement PasswordSafe parsing, vault behavior, URL auditing, synchronization, or a user interface.

## 2. Required Outcomes

The subproject is complete when it has:

1. Established a Git repository with an intentional tracked-file boundary and a reviewable commit history.
2. Defined the GPL-3.0-or-later project license and documented the unresolved iOS distribution-exception work.
3. Configured Python 3.14, strict typing, formatting, linting, tests, security checks, license checks, and continuous
   integration.
4. Enforced the project-specific Python source documentation and spacing rules.
5. Preserved a selected Gorilla revision in an untouched checkout outside the Bonobo repository.
6. Recorded the upstream URL, exact commit, retrieval instructions, observed license, and source-analysis boundary.
7. Produced a neutral behavior dossier, feature-parity matrix, and executable test-oracle catalog.
8. Created durable project memory that records decisions, status, verification evidence, and the next approved work.
9. Demonstrated that generated documentation is reproducible and that generated PDFs remain uncommitted.

## 3. Repository Boundary

The repository root is the current `Password Bonobo` workspace.  The initial tracked set will include:

- Root policy and contributor documents.
- Repository configuration and quality-tool configuration.
- Bonobo-authored specifications, plans, compatibility documents, and project memory.
- The empty `bonobo_core` package boundary and its foundation tests.
- Cross-platform validation tools owned by Bonobo.
- Continuous-integration workflows.

The initial tracked set will exclude:

- The locally mirrored shared standards under `docs/prompts/`.
- Generated PDFs and temporary render files.
- Logs, caches, local environments, build outputs, and editor state.
- PasswordSafe databases except explicitly allowlisted synthetic fixtures added by a later subproject.
- The Gorilla checkout and every other upstream source tree.
- Real credentials, tokens, personal vaults, or provider metadata.

The repository will use `main` as its primary branch.  Foundation work will occur on
`foundation/compatibility-dossier` after the initial baseline commit.

## 4. Upstream Gorilla Baseline

The selected compatibility reference is:

- Repository: `https://github.com/zdia/gorilla.git`
- Branch observed: `master`
- Commit: `6728e85c05ac25357b8f19f541487b9d26a97402`
- Observation date: 2026-08-22
- Declared license observed in the upstream README: GPL-2.0-or-later

The default research location will be the sibling directory
`../Password Bonobo Research/gorilla`.  An operator may choose another location outside the Bonobo repository, but the
recorded commit and verification procedure do not change.

The checkout will be detached at the selected commit and treated as read-only.  Updating the reference requires a
separate review, a new pinned commit, a dossier delta, and an explicit provenance entry.

## 5. Source-Analysis Boundary

Gorilla source is evidence about behavior, not implementation material for Bonobo.

The research pass may inspect:

- `sources/gorilla.tcl` for application workflows and user-visible behavior.
- `sources/pwsafe/*.tcl` for supported data concepts and compatibility behavior.
- `sources/help.txt`, message catalogs, and upstream README material for user-facing contracts.
- `unit-tests/**/*.test` and `unit-tests/**/*.tcl` for behavioral examples and edge cases.
- Upstream change history for compatibility-relevant corrections.

The research pass must not:

- Modify the Gorilla checkout.
- Copy source, comments, identifiers, file organization, control flow, UI assets, or translations into Bonobo.
- Import upstream `.psafe3` files as Bonobo fixtures without a separate provenance and sensitive-data review.
- Add Python type hints or Bonobo comments to Tcl files.
- Cite source fragments in product code.
- Treat the absence of an upstream test as proof that a behavior is unsupported.

The dossier will express behavior in neutral domain language.  It may cite an upstream path and line range as evidence,
but it will not reproduce source text.  Later product implementation will work from the approved Bonobo specifications,
the PasswordSafe format specification, the dossier, and synthetic tests.

## 6. Compatibility Deliverables

### 6.1 Upstream baseline record

`docs/compatibility/gorilla/upstream-baseline.md` will record the selected revision, retrieval and verification
commands, license observation, external checkout rule, evidence conventions, and update procedure.

### 6.2 Behavior dossier

`docs/compatibility/gorilla/behavior-dossier.md` will describe:

- Vault creation, opening, authentication, saving, closing, locking, and recovery behavior.
- Entry creation, editing, deletion, protection, history, aliases, and shortcuts.
- Groups, tree operations, search, filtering, and selection behavior.
- Password generation and policy behavior.
- Clipboard, browser launch, and AutoType behavior.
- Import, export, merge, backup, preference, and recent-file behavior.
- PasswordSafe version handling and user-authored metadata behavior.
- Errors, confirmations, destructive-action protections, and observable edge cases.
- Platform-specific behavior and known limitations.

Each behavioral statement will carry an evidence identifier.  Evidence records will include the upstream revision,
relative source or test path, line range or test name, evidence kind, and a neutral observation.  No copied code will be
included.

### 6.3 Feature-parity matrix

`docs/compatibility/gorilla/feature-parity-matrix.md` will use these statuses:

- `Required`: meaningful Gorilla compatibility required for stable Bonobo.
- `Modernized`: the behavior is required but its interaction design will change.
- `Deferred`: accepted for a named later Bonobo subproject.
- `Excluded`: intentionally unsupported with an approved rationale.
- `Bonobo extension`: behavior added by Bonobo rather than inherited from Gorilla.
- `Unverified`: evidence is insufficient and additional research is required.

Every row will identify its dossier evidence, Bonobo owner subproject, intended platforms, data-loss relevance, security
relevance, and acceptance-test identifier.

### 6.4 Test-oracle catalog

`docs/compatibility/gorilla/test-oracles.md` will define black-box scenarios using synthetic data.  Each scenario will
state setup, action, observable result, cleanup, supported evidence, and whether the result must be confirmed against
Gorilla, Password Safe, or both.

The catalog will distinguish:

- Normative PasswordSafe requirements.
- Observed Gorilla compatibility behavior.
- Bonobo product decisions.
- Unresolved questions that block a compatibility claim.

## 7. Python Foundation

The repository will target CPython `>=3.14,<3.15` for the first development baseline.  A version-floor change requires
platform and dependency review because the same core is intended for desktop, Android, and iOS.

The initial package boundary will be `src/bonobo_core/`.  It will contain no vault implementation in this subproject.
The package will be marked typed and expose only version metadata.

The project will use:

- Hatchling as the Python build backend.
- `uv` for Python installation, dependency locking, and reproducible command execution.
- autopep8 as the formatter, configured to preserve required three-blank-line spacing.
- Ruff as the linter and import-order checker.
- mypy in strict mode as the required static type checker.
- pytest and coverage for tests.
- Bandit and pip-audit for source and dependency security checks.
- REUSE tooling for machine-checkable license metadata.

A repository test will enforce the required module docstrings, `####` declaration blocks, decorator placement, and
three-blank-line separation for maintained Python files.  Tool configuration must not silently override those rules.

## 8. Continuous Integration

The foundation workflow will run on Windows, macOS, and Linux with Python 3.14.  Each job will:

1. Check out the Bonobo repository without any Gorilla source.
2. Install the pinned Python toolchain from the lock file.
3. Check formatting.
4. Run Ruff and strict mypy.
5. Run pytest with coverage.
6. Run the Python structure-policy test.
7. Run Bandit, pip-audit, and REUSE checks.
8. Verify that forbidden file types and likely credential artifacts are absent from tracked files.
9. Build the Python wheel and source distribution.

The workflow must not clone Gorilla, contact password providers, or require secrets.

## 9. Licensing and Contributions

Bonobo-authored code will use SPDX identifier `GPL-3.0-or-later`.  The repository will contain the complete
corresponding license text and machine-readable REUSE metadata.

The App Store distribution exception is not finalized by this subproject.  The repository will document its purpose,
scope constraints, dependency implications, and required legal review.  It will not publish provisional exception text
as if it were approved.

External contributions will remain disabled until the contribution terms can preserve both GPL-3.0-or-later licensing
and the ability to publish an approved distribution exception for Bonobo-authored iOS code.

## 10. Project Memory

Durable memory will record:

- The approved program and subproject specifications.
- The pinned Gorilla revision and source boundary.
- Toolchain and repository decisions with rationale.
- Current subproject status and verification evidence.
- Known risks and unresolved decisions.
- The exact next approved subproject.

Memory will not contain credentials, sensitive test data, copied Gorilla source, or transient command transcripts.

## 11. Verification

Foundation verification will include:

- A clean `git status` after each committed task, excluding intentionally untracked generated PDFs.
- A test proving the Python package is importable and typed.
- Passing formatter, Ruff, strict mypy, pytest, coverage, Bandit, pip-audit, and REUSE checks.
- A negative structure-policy fixture proving undocumented declarations are rejected.
- A tracked-file audit proving the Gorilla tree, PasswordSafe databases, PDFs, logs, and shared standards are excluded.
- A detached upstream checkout whose `HEAD` equals the selected commit and whose worktree is clean.
- Dossier evidence coverage for every initial parity-matrix row.
- A scan proving the dossier contains no copied multi-line source fragments or unresolved drafting tokens.
- Successful Markdown-to-LaTeX generation and XeLaTeX compilation for substantial project documents.
- Page-by-page visual inspection of generated PDFs.

## 12. Acceptance Criteria

This subproject is accepted when:

1. The repository boundary is explicit, enforced, and free of imported Gorilla implementation material.
2. The selected Gorilla revision can be independently retrieved and verified from the baseline record.
3. The upstream checkout remains untouched outside the Bonobo repository.
4. The behavior dossier and parity matrix cover every meaningful feature family found during the research pass.
5. Every parity row links to evidence and an acceptance-test identifier or is explicitly `Unverified`.
6. Later implementers can work from Bonobo documents without reading Gorilla source.
7. The Python foundation passes all required local and continuous-integration gates.
8. Licensing and provenance checks pass without implying that the iOS exception is already approved.
9. Project memory identifies the lossless PasswordSafe core as the next subproject.
10. Markdown and LaTeX sources are committed while generated PDFs remain uncommitted.

## 13. Known Risks

- A single researcher can unintentionally preserve upstream expression in notes; neutral prose and evidence-only
  citations reduce but do not eliminate that risk.
- Some Gorilla behavior may depend on Tcl/Tk, operating-system state, or unavailable legacy packages and may initially
  remain `Unverified`.
- Upstream test databases may contain data unsuitable for redistribution and therefore cannot be adopted by default.
- Python 3.14 support can vary among later binary dependencies and must be rechecked before each platform subproject.
- App Store rules and dependency licenses can change before the iOS release.

These risks do not relax the no-copy boundary or the no-loss compatibility requirement.

## 14. References

- Password Bonobo program design: `docs/specs/password-bonobo-python-reimplementation-design.md`
- Password Bonobo URL-audit design: `docs/specs/password-bonobo-url-audit-design.md`
- Password Gorilla: https://github.com/zdia/gorilla
- PasswordSafe V3 format: https://github.com/pwsafe/pwsafe/blob/master/docs/formatV3.txt
- Python on Android: https://docs.python.org/3.14/using/android.html
- Python on iOS: https://docs.python.org/3.14/using/ios.html
- REUSE specification: https://reuse.software/spec/
