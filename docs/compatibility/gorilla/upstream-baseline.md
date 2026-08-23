# Gorilla Upstream Baseline

## Selected revision

- Approved repository: `https://github.com/zdia/gorilla.git`
- Observed branch and remote default branch: `master` (`origin/HEAD -> origin/master`)
- Pinned commit: `6728e85c05ac25357b8f19f541487b9d26a97402`
- Tree: `b5d464a25ac51fa3a2753a7634b7a791f6f967dc`
- Commit author date: `2026-03-07T11:53:21-05:00`
- Commit subject: `Add [file home] shim if on pre-9.0 Tcl interpreter.`
- Observation date: `2026-08-22`

The upstream README's GPL-2.0-or-later declaration is a license observation about the external project.  It is not a
license grant for Password Bonobo material and does not change the Bonobo repository's licensing or provenance rules.

## External checkout boundary

The default external research checkout is `../Password Bonobo Research/gorilla`, resolved from the primary Password
Bonobo repository root.  An operator may use another location only if it is outside the Bonobo repository; the pinned
commit and verification procedure remain the same.  The checkout is detached at the pinned commit and is read-only for
research use.  It must not be modified, annotated, staged, copied into Bonobo, or included in a product build.

Create the default checkout only after confirming that the target is outside the repository and does not already exist:

```powershell
$bonoboRoot = (Resolve-Path -LiteralPath '.').Path
$researchRoot = Join-Path (Split-Path -Parent $bonoboRoot) 'Password Bonobo Research'
$gorillaRoot = Join-Path $researchRoot 'gorilla'
New-Item -ItemType Directory -Force -Path $researchRoot
git clone --filter=blob:none --no-checkout https://github.com/zdia/gorilla.git $gorillaRoot
git -C $gorillaRoot checkout --detach 6728e85c05ac25357b8f19f541487b9d26a97402
```

For an existing target, first confirm that its `origin` is the approved repository and that its worktree is clean.  Do
not reset, delete, or overwrite an existing checkout automatically.

## Identity and clean-worktree verification

Run these commands against the external checkout before research and before recording evidence:

```powershell
git -C $gorillaRoot remote get-url origin
git -C $gorillaRoot rev-parse HEAD
git -C $gorillaRoot status --short
git -C $gorillaRoot show -s --format='%H%n%T%n%aI%n%s' HEAD
git -C $gorillaRoot symbolic-ref --short refs/remotes/origin/HEAD
```

The origin must be `https://github.com/zdia/gorilla.git`, `HEAD` must be the pinned commit, and `status --short` must
produce no output.  The `show` command records the commit, tree, author date, and subject; the symbolic reference
records the remote default-branch observation.

## Evidence convention and permitted research categories

Each later compatibility evidence record must use neutral prose and identify:

- Revision: the pinned upstream revision.
- Location: repository-relative path and a line range or test name.
- Evidence kind: source inspection, test observation, documentation, or change history.
- Neutral observation: an observable behavior or an unresolved question without copied implementation text.

The approved research pass may inspect application workflows and user-visible behavior in `sources/gorilla.tcl`; data
concepts and compatibility behavior in `sources/pwsafe/*.tcl`; user-facing contracts in `sources/help.txt`, message
catalogs, and upstream README material; behavioral examples and edge cases in `unit-tests/**/*.test` and
`unit-tests/**/*.tcl`; and compatibility-relevant upstream change history.

Gorilla material is evidence of behavior, not implementation material.  Do not copy or adapt upstream source,
comments, identifiers, file organization, control flow, UI assets, translations, screenshots, test fixtures, or vault
files.  In particular, upstream `.psafe3` files remain external research-only and may not enter Bonobo tracked fixture
paths.  Do not quote source fragments in Bonobo product code or compatibility documents.

## Updating this baseline

Changing the external revision requires separate review, a newly pinned immutable revision, an updated provenance
entry, and a neutral dossier delta.  Preserve prior observations rather than replacing them solely because a later
revision differs, and keep every research checkout external and read-only throughout the update.
