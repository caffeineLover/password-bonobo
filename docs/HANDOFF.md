# Password Bonobo Reboot Handoff

Last updated: 2026-09-01

## Durable checkpoint

Continue on branch `feature/lossless-passwordsafe-core`.  Task 11's service-facade implementation is in commit
`8c2b30e`; the reboot checkpoint containing this handoff also includes the final test-only mypy narrowing adjustment.
Read `AGENTS.md`, the routed shared standards, `docs/PROJECT_MEMORY.md`, and its four linked project-memory records before
changing code.

Task 11 is functionally complete.  `VaultService` exposes create, open, save, master-passphrase rotation,
version-targeted export, destination-bound recovery discovery, and explicit restore.  Independent review found and the
implementation resolved publication-only completion, internal escape hatches, destination-scoped recovery, stable
record handles, exact same-version export, iteration-policy preservation, early candidate cleanup, committed-state
reconciliation after post-replace faults, and retryable cleanup of retired plaintext owners.  The final reviewer
reported no Critical or Important findings.

## Verified immediately before reboot

- Full suite: 590 collected, 578 passed, 12 platform-specific skips on Windows with CPython 3.14.7.
- Focused facade/public/package selection: 19 passed.
- Ruff: clean.
- Strict mypy: clean across 60 source files after the final test adjustment.
- Python structure checker: clean.
- Git diff whitespace check: clean.
- The final retired-owner regression passes and closes the owner on its third cleanup attempt after two deliberate
  still-live failures.

Earlier in the same Task 11 checkpoint, REUSE 3.3 lint, compatibility, provenance, Bandit, pip-audit, clean source and
wheel builds, wheel inspection, and locked dependency synchronization passed.  They were not repeated after the final
review-only lifecycle changes; repeat them before treating Task 11 as the release-ready input to Task 12 if fresh
evidence is desired.

## Resume commands

Use the module form because the `uv` console executable may not be on `PATH`:

```powershell
git status --short --branch
git log -3 --oneline
python -m uv run python -m pytest -q
python -m uv run ruff check .
python -m uv run mypy src tests tools
python -m uv run python -m tools.check_python_structure src tests tools
python -m uv run python -m tools.generate_documents --verify
```

If completing the remaining packaging/security refresh before Task 12, use the exact commands documented in
`docs/project-memory/VERIFICATION.md` and the repository workflows rather than inventing replacements.  Confirm a clean
working tree after verification.

## Next approved work

Task 12 in `docs/superpowers/plans/2026-08-23-lossless-passwordsafe-core.md` is next: property, fuzz, corruption, and
resource-safety evidence for the public lossless core.  Do not begin client applications or URL-audit behavior.  Keep
fixtures synthetic, preserve the established public API and ownership boundaries, update project memory when Task 12
state changes, and commit that checkpoint independently.
