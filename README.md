# Password Bonobo

Password Bonobo is an original, local-file-first password manager built around a fully typed Python core.

The repository foundation and compatibility dossier are complete.  Product behavior remains unimplemented, so this
project does not yet provide a usable vault.

## Design

The approved program design is in `docs/specs/password-bonobo-python-reimplementation-design.md`.

Future work starts with the durable [project memory](docs/PROJECT_MEMORY.md), which routes to the authoritative
identity, state, decisions, and verification records.

## Source boundary

Password Gorilla is studied only through an external, pinned, read-only research checkout.  Gorilla source and other
copyrightable implementation material do not enter this repository or Bonobo product builds.

## Security

Never add real credentials, personal PasswordSafe databases, tokens, or sensitive provider metadata.  Report security
issues through the [security policy](SECURITY.md).

## License

Bonobo-authored code is licensed under [GPL-3.0-or-later](LICENSES/GPL-3.0-or-later.txt).  Machine-readable metadata
is in [`REUSE.toml`](REUSE.toml).  External contributions remain closed while the iOS distribution-exception decision
is unresolved; see [CONTRIBUTING.md](CONTRIBUTING.md) and the
[App Store distribution exception plan](docs/legal/app-store-distribution-exception-plan.md).

## Development

Install the selected Python baseline and synchronize the locked development environment:

```powershell
uv python install 3.14
uv sync --locked --all-groups
```

Run the complete local validation sequence from the repository root:

```powershell
uv run autopep8 --in-place --recursive src tests tools
git diff --exit-code -- src tests tools
uv run ruff check src tests tools
uv run mypy src tests tools
uv run python -m pytest
uv run python -m tools.check_python_structure src tests tools
git ls-files -z | uv run python -m tools.check_tracked_files
uv run bandit -c pyproject.toml -r src tools
uv run pip-audit
uv run reuse --no-multiprocessing lint
uv build
```

These commands validate only the Bonobo repository and never require the external Gorilla research checkout.
