# Password Bonobo

Password Bonobo is an original, local-file-first password manager built around a fully typed Python core.

The repository foundation and compatibility dossier are complete.  Product behavior remains unimplemented, so this
project does not yet provide a usable vault.

## Design

The approved program design is in `docs/specs/password-bonobo-python-reimplementation-design.md`.

Future work starts with the single durable [project memory](docs/PROJECT_MEMORY.md), which contains current state,
decisions, verification, exact continuation order, and authoritative links.

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

Install [Git from its official distribution page](https://git-scm.com/downloads) and
[uv by its official installer](https://docs.astral.sh/uv/getting-started/installation/), then verify both commands:

```powershell
git --version
uv --version
```

Install the selected Python baseline and synchronize the locked development environment:

```powershell
uv python install 3.14
uv sync --locked --all-groups
```

Explicitly requested document generation and visual QA additionally require
[Pandoc](https://pandoc.org/installing.html), a XeLaTeX distribution such as
[MiKTeX](https://miktex.org/download), and Poppler's `pdfinfo` and `pdftoppm` commands.  Verify them before running
the document gate:

```powershell
pandoc --version
xelatex --version
pdfinfo -v
pdftoppm -v
```

Only after the user names a document, regenerate its tracked LaTeX source, ignored PDF, rendered review pages, logs,
and manifest with an explicit selection:

```powershell
uv run python -m tools.generate_documents --document docs/path/to/document.md --write --render
```

Repeat `--document` for each separately approved source.  There is no repository-wide generation mode, and the
Gorilla compatibility, legal, specification, implementation-plan, and approved-design documents are Markdown-only, so
do not select their sources unless that restriction is explicitly reversed.

Run the complete local validation sequence from the repository root:

```powershell
uv run autopep8 --in-place --recursive src tests tools
git diff --exit-code -- src tests tools
uv run ruff check src tests tools
uv run mypy src tests tools
uv run python -m pytest
uv run python -m tools.check_python_structure src tests tools
uv run python -m tools.check_compatibility
uv run python -m tools.check_provenance
git ls-files -z | uv run python -m tools.check_tracked_files
uv run bandit -c pyproject.toml -r src tools
uv run pip-audit
uv run reuse --no-multiprocessing lint
uv build
uv run python -m tools.check_wheel dist
git diff --cached --check
```

When a document derivative was explicitly requested, verify only that named source with
`uv run python -m tools.generate_documents --document docs/path/to/document.md --verify`.

Stage every intended file before the REUSE command so that it validates the exact release candidate.  These commands
validate only the Bonobo repository and never require the external Gorilla research checkout.  The artifact checker
requires the GPL text and typing marker in both source distribution and wheel, plus exact PEP 639 wheel metadata and
license bytes.
