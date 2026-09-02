# Password Bonobo

Password Bonobo is an original, local-file-first password manager built around a fully typed Python core.

The repository foundation, compatibility dossier, lossless PasswordSafe core, and an accessible PySide6/Qt Quick
desktop vertical slice are implemented.  Password Bonobo remains pre-alpha: native installers, signing, advanced vault
workflows, and mobile clients are not delivered yet.

## Design

The approved program design is in `docs/specs/password-bonobo-python-reimplementation-design.md`.

Developers can start with the [lossless core operations guide](docs/guides/lossless-passwordsafe-core.md). Future work
starts with the single durable [project memory](docs/PROJECT_MEMORY.md), which contains current state, decisions,
verification, exact continuation order, and authoritative links.

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
uv sync --locked --no-default-groups --group dev --group desktop-test --extra desktop
```

The `desktop` extra installs the qualified PySide6 6.11 line, while `desktop-test` adds the offscreen Qt test adapter.
The optional GUI expects a loader-visible Botan 3 shared library provisioned outside the Python wheel.  Start the
developer shell with:

```powershell
uv run password-bonobo
```

Inspect the deterministic native deployment command without building or installing a platform artifact:

```powershell
uv run pyside6-deploy --dry-run -c pysidedeploy.spec
```

The checked-in specification pins an executable deployment wrapper, output directory, complete packaged QML source
set, application name, and exact `Core`, `Gui`, `Qml`, `Quick`, `QuickControls2`, and `Widgets` Qt module closure.  The
Widgets module supplies only the Python-owned native file dialog; vault locators never enter QML.  Run the dry run
natively on Windows, macOS, or Linux; it is not a cross-build, installer, signing, or distribution command.

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

First build and select the pinned Botan library by following the
[lossless core operations guide](docs/guides/lossless-passwordsafe-core.md#build-and-select-the-pinned-botan-library).
`BONOBO_TEST_BOTAN_LIBRARY` must name that resolved host library. A run without it is not release evidence; CI fails if
the qualified library is absent.

```powershell
uv run autopep8 --in-place --recursive src tests tools examples
git diff --exit-code -- src tests tools examples
uv run ruff check src tests tools examples
uv run mypy src tests tools examples
$env:QT_QPA_PLATFORM = "offscreen"
uv run python -m pytest tests/desktop -q
uv run pyside6-deploy --dry-run -c pysidedeploy.spec
uv run python -m pytest
uv run python -m tools.check_python_structure src tests tools examples
uv run python -m tools.check_compatibility
uv run python -m tools.check_provenance
git ls-files -z | uv run python -m tools.check_tracked_files
uv run bandit -c pyproject.toml -r src tools examples
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
