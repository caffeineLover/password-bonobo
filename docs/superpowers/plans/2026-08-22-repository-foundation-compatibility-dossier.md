# Repository Foundation and Compatibility Dossier Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or
> superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Establish a policy-enforced Bonobo repository and convert a pinned, untouched Gorilla source baseline into a
neutral compatibility dossier, parity matrix, and test-oracle catalog.

**Architecture:** Gorilla remains in a detached sibling research checkout and never enters the Bonobo repository.  The
repository contains only original foundation code, enforceable quality policy, neutral behavioral documentation, and an
empty typed `bonobo_core` package boundary for the next subproject.

**Tech Stack:** Git, CPython 3.14, Hatchling, uv, autopep8, Ruff, mypy, pytest, Bandit, pip-audit, REUSE,
GitHub Actions, Pandoc, XeLaTeX, and Poppler.

**Spec:** `docs/specs/password-bonobo-repository-foundation-compatibility-dossier-spec.md`

## Global Constraints

- Gorilla baseline URL: `https://github.com/zdia/gorilla.git`.
- Gorilla baseline commit: `6728e85c05ac25357b8f19f541487b9d26a97402`.
- Gorilla source stays untouched and outside the Bonobo repository.
- No Gorilla source, comments, identifiers, file organization, control flow, UI assets, or translations enter Bonobo.
- No upstream PasswordSafe database becomes a fixture without separate provenance and sensitive-data review.
- Bonobo-authored code uses SPDX identifier `GPL-3.0-or-later`.
- The iOS distribution exception remains a review item; do not publish provisional wording as approved license text.
- Target CPython `>=3.14,<3.15`.
- Every maintained Python module has a responsibility-focused triple-double-quoted module docstring.
- Every maintained Python class, function, and method has the required immediately preceding `####` comment block.
- Every maintained Python declaration is fully typed and passes strict mypy.
- Required three-blank-line declaration spacing must survive formatting.
- Documentation lines are at most 120 characters.
- Real credentials, vaults, tokens, sensitive URLs, and provider metadata are prohibited.
- Markdown and same-basename LaTeX are committed for substantial documents; generated PDFs remain uncommitted.

---

## Planned File Structure

```text
Password Bonobo/
|-- .editorconfig                         # Cross-editor whitespace and line-length defaults.
|-- .gitattributes                        # Text normalization and binary-file declarations.
|-- .gitignore                            # Secret-bearing, generated, shared, and local-file exclusions.
|-- .python-version                       # CPython 3.14 development baseline.
|-- AGENTS.md                             # Project instruction router.
|-- CONTRIBUTING.md                       # Contribution hold and future acceptance requirements.
|-- LICENSES/
|   `-- GPL-3.0-or-later.txt              # Canonical project license text.
|-- README.md                             # Product intent, status, and safe development entry points.
|-- REUSE.toml                            # License annotations for non-source files.
|-- SECURITY.md                           # Private reporting and sensitive-data rules.
|-- pyproject.toml                        # Package metadata and all Python tool configuration.
|-- uv.lock                               # Reproducible development dependency lock.
|-- .github/workflows/foundation.yml      # Three-platform quality and package workflow.
|-- docs/compatibility/gorilla/
|   |-- upstream-baseline.md              # Exact source pin and external-checkout procedure.
|   |-- behavior-dossier.md               # Neutral behavior and evidence catalog.
|   |-- feature-parity-matrix.md          # Bonobo disposition for every feature family.
|   `-- test-oracles.md                   # Synthetic black-box compatibility scenarios.
|-- docs/legal/
|   |-- app-store-distribution-exception-plan.md
|   `-- source-provenance-policy.md
|-- docs/project-memory/
|   |-- DECISIONS.md
|   |-- PROJECT.md
|   |-- STATE.md
|   `-- VERIFICATION.md
|-- src/bonobo_core/
|   |-- __init__.py                       # Typed package identity only.
|   `-- py.typed                          # PEP 561 marker.
|-- tests/fixtures/python_structure/
|   |-- documented.py.txt                 # Positive structural-policy fixture.
|   `-- undocumented.py.txt               # Negative structural-policy fixture.
|-- tests/foundation/
|   |-- test_package_contract.py          # Package identity and typing marker tests.
|   `-- test_python_structure.py          # Structural-policy checker behavior.
`-- tools/
    |-- check_python_structure.py          # AST-backed source documentation validator.
    `-- check_tracked_files.py             # Tracked-file and credential-artifact validator.
```

The sibling research checkout defaults to `../Password Bonobo Research/gorilla` and is not part of this tree.

---

### Task 1: Establish the Git boundary and baseline controls

**Files:**

- Create: `.gitignore`
- Create: `.gitattributes`
- Create: `.editorconfig`
- Create: `README.md`
- Track: `AGENTS.md`
- Track: `docs/specs/password-bonobo-url-audit-design.md`
- Track: `docs/specs/password-bonobo-python-reimplementation-design.md`
- Track: `docs/specs/password-bonobo-python-reimplementation-design.tex`
- Track: `docs/specs/password-bonobo-repository-foundation-compatibility-dossier-spec.md`
- Track: `docs/specs/password-bonobo-repository-foundation-compatibility-dossier-spec.tex`
- Track: `docs/superpowers/plans/2026-08-22-repository-foundation-compatibility-dossier.md`
- Track: `docs/superpowers/plans/2026-08-22-repository-foundation-compatibility-dossier.tex`

**Interfaces:**

- Consumes: The existing workspace and approved specifications.
- Produces: A `main` repository whose ignore rules define every later task's tracked-file boundary.

- [ ] **Step 1: Reconfirm the repository boundary**

Run from the workspace root:

```powershell
$workspace = (Resolve-Path -LiteralPath '.').Path
$parent = (Resolve-Path -LiteralPath '..').Path
git -C $workspace rev-parse --show-toplevel
git -C $parent rev-parse --show-toplevel
```

Expected: both Git commands fail with `not a git repository`.  Stop if either resolves to an existing repository.

- [ ] **Step 2: Initialize the primary branch**

Run:

```powershell
git init -b main
git status --short
```

Expected: Git reports untracked workspace files and branch `main`.

- [ ] **Step 3: Create the repository exclusions**

Create `.gitignore` with exactly these initial rules:

```gitignore
# Shared standards are read from the canonical external standards repository.
/docs/prompts/

# Generated documentation and render intermediates are not versioned.
*.pdf
/tmp/

# Runtime and development state.
/logs/
/.venv/
/.mypy_cache/
/.pytest_cache/
/.ruff_cache/
/.coverage
/htmlcov/
/dist/
/build/
*.egg-info/
__pycache__/
*.py[cod]

# Editors and operating systems.
/.idea/
/.vscode/
.DS_Store
Thumbs.db

# Vaults are denied by default.  Later synthetic fixtures require an explicit exception.
*.psafe3
*.psafe
*.dat
!/tests/fixtures/synthetic/**/*.psafe3
!/tests/fixtures/synthetic/**/*.psafe
```

- [ ] **Step 4: Create text and editor policy**

Create `.gitattributes`:

```gitattributes
* text=auto eol=lf
*.ps1 text eol=crlf
*.png binary
*.jpg binary
*.jpeg binary
*.gif binary
*.pdf binary
*.psafe binary
*.psafe3 binary
```

Create `.editorconfig`:

```ini
root = true

[*]
charset = utf-8
end_of_line = lf
insert_final_newline = true
trim_trailing_whitespace = true
max_line_length = 120

[*.py]
indent_style = space
indent_size = 4

[*.{md,tex}]
trim_trailing_whitespace = false

[*.ps1]
end_of_line = crlf
indent_style = space
indent_size = 4
```

- [ ] **Step 5: Create the project entry document**

Create `README.md` with these sections and claims:

```markdown
# Password Bonobo

Password Bonobo is an original, local-file-first password manager built around a fully typed Python core.

The project is in foundation and compatibility-research development.  It does not yet provide a usable vault.

## Design

The approved program design is in `docs/specs/password-bonobo-python-reimplementation-design.md`.

## Source boundary

Password Gorilla is studied only through an external, pinned, read-only research checkout.  Gorilla source and other
copyrightable implementation material do not enter this repository or Bonobo product builds.

## Security

Never add real credentials, personal PasswordSafe databases, tokens, or sensitive provider metadata.  Report security
issues using `SECURITY.md` after that document is added by the foundation plan.

## License

Bonobo-authored code is intended for GPL-3.0-or-later licensing.  Formal license files and contribution terms are added
by the repository-foundation plan before product implementation begins.
```

- [ ] **Step 6: Verify the ignore boundary before staging**

Run:

```powershell
git check-ignore -v docs/prompts/AGENTS.md
git check-ignore -v docs/specs/password-bonobo-python-reimplementation-design.pdf
git check-ignore -v tmp/pdfs/password-bonobo-final-page-1.png
git status --short
```

Expected: each queried generated or shared file matches an ignore rule.  `git status` must not list `docs/prompts/`, any
PDF, or `tmp/`.

- [ ] **Step 7: Commit the intentional baseline**

Run:

```powershell
git add .editorconfig .gitattributes .gitignore AGENTS.md README.md docs/specs docs/superpowers/plans
git diff --cached --check
git diff --cached --name-only
git commit -m "docs: establish Password Bonobo design baseline"
git switch -c foundation/compatibility-dossier
```

Expected: the staged-name audit contains only Bonobo-authored policy and design files.  The commit succeeds, and the
working branch becomes `foundation/compatibility-dossier`.

---

### Task 2: Configure the typed Python package and reproducible toolchain

**Files:**

- Create: `.python-version`
- Create: `pyproject.toml`
- Create: `uv.lock`
- Create: `src/bonobo_core/__init__.py`
- Create: `src/bonobo_core/py.typed`
- Create: `tools/__init__.py`
- Create: `tests/foundation/test_package_contract.py`

**Interfaces:**

- Consumes: Git and repository policy from Task 1.
- Produces: `bonobo_core.__version__: Final[str]`, an importable typed package, and `uv run` quality commands.

- [ ] **Step 1: Install uv and CPython 3.14 outside the repository**

Run:

```powershell
python -m pip install --user uv
uv python install 3.14
uv python pin 3.14
```

Expected: `.python-version` contains `3.14`, and `uv run python --version` reports Python 3.14.x.

- [ ] **Step 2: Create package and tool configuration**

Create `pyproject.toml`:

```toml
[build-system]
requires = ["hatchling>=1.27,<2"]
build-backend = "hatchling.build"

[project]
name = "password-bonobo"
version = "0.0.0"
description = "A local-file-first PasswordSafe-compatible password manager core."
readme = "README.md"
requires-python = ">=3.14,<3.15"
license = "GPL-3.0-or-later"
authors = [{ name = "Password Bonobo contributors" }]
classifiers = [
  "Development Status :: 2 - Pre-Alpha",
  "License :: OSI Approved :: GNU General Public License v3 or later (GPLv3+)",
  "Programming Language :: Python :: 3.14",
  "Typing :: Typed",
]
dependencies = []

[dependency-groups]
dev = [
  "autopep8>=2.3,<3",
  "bandit[toml]>=1.8,<2",
  "build>=1.3,<2",
  "mypy>=1.18,<2",
  "pip-audit>=2.9,<3",
  "pytest>=8.4,<9",
  "pytest-cov>=7,<8",
  "reuse>=6.2,<7",
  "ruff>=0.12,<1",
]

[tool.hatch.build.targets.wheel]
packages = ["src/bonobo_core"]

[tool.autopep8]
max_line_length = 120
ignore = ["E303"]
recursive = true

[tool.ruff]
target-version = "py314"
line-length = 120
src = ["src", "tests", "tools"]

[tool.ruff.lint]
select = ["E", "F", "I", "N", "UP", "ANN", "B", "SIM", "RUF"]
ignore = ["E303"]

[tool.mypy]
python_version = "3.14"
strict = true
files = ["src", "tests", "tools"]
warn_unreachable = true

[tool.pytest.ini_options]
addopts = "--strict-config --strict-markers --cov=bonobo_core --cov=tools --cov-report=term-missing"
testpaths = ["tests"]

[tool.coverage.run]
branch = true
source = ["bonobo_core", "tools"]

[tool.bandit]
targets = ["src", "tools"]
```

- [ ] **Step 3: Lock and install the development environment**

Run:

```powershell
uv lock
uv sync --all-groups
```

Expected: `uv.lock` is created and `uv run python --version` reports Python 3.14.x.

- [ ] **Step 4: Write the failing package-contract test**

Create `tests/foundation/test_package_contract.py`:

```python
"""Verify that the foundation exposes only a typed package identity.

Product behavior remains excluded until the lossless PasswordSafe core subproject.
"""

from pathlib import Path

import bonobo_core



#### Verify that package metadata and the PEP 561 marker are present.
####
def test_package_identity_is_typed() -> None:
    assert bonobo_core.__file__ is not None
    package_directory = Path(bonobo_core.__file__).parent

    assert bonobo_core.__version__ == "0.0.0"
    assert (package_directory / "py.typed").is_file()
```

- [ ] **Step 5: Run the contract test and verify failure**

Run:

```powershell
uv run pytest tests/foundation/test_package_contract.py -v
```

Expected: collection fails with `ModuleNotFoundError: No module named 'bonobo_core'`.

- [ ] **Step 6: Add the minimum typed package identity**

Create `src/bonobo_core/__init__.py`:

```python
"""Define the public identity of the Password Bonobo core package.

Vault behavior is intentionally absent until the lossless PasswordSafe core subproject.
"""

from typing import Final

__version__: Final[str] = "0.0.0"
```

Create an empty `src/bonobo_core/py.typed` file.

Create `tools/__init__.py`:

```python
"""Provide repository-owned validation utilities that never enter product builds."""
```

- [ ] **Step 7: Run foundation quality checks**

Run:

```powershell
uv run autopep8 --diff --recursive src tests tools
uv run ruff check src tests
uv run mypy src tests
uv run pytest tests/foundation/test_package_contract.py -v
uv build
```

Expected: the formatter prints no diff; lint, typing, and test commands pass; wheel and source distribution are built.

- [ ] **Step 8: Commit the package foundation**

Run:

```powershell
git add .python-version pyproject.toml uv.lock src tools/__init__.py tests/foundation/test_package_contract.py
git diff --cached --check
git commit -m "build: add typed Python foundation"
```

---

### Task 3: Enforce Python documentation and spacing policy

**Files:**

- Modify: `tools/__init__.py`
- Create: `tools/check_python_structure.py`
- Create: `tests/foundation/test_python_structure.py`
- Create: `tests/fixtures/python_structure/documented.py.txt`
- Create: `tests/fixtures/python_structure/undocumented.py.txt`

**Interfaces:**

- Consumes: Python 3.14 and pytest from Task 2.
- Produces: `Violation`, `check_source(path, source)`, `check_paths(paths)`, and a CLI returning zero only when
  policy passes.

- [ ] **Step 1: Create positive and negative source fixtures**

Create `tests/fixtures/python_structure/documented.py.txt`:

```python
"""Provide a structurally valid sample module."""



#### Return the supplied value without transforming it.
####
def identity(value: str) -> str:
    return value
```

Create `tests/fixtures/python_structure/undocumented.py.txt`:

```python
def missing_comment(value):
    return value
```

- [ ] **Step 2: Write failing checker tests**

Create `tests/foundation/test_python_structure.py` with these public-contract tests:

```python
"""Verify the repository-specific Python source structure policy."""

from pathlib import Path

from tools.check_python_structure import check_paths, check_source

FIXTURE_DIRECTORY = Path(__file__).parents[1] / "fixtures" / "python_structure"



#### Accept a module with documentation, typing, and exact declaration spacing.
####
def test_documented_fixture_passes() -> None:
    path = FIXTURE_DIRECTORY / "documented.py.txt"

    assert check_source(path, path.read_text(encoding="utf-8")) == ()



#### Report each missing structural requirement in an undocumented declaration.
####
def test_undocumented_fixture_fails() -> None:
    path = FIXTURE_DIRECTORY / "undocumented.py.txt"
    messages = tuple(
        violation.message
        for violation in check_source(path, path.read_text(encoding="utf-8"))
    )

    assert "module docstring is required" in messages
    assert "declaration requires an immediately preceding #### block" in messages
    assert "parameter 'value' requires a type annotation" in messages
    assert "return type annotation is required" in messages



#### Check every maintained Python source file through the same public entry point.
####
def test_repository_python_sources_pass() -> None:
    assert check_paths((Path("src"), Path("tests"), Path("tools"))) == ()
```

- [ ] **Step 3: Run the tests and verify the missing checker failure**

Run:

```powershell
uv run pytest tests/foundation/test_python_structure.py -v
```

Expected: collection fails because `tools.check_python_structure` does not exist.

- [ ] **Step 4: Implement the AST-backed checker**

Keep the responsibility docstring in `tools/__init__.py`.  Implement `tools/check_python_structure.py` with these exact
public types and rules:

```python
"""Validate Bonobo's required Python documentation, typing, and spacing structure.

The checker complements Ruff and mypy where the project profile intentionally differs from conventional PEP 8 spacing.
"""

from __future__ import annotations

import argparse
import ast
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from pathlib import Path



#### Describe one source-policy failure at its original location.
####
@dataclass(frozen=True, slots=True)
class Violation:
    path: Path
    line: int
    message: str



#### Return all structural violations found in one source string.
####
def check_source(path: Path, source: str) -> tuple[Violation, ...]:
    tree = ast.parse(source, filename=str(path))
    lines = source.splitlines()
    violations: list[Violation] = []

    if ast.get_docstring(tree, clean=False) is None:
        violations.append(Violation(path, 1, "module docstring is required"))

    for node in ast.walk(tree):
        if not isinstance(node, (ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)):
            continue

        start_line = min(
            (decorator.lineno for decorator in node.decorator_list),
            default=node.lineno,
        )
        block_end = start_line - 1
        block_start = block_end
        while block_start > 0 and lines[block_start - 1].lstrip().startswith("####"):
            block_start -= 1

        block = lines[block_start:block_end]
        if not block or block[-1].strip() != "####":
            violations.append(
                Violation(path, start_line, "declaration requires an immediately preceding #### block")
            )
        elif any(line.strip() != "####" and not line.lstrip().startswith("#### ") for line in block):
            violations.append(Violation(path, start_line, "declaration block uses invalid #### syntax"))

        preceding = lines[max(0, block_start - 3):block_start]
        if len(preceding) != 3 or any(line.strip() for line in preceding):
            violations.append(Violation(path, start_line, "declaration requires exactly three preceding blank lines"))
        elif block_start >= 4 and not lines[block_start - 4].strip():
            violations.append(Violation(path, start_line, "declaration has more than three preceding blank lines"))

        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            arguments = (*node.args.posonlyargs, *node.args.args, *node.args.kwonlyargs)
            for argument in arguments:
                if argument.arg not in {"self", "cls"} and argument.annotation is None:
                    violations.append(
                        Violation(path, argument.lineno, f"parameter '{argument.arg}' requires a type annotation")
                    )
            if node.args.vararg is not None and node.args.vararg.annotation is None:
                violations.append(
                    Violation(path, node.lineno, "variadic positional parameter requires a type annotation")
                )
            if node.args.kwarg is not None and node.args.kwarg.annotation is None:
                violations.append(Violation(path, node.lineno, "variadic keyword parameter requires a type annotation"))
            if node.returns is None:
                violations.append(Violation(path, node.lineno, "return type annotation is required"))

    return tuple(sorted(violations, key=lambda item: (str(item.path), item.line, item.message)))



#### Check maintained Python files beneath the supplied files and directories.
####
def check_paths(paths: Iterable[Path]) -> tuple[Violation, ...]:
    files: set[Path] = set()
    for path in paths:
        if path.is_file() and path.suffix in {".py", ".pyi"}:
            files.add(path)
        elif path.is_dir():
            files.update(path.rglob("*.py"))
            files.update(path.rglob("*.pyi"))

    violations: list[Violation] = []
    for path in sorted(files):
        violations.extend(check_source(path, path.read_text(encoding="utf-8")))
    return tuple(violations)



#### Parse command-line paths, print safe diagnostics, and return process status.
####
def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("paths", nargs="+", type=Path)
    arguments = parser.parse_args(argv)
    violations = check_paths(arguments.paths)
    for violation in violations:
        print(f"{violation.path}:{violation.line}: {violation.message}")
    return 1 if violations else 0



# Return the command status to the invoking shell without configuring runtime logging.
if __name__ == "__main__":
    raise SystemExit(main())
```

Before accepting this implementation, add a test case for a decorated declaration and one for more than three blank
lines.  Use the same fixture-string approach and assert the exact violation messages shown above.

- [ ] **Step 5: Run the full validation cycle**

Run:

```powershell
uv run autopep8 --diff --recursive src tests tools
uv run ruff check src tests tools
uv run mypy src tests tools
uv run pytest tests/foundation -v
uv run python -m tools.check_python_structure src tests tools
```

Expected: every command passes.  Confirm manually that formatting did not remove required blank lines or `####` blocks.

- [ ] **Step 6: Commit the source-policy gate**

Run:

```powershell
git add tools tests/foundation/test_python_structure.py tests/fixtures/python_structure
git diff --cached --check
git commit -m "test: enforce Python source structure policy"
```

---

### Task 4: Enforce tracked-file safety

**Files:**

- Create: `tools/check_tracked_files.py`
- Create: `tests/foundation/test_tracked_files.py`

**Interfaces:**

- Consumes: Git repository and Python policy from Tasks 1-3.
- Produces: `find_forbidden(paths) -> tuple[ForbiddenPath, ...]` and a CI-safe tracked-file audit command.

- [ ] **Step 1: Write failing path-policy tests**

Create tests covering these exact cases:

```python
"""Verify that generated, upstream, and credential-bearing files cannot be tracked."""

from pathlib import Path

from tools.check_tracked_files import find_forbidden



#### Reject every prohibited tracked-file category.
####
def test_forbidden_categories_are_reported() -> None:
    paths = (
        Path("docs/prompts/AGENTS.md"),
        Path("docs/specs/generated.pdf"),
        Path("tmp/pdfs/page-1.png"),
        Path("research/gorilla/sources/gorilla.tcl"),
        Path("customer.psafe3"),
        Path("logs/bonobo.log"),
    )

    assert tuple(item.path for item in find_forbidden(paths)) == paths



#### Permit Bonobo sources and explicitly synthetic fixtures.
####
def test_safe_paths_are_allowed() -> None:
    paths = (
        Path("src/bonobo_core/__init__.py"),
        Path("docs/compatibility/gorilla/behavior-dossier.md"),
        Path("tests/fixtures/synthetic/minimal.psafe3"),
    )

    assert find_forbidden(paths) == ()
```

- [ ] **Step 2: Verify the tests fail because the module is missing**

Run:

```powershell
uv run pytest tests/foundation/test_tracked_files.py -v
```

Expected: collection fails because `tools.check_tracked_files` does not exist.

- [ ] **Step 3: Implement the tracked-file validator**

Implement `tools/check_tracked_files.py`:

```python
"""Reject generated, upstream, and credential-bearing repository paths.

The command examines path names only and never opens a possible vault or secret-bearing file.
"""

from __future__ import annotations

import argparse
import sys
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import cast



#### Describe one forbidden path without reading or exposing its contents.
####
@dataclass(frozen=True, slots=True)
class ForbiddenPath:
    path: Path
    reason: str



#### Return a safe rejection reason for one normalized repository path.
####
def _forbidden_reason(path: Path) -> str | None:
    normalized = path.as_posix().lstrip("./")
    lowered = normalized.lower()
    parts = lowered.split("/")

    for prefix in ("docs/prompts", "tmp", "logs", "research"):
        if lowered == prefix or lowered.startswith(f"{prefix}/"):
            return f"path is below prohibited directory '{prefix}'"

    allowed_gorilla_docs = lowered == "docs/compatibility/gorilla" or lowered.startswith(
        "docs/compatibility/gorilla/"
    )
    if "gorilla" in parts and not allowed_gorilla_docs:
        return "upstream Gorilla material is prohibited"

    if path.suffix.lower() == ".pdf":
        return "generated PDF is prohibited"

    synthetic_fixture = lowered.startswith("tests/fixtures/synthetic/")
    if path.suffix.lower() in {".psafe", ".psafe3", ".dat"} and not synthetic_fixture:
        return "vault-like file is outside the synthetic fixture allowlist"

    filename = path.name.lower()
    if filename == ".env" or filename.endswith((".key", ".pem")):
        return "secret-bearing filename is prohibited"
    if filename in {"id_rsa", "id_ed25519"}:
        return "private-key filename is prohibited"

    return None



#### Return prohibited repository paths in input order without reading them.
####
def find_forbidden(paths: Iterable[Path]) -> tuple[ForbiddenPath, ...]:
    violations: list[ForbiddenPath] = []
    for path in paths:
        reason = _forbidden_reason(path)
        if reason is not None:
            violations.append(ForbiddenPath(path, reason))
    return tuple(violations)



#### Read path arguments or standard input, print safe findings, and return process status.
####
def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("paths", nargs="*", type=Path)
    arguments = parser.parse_args(argv)
    paths = tuple(cast(list[Path], arguments.paths))
    if not paths:
        paths = tuple(Path(line.strip()) for line in sys.stdin if line.strip())

    violations = find_forbidden(paths)
    for violation in violations:
        print(f"{violation.path}: {violation.reason}")
    return 1 if violations else 0



# Return the command status to the invoking shell without configuring runtime logging.
if __name__ == "__main__":
    raise SystemExit(main())
```

The implementation rejects:

- Any path below `docs/prompts/`, `tmp/`, `logs/`, `research/`, or a directory named `gorilla` outside
  `docs/compatibility/gorilla/`.
- Any `.pdf` path.
- Any `.psafe`, `.psafe3`, or `.dat` path outside `tests/fixtures/synthetic/`.
- Any filename matching `.env`, `*.key`, `*.pem`, `id_rsa`, or `id_ed25519`.

When standard input is redirected, the command reads NUL-delimited Git paths from `git ls-files -z` to avoid Git's
C-style quoting ambiguity.  It prints only a path and non-sensitive reason, and returns one on a violation.

- [ ] **Step 4: Exercise the command entry point**

Run:

```powershell
uv run pytest tests/foundation/test_tracked_files.py -v
git ls-files -z | uv run python -m tools.check_tracked_files
uv run ruff check tools tests
uv run mypy tools tests
uv run python -m tools.check_python_structure tools tests
```

Expected: all commands pass and no tracked path is reported.

- [ ] **Step 5: Commit the tracked-file gate**

Run:

```powershell
git add tools/check_tracked_files.py tests/foundation/test_tracked_files.py
git diff --cached --check
git commit -m "test: block unsafe tracked artifacts"
```

---

### Task 5: Establish licensing, provenance, contribution, and security policy

**Files:**

- Create: `LICENSES/GPL-3.0-or-later.txt`
- Create: `REUSE.toml`
- Create: `CONTRIBUTING.md`
- Create: `SECURITY.md`
- Create: `docs/legal/source-provenance-policy.md`
- Create: `docs/legal/app-store-distribution-exception-plan.md`
- Modify: `README.md`

**Interfaces:**

- Consumes: REUSE installed by Task 2 and source boundary from the specification.
- Produces: Machine-checkable GPL licensing and human-readable rules for all later contributions and source research.

- [ ] **Step 1: Download the canonical GPL text with REUSE**

Run:

```powershell
uv run reuse download GPL-3.0-or-later
```

Expected: `LICENSES/GPL-3.0-or-later.txt` exists and `reuse lint` recognizes the license identifier.

- [ ] **Step 2: Create machine-readable file annotations**

Create `REUSE.toml` using REUSE specification version 3.3:

```toml
version = 1
SPDX-PackageName = "Password Bonobo"
SPDX-PackageSupplier = "NOASSERTION"
SPDX-PackageDownloadLocation = "NOASSERTION"

[[annotations]]
path = "**"
precedence = "aggregate"
SPDX-FileCopyrightText = "2026 Password Bonobo contributors"
SPDX-License-Identifier = "GPL-3.0-or-later"
```

This annotation covers Bonobo-authored source, tests, tools, configuration, documentation, and the canonical license
artifact.  Ignored `docs/prompts/`, generated PDFs, and the external Gorilla checkout are not repository content.

- [ ] **Step 3: Create the source-provenance policy**

Write `docs/legal/source-provenance-policy.md` with these mandatory sections:

1. Purpose and scope.
2. Allowed authoritative inputs: Bonobo specifications, official format documentation, neutral dossier, and synthetic
   tests.
3. External research boundary and read-only checkout rules.
4. Prohibited copying categories.
5. Evidence citation format: revision, relative path, line range or test name, evidence kind, neutral observation.
6. Fixture intake: origin, license, synthetic-data proof, sensitive-data scan, and approval.
7. Dependency and asset ledger requirements.
8. Upstream revision update procedure.
9. Incident response for suspected copied expression.

- [ ] **Step 4: Document the iOS exception work without publishing license language**

Write `docs/legal/app-store-distribution-exception-plan.md` with:

- The distribution problem the exception is intended to address.
- Scope limited to Bonobo-authored code whose contributors granted the necessary permission.
- Exclusion of Gorilla-derived code and incompatible dependencies from the iOS build.
- Required dependency, contributor, Apple-term, and legal reviews.
- A decision gate before accepting external contributions.
- A decision gate before the first iOS distribution build.
- A statement that this planning document is not license text or legal advice.

- [ ] **Step 5: Add contribution and security entry points**

Create `CONTRIBUTING.md` stating that external contributions are not yet accepted, why the distribution-exception rights
must first be settled, and how that status will be changed deliberately.  Create `SECURITY.md` prohibiting public issue
content that includes credentials or vaults and directing reporters to the repository owner's private GitHub security
reporting channel once enabled.  Do not invent an email address.

Update `README.md` so the license and security links point to these completed files.

- [ ] **Step 6: Verify policy and license metadata**

Run:

```powershell
uv run reuse lint
git ls-files -z | uv run python -m tools.check_tracked_files
rg -n "Gorilla source|GPL-3.0-or-later|not license text" README.md CONTRIBUTING.md SECURITY.md docs/legal REUSE.toml
```

Expected: REUSE passes, the tracked-file audit passes, and each required policy phrase appears in its intended document.

- [ ] **Step 7: Commit licensing and policy**

Run:

```powershell
git add LICENSES REUSE.toml README.md CONTRIBUTING.md SECURITY.md docs/legal
git diff --cached --check
git commit -m "docs: establish licensing and provenance policy"
```

---

### Task 6: Pin and verify the external Gorilla research checkout

**Files:**

- Create: `docs/compatibility/gorilla/upstream-baseline.md`
- External create: `../Password Bonobo Research/gorilla/`

**Interfaces:**

- Consumes: Upstream URL and commit from Global Constraints.
- Produces: A reproducible detached checkout and an evidence-citation baseline for Tasks 7 and 8.

- [ ] **Step 1: Resolve and verify the external target**

Run from the Bonobo root:

```powershell
$bonoboRoot = (Resolve-Path -LiteralPath '.').Path
$researchRoot = Join-Path (Split-Path -Parent $bonoboRoot) 'Password Bonobo Research'
$gorillaRoot = Join-Path $researchRoot 'gorilla'
Write-Output "BONOBO=$bonoboRoot"
Write-Output "RESEARCH=$researchRoot"
Write-Output "GORILLA=$gorillaRoot"
```

Expected: `$gorillaRoot` is not inside `$bonoboRoot`.  Stop if it resolves beneath the Bonobo repository.

- [ ] **Step 2: Create the research checkout at the exact revision**

If the target does not exist, run:

```powershell
New-Item -ItemType Directory -Path $researchRoot
git clone --filter=blob:none --no-checkout https://github.com/zdia/gorilla.git $gorillaRoot
git -C $gorillaRoot checkout --detach 6728e85c05ac25357b8f19f541487b9d26a97402
```

If the target already exists, verify that it is the expected Gorilla repository and contains no local changes before
fetching the exact commit.  Never reset or delete an existing research checkout automatically.

- [ ] **Step 3: Verify identity and immutability evidence**

Run:

```powershell
git -C $gorillaRoot remote get-url origin
git -C $gorillaRoot rev-parse HEAD
git -C $gorillaRoot status --short
git -C $gorillaRoot show -s --format='%H%n%T%n%aI%n%s' HEAD
```

Expected: origin equals the approved URL, `HEAD` equals the pinned commit, the worktree is clean, and Git prints the
commit hash, tree hash, author date, and subject for the evidence record.

- [ ] **Step 4: Write the upstream baseline record**

Create `docs/compatibility/gorilla/upstream-baseline.md` with:

- Approved URL, branch observation, exact commit, observation date, and the tree hash from Step 3.
- The upstream GPL-2.0-or-later declaration as a license observation, not a Bonobo license grant.
- The default external path and the rule permitting another external location.
- Exact clone, detached-checkout, identity, and clean-worktree commands.
- The evidence-record fields used by the dossier.
- The no-modification and no-copy rules.
- The reviewed source categories from the subproject specification.
- The update procedure requiring a new pin and dossier delta.

- [ ] **Step 5: Prove that upstream material is absent from Bonobo**

Run:

```powershell
git status --short
git ls-files -z | uv run python -m tools.check_tracked_files
git ls-files | Select-String -Pattern '(^|/)gorilla/(sources|unit-tests)/'
```

Expected: only the new neutral baseline Markdown is untracked; the validators pass; no upstream source path is tracked.

- [ ] **Step 6: Commit the baseline record**

Run:

```powershell
git add docs/compatibility/gorilla/upstream-baseline.md
git diff --cached --check
git commit -m "docs: pin Gorilla research baseline"
```

---

### Task 7: Produce the neutral Gorilla behavior dossier

**Files:**

- Create: `docs/compatibility/gorilla/behavior-dossier.md`
- Modify: `docs/compatibility/gorilla/upstream-baseline.md` only if the evidence convention needs clarification

**Interfaces:**

- Consumes: Detached Gorilla checkout and evidence format from Task 6.
- Produces: Stable behavior identifiers `GOR-BEH-001` onward for the parity matrix and test oracles.

- [ ] **Step 1: Inventory the upstream evidence without modifying it**

Run read-only searches from `$gorillaRoot`:

```powershell
rg -n "proc |method |Save|Open|Lock|Merge|Backup|Import|Export|AutoType|Clipboard|Password|History|Alias|Shortcut" `
  sources/gorilla.tcl sources/pwsafe sources/help.txt unit-tests
git -C $gorillaRoot status --short
```

Expected: the search identifies candidate evidence, and the upstream worktree remains clean.

- [ ] **Step 2: Establish the dossier evidence schema**

Begin `behavior-dossier.md` with:

```markdown
# Password Gorilla Neutral Behavior Dossier

## Evidence convention

Each statement uses a sequential three-digit `GOR-BEH` identifier.  Evidence is recorded as revision, relative path,
line range or test name, evidence kind (`source`, `test`, `help`, `message`, or `observed`), and a neutral behavioral
observation.  Source text, source identifiers, control flow, and UI expression are not reproduced.

## Confidence

- `Confirmed`: supported by at least two independent evidence kinds or one executable black-box observation.
- `Supported`: supported by one direct source, test, or user-documentation item.
- `Unverified`: evidence is incomplete, contradictory, or unavailable in the research environment.
```

- [ ] **Step 3: Analyze vault and record lifecycle behavior**

Read the relevant regions of `sources/gorilla.tcl`, `sources/pwsafe/*.tcl`, `sources/help.txt`, and corresponding unit
tests.  Record separate `GOR-BEH` entries for creation, open/authentication, save/save-as, close, lock, timeout, backup,
recovery, entry create/edit/delete, protected entries, password history, aliases, and shortcuts.

For every entry, write:

```markdown
### GOR-BEH-001 - Create a new vault

- Confidence: `Confirmed`, `Supported`, or `Unverified`.
- Preconditions: User-visible state required before the action.
- Action: User or lifecycle event expressed without Tcl or widget terminology.
- Observable result: State, file, confirmation, or error visible outside the implementation.
- Data effect: Created, changed, preserved, or deleted user-authored data.
- Evidence: Pinned revision, relative path, exact line range or test name, and evidence kind.
- Bonobo note: Compatibility implication stated without implementation direction.
```

Increment the identifier for each analyzed behavior and replace the example statements with evidence-backed facts.

- [ ] **Step 4: Analyze navigation and user workflows**

Add evidence-backed entries for groups, tree operations, selection, search, filtering, recent files, preferences,
password generation and policies, clipboard, browser launch, AutoType, confirmations, and error presentation.

Record behavior rather than pixel layout.  Preserve distinctions that affect keyboard access, destructive-action safety,
or user-authored data.

- [ ] **Step 5: Analyze interchange and edge cases**

Add entries for CSV import/export, merge, PasswordSafe version handling, unknown or unsupported content, malformed
files, database locking, backup behavior, interrupted operations, and relevant platform differences.  Treat upstream
test databases only as research evidence; do not copy them.

- [ ] **Step 6: Run dossier quality and boundary checks**

Run:

```powershell
$dossier = 'docs/compatibility/gorilla/behavior-dossier.md'
rg -n "GOR-BEH-[0-9]{3}" $dossier
rg -n "example statements|Unassigned|INSERT" $dossier
$line = 0; Get-Content -LiteralPath $dossier | ForEach-Object { $line++; if ($_.Length -gt 120) { "$line" } }
git -C $gorillaRoot status --short
git ls-files -z | uv run python -m tools.check_tracked_files
```

Expected: the first command lists every behavior; the token scan prints nothing; the line-length scan prints nothing;
the Gorilla checkout remains clean; the tracked-file audit passes.

- [ ] **Step 7: Commit the neutral dossier**

Run:

```powershell
git add docs/compatibility/gorilla/behavior-dossier.md docs/compatibility/gorilla/upstream-baseline.md
git diff --cached --check
git commit -m "docs: record Gorilla behavior dossier"
```

---

### Task 8: Build the parity matrix and test-oracle catalog

**Files:**

- Create: `docs/compatibility/gorilla/feature-parity-matrix.md`
- Create: `docs/compatibility/gorilla/test-oracles.md`
- Modify: `docs/compatibility/gorilla/behavior-dossier.md` when a missing evidence link is discovered

**Interfaces:**

- Consumes: Three-digit `GOR-BEH` identifiers from Task 7.
- Produces: Three-digit `GOR-FEAT` rows and `GOR-TEST` scenarios for all later subprojects.

- [ ] **Step 1: Create the parity-matrix schema and required feature families**

Create a Markdown table with columns:

```markdown
| ID | Feature family | Disposition | Evidence | Owner | Platforms | Data-loss | Security | Tests |
|---|---|---|---|---|---|---|---|---|
```

Create rows for vault lifecycle, entry lifecycle, groups, search/filter, generator/policies, history, aliases,
shortcuts, protected entries, clipboard, browser launch, AutoType, import, export, merge, backup/recovery, preferences,
recent files, locking/idle timeout, PasswordSafe versions, errors, localization, help, and accessibility-relevant
keyboard behavior.

Add Bonobo-extension rows for URL audit/cleanup, provider conflict safety, Android Autofill, biometric unlock, and the
iOS credential provider.  Use only the dispositions defined in the subproject specification.

- [ ] **Step 2: Assign evidence and owner subprojects**

For every `GOR-FEAT` row:

- Link at least one `GOR-BEH` identifier, or use `Unverified` with a precise evidence gap.
- Assign one of the eight owner subprojects from the program design.
- List applicable desktop, Android, ChromeOS, iOS, or BSD targets.
- Mark data-loss and security relevance as `Critical`, `Material`, or `Routine`.
- Link one or more `GOR-TEST` identifiers created in the next step.

- [ ] **Step 3: Create black-box test-oracle scenarios**

Begin `test-oracles.md` with definitions for evidence authority and synthetic-data rules.  For each matrix feature, add:

```markdown
### GOR-TEST-001 - Create and reopen a synthetic vault

- Authority: `PasswordSafe`, `Gorilla`, or `Bonobo`.
- Evidence: One or more `GOR-BEH` identifiers or an approved Bonobo specification section.
- Synthetic setup: Exact vault state with non-secret example values.
- Action: Exact user or lifecycle operation.
- Expected observation: File, state, prompt, classification, or error visible to a black-box test.
- Preservation requirement: User-authored fields and identifiers that must remain unchanged.
- Cleanup: Files or state removed after the test.
- Required clients: Bonobo plus Gorilla, Password Safe, or both when cross-client confirmation is required.
```

Increment the identifier for each scenario and replace the example statements with exact synthetic test facts.

- [ ] **Step 4: Add no-loss and cross-client oracle coverage**

Include explicit scenarios for:

- Open and save without semantic edits.
- Edit one known field while preserving unrelated and unknown fields.
- Unsupported content failing closed with original encrypted bytes retained.
- Archive creation, reopen, identity verification, and deletion staging.
- Ordinary edit persistence independent of staged URL-audit cleanup.
- External file mutation causing conflict rather than overwrite.
- Gorilla and Password Safe round trips for every claimed metadata extension.

- [ ] **Step 5: Validate matrix closure**

Run:

```powershell
$matrix = 'docs/compatibility/gorilla/feature-parity-matrix.md'
$oracles = 'docs/compatibility/gorilla/test-oracles.md'
$dossier = 'docs/compatibility/gorilla/behavior-dossier.md'
rg -n "GOR-FEAT-[0-9]{3}" $matrix
rg -n "GOR-TEST-[0-9]{3}" $matrix $oracles
rg -n "GOR-BEH-[0-9]{3}" $matrix $oracles $dossier
rg -n "example statements|Unassigned|INSERT" $matrix $oracles
```

Expected: every identifier class is present; the token scan prints nothing; every matrix row has evidence, owner,
platform, relevance, and test values.

- [ ] **Step 6: Commit the compatibility contract**

Run:

```powershell
git add docs/compatibility/gorilla
git diff --cached --check
git commit -m "docs: define Gorilla parity and test oracles"
```

---

### Task 9: Add continuous integration, project memory, and final verification

**Files:**

- Create: `.github/workflows/foundation.yml`
- Create: `docs/project-memory/PROJECT.md`
- Create: `docs/project-memory/STATE.md`
- Create: `docs/project-memory/DECISIONS.md`
- Create: `docs/project-memory/VERIFICATION.md`
- Modify: `README.md`

**Interfaces:**

- Consumes: All local validation commands and compatibility documents from Tasks 1-8.
- Produces: Three-platform CI, durable handoff state, and evidence that subproject 1 is complete.

- [ ] **Step 1: Create the three-platform workflow**

Create `.github/workflows/foundation.yml` with:

```yaml
name: foundation

on:
  push:
  pull_request:

permissions:
  contents: read

jobs:
  quality:
    strategy:
      fail-fast: false
      matrix:
        os: [windows-latest, macos-latest, ubuntu-latest]
    runs-on: ${{ matrix.os }}
    steps:
      - uses: actions/checkout@11d5960a326750d5838078e36cf38b85af677262 # v4
      - uses: astral-sh/setup-uv@d0d8abe699bfb85fec6de9f7adb5ae17292296ff # v6
        with:
          python-version: "3.14"
          enable-cache: true
      - run: uv sync --locked --all-groups
      - run: uv run autopep8 --diff --recursive src tests tools
      - run: uv run ruff check src tests tools
      - run: uv run mypy src tests tools
      - run: uv run python -m pytest
      - run: uv run python -m tools.check_python_structure src tests tools
      - shell: bash
        run: git ls-files -z | uv run python -m tools.check_tracked_files
      - run: uv run bandit -c pyproject.toml -r src tools
      - run: uv run pip-audit
      - run: uv run reuse lint
      - run: uv build
```

Verify the two pinned action commits against their documented major-version refs before committing.  Record each
tag-to-SHA resolution in `docs/project-memory/VERIFICATION.md`; do not introduce floating tags.

- [ ] **Step 2: Write durable project identity and current state**

Create memory files with these responsibilities:

- `PROJECT.md`: product purpose, supported platforms, local-file-first rule, no-loss rule, licensing intent, and links
  to approved specifications.
- `STATE.md`: subproject 1 status, current branch, completed artifacts, active risks, and next approved subproject
  `Lossless PasswordSafe core`.
- `DECISIONS.md`: dated records for clean-room source boundary, Gorilla pin, Python 3.14, tool choices, Git boundary,
  generated-document policy, and external contribution hold.
- `VERIFICATION.md`: exact commands, dates, results, environment limitations, PDF page counts, and CI action pin
  evidence.

Do not include raw command transcripts, machine-specific research paths, credentials, or copied upstream content.

- [ ] **Step 3: Update the README development entry points**

Add concise setup and validation commands:

```powershell
uv python install 3.14
uv sync --locked --all-groups
uv run autopep8 --diff --recursive src tests tools
uv run ruff check src tests tools
uv run mypy src tests tools
uv run python -m pytest
uv run python -m tools.check_python_structure src tests tools
git ls-files -z | uv run python -m tools.check_tracked_files
uv run bandit -c pyproject.toml -r src tools
uv run pip-audit
uv run reuse lint
uv build
```

State explicitly that these commands never require the Gorilla checkout.

- [ ] **Step 4: Generate LaTeX and PDFs for substantial new documents**

For each substantial Markdown document created by this plan, run Pandoc to create a same-basename `.tex`, compile it
with XeLaTeX into `tmp/pdfs/`, and copy the PDF beside its Markdown source for local review.  At minimum this includes:

- The subproject specification.
- This implementation plan.
- The behavior dossier.
- The feature-parity matrix.
- The test-oracle catalog.

Run XeLaTeX until references stabilize.  Render every final PDF page with `pdftoppm`, inspect every page, and correct
all clipping, overlap, glyph, hierarchy, and page-transition defects.  Add only Markdown and LaTeX sources to Git.

- [ ] **Step 5: Run the complete local release gate**

Run:

```powershell
uv sync --locked --all-groups
uv run autopep8 --diff --recursive src tests tools
uv run ruff check src tests tools
uv run mypy src tests tools
uv run python -m pytest
uv run python -m tools.check_python_structure src tests tools
git ls-files -z | uv run python -m tools.check_tracked_files
uv run bandit -c pyproject.toml -r src tools
uv run pip-audit
uv run reuse lint
uv build
git diff --check
git status --short
```

Expected: every validation command passes.  `git status` lists only intended Markdown/LaTeX changes and ignored PDFs do
not appear.

- [ ] **Step 6: Commit CI, memory, and generated LaTeX sources**

Run:

```powershell
git add .github README.md docs/project-memory docs/compatibility docs/specs docs/superpowers/plans
git diff --cached --check
git diff --cached --name-only
git commit -m "ci: complete repository foundation and dossier gates"
```

Expected: no PDF, Gorilla source, shared standards file, vault, log, or temporary render file is staged.

- [ ] **Step 7: Review the completed branch**

Run:

```powershell
git status --short
git log --oneline --decorate main..HEAD
git diff --stat main...HEAD
git diff --check main...HEAD
```

Expected: the branch is clean except ignored local PDFs, commits are task-scoped, and the diff contains foundation and
neutral compatibility artifacts only.  Use the requesting-code-review and verification-before-completion skills before
claiming the subproject is ready to integrate.
