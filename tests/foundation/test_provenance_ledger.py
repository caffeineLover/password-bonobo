"""Verify dependency, action, documentation-tool, and repository-asset ledger freshness."""

from pathlib import Path

from tools.check_provenance import check_provenance_sources, check_repository_provenance



#### Return a complete small ledger whose expected facts are independent test literals.
####
def _synthetic_ledger() -> str:
    return """# Dependency and Asset Provenance Ledger

## Python packages

| Name | Rel | Constraint | Version | Origin | Terms | Use | Dist | Evidence | Review |
|---|---|---|---|---|---|---|---|---|---|
| hatchling | DB | hatchling>=1.27,<2 | NOASSERTION | NOASSERTION | NOASSERTION | BT | N | P | P |
| packaging | T | N | 25.0 | https://pypi.org/simple | NOASSERTION | TS | N | L | P |
| pytest | DD | pytest>=9,<10 | 9.1.0 | https://pypi.org/simple | NOASSERTION | BT | N | L | P |

## GitHub Actions

| Action | Version | Revision | Origin | Terms | Use | Dist | Evidence | Review |
|---|---|---|---|---|---|---|---|---|
|`actions/checkout`|v4|`aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa`|`github.com/actions/checkout`|N|CI|N|W|P|

## Documentation tools

| Tool | Version | Origin | Terms | Use | Dist | Evidence | Review |
|---|---|---|---|---|---|---|---|
|pandoc|3.10.2|pandoc.org|N|DG|N|V|P|
|xelatex|4.16|miktex.org|N|DG|N|V|P|
|pdfinfo|24.04.0|poppler.freedesktop.org|N|DG|N|V|P|
|pdftoppm|24.04.0|poppler.freedesktop.org|N|DG|N|V|P|

## Repository assets

| Path | Version | Origin | Terms | Use | Dist | Evidence | Review |
|---|---|---|---|---|---|---|---|
|`LICENSES/GPL-3.0-or-later.txt`|GPL-3.0-or-later|REUSE|GPL-3.0-or-later|LT|S+W|R|V|
|`src/sample/py.typed`|Current|Bonobo|GPL-3.0-or-later|TM|S+W|R|V|
"""



#### Accept exact lock, declaration, workflow, tool, and asset coverage.
####
def test_complete_provenance_ledger_passes() -> None:
    pyproject = """[build-system]
requires = ["hatchling>=1.27,<2"]

[project]
dependencies = []

[dependency-groups]
dev = ["pytest>=9,<10"]
"""
    lock = """version = 1

[[package]]
name = "packaging"
version = "25.0"
source = { registry = "https://pypi.org/simple" }

[[package]]
name = "pytest"
version = "9.1.0"
source = { registry = "https://pypi.org/simple" }

[[package]]
name = "sample"
version = "0.0.0"
source = { editable = "." }
"""
    workflow = "uses: actions/checkout@aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n"
    tracked_paths = (Path("LICENSES/GPL-3.0-or-later.txt"), Path("src/sample/py.typed"))

    assert check_provenance_sources(pyproject, lock, workflow, _synthetic_ledger(), tracked_paths) == ()



#### Report stale resolved versions and newly uncovered actions and assets.
####
def test_provenance_ledger_detects_freshness_and_coverage_drift() -> None:
    pyproject = """[build-system]
requires = ["hatchling>=1.27,<2"]
[project]
dependencies = []
[dependency-groups]
dev = ["pytest>=9,<10"]
"""
    lock = _synthetic_ledger_lock_with_packaging_version("26.0")
    workflow = (
        "uses: actions/checkout@aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n"
        "uses: owner/new-action@bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\n"
    )
    tracked_paths = (
        Path("LICENSES/GPL-3.0-or-later.txt"),
        Path("src/sample/py.typed"),
        Path("docs/pandoc/new-filter.lua"),
    )

    messages = tuple(
        violation.message
        for violation in check_provenance_sources(
            pyproject,
            lock,
            workflow,
            _synthetic_ledger(),
            tracked_paths,
        )
    )

    assert "Python package packaging ledger version 25.0 does not match uv.lock 26.0" in messages
    assert "GitHub Action is missing from the ledger: owner/new-action" in messages
    assert "repository asset is missing from the ledger: docs/pandoc/new-filter.lua" in messages



#### Reject present rows whose required review facts are blank.
####
def test_provenance_ledger_rejects_incomplete_review_cells() -> None:
    pyproject = """[build-system]
requires = ["hatchling>=1.27,<2"]
[project]
dependencies = []
[dependency-groups]
dev = ["pytest>=9,<10"]
"""
    workflow = "uses: actions/checkout@aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n"
    ledger = _synthetic_ledger()
    ledger = ledger.replace("|`github.com/actions/checkout`|N|", "||N|", 1)
    ledger = ledger.replace("|pandoc.org|N|", "|pandoc.org||", 1)
    ledger = ledger.replace("|LT|S+W|R|V|", "|LT|S+W||V|", 1)

    messages = tuple(
        violation.message
        for violation in check_provenance_sources(
            pyproject,
            _synthetic_ledger_lock_with_packaging_version("25.0"),
            workflow,
            ledger,
            (Path("LICENSES/GPL-3.0-or-later.txt"), Path("src/sample/py.typed")),
        )
    )

    assert "GitHub Action actions/checkout lacks Origin" in messages
    assert "documentation tool pandoc lacks Terms" in messages
    assert "repository asset LICENSES/GPL-3.0-or-later.txt lacks Evidence" in messages



#### Reject a floating GitHub Action tag before comparing it with ledger facts.
####
def test_provenance_rejects_floating_action_tag() -> None:
    messages = _messages_for_workflow("uses: actions/checkout@v7\n")

    assert "GitHub Action revision must be exactly lowercase 40-hex: actions/checkout@v7" in messages



#### Reject a floating GitHub Action branch before comparing it with ledger facts.
####
def test_provenance_rejects_floating_action_branch() -> None:
    messages = _messages_for_workflow("uses: actions/checkout@stable\n")

    assert "GitHub Action revision must be exactly lowercase 40-hex: actions/checkout@stable" in messages



#### Reject an abbreviated GitHub Action commit before comparing it with ledger facts.
####
def test_provenance_rejects_abbreviated_action_revision() -> None:
    messages = _messages_for_workflow("uses: actions/checkout@abcdef1\n")

    assert "GitHub Action revision must be exactly lowercase 40-hex: actions/checkout@abcdef1" in messages



#### Reject an uppercase GitHub Action commit before comparing it with ledger facts.
####
def test_provenance_rejects_uppercase_action_revision() -> None:
    revision = "ABCDEFABCDEFABCDEFABCDEFABCDEFABCDEFABCD"
    messages = _messages_for_workflow(f"uses: actions/checkout@{revision}\n")

    assert f"GitHub Action revision must be exactly lowercase 40-hex: actions/checkout@{revision}" in messages



#### Enforce combined sdist-and-wheel facts for packaged repository assets.
####
def test_provenance_rejects_inaccurate_packaged_asset_distribution() -> None:
    ledger = _synthetic_ledger().replace("|LT|S+W|R|V|", "|LT|W|R|V|", 1)
    messages = _messages_for_workflow(
        "uses: actions/checkout@aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n",
        ledger=ledger,
    )

    assert "repository asset LICENSES/GPL-3.0-or-later.txt distribution must be S+W" in messages



#### Return a synthetic lock while varying one independently asserted resolved version.
####
def _synthetic_ledger_lock_with_packaging_version(packaging_version: str) -> str:
    return f'''version = 1

[[package]]
name = "packaging"
version = "{packaging_version}"
source = {{ registry = "https://pypi.org/simple" }}

[[package]]
name = "pytest"
version = "9.1.0"
source = {{ registry = "https://pypi.org/simple" }}

[[package]]
name = "sample"
version = "0.0.0"
source = {{ editable = "." }}
'''



#### Return provenance findings for one synthetic workflow and otherwise-complete authorities.
####
def _messages_for_workflow(workflow: str, *, ledger: str | None = None) -> tuple[str, ...]:
    pyproject = """[build-system]
requires = ["hatchling>=1.27,<2"]
[project]
dependencies = []
[dependency-groups]
dev = ["pytest>=9,<10"]
"""
    violations = check_provenance_sources(
        pyproject,
        _synthetic_ledger_lock_with_packaging_version("25.0"),
        workflow,
        _synthetic_ledger() if ledger is None else ledger,
        (Path("LICENSES/GPL-3.0-or-later.txt"), Path("src/sample/py.typed")),
    )
    return tuple(violation.message for violation in violations)



#### Check the repository's tracked paired provenance ledger through the release-gate entry point.
####
def test_repository_provenance_ledger_passes() -> None:
    assert check_repository_provenance(Path.cwd()) == ()
