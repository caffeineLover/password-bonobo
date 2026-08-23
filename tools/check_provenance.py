"""Check dependency and asset provenance ledger coverage against repository authorities.

The checker derives package versions from uv.lock, direct declarations from pyproject.toml, action pins from the
workflow, document tools from the tracked generator contract, and asset paths from Git's tracked-file namespace.
"""

from __future__ import annotations

import argparse
import re
import subprocess  # nosec B404
import tomllib
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import cast



LEDGER_RELATIVE_PATH = Path("docs/legal/dependency-asset-provenance-ledger.md")
DOCUMENTATION_TOOLS = frozenset({"pandoc", "xelatex", "pdfinfo", "pdftoppm"})
ACTION_REFERENCE = re.compile(r"(?m)^\s*-?\s*uses:\s*([^@\s]+)@([0-9a-f]{40})\s*(?:#.*)?$")
REQUIREMENT_NAME = re.compile(r"^([A-Za-z0-9_.-]+)(?:\[[^]]+\])?")



#### Describe one stale, missing, or unsupported provenance-ledger fact.
####
@dataclass(frozen=True, slots=True)
class ProvenanceViolation:
    message: str



#### Describe one resolved non-project package from uv.lock.
####
@dataclass(frozen=True, slots=True)
class LockedPackage:
    name: str
    version: str
    origin: str



#### Normalize Python distribution names by the packaging specification's comparison rule.
####
def _normalize_name(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()



#### Return a validated list of strings from one TOML array value.
####
def _string_list(value: object, field: str) -> tuple[str, ...]:
    if not isinstance(value, list) or any(not isinstance(item, str) for item in value):
        raise ValueError(f"{field} must be an array of strings")
    return tuple(cast(list[str], value))



#### Return direct requirement text and scope labels keyed by normalized distribution name.
####
def _direct_requirements(pyproject_source: str) -> dict[str, tuple[tuple[str, str], ...]]:
    document = tomllib.loads(pyproject_source)
    direct: dict[str, list[tuple[str, str]]] = {}

    build_system = document.get("build-system", {})
    if not isinstance(build_system, dict):
        raise ValueError("build-system must be a table")
    requirement_groups: list[tuple[str, tuple[str, ...]]] = [
        ("build", _string_list(build_system.get("requires", []), "build-system.requires")),
    ]

    project = document.get("project", {})
    if not isinstance(project, dict):
        raise ValueError("project must be a table")
    requirement_groups.append(
        ("runtime", _string_list(project.get("dependencies", []), "project.dependencies"))
    )

    dependency_groups = document.get("dependency-groups", {})
    if not isinstance(dependency_groups, dict):
        raise ValueError("dependency-groups must be a table")
    for group_name, requirements in dependency_groups.items():
        scope = "development" if group_name == "dev" else f"development {group_name}"
        requirement_groups.append(
            (scope, _string_list(requirements, f"dependency-groups.{group_name}"))
        )

    for scope, requirements in requirement_groups:
        for requirement in requirements:
            match = REQUIREMENT_NAME.match(requirement)
            if match is None:
                raise ValueError(f"cannot parse direct requirement: {requirement}")
            name = _normalize_name(match.group(1))
            direct.setdefault(name, []).append((scope, requirement))
    return {name: tuple(values) for name, values in direct.items()}



#### Return resolved registry packages while excluding the editable local project.
####
def _locked_packages(lock_source: str) -> tuple[LockedPackage, ...]:
    document = tomllib.loads(lock_source)
    packages = document.get("package", [])
    if not isinstance(packages, list):
        raise ValueError("uv.lock package value must be an array of tables")
    resolved: list[LockedPackage] = []
    for raw_package in packages:
        if not isinstance(raw_package, dict):
            raise ValueError("uv.lock package entry must be a table")
        source = raw_package.get("source", {})
        if not isinstance(source, dict):
            raise ValueError("uv.lock package source must be a table")
        if "editable" in source:
            continue
        name = raw_package.get("name")
        version = raw_package.get("version")
        origin = source.get("registry", "NOASSERTION")
        if not isinstance(name, str) or not isinstance(version, str) or not isinstance(origin, str):
            raise ValueError("uv.lock registry package requires string name, version, and origin")
        resolved.append(LockedPackage(_normalize_name(name), version, origin))
    return tuple(sorted(resolved, key=lambda package: package.name))



#### Normalize one ledger cell while allowing code formatting for long breakable values.
####
def _normalize_ledger_cell(raw_cell: str) -> str:
    cell = raw_cell.strip()
    if cell.startswith("`") and cell.endswith("`"):
        return cell[1:-1]
    return cell



#### Parse a Markdown table below one exact second-level heading.
####
def _ledger_table(ledger_source: str, heading: str, key_column: str) -> tuple[dict[str, str], ...]:
    section_marker = f"## {heading}"
    start = ledger_source.find(section_marker)
    if start < 0:
        return ()
    section = ledger_source[start + len(section_marker):]
    next_heading = section.find("\n## ")
    if next_heading >= 0:
        section = section[:next_heading]

    headings: tuple[str, ...] | None = None
    rows: list[dict[str, str]] = []
    for line in section.splitlines():
        if not line.startswith("|"):
            continue
        cells = tuple(_normalize_ledger_cell(raw_cell) for raw_cell in line.strip().strip("|").split("|"))
        if key_column in cells:
            headings = cells
            continue
        if headings is None or not cells or set(cells) == {"---"}:
            continue
        if len(cells) == len(headings):
            rows.append(dict(zip(headings, cells, strict=True)))
    return tuple(rows)



#### Return direct relationship prose and exact declaration text for one resolved package.
####
def _expected_direct_cells(
    name: str,
    direct: Mapping[str, tuple[tuple[str, str], ...]],
) -> tuple[str, str]:
    declarations = direct.get(name, ())
    if not declarations:
        return "T", "N"
    scopes = tuple(dict.fromkeys(scope for scope, _ in declarations))
    requirements = tuple(dict.fromkeys(requirement for _, requirement in declarations))
    scope_codes = {"build": "DB", "runtime": "DR", "development": "DD"}
    relationship = "+".join(scope_codes.get(scope, f"DD:{scope}") for scope in scopes)
    return relationship, "; ".join(requirements)



#### Return tracked paths that function as repository-distributed or generation-support assets.
####
def _asset_paths(tracked_paths: Sequence[Path]) -> frozenset[str]:
    assets: set[str] = set()
    for path in tracked_paths:
        posix_path = path.as_posix()
        if (
            posix_path.startswith("LICENSES/")
            or posix_path.startswith("docs/pandoc/")
            or posix_path.startswith("tests/fixtures/")
            or posix_path.endswith("/py.typed")
        ):
            assets.add(posix_path)
    return frozenset(assets)



#### Report duplicate row keys and blank required cells for one ledger table.
####
def _check_complete_rows(
    rows: Sequence[Mapping[str, str]],
    key_column: str,
    required_columns: Sequence[str],
    label: str,
) -> tuple[ProvenanceViolation, ...]:
    violations: list[ProvenanceViolation] = []
    keys = tuple(row.get(key_column, "") for row in rows)
    if len(set(keys)) != len(keys):
        violations.append(ProvenanceViolation(f"{label} ledger names must be unique"))
    for row in rows:
        key = row.get(key_column, "")
        for column in required_columns:
            if not row.get(column):
                violations.append(ProvenanceViolation(f"{label} {key} lacks {column}"))
    return tuple(violations)



#### Check ledger freshness and coverage against supplied repository-source snapshots.
####
def check_provenance_sources(
    pyproject_source: str,
    lock_source: str,
    workflow_source: str,
    ledger_source: str,
    tracked_paths: Sequence[Path],
) -> tuple[ProvenanceViolation, ...]:
    violations: list[ProvenanceViolation] = []
    direct = _direct_requirements(pyproject_source)
    locked = _locked_packages(lock_source)
    package_rows = _ledger_table(ledger_source, "Python packages", "Name")
    packages_by_name = {row.get("Name", ""): row for row in package_rows}
    violations.extend(
        _check_complete_rows(
            package_rows,
            "Name",
            ("Name", "Rel", "Constraint", "Version", "Origin", "Terms", "Use", "Dist", "Evidence", "Review"),
            "Python package",
        )
    )
    locked_names = {package.name for package in locked}
    for package in locked:
        row = packages_by_name.get(package.name)
        if row is None:
            violations.append(ProvenanceViolation(f"Python package is missing from the ledger: {package.name}"))
            continue
        if row.get("Version") != package.version:
            violations.append(
                ProvenanceViolation(
                    f"Python package {package.name} ledger version {row.get('Version', '')} "
                    f"does not match uv.lock {package.version}"
                )
            )
        if row.get("Origin") != package.origin:
            violations.append(ProvenanceViolation(f"Python package {package.name} origin does not match uv.lock"))
        expected_relationship, expected_constraint = _expected_direct_cells(package.name, direct)
        if row.get("Rel") != expected_relationship:
            violations.append(
                ProvenanceViolation(f"Python package {package.name} relationship is stale")
            )
        if row.get("Constraint") != expected_constraint:
            violations.append(
                ProvenanceViolation(f"Python package {package.name} declared constraint is stale")
            )
    for name in sorted(set(direct) - locked_names):
        row = packages_by_name.get(name)
        if row is None:
            violations.append(ProvenanceViolation(f"declared Python dependency is missing from the ledger: {name}"))
            continue
        expected_relationship, expected_constraint = _expected_direct_cells(name, direct)
        if row.get("Rel") != expected_relationship:
            violations.append(ProvenanceViolation(f"Python package {name} relationship is stale"))
        if row.get("Constraint") != expected_constraint:
            violations.append(ProvenanceViolation(f"Python package {name} declared constraint is stale"))
        if row.get("Version") != "NOASSERTION":
            violations.append(
                ProvenanceViolation(f"unlocked Python build dependency {name} must record unresolved version status")
            )
    for extra in sorted(set(packages_by_name) - locked_names - set(direct)):
        violations.append(ProvenanceViolation(f"Python package ledger row is absent from uv.lock: {extra}"))

    action_rows = _ledger_table(ledger_source, "GitHub Actions", "Action")
    actions_by_name = {row.get("Action", ""): row for row in action_rows}
    violations.extend(
        _check_complete_rows(
            action_rows,
            "Action",
            ("Action", "Version", "Revision", "Origin", "Terms", "Use", "Dist", "Evidence", "Review"),
            "GitHub Action",
        )
    )
    workflow_actions = {name: revision for name, revision in ACTION_REFERENCE.findall(workflow_source)}
    for name, revision in sorted(workflow_actions.items()):
        row = actions_by_name.get(name)
        if row is None:
            violations.append(ProvenanceViolation(f"GitHub Action is missing from the ledger: {name}"))
        elif row.get("Revision") != revision:
            violations.append(ProvenanceViolation(f"GitHub Action pin is stale: {name}"))
    for extra in sorted(set(actions_by_name) - set(workflow_actions)):
        violations.append(ProvenanceViolation(f"GitHub Action ledger row is absent from the workflow: {extra}"))

    tool_rows = _ledger_table(ledger_source, "Documentation tools", "Tool")
    violations.extend(
        _check_complete_rows(
            tool_rows,
            "Tool",
            ("Tool", "Version", "Origin", "Terms", "Use", "Dist", "Evidence", "Review"),
            "documentation tool",
        )
    )
    documented_tools = {row.get("Tool", "") for row in tool_rows}
    for missing in sorted(DOCUMENTATION_TOOLS - documented_tools):
        violations.append(ProvenanceViolation(f"documentation tool is missing from the ledger: {missing}"))
    for extra in sorted(documented_tools - DOCUMENTATION_TOOLS):
        violations.append(ProvenanceViolation(f"documentation tool is absent from the generator: {extra}"))

    asset_rows = _ledger_table(ledger_source, "Repository assets", "Path")
    violations.extend(
        _check_complete_rows(
            asset_rows,
            "Path",
            ("Path", "Version", "Origin", "Terms", "Use", "Dist", "Evidence", "Review"),
            "repository asset",
        )
    )
    documented_assets = {row.get("Path", "") for row in asset_rows}
    tracked_assets = _asset_paths(tracked_paths)
    for missing in sorted(tracked_assets - documented_assets):
        violations.append(ProvenanceViolation(f"repository asset is missing from the ledger: {missing}"))
    for extra in sorted(documented_assets - tracked_assets):
        violations.append(ProvenanceViolation(f"repository asset ledger row is not tracked: {extra}"))
    return tuple(violations)



#### Read the tracked path namespace through Git's NUL-safe output.
####
def _tracked_paths(repository_root: Path) -> tuple[Path, ...]:
    # The executable and arguments are fixed literals, and shell expansion remains disabled.
    result = subprocess.run(  # nosec B603
        ("git", "ls-files", "-z"),
        cwd=repository_root,
        capture_output=True,
        check=False,
    )
    if result.returncode != 0:
        raise RuntimeError(result.stderr.decode("utf-8", errors="replace"))
    return tuple(
        Path(record.decode("utf-8", errors="surrogateescape"))
        for record in result.stdout.split(b"\0")
        if record
    )



#### Check the repository's canonical ledger against all tracked authorities.
####
def check_repository_provenance(repository_root: Path) -> tuple[ProvenanceViolation, ...]:
    ledger_path = repository_root / LEDGER_RELATIVE_PATH
    if not ledger_path.is_file():
        return (ProvenanceViolation(f"provenance ledger is missing: {LEDGER_RELATIVE_PATH.as_posix()}"),)
    return check_provenance_sources(
        (repository_root / "pyproject.toml").read_text(encoding="utf-8"),
        (repository_root / "uv.lock").read_text(encoding="utf-8"),
        (repository_root / ".github/workflows/foundation.yml").read_text(encoding="utf-8"),
        ledger_path.read_text(encoding="utf-8"),
        _tracked_paths(repository_root),
    )



#### Print provenance findings and return process status for local and hosted gates.
####
def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("repository_root", nargs="?", type=Path, default=Path.cwd())
    arguments = parser.parse_args(argv)
    violations = check_repository_provenance(cast(Path, arguments.repository_root).resolve())
    for violation in violations:
        print(violation.message)
    if violations:
        return 1
    print("provenance ledger: package, action, documentation-tool, and asset coverage is current")
    return 0


# Return the command status to the invoking shell without configuring runtime logging.
if __name__ == "__main__":
    raise SystemExit(main())
