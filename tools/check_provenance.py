"""Check dependency and asset provenance ledger coverage against repository authorities.

The checker derives package versions from uv.lock, direct declarations from pyproject.toml, action pins from the
workflow, document tools from the tracked generator contract, and asset paths from Git's tracked-file namespace.
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess  # nosec B404
import tomllib
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import cast



LEDGER_RELATIVE_PATH = Path("docs/legal/dependency-asset-provenance-ledger.md")
BOTAN_PIN_RELATIVE_PATH = Path("tools/botan-source.json")
DOCUMENTATION_TOOLS = frozenset({"pandoc", "xelatex", "pdfinfo", "pdftoppm"})
ACTION_USE_LINE = re.compile(r"(?m)^\s*-?\s*uses:\s*(.*?)\s*$")
PINNED_ACTION_REVISION = re.compile(r"[0-9a-f]{40}")
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



#### Compare the Botan machine-readable pin with its native-dependency ledger row.
####
#### The binary build has no Python package declaration, so this explicit comparison
#### keeps the reviewed release identity, archive digest, and minimized module set in
#### one checked supply-chain boundary.
####
def check_botan_provenance_sources(pin_source: str, ledger_source: str) -> tuple[ProvenanceViolation, ...]:
    violations: list[ProvenanceViolation] = []
    try:
        pin_document = json.loads(pin_source)
    except json.JSONDecodeError:
        return (ProvenanceViolation("Botan source pin is invalid JSON"),)
    if not isinstance(pin_document, dict):
        return (ProvenanceViolation("Botan source pin must be a JSON object"),)
    pin = cast(dict[str, object], pin_document)
    version = pin.get("version")
    archive = pin.get("archive")
    source = pin.get("source")
    sha256 = pin.get("sha256")
    modules = pin.get("modules")
    if (
        not all(isinstance(value, str) and value for value in (version, archive, source, sha256))
        or not isinstance(modules, list)
        or any(not isinstance(module, str) or not module for module in modules)
    ):
        return (ProvenanceViolation("Botan source pin fields are invalid"),)

    rows = _ledger_table(ledger_source, "Native dependencies", "Fact")
    violations.extend(
        _check_complete_rows(
            rows,
            "Fact",
            (
                "Name",
                "Fact",
                "Value",
                "Terms",
                "Dist",
                "Evidence",
                "Review",
            ),
            "native dependency",
        )
    )
    botan_rows = tuple(row for row in rows if row.get("Name") == "Botan")
    rows_by_fact = {row.get("Fact", ""): row for row in botan_rows}
    expected_values = {
        "Relationship": "DNR",
        "Version": version,
        "Source": source,
        "Archive": archive,
        "SHA-256": sha256,
        "Modules": ",".join(cast(list[str], modules)),
    }
    mismatch_messages = {
        "Relationship": "Botan native dependency relationship must be DNR",
        "Version": "Botan version does not match source pin",
        "Source": "Botan source does not match source pin",
        "Archive": "Botan archive does not match source pin",
        "SHA-256": "Botan archive checksum does not match source pin",
        "Modules": "Botan enabled modules do not match source pin",
    }
    for column, expected_value in expected_values.items():
        row = rows_by_fact.get(column)
        actual_value = "" if row is None else row.get("Value", "")
        if column == "SHA-256":
            actual_value = actual_value.replace(" ", "")
        if actual_value != expected_value:
            violations.append(ProvenanceViolation(mismatch_messages[column]))
    for row in botan_rows:
        for column, expected_value in {"Terms": "BSD-2-Clause", "Dist": "A"}.items():
            if row.get(column) != expected_value:
                violations.append(ProvenanceViolation(f"Botan native dependency {column} must be {expected_value}"))
    return tuple(violations)



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



#### Parse every workflow action reference and reject any revision that is not an exact immutable pin.
####
def _workflow_action_references(
    workflow_source: str,
) -> tuple[tuple[tuple[str, str], ...], tuple[ProvenanceViolation, ...]]:
    references: list[tuple[str, str]] = []
    violations: list[ProvenanceViolation] = []
    for raw_value in ACTION_USE_LINE.findall(workflow_source):
        value = re.sub(r"\s+#.*$", "", raw_value).strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in {'"', "'"}:
            value = value[1:-1]
        action, separator, revision = value.rpartition("@")
        if not separator or not action or PINNED_ACTION_REVISION.fullmatch(revision) is None:
            violations.append(
                ProvenanceViolation(
                    f"GitHub Action revision must be exactly lowercase 40-hex: {value}"
                )
            )
            continue
        references.append((action, revision))
    return tuple(references), tuple(violations)



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
    workflow_actions, action_pin_violations = _workflow_action_references(workflow_source)
    violations.extend(action_pin_violations)
    if not action_pin_violations:
        for name, revision in sorted(workflow_actions):
            row = actions_by_name.get(name)
            if row is None:
                violations.append(ProvenanceViolation(f"GitHub Action is missing from the ledger: {name}"))
            elif row.get("Revision") != revision:
                violations.append(ProvenanceViolation(f"GitHub Action pin is stale: {name}"))
        workflow_action_names = {name for name, _ in workflow_actions}
        for extra in sorted(set(actions_by_name) - workflow_action_names):
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
    assets_by_path = {row.get("Path", ""): row for row in asset_rows}
    documented_assets = set(assets_by_path)
    tracked_assets = _asset_paths(tracked_paths)
    for missing in sorted(tracked_assets - documented_assets):
        violations.append(ProvenanceViolation(f"repository asset is missing from the ledger: {missing}"))
    for extra in sorted(documented_assets - tracked_assets):
        violations.append(ProvenanceViolation(f"repository asset ledger row is not tracked: {extra}"))
    for path, row in sorted(assets_by_path.items()):
        if (
            path == "LICENSES/GPL-3.0-or-later.txt" or path.endswith("/py.typed")
        ) and row.get("Dist") != "S+W":
            violations.append(
                ProvenanceViolation(f"repository asset {path} distribution must be S+W")
            )
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
    botan_pin_path = repository_root / BOTAN_PIN_RELATIVE_PATH
    if not botan_pin_path.is_file():
        return (ProvenanceViolation(f"Botan source pin is missing: {BOTAN_PIN_RELATIVE_PATH.as_posix()}"),)
    workflow_root = repository_root / ".github" / "workflows"
    workflow_paths = tuple(sorted((*workflow_root.glob("*.yml"), *workflow_root.glob("*.yaml"))))
    workflow_source = "\n".join(path.read_text(encoding="utf-8") for path in workflow_paths)
    ledger_source = ledger_path.read_text(encoding="utf-8")
    return (
        *check_provenance_sources(
            (repository_root / "pyproject.toml").read_text(encoding="utf-8"),
            (repository_root / "uv.lock").read_text(encoding="utf-8"),
            workflow_source,
            ledger_source,
            _tracked_paths(repository_root),
        ),
        *check_botan_provenance_sources(botan_pin_path.read_text(encoding="utf-8"), ledger_source),
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
