"""Enforce compatibility traceability and the clean-room expression boundary.

The checker validates only Bonobo-authored compatibility records.  It never opens or imports the external Gorilla
checkout, and its allowlist is limited to neutral platform, format-document, and local bootstrap terms.
"""

from __future__ import annotations

import argparse
import hashlib
import re
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path



COMPATIBILITY_MARKDOWN_PATHS = (
    Path("docs/compatibility/gorilla/behavior-dossier.md"),
    Path("docs/compatibility/gorilla/feature-parity-matrix.md"),
    Path("docs/compatibility/gorilla/test-oracles.md"),
    Path("docs/compatibility/gorilla/upstream-baseline.md"),
)
CAMEL_CASE_IDENTIFIER = re.compile(r"\b[a-z][a-z0-9]{0,20}(?:[A-Z][A-Za-z0-9]*)+\b")
WORD_IDENTIFIER = re.compile(r"\b[A-Za-z_][A-Za-z0-9_]*\b")
BEHAVIOR_HEADING = re.compile(r"(?m)^### (GOR-BEH-\d{3})\b")
FEATURE_IDENTIFIER = re.compile(r"GOR-FEAT-(\d{3})")
TEST_HEADING = re.compile(r"(?m)^### (GOR-TEST-\d{3})\b")
BEHAVIOR_REFERENCE = re.compile(r"GOR-BEH-\d{3}")
TEST_REFERENCE = re.compile(r"GOR-TEST-\d{3}")
FEATURE_HEADER_SCHEMA = (
    "ID",
    "Feature family",
    "Disposition",
    "Evidence",
    "Owner",
    "Platforms",
    "Data-loss",
    "Security",
    "Tests",
)
LOCAL_SDD_EVIDENCE_ROOT = Path(".superpowers/sdd")
PROHIBITED_LOCAL_EVIDENCE_IDENTIFIER_DIGESTS = frozenset(
    {
        "09602e9d9076d9b934d439545ef895fb792d3e684df987dbb37775239273e37c",
        "ca2b5c9ce1579c2ab4ea3756422f6c8420fe4ad3d089943bc480951bdcec6395",
    }
)
CLEAN_ROOM_ALLOWLIST = {
    # Official platform spelling is user-visible vocabulary, not an upstream implementation identifier.
    "macOS",
    "iOS",
    # The official PasswordSafe format document uses this stable filename.
    "formatV3",
    # This is Git's strict ISO-8601 author-date pretty-format placeholder in the baseline command.
    "aI",
    # These variables belong to Bonobo's documented local checkout bootstrap command.
    "bonoboRoot",
    "researchRoot",
    "gorillaRoot",
}



#### Describe one compatibility-policy failure without exposing external source content.
####
@dataclass(frozen=True, slots=True)
class CompatibilityViolation:
    path: Path
    line: int
    message: str
    token: str | None = None



#### Describe traceability totals for release evidence and project memory.
####
@dataclass(frozen=True, slots=True)
class CompatibilityCounts:
    behaviors: int
    features: int
    oracles: int



#### Split one Markdown table row into trimmed cell values.
####
def _split_table_row(line: str) -> tuple[str, ...]:
    return tuple(cell.strip() for cell in line.strip().strip("|").split("|"))



#### Return feature rows and exact-schema violations without skipping feature-looking input.
####
def _parse_feature_rows(
    matrix_source: str,
) -> tuple[tuple[dict[str, str], ...], tuple[CompatibilityViolation, ...]]:
    matrix_path = COMPATIBILITY_MARKDOWN_PATHS[1]
    found_header = False
    rows: list[dict[str, str]] = []
    violations: list[CompatibilityViolation] = []
    for line_number, line in enumerate(matrix_source.splitlines(), start=1):
        if not line.lstrip().startswith("|"):
            continue
        cells = _split_table_row(line)
        if cells and cells[0] == "ID":
            found_header = True
            if cells != FEATURE_HEADER_SCHEMA:
                violations.append(
                    CompatibilityViolation(
                        matrix_path,
                        line_number,
                        "feature table header does not match the required schema",
                    )
                )
            continue
        if not cells or not cells[0].startswith("GOR-FEAT-"):
            continue
        if FEATURE_IDENTIFIER.fullmatch(cells[0]) is None:
            violations.append(
                CompatibilityViolation(
                    matrix_path,
                    line_number,
                    f"feature row {cells[0]} has malformed identifier; expected GOR-FEAT-NNN",
                )
            )
            continue
        if len(cells) != len(FEATURE_HEADER_SCHEMA):
            violations.append(
                CompatibilityViolation(
                    matrix_path,
                    line_number,
                    f"feature row {cells[0]} has {len(cells)} cells; expected {len(FEATURE_HEADER_SCHEMA)}",
                )
            )
            continue
        rows.append(dict(zip(FEATURE_HEADER_SCHEMA, cells, strict=True)))
    if not found_header:
        violations.append(
            CompatibilityViolation(
                matrix_path,
                1,
                "feature table header does not match the required schema",
            )
        )
    return tuple(rows), tuple(violations)



#### Return valid feature rows keyed by the required schema.
####
def _feature_rows(matrix_source: str) -> tuple[dict[str, str], ...]:
    rows, _ = _parse_feature_rows(matrix_source)
    return rows



#### Return oracle sections keyed by their stable test identifiers.
####
def _oracle_sections(oracles_source: str) -> dict[str, str]:
    matches = tuple(TEST_HEADING.finditer(oracles_source))
    sections: dict[str, str] = {}
    for index, match in enumerate(matches):
        end = matches[index + 1].start() if index + 1 < len(matches) else len(oracles_source)
        sections[match.group(1)] = oracles_source[match.start():end]
    return sections



#### Expand full and compact numeric identifier ranges without inferring missing authored evidence.
####
def _expand_references(source: str, prefix: str) -> tuple[str, ...]:
    separator = f"(?:{chr(0x2013)}|-)"
    pattern = re.compile(
        rf"{re.escape(prefix)}-(\d{{3}})(?:\s*{separator}\s*(?:{re.escape(prefix)}-)?(\d{{3}}))?"
    )
    references: list[str] = []
    for match in pattern.finditer(source):
        start = int(match.group(1))
        end = int(match.group(2)) if match.group(2) is not None else start
        references.extend(f"{prefix}-{number:03d}" for number in range(start, end + 1))
    return tuple(references)



#### Check one authored compatibility source for short camelCase implementation identifiers.
####
def check_clean_room_source(path: Path, source: str) -> tuple[CompatibilityViolation, ...]:
    violations: list[CompatibilityViolation] = []
    for line_number, line in enumerate(source.splitlines(), start=1):
        for match in CAMEL_CASE_IDENTIFIER.finditer(line):
            token = match.group(0)
            if token not in CLEAN_ROOM_ALLOWLIST:
                violations.append(
                    CompatibilityViolation(
                        path,
                        line_number,
                        "short camelCase implementation identifier is prohibited",
                        token,
                    )
                )
    return tuple(violations)



#### Check optional ignored SDD Markdown through non-reversible identifier fingerprints.
####
def check_local_evidence_corpus(
    repository_root: Path,
    *,
    forbidden_identifier_digests: frozenset[str] = PROHIBITED_LOCAL_EVIDENCE_IDENTIFIER_DIGESTS,
) -> tuple[CompatibilityViolation, ...]:
    evidence_root = repository_root / LOCAL_SDD_EVIDENCE_ROOT
    if not evidence_root.is_dir():
        return ()
    violations: list[CompatibilityViolation] = []
    for path in sorted(evidence_root.rglob("*.md")):
        source = path.read_text(encoding="utf-8")
        for line_number, line in enumerate(source.splitlines(), start=1):
            for match in WORD_IDENTIFIER.finditer(line):
                digest = hashlib.sha256(match.group(0).encode("utf-8")).hexdigest()
                if digest in forbidden_identifier_digests:
                    violations.append(
                        CompatibilityViolation(
                            path.relative_to(repository_root),
                            line_number,
                            "prohibited upstream identifier is present in local SDD evidence",
                        )
                    )
    return tuple(violations)



#### Check cross-document identifier closure and the disjoint no-loss merge contract.
####
def check_traceability_sources(
    dossier_source: str,
    matrix_source: str,
    oracles_source: str,
) -> tuple[CompatibilityViolation, ...]:
    violations: list[CompatibilityViolation] = []
    behavior_ids = tuple(BEHAVIOR_HEADING.findall(dossier_source))
    oracle_ids = tuple(TEST_HEADING.findall(oracles_source))
    rows, feature_table_violations = _parse_feature_rows(matrix_source)
    violations.extend(feature_table_violations)
    feature_ids = tuple(row["ID"] for row in rows)
    mapped_behaviors = {
        reference
        for row in rows
        for reference in _expand_references(row["Evidence"], "GOR-BEH")
    }
    mapped_tests = {
        reference
        for row in rows
        for reference in TEST_REFERENCE.findall(row["Tests"])
    }

    for identifier, identifiers, label in (
        (behavior_ids, behavior_ids, "behavior"),
        (feature_ids, feature_ids, "feature"),
        (oracle_ids, oracle_ids, "oracle"),
    ):
        if len(identifier) != len(set(identifiers)):
            violations.append(PathViolation.compatibility(f"duplicate {label} identifier"))

    for missing in sorted(set(behavior_ids) - mapped_behaviors):
        violations.append(PathViolation.compatibility(f"behavior is not mapped by a feature: {missing}"))
    for dangling in sorted(mapped_behaviors - set(behavior_ids)):
        violations.append(PathViolation.compatibility(f"feature cites an unknown behavior: {dangling}"))
    for missing in sorted(set(oracle_ids) - mapped_tests):
        violations.append(PathViolation.compatibility(f"oracle is not mapped by a feature: {missing}"))
    for dangling in sorted(mapped_tests - set(oracle_ids)):
        violations.append(PathViolation.compatibility(f"feature cites an unknown oracle: {dangling}"))

    if "GOR-BEH-063" in behavior_ids:
        loss_rows = tuple(
            row
            for row in rows
            if "GOR-BEH-063" in _expand_references(row["Evidence"], "GOR-BEH")
        )
        if len(loss_rows) != 1 or loss_rows[0]["Disposition"] != "Excluded":
            violations.append(
                PathViolation.compatibility("GOR-BEH-063 must appear only in an Excluded feature")
            )

        characterization_rows = tuple(
            row
            for row in rows
            if "GOR-TEST-054" in TEST_REFERENCE.findall(row["Tests"])
        )
        if (
            len(characterization_rows) != 1
            or characterization_rows[0]["Disposition"] != "Excluded"
            or "GOR-BEH-063" not in _expand_references(characterization_rows[0]["Evidence"], "GOR-BEH")
        ):
            violations.append(
                PathViolation.compatibility(
                    "GOR-TEST-054 must appear only in the Excluded loss-characterization feature"
                )
            )

        no_loss_rows = tuple(
            row
            for row in rows
            if "GOR-TEST-055" in TEST_REFERENCE.findall(row["Tests"])
        )
        if (
            not any(row["Disposition"] == "Modernized" for row in no_loss_rows)
            or any(row["Disposition"] == "Excluded" for row in no_loss_rows)
        ):
            violations.append(
                PathViolation.compatibility(
                    "GOR-TEST-055 must remain a non-Excluded Modernized Bonobo contract"
                )
            )

        sections = _oracle_sections(oracles_source)
        characterization = sections.get("GOR-TEST-054", "")
        if (
            "- Authority: `Gorilla`." not in characterization
            or "excluded-gorilla-only-characterization" not in characterization
            or "Bonobo" in next(
                (line for line in characterization.splitlines() if line.startswith("- Required clients:")),
                "",
            )
        ):
            violations.append(
                PathViolation.compatibility("GOR-TEST-054 must remain a Gorilla-only excluded characterization")
            )

        no_loss = sections.get("GOR-TEST-055", "")
        if (
            "- Authority: `Bonobo`." not in no_loss
            or "transactional-merge-resolution-no-loss" not in no_loss
        ):
            violations.append(
                PathViolation.compatibility("GOR-TEST-055 must carry the Bonobo transactional no-loss authority")
            )

    return tuple(violations)



#### Provide fixed repository paths for violations that span compatibility documents.
####
class PathViolation:



    #### Build one cross-document compatibility violation.
    ####
    @staticmethod
    def compatibility(message: str) -> CompatibilityViolation:
        return CompatibilityViolation(Path("docs/compatibility/gorilla"), 1, message)



#### Check that an identifier family is unique, sequential, and starts at one.
####
def _check_identifier_sequence(
    path: Path,
    identifiers: tuple[str, ...],
    pattern: re.Pattern[str],
    label: str,
) -> tuple[CompatibilityViolation, ...]:
    numbers = tuple(int(match.group(1)) for identifier in identifiers if (match := pattern.fullmatch(identifier)))
    expected = tuple(range(1, len(numbers) + 1))
    if numbers == expected and len(numbers) == len(set(numbers)):
        return ()
    return (CompatibilityViolation(path, 1, f"{label} identifiers must be unique and sequential from 001"),)



#### Return current behavior, feature, and oracle totals from authored sources.
####
def compatibility_counts(dossier_source: str, matrix_source: str, oracles_source: str) -> CompatibilityCounts:
    return CompatibilityCounts(
        len(BEHAVIOR_HEADING.findall(dossier_source)),
        len(_feature_rows(matrix_source)),
        len(TEST_HEADING.findall(oracles_source)),
    )



#### Check every tracked authored compatibility document through one release-gate entry point.
####
def check_repository_contract(repository_root: Path) -> tuple[CompatibilityViolation, ...]:
    sources = {
        path: (repository_root / path).read_text(encoding="utf-8")
        for path in COMPATIBILITY_MARKDOWN_PATHS
    }
    dossier_path, matrix_path, oracles_path, _ = COMPATIBILITY_MARKDOWN_PATHS
    dossier_source = sources[dossier_path]
    matrix_source = sources[matrix_path]
    oracles_source = sources[oracles_path]
    rows = _feature_rows(matrix_source)
    violations: list[CompatibilityViolation] = []
    for path, source in sources.items():
        violations.extend(check_clean_room_source(path, source))
    violations.extend(check_local_evidence_corpus(repository_root))
    violations.extend(check_traceability_sources(dossier_source, matrix_source, oracles_source))
    violations.extend(
        _check_identifier_sequence(
            dossier_path,
            tuple(BEHAVIOR_HEADING.findall(dossier_source)),
            re.compile(r"GOR-BEH-(\d{3})"),
            "behavior",
        )
    )
    violations.extend(
        _check_identifier_sequence(
            matrix_path,
            tuple(row["ID"] for row in rows),
            FEATURE_IDENTIFIER,
            "feature",
        )
    )
    violations.extend(
        _check_identifier_sequence(
            oracles_path,
            tuple(TEST_HEADING.findall(oracles_source)),
            re.compile(r"GOR-TEST-(\d{3})"),
            "oracle",
        )
    )
    return tuple(violations)



#### Print repository compatibility findings and traceability totals for the invoking gate.
####
def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("repository_root", nargs="?", type=Path, default=Path.cwd())
    arguments = parser.parse_args(argv)
    repository_root = arguments.repository_root.resolve()
    violations = check_repository_contract(repository_root)
    for violation in violations:
        token = f" ({violation.token})" if violation.token is not None else ""
        print(f"{violation.path}:{violation.line}: {violation.message}{token}")
    if violations:
        return 1

    dossier_source = (repository_root / COMPATIBILITY_MARKDOWN_PATHS[0]).read_text(encoding="utf-8")
    matrix_source = (repository_root / COMPATIBILITY_MARKDOWN_PATHS[1]).read_text(encoding="utf-8")
    oracles_source = (repository_root / COMPATIBILITY_MARKDOWN_PATHS[2]).read_text(encoding="utf-8")
    counts = compatibility_counts(dossier_source, matrix_source, oracles_source)
    print(
        f"compatibility contract: behaviors={counts.behaviors} features={counts.features} oracles={counts.oracles}"
    )
    return 0


# Return the command status to the invoking shell without configuring runtime logging.
if __name__ == "__main__":
    raise SystemExit(main())
