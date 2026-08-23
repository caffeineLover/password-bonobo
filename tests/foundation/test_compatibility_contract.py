"""Verify compatibility traceability and the clean-room expression boundary."""

from pathlib import Path

from tools.check_compatibility import (
    check_clean_room_source,
    check_repository_contract,
    check_traceability_sources,
)



FEATURE_HEADER = """| ID | Feature family | Disposition | Evidence | Owner | Platforms | Data-loss | Security | Tests |
|---|---|---|---|---|---|---|---|---|
"""



#### Reject an independently fabricated camelCase identifier while permitting explicit neutral terms.
####
def test_clean_room_audit_rejects_short_camelcase_identifiers() -> None:
    source = (
        "Use the visible backup controls on macOS and consult formatV3.txt. "
        "Do not expose fabricatedPolicyState."
    )

    violations = check_clean_room_source(Path("oracles.md"), source)

    assert tuple(violation.token for violation in violations) == ("fabricatedPolicyState",)



#### Reject a fabricated camelCase identifier whose lowercase prefix is one letter long.
####
def test_clean_room_audit_rejects_one_letter_prefix_camelcase_identifier() -> None:
    violations = check_clean_room_source(Path("oracles.md"), "Select qAccessMode in the synthetic harness.")

    assert tuple(violation.token for violation in violations) == ("qAccessMode",)



#### Preserve ordinary prose, acronyms, and the explicit neutral clean-room allowlist.
####
def test_clean_room_audit_accepts_prose_acronyms_and_neutral_terms() -> None:
    source = "A visible control uses URL and JSON labels on macOS and iOS; consult formatV3.txt and Git %aI."

    assert check_clean_room_source(Path("oracles.md"), source) == ()



#### Reject destructive Gorilla loss evidence from a normal modernized feature.
####
def test_traceability_rejects_loss_behavior_in_modernized_feature() -> None:
    dossier = """### GOR-BEH-001 - Merge records

### GOR-BEH-063 - Lose a resolution
"""
    matrix = FEATURE_HEADER + (
        "|GOR-FEAT-001|Merge|Modernized|GOR-BEH-001, GOR-BEH-063|O3|ALL|Critical|Critical|GOR-TEST-001|\n"
    )
    oracles = """### GOR-TEST-001 - Merge records

- Authority: `Gorilla`.
- Required clients: Bonobo and Gorilla at the pinned revision.
"""

    messages = tuple(
        violation.message
        for violation in check_traceability_sources(dossier, matrix, oracles)
    )

    assert "GOR-BEH-063 must appear only in an Excluded feature" in messages



#### Expand compact evidence ranges so every intermediate behavior is mapped.
####
def test_traceability_expands_compact_behavior_ranges() -> None:
    dossier = """### GOR-BEH-001 - First behavior

### GOR-BEH-002 - Second behavior

### GOR-BEH-003 - Third behavior
"""
    matrix = FEATURE_HEADER + (
        "|GOR-FEAT-001|Lifecycle|Modernized|GOR-BEH-001"
        + chr(0x2013)
        + "003|O3|ALL|Critical|Critical|GOR-TEST-001|\n"
    )
    oracles = """### GOR-TEST-001 - Exercise lifecycle

- Authority: `Gorilla`.
- Required clients: Bonobo and Gorilla at the pinned revision.
"""

    assert check_traceability_sources(dossier, matrix, oracles) == ()



#### Accept disjoint merge parity, excluded characterization, and Bonobo no-loss authority.
####
def test_traceability_accepts_split_no_loss_contract() -> None:
    dossier = """### GOR-BEH-001 - Merge records

### GOR-BEH-063 - Lose a resolution
"""
    matrix = FEATURE_HEADER + (
        "|GOR-FEAT-001|Merge|Modernized|GOR-BEH-001|O3|ALL|Critical|Critical|"
        "GOR-TEST-001, GOR-TEST-055|\n"
        "|GOR-FEAT-002|Gorilla resolution loss|Excluded|GOR-BEH-063|O3|ALL|Critical|Critical|GOR-TEST-054|\n"
    )
    oracles = """### GOR-TEST-001 - Merge records

- Authority: `Gorilla`.
- Required clients: Bonobo and Gorilla at the pinned revision.

### GOR-TEST-054 - Characterize Gorilla resolution loss

- Authority: `Gorilla`.
- Contract: `excluded-gorilla-only-characterization`.
- Required clients: Gorilla at the pinned revision only.

### GOR-TEST-055 - Persist Bonobo resolution transactionally

- Authority: `Bonobo`.
- Coverage: transactional-merge-resolution-no-loss.
- Required clients: Bonobo.
"""

    assert check_traceability_sources(dossier, matrix, oracles) == ()



#### Reject reuse of the Gorilla-only characterization oracle by Bonobo's normal merge feature.
####
def test_traceability_rejects_characterization_oracle_in_modernized_feature() -> None:
    dossier = """### GOR-BEH-063 - Lose a resolution
"""
    matrix = FEATURE_HEADER + (
        "|GOR-FEAT-001|Merge|Modernized|GOR-BEH-063|O3|ALL|Critical|Critical|"
        "GOR-TEST-054, GOR-TEST-055|\n"
        "|GOR-FEAT-002|Gorilla resolution loss|Excluded|GOR-BEH-063|O3|ALL|Critical|Critical|GOR-TEST-054|\n"
    )
    oracles = """### GOR-TEST-054 - Characterize Gorilla resolution loss

- Authority: `Gorilla`.
- Contract: `excluded-gorilla-only-characterization`.
- Required clients: Gorilla at the pinned revision only.

### GOR-TEST-055 - Persist Bonobo resolution transactionally

- Authority: `Bonobo`.
- Coverage: transactional-merge-resolution-no-loss.
- Required clients: Bonobo.
"""

    messages = tuple(
        violation.message
        for violation in check_traceability_sources(dossier, matrix, oracles)
    )

    assert "GOR-TEST-054 must appear only in the Excluded loss-characterization feature" in messages



#### Reject a feature-looking row that omits one required schema column.
####
def test_traceability_rejects_feature_row_with_missing_column() -> None:
    dossier = "### GOR-BEH-001 - Fabricated behavior\n"
    matrix = FEATURE_HEADER + "|GOR-FEAT-001|Fabricated|Required|GOR-BEH-001|O3|ALL|Critical|GOR-TEST-001|\n"
    oracles = "### GOR-TEST-001 - Fabricated oracle\n"

    messages = tuple(
        violation.message
        for violation in check_traceability_sources(dossier, matrix, oracles)
    )

    assert "feature row GOR-FEAT-001 has 8 cells; expected 9" in messages



#### Reject a feature-looking row that adds one unsupported schema column.
####
def test_traceability_rejects_feature_row_with_extra_column() -> None:
    dossier = "### GOR-BEH-001 - Fabricated behavior\n"
    matrix = (
        FEATURE_HEADER
        + "|GOR-FEAT-001|Fabricated|Required|GOR-BEH-001|O3|ALL|Critical|Critical|unexpected|GOR-TEST-001|\n"
    )
    oracles = "### GOR-TEST-001 - Fabricated oracle\n"

    messages = tuple(
        violation.message
        for violation in check_traceability_sources(dossier, matrix, oracles)
    )

    assert "feature row GOR-FEAT-001 has 10 cells; expected 9" in messages



#### Reject a feature table whose authored header differs from the exact schema.
####
def test_traceability_rejects_malformed_feature_header() -> None:
    dossier = "### GOR-BEH-001 - Fabricated behavior\n"
    matrix = """| ID | Feature family | Disposition | Evidence | Owner | Platforms | Data-loss | Security | Cases |
|---|---|---|---|---|---|---|---|---|
|GOR-FEAT-001|Fabricated|Required|GOR-BEH-001|O3|ALL|Critical|Critical|GOR-TEST-001|
"""
    oracles = "### GOR-TEST-001 - Fabricated oracle\n"

    messages = tuple(
        violation.message
        for violation in check_traceability_sources(dossier, matrix, oracles)
    )

    assert "feature table header does not match the required schema" in messages



#### Check the tracked compatibility corpus through the release-gate entry point.
####
def test_repository_compatibility_documents_pass() -> None:
    assert check_repository_contract(Path.cwd()) == ()
