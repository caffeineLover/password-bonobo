"""Verify compatibility traceability and the clean-room expression boundary."""

from pathlib import Path

from tools.check_compatibility import check_clean_room_source, check_repository_contract, check_traceability_sources



#### Reject upstream-style camelCase identifiers while permitting explicit neutral terms.
####
def test_clean_room_audit_rejects_short_camelcase_identifiers() -> None:
    source = (
        "Use the visible backup controls on macOS and consult formatV3.txt. "
        "Do not expose timeStampBackup or backupPath."
    )

    violations = check_clean_room_source(Path("oracles.md"), source)

    assert tuple(violation.token for violation in violations) == ("timeStampBackup", "backupPath")



#### Reject destructive Gorilla loss evidence from a normal modernized feature.
####
def test_traceability_rejects_loss_behavior_in_modernized_feature() -> None:
    dossier = """### GOR-BEH-001 - Merge records

### GOR-BEH-063 - Lose a resolution
"""
    matrix = """| ID | Feature family | Disposition | Evidence | Tests |
|---|---|---|---|---|
| GOR-FEAT-001 | Merge | Modernized | GOR-BEH-001, GOR-BEH-063 | GOR-TEST-001 |
"""
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
    matrix = """| ID | Feature family | Disposition | Evidence | Tests |
|---|---|---|---|---|
| GOR-FEAT-001 | Lifecycle | Modernized | GOR-BEH-001""" + chr(0x2013) + """003 | GOR-TEST-001 |
"""
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
    matrix = """| ID | Feature family | Disposition | Evidence | Tests |
|---|---|---|---|---|
| GOR-FEAT-001 | Merge | Modernized | GOR-BEH-001 | GOR-TEST-001, GOR-TEST-055 |
| GOR-FEAT-002 | Gorilla resolution loss | Excluded | GOR-BEH-063 | GOR-TEST-054 |
"""
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
    matrix = """| ID | Feature family | Disposition | Evidence | Tests |
|---|---|---|---|---|
| GOR-FEAT-001 | Merge | Modernized | GOR-BEH-063 | GOR-TEST-054, GOR-TEST-055 |
| GOR-FEAT-002 | Gorilla resolution loss | Excluded | GOR-BEH-063 | GOR-TEST-054 |
"""
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



#### Check the tracked compatibility corpus through the release-gate entry point.
####
def test_repository_compatibility_documents_pass() -> None:
    assert check_repository_contract(Path.cwd()) == ()
