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
