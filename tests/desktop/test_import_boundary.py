"""Verify that the reusable application core excludes desktop dependencies."""

from __future__ import annotations

import ast
import os
import subprocess
import sys
import tomllib
from pathlib import Path



#### Return every import of an optional desktop package below one source directory.
####
#### The application core must remain importable from the base wheel, so this
#### static boundary rejects both the desktop adapter and Qt bindings before
#### packaging can make either dependency mandatory.
####
def forbidden_imports(directory: Path) -> tuple[str, ...]:
    forbidden_roots = frozenset({"PySide6", "bonobo_desktop"})
    imports: list[str] = []
    for path in sorted(directory.rglob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            names = node.names if isinstance(node, (ast.Import, ast.ImportFrom)) else ()
            for imported in names:
                root = imported.name.partition(".")[0]
                if root in forbidden_roots:
                    imports.append(imported.name)
    return tuple(imports)



#### Report a forbidden import without retaining the source file's private locator.
####
#### The boundary result is test-diagnostic data, so callers may receive only
#### the offending import identifier and never a checkout, temporary, or user
#### path derived while parsing source.
####
def test_forbidden_import_diagnostic_contains_only_the_import_identifier(tmp_path: Path) -> None:
    source = tmp_path / "private-source.py"
    source.write_text("import PySide6.QtCore\n", encoding="utf-8")

    assert forbidden_imports(tmp_path) == ("PySide6.QtCore",)



#### Keep the public application facade independent of optional desktop bindings.
####
def test_application_core_never_imports_desktop_or_pyside() -> None:
    assert forbidden_imports(Path("src/bonobo_core/application")) == ()



#### Load the configured GUI entry module in an isolated core-only interpreter.
####
#### Entry-point discovery imports its declared module before calling the target.
#### A base installation therefore needs that module to stay importable without
#### Qt and to return one fixed status without emitting the missing-import detail.
####
def test_configured_gui_entry_fails_safely_without_desktop_extra() -> None:
    project = tomllib.loads(Path("pyproject.toml").read_text(encoding="utf-8"))
    entry = project["project"]["scripts"]["password-bonobo"]
    assert isinstance(entry, str)
    module_name, separator, callable_name = entry.partition(":")
    assert separator == ":"
    environment = os.environ | {
        "PYTHONDONTWRITEBYTECODE": "1",
        "PYTHONPATH": str(Path("src").resolve()),
    }
    command = (
        f"from {module_name} import {callable_name}; "
        f"raise SystemExit({callable_name}(['password-bonobo']))"
    )

    result = subprocess.run(
        (sys.executable, "-S", "-c", command),
        capture_output=True,
        check=False,
        env=environment,
        text=True,
    )

    assert result.returncode == 1
    assert result.stdout == ""
    assert result.stderr == ""
