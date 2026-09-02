"""Verify that the reusable application core excludes desktop dependencies."""

from __future__ import annotations

import ast
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
