"""Validate Bonobo's required Python documentation, typing, and spacing structure.

The checker complements Ruff and mypy where the project profile intentionally differs from conventional PEP 8 spacing.
"""

from __future__ import annotations

import argparse
import ast
import io
import tokenize
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



#### Return whether the AST module docstring uses an unprefixed triple-double-quoted token.
####
def _uses_triple_double_quoted_module_docstring(tree: ast.Module, source: str) -> bool:
    if not tree.body:
        return False

    first_statement = tree.body[0]
    if not isinstance(first_statement, ast.Expr) or not isinstance(first_statement.value, ast.Constant):
        return False
    if not isinstance(first_statement.value.value, str):
        return False

    docstring_location = (first_statement.value.lineno, first_statement.value.col_offset)
    for token in tokenize.generate_tokens(io.StringIO(source).readline):
        if token.type == tokenize.STRING and token.start == docstring_location:
            return token.string.startswith('"""')

    return False



#### Return all structural violations found in one source string.
####
def check_source(path: Path, source: str) -> tuple[Violation, ...]:
    tree = ast.parse(source, filename=str(path))
    lines = source.splitlines()
    violations: list[Violation] = []

    if ast.get_docstring(tree, clean=False) is None:
        violations.append(Violation(path, 1, "module docstring is required"))
    elif not _uses_triple_double_quoted_module_docstring(tree, source):
        violations.append(Violation(path, 1, "module docstring must use triple double quotes"))

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

        if node.decorator_list:
            decorator_end_lines = tuple(decorator.end_lineno or decorator.lineno for decorator in node.decorator_list)
            following_lines = (*tuple(decorator.lineno for decorator in node.decorator_list[1:]), node.lineno)
            if any(following_line != end_line + 1 for end_line, following_line in zip(
                decorator_end_lines,
                following_lines,
                strict=True,
            )):
                violations.append(
                    Violation(path, start_line, "decorator stack and declaration must be contiguous")
                )

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
