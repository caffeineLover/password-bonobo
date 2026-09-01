"""Verify the repository-specific Python source structure policy."""

import tomllib
from pathlib import Path

from tools.check_python_structure import check_paths, check_source



FIXTURE_DIRECTORY = Path(__file__).parents[1] / "fixtures" / "python_structure"



#### Accept a module with documentation, typing, and exact declaration spacing.
####
def test_documented_fixture_passes() -> None:
    path = FIXTURE_DIRECTORY / "documented.py.txt"

    assert check_source(path, path.read_text(encoding="utf-8")) == ()



#### Report each missing structural requirement in an undocumented declaration.
####
def test_undocumented_fixture_fails() -> None:
    path = FIXTURE_DIRECTORY / "undocumented.py.txt"
    messages = tuple(
        violation.message
        for violation in check_source(path, path.read_text(encoding="utf-8"))
    )

    assert "module docstring is required" in messages
    assert "declaration requires an immediately preceding #### block" in messages
    assert "parameter 'value' requires a type annotation" in messages
    assert "return type annotation is required" in messages



#### Reject a single-quoted module docstring despite its otherwise-valid structure.
####
def test_single_quoted_module_docstring_fails() -> None:
    source = """'''Use a single-quoted module docstring.'''



#### Return the supplied value without transforming it.
####
def identity(value: str) -> str:
    return value
"""

    messages = tuple(violation.message for violation in check_source(Path("single.py"), source))

    assert messages == ("module docstring must use triple double quotes",)



#### Accept a decorator stack immediately following its declaration block.
####
def test_decorated_declaration_with_adjacent_block_passes() -> None:
    source = '''"""Provide a module with a decorated declaration."""



#### Return the supplied value without transforming it.
####
@decorator_one
@decorator_two
def identity(value: str) -> str:
    return value
'''

    assert check_source(Path("decorated.py"), source) == ()



#### Accept a multiline decorator whose own physical lines remain contiguous.
####
def test_multiline_decorator_with_adjacent_declaration_passes() -> None:
    source = '''"""Provide a module with a multiline decorator."""



#### Return the supplied value without transforming it.
####
@configured(
    first="one",
    second="two",
)
def identity(value: str) -> str:
    return value
'''

    assert check_source(Path("multiline.py"), source) == ()



#### Reject a blank line inside a decorator stack.
####
def test_blank_line_between_decorators_fails() -> None:
    source = '''"""Provide a module with a separated decorator stack."""



#### Return the supplied value without transforming it.
####
@decorator_one

@decorator_two
def identity(value: str) -> str:
    return value
'''

    messages = tuple(violation.message for violation in check_source(Path("decorator-blank.py"), source))

    assert messages == ("decorator stack and declaration must be contiguous",)



#### Reject an intervening comment inside a decorator stack.
####
def test_comment_between_decorators_fails() -> None:
    source = '''"""Provide a module with a commented decorator gap."""



#### Return the supplied value without transforming it.
####
@decorator_one
# This comment breaks the documented declaration unit.
@decorator_two
def identity(value: str) -> str:
    return value
'''

    messages = tuple(violation.message for violation in check_source(Path("decorator-comment.py"), source))

    assert messages == ("decorator stack and declaration must be contiguous",)



#### Reject a gap between the final decorator and its declaration.
####
def test_gap_between_final_decorator_and_declaration_fails() -> None:
    source = '''"""Provide a module with a final decorator gap."""



#### Return the supplied value without transforming it.
####
@decorator

def identity(value: str) -> str:
    return value
'''

    messages = tuple(violation.message for violation in check_source(Path("decorator-final.py"), source))

    assert messages == ("decorator stack and declaration must be contiguous",)



#### Reject a declaration block separated from its decorator stack.
####
def test_decorated_declaration_requires_an_adjacent_block() -> None:
    source = '''"""Provide a module with a separated declaration block."""



#### Return the supplied value without transforming it.
####

@decorator
def identity(value: str) -> str:
    return value
'''

    messages = tuple(violation.message for violation in check_source(Path("separated.py"), source))

    assert "declaration requires an immediately preceding #### block" in messages



#### Reject a declaration preceded by more than three blank lines.
####
def test_declaration_with_more_than_three_blank_lines_fails() -> None:
    source = '''"""Provide a module with excess declaration spacing."""




#### Return the supplied value without transforming it.
####
def identity(value: str) -> str:
    return value
'''

    messages = tuple(violation.message for violation in check_source(Path("spacing.py"), source))

    assert messages == ("declaration has more than three preceding blank lines",)



#### Keep the formatter from separating declaration comments from their callables.
####
def test_autopep8_preserves_documented_declaration_units() -> None:
    configuration = tomllib.loads(Path("pyproject.toml").read_text(encoding="utf-8"))

    assert set(configuration["tool"]["autopep8"]["ignore"]) >= {
        "E266",
        "E301",
        "E302",
        "E303",
        "E305",
        "E306",
    }



#### Check every maintained Python source file through the same public entry point.
####
def test_repository_python_sources_pass() -> None:
    assert check_paths((Path("src"), Path("tests"), Path("tools"))) == ()
