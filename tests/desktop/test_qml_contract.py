"""Verify packaged QML loads and keeps the desktop binding surface closed."""

import re
from pathlib import Path

from PySide6.QtCore import QUrl
from PySide6.QtQml import QQmlApplicationEngine, QQmlComponent
from pytestqt.qtbot import QtBot

from bonobo_desktop import resources



_QML_COMPONENTS = (
    "Main.qml",
    "WelcomeView.qml",
    "UnlockView.qml",
    "VaultView.qml",
    "RecordEditor.qml",
    "DecisionDialog.qml",
)
_FORBIDDEN_BINDING_IDENTIFIERS = frozenset(
    {
        "VaultSession",
        "RecordHandle",
        "RevisionToken",
        "SecretBuffer",
        "path",
        "uuid",
        "urlValue",
        "passwordValue",
        "notesValue",
        "exception",
        "message",
        "errorString",
    }
)
_QML_IDENTIFIER = re.compile(r"\b[A-Za-z_]\w*\b")
_REGEX_PREFIX_KEYWORDS = frozenset(
    {
        "await",
        "case",
        "delete",
        "in",
        "instanceof",
        "new",
        "return",
        "throw",
        "typeof",
        "void",
        "yield",
    }
)



#### Return the first position after a complete JavaScript regex literal.
####
#### Escapes and character classes suppress delimiter meaning inside the
#### pattern.  An absent closing slash leaves the caller to treat `/` as an
#### operator instead of swallowing the remaining QML source.
####
def _scan_qml_regex_literal(text: str, start: int) -> int | None:
    index = start + 1
    in_character_class = False
    while index < len(text):
        character = text[index]
        if character in {"\r", "\n"}:
            return None
        if character == "\\":
            if index + 1 >= len(text) or text[index + 1] in {"\r", "\n"}:
                return None
            index += 2
        elif character == "[" and not in_character_class:
            in_character_class = True
            index += 1
        elif character == "]" and in_character_class:
            in_character_class = False
            index += 1
        elif character == "/" and not in_character_class:
            index += 1
            while index < len(text) and text[index].isalpha():
                index += 1
            return index
        else:
            index += 1
    return None



#### Scan one QML code segment while removing strings, comments, and template text.
####
def _scan_qml_code(text: str, start: int = 0, *, interpolation: bool = False) -> tuple[str, int]:
    code: list[str] = []
    index = start
    depth = 1 if interpolation else 0
    regex_allowed = True
    while index < len(text):
        character = text[index]
        following = text[index + 1] if index + 1 < len(text) else ""
        if character in {'"', "'"}:
            quote = character
            index += 1
            while index < len(text):
                if text[index] == "\\":
                    index += 2
                elif text[index] == quote:
                    index += 1
                    break
                else:
                    index += 1
            code.append(" ")
            regex_allowed = False
        elif character == "/" and following == "/":
            newline = text.find("\n", index + 2)
            index = len(text) if newline < 0 else newline
            code.append(" ")
        elif character == "/" and following == "*":
            closing = text.find("*/", index + 2)
            index = len(text) if closing < 0 else closing + 2
            code.append(" ")
        elif character == "`":
            nested, index = _scan_qml_template(text, index + 1)
            code.extend((" ", nested, " "))
            regex_allowed = False
        elif character == "/" and regex_allowed:
            regex_end = _scan_qml_regex_literal(text, index)
            if regex_end is None:
                code.append(character)
                index += 1
                regex_allowed = True
            else:
                code.append(" ")
                index = regex_end
                regex_allowed = False
        elif interpolation and character == "{":
            depth += 1
            code.append(character)
            index += 1
            regex_allowed = True
        elif interpolation and character == "}":
            depth -= 1
            index += 1
            if depth == 0:
                return "".join(code), index
            code.append(character)
            regex_allowed = False
        elif character.isalpha() or character in {"_", "$"}:
            identifier_start = index
            index += 1
            while index < len(text) and (text[index].isalnum() or text[index] in {"_", "$"}):
                index += 1
            identifier = text[identifier_start:index]
            code.append(identifier)
            regex_allowed = identifier in _REGEX_PREFIX_KEYWORDS
        elif character.isdigit():
            number_start = index
            index += 1
            while index < len(text) and (text[index].isalnum() or text[index] in {"_", "."}):
                index += 1
            code.append(text[number_start:index])
            regex_allowed = False
        elif character in {"+", "-"} and following == character:
            code.extend((character, following))
            index += 2
        else:
            code.append(character)
            index += 1
            if character.isspace():
                continue
            regex_allowed = character not in {")", "]", "}", "."}
    return "".join(code), index



#### Preserve only nested code expressions from one JavaScript template literal.
####
def _scan_qml_template(text: str, start: int) -> tuple[str, int]:
    code: list[str] = []
    index = start
    while index < len(text):
        character = text[index]
        following = text[index + 1] if index + 1 < len(text) else ""
        if character == "\\":
            index += 2
        elif character == "`":
            return "".join(code), index + 1
        elif character == "$" and following == "{":
            expression, index = _scan_qml_code(text, index + 2, interpolation=True)
            code.extend((" ", expression, " "))
        else:
            index += 1
    return "".join(code), index



#### Return exact identifiers from QML code after removing non-code regions.
####
#### Resource locators and translated prose are deliberately ignored, while a
#### forbidden member on either side of a binding remains visible to the gate.
####
def _qml_identifiers(text: str) -> frozenset[str]:
    code, _end = _scan_qml_code(text)
    return frozenset(_QML_IDENTIFIER.findall(code))



#### Return the exact approved component URLs from the desktop package directory.
####
def packaged_qml_components() -> tuple[QUrl, ...]:
    qml_directory = Path(resources.__file__).parent / "qml"
    return tuple(QUrl.fromLocalFile(str(qml_directory / name)) for name in _QML_COMPONENTS)



#### Parse property and binding identifiers without treating string contents as identifiers.
####
def qml_forbidden_tokens() -> tuple[str, ...]:
    findings: list[str] = []
    for component in packaged_qml_components():
        source = Path(component.toLocalFile())
        if not source.is_file():
            continue
        text = source.read_text(encoding="utf-8")
        identifiers = _qml_identifiers(text)
        findings.extend(sorted(identifiers & _FORBIDDEN_BINDING_IDENTIFIERS))
    return tuple(findings)



#### Create one isolated declarative engine for component compilation checks.
####
def _qml_engine(_qtbot: QtBot) -> QQmlApplicationEngine:
    return QQmlApplicationEngine()



#### Load every approved component from the package instead of testing framework stubs.
####
def test_every_qml_component_loads_offscreen(qtbot: QtBot) -> None:
    qml_engine = _qml_engine(qtbot)
    for component in packaged_qml_components():
        loaded = QQmlComponent(qml_engine, component)
        assert loaded.status() is QQmlComponent.Status.Ready, loaded.errorString()



#### Reject domain, identity, secret, locator, and raw diagnostic binding identifiers.
####
def test_qml_never_names_forbidden_domain_or_secret_properties() -> None:
    assert qml_forbidden_tokens() == ()



#### Parse exact QML identifiers while ignoring legitimate resource-string contents.
####
def test_qml_boundary_parser_ignores_strings_but_finds_member_bindings() -> None:
    identifiers = _qml_identifiers(
        'Image { source: "qrc:/images/path-safe.svg"; text: controller.passwordValue }'
    )

    assert "path" not in identifiers
    assert "passwordValue" in identifiers



#### Preserve code inside template interpolation while ignoring its literal text.
####
def test_qml_boundary_parser_finds_forbidden_member_inside_template_interpolation() -> None:
    identifiers = _qml_identifiers(
        "Text { text: `safe resource text ${desktopController.passwordValue}` }"
    )

    assert "safe" not in identifiers
    assert "passwordValue" in identifiers



#### Keep braces inside JavaScript regex literals from terminating template interpolation.
####
def test_qml_boundary_parser_finds_forbidden_member_after_regex_literal_brace() -> None:
    identifiers = _qml_identifiers(
        "Text { text: `${/}/.test(value) ? desktopController.passwordValue : 0}` }"
    )

    assert "passwordValue" in identifiers



#### Ignore an escaped closing brace inside a JavaScript regex literal.
####
def test_qml_boundary_parser_finds_forbidden_member_after_escaped_regex_brace() -> None:
    identifiers = _qml_identifiers(
        r"Text { text: `${/\}/.test(value) ? desktopController.passwordValue : 0}` }"
    )

    assert "passwordValue" in identifiers



#### Ignore a closing brace inside a JavaScript regex character class.
####
def test_qml_boundary_parser_finds_forbidden_member_after_regex_class_brace() -> None:
    identifiers = _qml_identifiers(
        "Text { text: `${/[}]/.test(value) ? desktopController.passwordValue : 0}` }"
    )

    assert "passwordValue" in identifiers



#### Keep division operands visible instead of consuming them as a regex literal.
####
def test_qml_boundary_parser_preserves_division_expression_identifiers() -> None:
    identifiers = _qml_identifiers(
        "Text { text: `${numerator / denominator ? desktopController.passwordValue : 0}` }"
    )

    assert {"numerator", "denominator", "passwordValue"} <= identifiers
