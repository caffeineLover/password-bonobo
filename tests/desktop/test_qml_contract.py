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



#### Scan one QML code segment while removing strings, comments, and template text.
####
def _scan_qml_code(text: str, start: int = 0, *, interpolation: bool = False) -> tuple[str, int]:
    code: list[str] = []
    index = start
    depth = 1 if interpolation else 0
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
        elif interpolation and character == "{":
            depth += 1
            code.append(character)
            index += 1
        elif interpolation and character == "}":
            depth -= 1
            index += 1
            if depth == 0:
                return "".join(code), index
            code.append(character)
        else:
            code.append(character)
            index += 1
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
