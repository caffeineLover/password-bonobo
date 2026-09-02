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
_NON_CODE_QML = re.compile(
    r'"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'|`(?:\\.|[^`\\])*`|//[^\r\n]*|/\*.*?\*/',
    re.DOTALL,
)
_QML_IDENTIFIER = re.compile(r"\b[A-Za-z_]\w*\b")



#### Return exact identifiers from QML code after removing strings and comments.
####
#### Resource locators and translated prose are deliberately ignored, while a
#### forbidden member on either side of a binding remains visible to the gate.
####
def _qml_identifiers(text: str) -> frozenset[str]:
    code = _NON_CODE_QML.sub(" ", text)
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
