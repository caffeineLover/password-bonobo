"""Verify fail-closed desktop composition-root startup behavior."""

from __future__ import annotations

import pytest
from PySide6.QtCore import QUrl

from bonobo_desktop import resources
from bonobo_desktop.main import main



#### Return a safe nonzero status when the packaged QML root cannot load.
####
#### The missing root is an observable startup failure.  The desktop adapter
#### must not continue into Qt's event loop without a root object.
####
def test_desktop_main_fails_safely_when_qml_root_is_unavailable(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(resources, "main_qml_url", lambda: QUrl())
    assert main(["password-bonobo"]) == 1
