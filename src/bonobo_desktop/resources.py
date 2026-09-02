"""Locate packaged Qt Quick files owned by the optional desktop adapter.

The filesystem-backed package URL stays in the desktop boundary so the reusable
core neither imports Qt nor takes responsibility for GUI packaging.
"""

from pathlib import Path
from typing import TYPE_CHECKING



if TYPE_CHECKING:
    from PySide6.QtCore import QUrl



#### Return the installed package directory containing the approved QML shell.
####
def qml_directory() -> Path:
    return Path(__file__).resolve().with_name("qml")



#### Return the stable installed-package URL for the desktop QML root.
####
#### The QML files ship inside the optional desktop package rather than the base
#### core package.  Importing this locator remains safe without PySide6 until a
#### desktop launch requests the URL.
####
def main_qml_url() -> QUrl:
    from PySide6.QtCore import QUrl

    return QUrl.fromLocalFile(str(qml_directory() / "Main.qml"))
