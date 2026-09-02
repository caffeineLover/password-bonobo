"""Locate Qt Quick resources owned by the optional desktop adapter.

The QML resource URL stays in the desktop boundary so the reusable core neither
imports Qt nor takes responsibility for GUI packaging.
"""

from typing import TYPE_CHECKING



if TYPE_CHECKING:
    from PySide6.QtCore import QUrl



#### Return the stable Qt resource URL for the desktop QML root.
####
#### The Qt resource collection is supplied with the desktop shell rather than
#### the base wheel.  Importing this locator remains safe without PySide6 until
#### a desktop launch requests the URL.
####
def main_qml_url() -> QUrl:
    from PySide6.QtCore import QUrl

    return QUrl("qrc:/bonobo_desktop/qml/Main.qml")
