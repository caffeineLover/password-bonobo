"""Open explicitly leased URLs through one synchronous Qt GUI operation.

URL conversion and the QUrl object exist only inside the leased operation.
Neither the adapter nor its diagnostics retain or publish the value.
"""

from PySide6.QtCore import QByteArray, QUrl
from PySide6.QtGui import QDesktopServices

from bonobo_core.passwordsafe import SecretLease

from .tasks import GuiThreadInvoker



#### Adapt one leased UTF-8 URL to the GUI-thread desktop-services API.
####
class QtBrowserPort:
    _invoker: GuiThreadInvoker



    #### Initialize a synchronous bridge on the constructing GUI thread.
    ####
    def __init__(self) -> None:
        self._invoker = GuiThreadInvoker()



    #### Convert and open the URL only while the supplied lease remains active.
    ####
    def open(self, value: SecretLease) -> bool:



        #### Perform the complete conversion and platform call on the GUI thread.
        ####
        def launch() -> bool:
            temporary = bytearray(value.borrow())
            try:
                url = QUrl.fromEncoded(QByteArray(temporary), QUrl.ParsingMode.StrictMode)
                return bool(url.isValid() and not url.isEmpty() and QDesktopServices.openUrl(url))
            finally:
                temporary[:] = b"\x00" * len(temporary)

        return self._invoker.call(launch)
