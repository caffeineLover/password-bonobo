"""Define UI-independent ports for short-lived clipboard and browser actions.

The facade owns leases and calls these protocols only while each lease remains
open.  Platform adapters must never retain the supplied lease after returning.
"""

from typing import Protocol

from bonobo_core.passwordsafe import SecretLease



#### Accept one explicit copied secret while its lease remains open.
####
#### Adapters own platform-specific expiry and ownership tracking.  They clear
#### only a value that remains owned by this application.
####
class ClipboardPort(Protocol):



    #### Copy the currently leased value for the approved finite lifetime.
    ####
    def copy(self, value: SecretLease, *, lifetime_seconds: int) -> None:
        raise NotImplementedError



    #### Clear a clipboard value only when this adapter still owns it.
    ####
    def clear_owned(self) -> None:
        raise NotImplementedError



#### Open one explicitly requested URL while its lease remains open.
####
#### The browser adapter converts the leased value only for its immediate
#### platform call and returns whether the platform accepted that request.
####
class BrowserPort(Protocol):



    #### Attempt to open the currently leased URL without retaining it.
    ####
    def open(self, value: SecretLease) -> bool:
        raise NotImplementedError
