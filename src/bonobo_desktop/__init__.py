"""Provide the optional PySide6 desktop adapter package boundary.

Importing this package never imports PySide6.  The GUI entry point loads Qt only
when a desktop-extra installation explicitly launches the application.
"""



__all__: tuple[str, ...] = ()
