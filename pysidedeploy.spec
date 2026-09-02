[app]
title = Password Bonobo
project_dir = .
input_file = src/bonobo_desktop/main.py
exec_directory = dist/desktop
project_file =
icon =

[python]
python_path =
packages = Nuitka==4.1.1

[qt]
qml_files = src/bonobo_desktop/qml/DecisionDialog.qml,src/bonobo_desktop/qml/Main.qml,src/bonobo_desktop/qml/RecordEditor.qml,src/bonobo_desktop/qml/UnlockView.qml,src/bonobo_desktop/qml/VaultView.qml,src/bonobo_desktop/qml/WelcomeView.qml
excluded_qml_plugins =
modules = Core,Gui,Qml,Quick,QuickControls2
plugins =

[nuitka]
macos.permissions =
mode = onefile
extra_args = --quiet --noinclude-qt-translations
