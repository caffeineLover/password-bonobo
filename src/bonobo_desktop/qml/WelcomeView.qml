import QtQuick
import QtQuick.Controls
import QtQuick.Layouts

Pane {
    id: root
    required property var controller

    function submit(createNew) {
        root.controller.passphrase = welcomePassword.text
        welcomePassword.clear()
        if (createNew)
            root.controller.createVault(labelField.text)
        else
            root.controller.openVault(labelField.text)
    }

    ColumnLayout {
        anchors.centerIn: parent
        width: Math.min(parent.width - 48, 520)
        spacing: 12

        Label {
            text: qsTr("Welcome to Password Bonobo")
            font.pixelSize: 28
            Layout.alignment: Qt.AlignHCenter
        }

        Label {
            text: qsTr("Create a local vault or open an existing PasswordSafe file.")
            wrapMode: Text.WordWrap
            Layout.fillWidth: true
        }

        TextField {
            id: labelField
            objectName: "welcomeLabel"
            placeholderText: qsTr("Display name")
            Accessible.name: qsTr("Display name")
            activeFocusOnTab: true
            Layout.fillWidth: true
            KeyNavigation.tab: welcomePassword
        }

        TextField {
            id: welcomePassword
            objectName: "welcomePassword"
            placeholderText: qsTr("Passphrase")
            echoMode: TextInput.Password
            Accessible.name: qsTr("Vault passphrase")
            activeFocusOnTab: true
            Layout.fillWidth: true
            KeyNavigation.tab: createButton
        }

        RowLayout {
            Layout.alignment: Qt.AlignHCenter

            Button {
                id: createButton
                objectName: "createButton"
                text: qsTr("&Create")
                Accessible.name: qsTr("Create vault")
                activeFocusOnTab: true
                KeyNavigation.tab: openButton
                onClicked: root.submit(true)
            }

            Button {
                id: openButton
                objectName: "openButton"
                text: qsTr("&Open")
                Accessible.name: qsTr("Open vault")
                activeFocusOnTab: true
                KeyNavigation.tab: labelField
                onClicked: root.submit(false)
            }
        }
    }

    Component.onCompleted: labelField.forceActiveFocus()
}
