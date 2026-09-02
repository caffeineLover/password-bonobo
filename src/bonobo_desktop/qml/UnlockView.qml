import QtQuick
import QtQuick.Controls
import QtQuick.Layouts

Pane {
    id: root
    required property var controller

    function submit() {
        root.controller.passphrase = unlockPassword.text
        unlockPassword.text = ""
        root.controller.unlockVault()
    }

    ColumnLayout {
        anchors.centerIn: parent
        width: Math.min(parent.width - 48, 440)
        spacing: 12

        Label {
            text: qsTr("Unlock %1").arg(root.controller.displayLabel)
            font.pixelSize: 26
            Layout.alignment: Qt.AlignHCenter
        }

        TextField {
            id: unlockPassword
            objectName: "unlockPassword"
            placeholderText: qsTr("Passphrase")
            echoMode: TextInput.Password
            Accessible.name: qsTr("Vault passphrase")
            activeFocusOnTab: true
            Layout.fillWidth: true
            KeyNavigation.tab: unlockButton
        }

        Button {
            id: unlockButton
            objectName: "unlockButton"
            text: qsTr("&Unlock")
            Accessible.name: qsTr("Unlock vault")
            activeFocusOnTab: true
            Layout.alignment: Qt.AlignHCenter
            KeyNavigation.tab: unlockPassword
            onClicked: root.submit()
        }
    }

    Component.onCompleted: unlockPassword.forceActiveFocus()
}
