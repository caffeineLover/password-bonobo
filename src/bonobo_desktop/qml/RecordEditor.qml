import QtQuick
import QtQuick.Controls
import QtQuick.Layouts

Dialog {
    id: root
    required property var controller
    property int editKey: 0
    property bool editProtected: false
    property bool awaitingConfirmation: false
    modal: true
    anchors.centerIn: parent
    width: Math.min(parent ? parent.width - 48 : 520, 520)
    title: editKey === 0 ? qsTr("Add record") : qsTr("Edit record")
    closePolicy: awaitingConfirmation ? Popup.NoAutoClose : Popup.CloseOnEscape

    function clearLocalSecret() {
        editorPassword.clear()
    }

    function openNew() {
        awaitingConfirmation = false
        editKey = 0
        editProtected = false
        editorTitle.clear()
        editorGroup.clear()
        editorUsername.clear()
        clearLocalSecret()
        open()
    }

    function openExisting(key, title, group, username, isProtected) {
        awaitingConfirmation = false
        editKey = key
        editProtected = isProtected
        editorTitle.text = title
        editorGroup.text = group
        editorUsername.text = username
        clearLocalSecret()
        open()
    }

    function confirm() {
        if (awaitingConfirmation)
            return
        const submittedPassword = editorPassword.text
        awaitingConfirmation = root.controller.confirmRecord(
            root.editKey, editorTitle.text, editorGroup.text, editorUsername.text,
            root.editProtected, submittedPassword)
    }

    onOpened: editorTitle.forceActiveFocus()
    onRejected: {
        awaitingConfirmation = false
        clearLocalSecret()
    }
    onClosed: clearLocalSecret()

    Connections {
        target: root.controller

        function onRecordCommitted() {
            if (!root.awaitingConfirmation)
                return
            root.awaitingConfirmation = false
            editorTitle.clear()
            editorGroup.clear()
            editorUsername.clear()
            root.clearLocalSecret()
            root.close()
        }

        function onRecordRejected() {
            root.awaitingConfirmation = false
        }

        function onCommandRejected() {
            root.awaitingConfirmation = false
        }
    }

    contentItem: ColumnLayout {
        spacing: 10

        TextField {
            id: editorTitle
            objectName: "editorTitle"
            placeholderText: qsTr("Title")
            Accessible.name: qsTr("Record title")
            activeFocusOnTab: true
            Layout.fillWidth: true
            KeyNavigation.tab: editorGroup
        }

        TextField {
            id: editorGroup
            objectName: "editorGroup"
            placeholderText: qsTr("Group")
            Accessible.name: qsTr("Record group")
            activeFocusOnTab: true
            Layout.fillWidth: true
            KeyNavigation.tab: editorUsername
        }

        TextField {
            id: editorUsername
            objectName: "editorUsername"
            placeholderText: qsTr("Username")
            Accessible.name: qsTr("Record username")
            activeFocusOnTab: true
            Layout.fillWidth: true
            KeyNavigation.tab: editorPassword
        }

        TextField {
            id: editorPassword
            objectName: "editorPassword"
            placeholderText: root.editKey === 0 ? qsTr("Password") : qsTr("New password (optional)")
            echoMode: TextInput.Password
            Accessible.name: qsTr("Record password")
            activeFocusOnTab: true
            Layout.fillWidth: true
            KeyNavigation.tab: confirmButton
        }
    }

    footer: DialogButtonBox {
        Button {
            id: confirmButton
            objectName: "editorConfirmButton"
            text: qsTr("&Confirm")
            Accessible.name: qsTr("Confirm record changes")
            activeFocusOnTab: true
            KeyNavigation.tab: cancelButton
            onClicked: root.confirm()
        }

        Button {
            id: cancelButton
            objectName: "editorCancelButton"
            text: qsTr("&Cancel")
            enabled: !root.awaitingConfirmation
            Accessible.name: qsTr("Cancel record changes")
            activeFocusOnTab: true
            KeyNavigation.tab: editorTitle
            onClicked: root.reject()
        }
    }
}
