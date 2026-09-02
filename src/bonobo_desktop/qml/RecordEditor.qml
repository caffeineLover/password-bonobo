import QtQuick
import QtQuick.Controls
import QtQuick.Layouts

Dialog {
    id: root
    required property var controller
    property int editKey: 0
    property bool editProtected: false
    modal: true
    anchors.centerIn: parent
    width: Math.min(parent ? parent.width - 48 : 520, 520)
    title: editKey === 0 ? qsTr("Add record") : qsTr("Edit record")
    closePolicy: Popup.CloseOnEscape

    function clearLocalSecret() {
        editorPassword.clear()
    }

    function openNew() {
        editKey = 0
        editProtected = false
        editorTitle.clear()
        editorGroup.clear()
        editorUsername.clear()
        clearLocalSecret()
        open()
    }

    function openExisting(key, title, group, username, isProtected) {
        editKey = key
        editProtected = isProtected
        editorTitle.text = title
        editorGroup.text = group
        editorUsername.text = username
        clearLocalSecret()
        open()
    }

    function confirm() {
        const submittedPassword = editorPassword.text
        clearLocalSecret()
        root.controller.confirmRecord(root.editKey, editorTitle.text, editorGroup.text,
                                      editorUsername.text, root.editProtected, submittedPassword)
        close()
    }

    onOpened: editorTitle.forceActiveFocus()
    onRejected: clearLocalSecret()
    onClosed: clearLocalSecret()

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
            Accessible.name: qsTr("Cancel record changes")
            activeFocusOnTab: true
            KeyNavigation.tab: editorTitle
            onClicked: root.reject()
        }
    }
}
