import QtQuick
import QtQuick.Controls

Dialog {
    id: root
    required property var controller
    modal: true
    anchors.centerIn: parent
    width: 420
    title: qsTr("Unsaved changes")
    closePolicy: Popup.CloseOnEscape
    onRejected: root.controller.resolveClose("cancel")

    contentItem: Label {
        text: qsTr("Save or discard the current changes before continuing?")
        wrapMode: Text.WordWrap
        Accessible.name: text
    }

    footer: DialogButtonBox {
        Button {
            id: decisionSaveButton
            objectName: "decisionSaveButton"
            text: qsTr("&Save")
            Accessible.name: qsTr("Save changes and continue")
            activeFocusOnTab: true
            KeyNavigation.tab: decisionDiscardButton
            onClicked: {
                root.close()
                root.controller.resolveClose("save")
            }
        }

        Button {
            id: decisionDiscardButton
            objectName: "decisionDiscardButton"
            text: qsTr("&Discard")
            Accessible.name: qsTr("Discard changes and continue")
            activeFocusOnTab: true
            KeyNavigation.tab: decisionCancelButton
            onClicked: {
                root.close()
                root.controller.resolveClose("discard")
            }
        }

        Button {
            id: decisionCancelButton
            objectName: "decisionCancelButton"
            text: qsTr("&Cancel")
            Accessible.name: qsTr("Cancel and keep editing")
            activeFocusOnTab: true
            KeyNavigation.tab: decisionSaveButton
            onClicked: root.reject()
        }
    }
}
