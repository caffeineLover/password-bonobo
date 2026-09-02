pragma ComponentBehavior: Bound

import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import QtQml.Models

Pane {
    id: root
    required property var controller
    property int retainedKey: 0
    property int retainedRow: -1
    property string selectedTitle: ""
    property string selectedGroup: ""
    property string selectedUsername: ""
    property bool selectedProtected: false

    function selectRecord(key, row, title, group, username, isProtected) {
        root.retainedKey = key
        root.retainedRow = row
        root.selectedTitle = title
        root.selectedGroup = group
        root.selectedUsername = username
        root.selectedProtected = isProtected
    }

    DelegateModel {
        id: recordDelegates
        model: root.controller.records

        delegate: ItemDelegate {
            required property var model
            required property int index
            readonly property int recordKey: model.key
            readonly property string recordTitle: model.title
            readonly property string recordGroup: model.group
            readonly property string recordUsername: model.username
            readonly property bool recordProtected: model["protected"]
            width: ListView.view.width
            text: recordGroup
                  ? qsTr("%1 — %2 — %3").arg(recordTitle).arg(recordUsername).arg(recordGroup)
                  : qsTr("%1 — %2").arg(recordTitle).arg(recordUsername)
            Accessible.name: text
            highlighted: ListView.isCurrentItem
            ListView.onIsCurrentItemChanged: {
                if (ListView.isCurrentItem)
                    root.selectRecord(recordKey, index, recordTitle, recordGroup,
                                      recordUsername, recordProtected)
            }
            onClicked: {
                recordList.currentIndex = index
                root.selectRecord(recordKey, index, recordTitle, recordGroup,
                                  recordUsername, recordProtected)
            }
        }
    }

    function openSelected() {
        if (root.retainedKey === 0)
            return
        editor.openExisting(root.retainedKey, root.selectedTitle, root.selectedGroup,
                            root.selectedUsername, root.selectedProtected)
    }

    ColumnLayout {
        anchors.fill: parent
        spacing: 10

        RowLayout {
            Layout.fillWidth: true

            Label {
                text: root.controller.displayLabel
                font.pixelSize: 22
                Layout.fillWidth: true
            }

            Label {
                text: root.controller.dirty ? qsTr("Unsaved changes") : qsTr("Saved")
                Accessible.name: text
            }

            Button {
                id: saveButton
                objectName: "saveButton"
                text: qsTr("&Save")
                Accessible.name: qsTr("Save vault")
                activeFocusOnTab: true
                KeyNavigation.tab: lockButton
                onClicked: root.controller.save()
            }

            Button {
                id: lockButton
                objectName: "lockButton"
                text: qsTr("&Lock")
                Accessible.name: qsTr("Lock vault")
                activeFocusOnTab: true
                KeyNavigation.tab: searchField
                onClicked: root.controller.lock()
            }
        }

        TextField {
            id: searchField
            objectName: "searchField"
            placeholderText: qsTr("Search records")
            Accessible.name: qsTr("Search records")
            activeFocusOnTab: true
            Layout.fillWidth: true
            KeyNavigation.tab: recordList
            onTextEdited: root.controller.setSearch(text)
        }

        ListView {
            id: recordList
            objectName: "recordList"
            model: recordDelegates
            clip: true
            activeFocusOnTab: true
            Accessible.name: qsTr("Vault records")
            Layout.fillWidth: true
            Layout.fillHeight: true
            currentIndex: count > 0 ? 0 : -1
            highlight: Rectangle { color: palette.highlight; radius: 4 }
            highlightMoveDuration: 0
            KeyNavigation.tab: addButton

            Keys.onReturnPressed: root.openSelected()
            Keys.onEnterPressed: root.openSelected()
            onCountChanged: {
                if (count === 0 && activeFocus)
                    searchField.forceActiveFocus()
            }
        }

        RowLayout {
            Layout.fillWidth: true

            Button {
                id: addButton
                objectName: "addButton"
                text: qsTr("&Add")
                Accessible.name: qsTr("Add record")
                activeFocusOnTab: true
                KeyNavigation.tab: editButton
                onClicked: editor.openNew()
            }

            Button {
                id: editButton
                objectName: "editButton"
                text: qsTr("&Edit")
                Accessible.name: qsTr("Edit selected record")
                activeFocusOnTab: true
                enabled: root.retainedKey !== 0
                KeyNavigation.tab: copyUsernameButton
                onClicked: root.openSelected()
            }

            Button {
                id: copyUsernameButton
                objectName: "copyUsernameButton"
                text: qsTr("Copy &username")
                Accessible.name: qsTr("Copy selected username")
                activeFocusOnTab: true
                enabled: root.retainedKey !== 0
                KeyNavigation.tab: copyPasswordButton
                onClicked: root.controller.copyUsername(root.retainedKey)
            }

            Button {
                id: copyPasswordButton
                objectName: "copyPasswordButton"
                text: qsTr("Copy &password")
                Accessible.name: qsTr("Copy selected password")
                activeFocusOnTab: true
                enabled: root.retainedKey !== 0
                KeyNavigation.tab: openWebsiteButton
                onClicked: root.controller.copyPassword(root.retainedKey)
            }

            Button {
                id: openWebsiteButton
                objectName: "openWebsiteButton"
                text: qsTr("Open &website")
                Accessible.name: qsTr("Open selected website")
                activeFocusOnTab: true
                enabled: root.retainedKey !== 0
                KeyNavigation.tab: saveButton
                onClicked: root.controller.openWebsite(root.retainedKey)
            }
        }
    }

    RecordEditor {
        id: editor
        objectName: "recordEditor"
        controller: root.controller
    }

    Shortcut {
        sequence: "Ctrl+S"
        context: Qt.ApplicationShortcut
        onActivated: root.controller.save()
    }

    Shortcut {
        sequence: "Ctrl+L"
        context: Qt.ApplicationShortcut
        onActivated: root.controller.lock()
    }

    Shortcut {
        sequence: "Ctrl+F"
        context: Qt.ApplicationShortcut
        onActivated: searchField.forceActiveFocus()
    }

    Component.onCompleted: searchField.forceActiveFocus()
}
