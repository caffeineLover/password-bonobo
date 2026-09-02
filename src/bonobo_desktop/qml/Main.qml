pragma ComponentBehavior: Bound

import QtQuick
import QtQuick.Controls

ApplicationWindow {
    id: root
    objectName: "mainWindow"
    width: 960
    height: 640
    minimumWidth: 720
    minimumHeight: 480
    visible: true
    title: qsTr("Password Bonobo")

    // The composition root owns this one closed context object.
    // qmllint disable unqualified
    readonly property var controller: desktopController
    // qmllint enable unqualified
    readonly property string currentPhase: controller.phase
    property string statusCopy: ""

    function failureStatus(key) {
        switch (key) {
        case "application.failure.authentication-failed":
            return qsTr("The passphrase was not accepted.")
        case "application.failure.integrity-failed":
            return qsTr("Vault integrity verification failed.")
        case "application.failure.malformed-vault":
            return qsTr("The vault data is malformed.")
        case "application.failure.unsupported-format":
            return qsTr("This vault format is not supported.")
        case "application.failure.incompatible-export":
            return qsTr("The vault uses incompatible export settings.")
        case "application.failure.resource-limit":
            return qsTr("The vault exceeds supported resource limits.")
        case "application.failure.crypto-backend":
            return qsTr("Secure vault processing is unavailable.")
        case "application.failure.protected-record":
            return qsTr("That protected record cannot be changed.")
        case "application.failure.stale-revision":
            return qsTr("The vault changed. Review the latest data and try again.")
        case "application.failure.unsaved-changes":
            return qsTr("Save or discard the pending changes first.")
        case "application.failure.external-modification":
            return qsTr("The vault changed outside Password Bonobo.")
        case "application.failure.storage":
            return qsTr("The vault could not be read or written.")
        case "application.failure.recovery-available":
            return qsTr("Recovery data is available for this vault.")
        case "application.failure.clipboard-unavailable":
            return qsTr("The clipboard is unavailable.")
        case "application.failure.browser-unavailable":
            return qsTr("The website could not be opened.")
        case "application.failure.unexpected":
            return qsTr("The action could not be completed.")
        default:
            return ""
        }
    }

    function presentStatus(copy) {
        root.statusCopy = copy
        if (copy.length > 0)
            statusSurface.Accessible.announce(copy, Accessible.Polite)
    }

    Loader {
        id: viewLoader
        anchors.fill: parent
        sourceComponent: root.currentPhase === "empty"
                         ? welcomeComponent
                         : root.currentPhase === "locked"
                           ? unlockComponent
                           : vaultComponent
    }

    Component {
        id: welcomeComponent
        WelcomeView {
            controller: root.controller
        }
    }

    Component {
        id: unlockComponent
        UnlockView {
            controller: root.controller
        }
    }

    Component {
        id: vaultComponent
        VaultView {
            controller: root.controller
        }
    }

    DecisionDialog {
        id: decisionDialog
        objectName: "decisionDialog"
        controller: root.controller
        visible: root.controller.decisionRequired
    }

    Label {
        id: statusSurface
        objectName: "applicationStatus"
        anchors.left: parent.left
        anchors.right: parent.right
        anchors.bottom: parent.bottom
        anchors.margins: 12
        z: 10
        visible: text.length > 0
        text: root.statusCopy
        horizontalAlignment: Text.AlignHCenter
        wrapMode: Text.Wrap
        padding: 10
        Accessible.role: Accessible.AlertMessage
        Accessible.name: text

        background: Rectangle {
            color: statusSurface.palette.midlight
            radius: 4
        }
    }

    Connections {
        target: root.controller

        function onSnapshotChanged() {
            root.presentStatus(root.failureStatus(root.controller.failureKey))
        }

        function onCommandRejected() {
            root.presentStatus(qsTr("The action could not be completed."))
        }
    }

    Component.onCompleted: root.presentStatus(root.failureStatus(root.controller.failureKey))
}
