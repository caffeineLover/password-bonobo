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
}
