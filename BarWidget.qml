import QtQuick
import Quickshell
import qs.Ui as Ui

Ui.BarWidget {
    id: root
    moduleName: "io.github.sjmaquina.ssh-desk"

    implicitWidth: button.implicitWidth
    implicitHeight: button.implicitHeight

    function open() {
        const scriptUrl = Qt.resolvedUrl("ssh_desk.py").toString()
        const scriptPath = decodeURIComponent(scriptUrl.replace(/^file:\/\//, ""))
        Quickshell.execDetached(["python3", scriptPath, "--launch"])
    }

    Ui.WidgetButton {
        id: button
        anchors.fill: parent
        bar: root.bar
        text: ">_"
        tooltipText: "Open SSH Desk"
        onPressed: function(buttonCode) {
            if (buttonCode === Qt.LeftButton) root.open()
        }
    }
}
