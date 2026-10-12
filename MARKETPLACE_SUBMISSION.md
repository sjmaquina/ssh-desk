### Repository URL

https://github.com/sjmaquina/ssh-desk

### Category

Developer Tools

### Tags

Bar, Launcher, Security

### Maintainer notes

SSH Desk is an MIT-licensed Omarchy Quattro bar plugin that launches a retro
terminal SSH connection manager. The repository root contains manifest.json
and BarWidget.qml, with the Python app and askpass helper bundled beside them.

Click the >_ bar button to open the manager in a terminal. No separate app
installation, sudo, service installation, or configuration overwrite is needed.
Dependencies: Omarchy Quattro/Quickshell, Python 3.10+, OpenSSH client tools,
OpenSSL, and a supported terminal launcher. No pip packages or runtime downloads.

The app stores connection profiles in an authenticated, encrypted vault and
supports master-password changes, explicit first-connection fingerprint approval,
individual session closing, automatic reconnects, and Linux host telemetry.
First-time proxy/jump-host scans and interactive MFA are not supported.

Credentials remain in the Python app, not the shell widget. Network access occurs
when the user connects. Runtime credentials use private Unix sockets; encrypted
profiles and approved host keys are saved under ~/.local/share/ssh-desk.
Removal preserves user data; close the manager and sessions before updating or
removing the code. Installation/removal and dependencies are documented in README.

Manifest validation and qmllint pass locally. The Python suite has 24 passing
results across the sandbox and the author's desktop, including a real socket
handoff test. Live bar launch and SSH authentication still need desktop verification. Listing approval is not represented as a security audit.

### Submission checklist

- [ ] The repository is public and contains installation and removal instructions.
- [x] I have documented the plugin license and any external dependencies.
- [x] I confirm that I own or have permission to submit this plugin and its preview assets.
- [x] The plugin does not overwrite user configuration without explicit consent.
- [x] I understand that approval is for listing and is not a security review.
