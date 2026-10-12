# SSH Desk 0.1.0 release review

## Completed

- Reviewed profile validation, encrypted vault persistence and passphrase changes,
  host-key approval, credential handoff, terminal launch, telemetry, reconnects,
  session closing/filtering, and terminal layout.
- Preserved the SSHDESK1 vault format and existing data.
- Replaced the askpass dependency on `/usr/bin/python` with the worker's Python
  interpreter, with a `python3` fallback.
- Added terminal discovery, `--launch`, `--version`, dependency checks, and a
  friendly error when started without a terminal.
- Fixed key passphrase selection when the key filename contains “password”.
- Limited new master passwords by UTF-8 byte length and rejected line/control
  characters so OpenSSL receives the intended passphrase.
- Clear credential handoffs after failed terminal launches; close sockets after
  failed broker initialization.
- Refresh reconnect status during long retry delays so the manager keeps showing it.
- Ignore malformed session-state records and keep profile edit/delete actions in
  the profiles panel.
- Added a portable user-local installer, safe removal that preserves data, desktop
  launcher, changelog, security notes, and public installation instructions.
- Replaced personal network aliases/IPs in tests with invented fixtures and a
  documentation-only example address. No vaults, host keys, private keys, or live
  session files are included in the source bundle.

## Verification

- Python compilation and shell syntax checks passed.
- All 24 checks now have passing results: 23 passed in the sandbox, and the real
  Unix-socket handoff check passed separately in the user's normal terminal on
  Python 3.14. The socket check verifies delivery and rejects reuse of the token.
- Verified wrong-password retry and a subsequent successful login in a real
  pseudo-terminal; both passwords remained hidden and the vault stayed unchanged.
- Installation, command execution, desktop entry validation, and uninstallation
  passed in a temporary prefix containing spaces. The installed version is 0.1.0.
- The generated GitHub Actions workflow targets Python 3.10, 3.12, and 3.14. It has
  not run on GitHub yet. The action versions follow the official
  [checkout](https://github.com/actions/checkout) and
  [setup-python](https://github.com/actions/setup-python) documentation.

## Before a public release

- Publish the source to https://github.com/sjmaquina/ssh-desk.
  The destination is set; uploading remains blocked by this session's network access.
  The MIT license is now set, with Sergio Justiniano as copyright holder.
- The Omarchy manifest and QML bar launcher pass local validation, including
  qmllint with the installed Quattro imports. Test the launcher on the live bar
  before submitting the marketplace issue.
- Run the CI workflow and a desktop check of real SSH password/key authentication,
  terminal launch, reconnect, and session closing. The real local credential
  handoff is verified; live SSH and desktop checks remain to be completed.
- First-time host-key scans require direct access; ProxyJump/ProxyCommand first
  connections and interactive MFA are not supported. The README documents these limits.
- This application has not had an independent security audit. Its encrypted vault
  is reviewed locally, but that does not establish a formal security certification.

The preview archive includes the MIT license and Omarchy plugin files.
Nothing has been published remotely.
