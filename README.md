# SSH Desk

A keyboard-driven SSH connection manager for Linux, with an Omarchy bar launcher.
Licensed under [MIT](LICENSE). No pip packages required.

The TUI uses a classic green terminal palette, cyan box borders, and amber
highlights. Profiles, sessions, and status have separate panels; session colors
indicate connection state. Monochrome terminals retain bold and reverse-video
highlights. Press **t** to cycle through six palettes (Phosphor, Amber, Ice, DOS, Neon,
and Paper); your choice is saved and used in the input forms too.
Use at least 48 columns by 24 rows (80+ columns shows more telemetry).

## Omarchy plugin

Plugin ID: `io.github.sjmaquina.ssh-desk`. It adds a small **>_** button to the right
side of the bar. Click it to open the SSH Desk terminal UI. The master password
and credentials stay in the Python application; the bar widget only launches it.

Install from the public GitHub repository once published:

```sh
omarchy plugin add https://github.com/sjmaquina/ssh-desk.git --enable
```

No separate installer is needed for the plugin: Python, the askpass helper, and
the QML widget are all included in the repository. Dependencies are Python 3.10+,
OpenSSH client tools, OpenSSL, a supported terminal, and Omarchy Quattro's
Quickshell runtime. The existing Omarchy installation supplies the shell/terminal;
SSH Desk installs no services and downloads no additional code at runtime.

Move or disable the launcher:

```sh
omarchy bar move io.github.sjmaquina.ssh-desk --section right
omarchy plugin disable io.github.sjmaquina.ssh-desk
```

Close the manager and SSH session windows before updating or removing the plugin:

```sh
omarchy plugin remove io.github.sjmaquina.ssh-desk
```

Removal deletes the plugin code. Your encrypted vault and saved host keys remain
in `~/.local/share/ssh-desk`; delete that directory yourself only if you want to
remove your data. The plugin does not edit your Hyprland keybindings, install
system packages, run sudo, or request network access before you open the manager
and start an SSH connection.

## Install and start

SSH Desk 0.1.0 supports Linux with Python 3.10+ (including the standard `curses`
module), OpenSSH client tools (`ssh`, `ssh-keyscan`, `ssh-keygen`), and OpenSSL.
No pip dependencies are required. Windows and macOS are not supported in this release.

Install the requirements through your distribution's package manager. For example:

```sh
# Debian / Ubuntu
sudo apt install python3 openssh-client openssl xterm

# Arch Linux
sudo pacman -S python openssh openssl xterm

# Fedora
sudo dnf install python3 openssh-clients openssl xterm
```

Use your existing terminal if you prefer. Supported launchers, in priority order:
`xdg-terminal-exec`, `foot`, `kitty`, `alacritty`, `ghostty`, `gnome-terminal`,
`konsole`, `xfce4-terminal`, and `xterm`. Configure `xdg-terminal-exec` if you
want to choose the preferred terminal explicitly.

Download and extract the source release, or clone this repository. From its directory:

```sh
python3 install.py
~/.local/bin/ssh-desk
```

The installer copies the app to `~/.local/share/ssh-desk`, creates the command in
`~/.local/bin`, and adds **SSH Desk** to the desktop application launcher. No sudo
is needed for installing the app. If `~/.local/bin` is on your PATH, use `ssh-desk`.
Use `ssh-desk --launch` to open a new terminal or `ssh-desk --version` to check the version.
Run `python3 ssh_desk.py` in a terminal to try it without installation.
Re-running `python3 install.py` updates application files while preserving your data.
Close the manager and session windows before updating.

To remove application files:

```sh
python3 install.py --uninstall
```

Uninstallation preserves your encrypted vault and saved host keys. The installer
also supports `--prefix /your/chosen/location` for installation and removal.

On first launch choose a master passphrase (12 characters minimum). Unlock the
vault with that passphrase on later launches. Press **m** in the manager to change
the master password; this re-encrypts all saved profiles. Existing sessions continue.
A wrong master password keeps the login window open and prompts you again;
press Ctrl+C to quit. Setup also retries if the confirmation does not match.
There is no forgotten-passphrase recovery.

## Keys

| Key | Action |
| --- | --- |
| Tab | Switch between profiles and sessions |
| Up / Down | Select a row in the focused panel |
| a | Add a connection |
| e | Edit selected connection |
| d | Delete selected connection, with confirmation |
| Enter | Open selected connection in a new terminal window |
| x | Close selected session, or all sessions for selected profile |
| m | Change master password (current password, new password, confirmation) |
| t | Cycle through six retro color palettes |
| q | Close manager; existing session windows continue running |
| Ctrl+] in a session window | Disconnect without reconnecting |
| Ctrl+C during reconnect delay | Cancel retries |

The profiles table has Device, User, IP, and Port columns (IP also accepts hostnames).

Profiles contain a name, hostname/IP, port, username, password, optional private
key path and optional private-key passphrase. Blank passwords use your SSH agent
or keys. SSH configuration is read by OpenSSH; entered host, port and user are explicit.
Interactive MFA/OTP is not currently supported by the password helper.

The bottom **STATUS** panel shows results of actions and errors. **RX** and **TX**
in the session table mean received and sent terminal data.

The sessions panel shows only current connections and connection/reconnection
attempts; closed, failed, and stale sessions are hidden.

Each Enter press creates a separate connection/window. The table lists session
age, state, received/sent **interactive terminal bytes**, reconnect count, and
host CPU/RAM usage. These byte totals include terminal output/control sequences;
they exclude SSH encryption overhead and the separate multiplexed telemetry channel.
They are not NIC or whole-host traffic counters. CPU is a sampled utilization
percentage; RAM is (MemTotal - MemAvailable) / MemTotal. Telemetry refreshes about
every three seconds on Linux hosts with `/proc`; no remote installation or root
access is required. Other hosts still have interactive sessions with unavailable metrics.

Connection loss triggers retries with exponential delays capped at 30 seconds.
An intentional remote `exit`, Ctrl+] or manager disconnect stops the session.
Authentication and host-key errors stop rather than repeatedly retrying.
A reconnected SSH session creates a **new remote shell**; it cannot restore running
foreground commands. Use `tmux` on the remote server for persistent work.

On first connection, SSH Desk resolves SSH config aliases to their configured
hostname before scanning keys. Scan failures show the target and underlying error.
The initial key scan requires direct access to the host, including any needed VPN. First connections through ProxyJump/ProxyCommand
are not supported by this initial scan; use a direct reachable host.
The session window shows scanned host-key fingerprints.
Verify them using a trusted source, then type `yes` to pin those keys. Later
connections enforce host-key checking. Changed host keys require investigation;
the app never silently replaces trusted keys.

## Storage and security

- `~/.local/share/ssh-desk/profiles.vault`: the entire profile list is encrypted,
  including passwords, usernames, hostnames, and key passphrases.
- AES-256-CBC via OpenSSL, with PBKDF2-SHA256 (600,000 iterations) and a fresh
  encryption salt. An independent scrypt-derived key (N=65536, r=8, p=1, 64 MiB)
  authenticates the envelope with HMAC-SHA256 **before** decryption.
- The master passphrase is never saved. Passphrases reach OpenSSL through an
  anonymous pipe, not command arguments or environment variables.
- Local password handoffs use private Unix sockets; passwords stay in process
  memory, not on disk or in SSH arguments/environment. The SSH askpass environment
  contains only a socket path.
- Vault and status files use permissions 0600; directories use 0700.
- `~/.local/share/ssh-desk/known_hosts`: pinned public keys, unencrypted.
- `$XDG_RUNTIME_DIR/ssh-desk-UID/`: session statistics and private sockets.
  Statistics contain connection names, host telemetry and process IDs, but no
  credentials. This directory normally disappears at reboot; without
  XDG_RUNTIME_DIR, a private directory under `/tmp` is used.
- Closing the manager leaves existing sessions alive; reopening it shows those
  windows' statistics. Restarting the desktop/computer does not reopen connections.
- One manager instance at a time prevents concurrent vault edits.

Decrypted credentials necessarily exist in RAM while unlocked/connected; disk
encryption does not protect against software running as your user or root.
Use a strong unique master passphrase. Back up the encrypted vault if needed.
Private key files remain wherever you already store them; this tool does not copy them.

## Development / verification

Validate the plugin manifest on Omarchy:

```sh
omarchy plugin validate .
```


```sh
python -m unittest discover -s tests -v
python -m py_compile ssh_desk.py
```

Tests cover vault round-trip, passphrase changes, wrong passphrases, tamper detection,
permissions, validation, terminal fallback, installation/removal, credential handoff,
host-key checks, active-session filtering/closing, terminal form entry, telemetry,
disconnect and reconnect. Worker integration uses a fake SSH executable in real
pseudo-terminals. The real socket handoff test runs where Unix sockets are allowed;
restricted sandboxes skip it explicitly. GitHub Actions checks Python 3.10, 3.12,
and 3.14 on Linux. Real server authentication and graphical terminal launching
still require desktop testing.

See [CHANGELOG.md](CHANGELOG.md) for release notes and [SECURITY.md](SECURITY.md)
for vulnerability reporting and security limitations.

## Publishing (maintainer)

The repository destination is `sjmaquina/ssh-desk`, with plugin ID
`io.github.sjmaquina.ssh-desk`. After reviewing the committed source and testing
on the desktop, publish from a normal terminal with GitHub CLI authenticated:

```sh
gh auth login
./publish.sh
```

The script creates the public repository if needed, pushes `main` without force,
and submits [the prepared listing](MARKETPLACE_SUBMISSION.md) to the Omarchy
marketplace. It preserves an existing private repository, refuses an unrelated
`origin`, and checks for an existing submission before creating another issue.
Maintainer approval determines whether the marketplace lists the plugin.
