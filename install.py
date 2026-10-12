#!/usr/bin/env python3
"""Install or remove SSH Desk for the current user, without sudo."""
import argparse
import os
from pathlib import Path
import shlex
import shutil
import tempfile

SOURCE = Path(__file__).resolve().parent


def write_file(path, data, mode):
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(dir=path.parent)
    try:
        with os.fdopen(fd, 'wb') as stream:
            stream.write(data)
            os.fchmod(stream.fileno(), mode)
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def desktop_quote(path):
    value = str(path).replace('%', '%%')
    for char in ('\\', '"', '`', '$'):
        value = value.replace(char, '\\'+char)
    # Desktop files have a string escape layer before Exec argument parsing.
    return '"'+value.replace('\\', '\\\\')+'"'


def install(prefix):
    app_dir = prefix/'share/ssh-desk'
    for name in ('ssh_desk.py', 'askpass'):
        write_file(app_dir/name, (SOURCE/name).read_bytes(), 0o755)
    for name in ('README.md', 'LICENSE', 'SECURITY.md'):
        if (SOURCE/name).exists():
            write_file(app_dir/name, (SOURCE/name).read_bytes(), 0o644)
    command = prefix/'bin/ssh-desk'
    wrapper = '#!/bin/sh\nexec python3 '+shlex.quote(str(app_dir/'ssh_desk.py'))+' "$@"\n'
    write_file(command, wrapper.encode(), 0o755)
    desktop = ('[Desktop Entry]\nType=Application\nName=SSH Desk\n'
               'Comment=Encrypted SSH connection manager\nExec='+desktop_quote(command)+' --launch\n'
               'Terminal=false\nIcon=network-server\nCategories=Network;RemoteAccess;\n')
    write_file(prefix/'share/applications/ssh-desk.desktop', desktop.encode(), 0o644)
    print(f'Installed SSH Desk to {command}')
    print(f'Run {command}, or choose SSH Desk in your application launcher.')


def uninstall(prefix):
    paths = [prefix/'bin/ssh-desk', prefix/'share/applications/ssh-desk.desktop']
    app_dir = prefix/'share/ssh-desk'
    paths += [app_dir/name for name in ('ssh_desk.py', 'askpass', 'README.md', 'LICENSE', 'SECURITY.md')]
    for path in paths:
        path.unlink(missing_ok=True)
    try:
        app_dir.rmdir()
    except OSError:
        pass
    print('Removed SSH Desk application files. Your vault and saved host keys are preserved.')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--prefix', type=Path, default=Path.home()/'.local', help='Installation prefix (default: ~/.local)')
    parser.add_argument('--uninstall', action='store_true', help='Remove application files; preserve user data')
    args = parser.parse_args()
    prefix = args.prefix.expanduser().resolve()
    if '\n' in str(prefix) or '\r' in str(prefix):
        parser.error('The installation prefix must not contain newlines')
    if args.uninstall:
        uninstall(prefix)
    else:
        if not shutil.which('python3'):
            parser.error('Python 3 is required')
        install(prefix)


if __name__ == '__main__':
    main()
