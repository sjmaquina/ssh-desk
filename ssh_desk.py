#!/usr/bin/env python3
"""SSH Desk: encrypted profiles, OpenSSH windows and Linux telemetry."""
import argparse
import curses
import getpass
import hashlib
import hmac
import json
import os
from pathlib import Path
import pty
import secrets
import select
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import termios
import threading
import time
import tty
import uuid

ROOT = Path(__file__).resolve().parent
DATA = Path(os.environ.get('SSH_DESK_DATA', Path.home() / '.local/share/ssh-desk'))
RUN = Path(os.environ.get('XDG_RUNTIME_DIR', '/tmp')) / ('ssh-desk-' + str(os.getuid()))
SCRIPT = str(Path(__file__).resolve())
VERSION = '0.1.0'


def private_dir(path):
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    if path.is_symlink() or path.stat().st_uid != os.getuid():
        raise ValueError('Unsafe data directory')
    path.chmod(0o700)


def atomic(path, data):
    fd, name = tempfile.mkstemp(dir=path.parent)
    try:
        with os.fdopen(fd, 'wb') as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        os.replace(name, path)
    finally:
        if os.path.exists(name):
            os.unlink(name)


class VaultUnlockError(ValueError):
    """The passphrase did not authenticate the encrypted vault."""


def crypt(data, phrase, decrypt=False):
    """OpenSSL AES-256-CBC with encrypt-then-MAC (HMAC-SHA256).

    CBC key/IV: OpenSSL PBKDF2-SHA256 (600,000 iterations, random salt).
    Independent authentication key: scrypt with a separate random salt.
    Verify authentication before ever passing ciphertext to the decryptor.
    """
    magic = b'SSHDESK1'
    if decrypt:
        if len(data) < 72 or data[:8] != magic:
            raise ValueError('Invalid vault format')
        salt = data[8:24]
        ciphertext, tag = data[24:-32], data[-32:]
    else:
        salt = os.urandom(16)
    mac_key = hashlib.scrypt(phrase.encode(), salt=salt, n=65536, r=8, p=1, maxmem=128*1024*1024, dklen=32)
    if decrypt and not hmac.compare_digest(hmac.digest(mac_key, data[:-32], 'sha256'), tag):
        raise VaultUnlockError('Could not unlock vault (wrong passphrase or damaged file)')
    r, w = os.pipe()
    try:
        os.write(w, phrase.encode() + b'\n')
        os.close(w)
        w = None
        args = ['openssl', 'enc', '-aes-256-cbc', '-pbkdf2', '-iter', '600000',
                '-md', 'sha256', '-pass', 'fd:' + str(r)]
        if decrypt:
            args += ['-d']
        result = subprocess.run(args, input=ciphertext if decrypt else data,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, pass_fds=(r,))
        if result.returncode:
            raise ValueError('Vault decryption failed' if decrypt else 'OpenSSL encryption failed')
        if decrypt:
            return result.stdout
        envelope = magic + salt + result.stdout
        return envelope + hmac.digest(mac_key, envelope, 'sha256')
    finally:
        os.close(r)
        if w is not None:
            os.close(w)


class Vault:
    def __init__(self, phrase):
        private_dir(DATA)
        self.phrase = phrase
        self.path = DATA / 'profiles.vault'
        self.profiles = json.loads(crypt(self.path.read_bytes(), phrase, True)) if self.path.exists() else []

    def save(self):
        atomic(self.path, crypt(json.dumps(self.profiles).encode(), self.phrase))

    def change_phrase(self, current, replacement):
        if not hmac.compare_digest(current.encode(), self.phrase.encode()):
            raise ValueError('Current master password is incorrect.')
        validate_new_phrase(replacement)
        # Update the in-memory key only after the encrypted vault is replaced.
        encrypted = crypt(json.dumps(self.profiles).encode(), replacement)
        atomic(self.path, encrypted)
        self.phrase = replacement


def validate(p):
    for key in ('name', 'host', 'user'):
        if not p[key] or any(ord(c) < 32 or ord(c) == 127 for c in p[key]):
            raise ValueError(f'{key} is required and must contain no control characters')
    if p['host'].startswith('-') or any(c.isspace() for c in p['host']) or '@' in p['host']:
        raise ValueError('Enter a hostname or IP address, without user@ or SSH options')
    if not 1 <= int(p['port']) <= 65535:
        raise ValueError('Port must be between 1 and 65535')
    if p.get('key') and not Path(p['key']).expanduser().is_file():
        raise ValueError('Private key file does not exist')


def terminal_command(command):
    """Run a command in a new terminal on common Linux desktops."""
    for name, options in (
        ('xdg-terminal-exec', []), ('foot', ['-e']), ('kitty', ['-e']),
        ('alacritty', ['-e']), ('ghostty', ['-e']), ('gnome-terminal', ['--']),
        ('konsole', ['-e']), ('xfce4-terminal', ['-x']), ('xterm', ['-e']),
    ):
        if executable := shutil.which(name):
            return [executable]+options+list(command)
    raise ValueError('No supported terminal found. Install xdg-terminal-exec, foot, kitty, alacritty, ghostty, gnome-terminal, konsole, xfce4-terminal or xterm.')


def check_requirements():
    missing = [name for name in ('ssh', 'ssh-keyscan', 'ssh-keygen', 'openssl') if not shutil.which(name)]
    if missing:
        raise ValueError('Missing required commands: '+', '.join(missing))
    if not sys.stdin.isatty() or not sys.stdout.isatty():
        raise ValueError('Run SSH Desk in a terminal, or use ssh-desk --launch.')


def validate_new_phrase(phrase):
    if len(phrase) < 12 or len(phrase.encode()) > 1023 or any(ord(c) < 32 or ord(c) == 127 for c in phrase):
        raise ValueError('Use a master password of at least 12 characters and at most 1023 UTF-8 bytes, without control characters.')


class Broker:
    """One-use credential handoffs to local window workers; no plaintext files."""
    def __init__(self):
        private_dir(RUN)
        self.path = RUN / (uuid.uuid4().hex + '.sock')
        self.pending = {}
        self.lock = threading.Lock()
        self.sock = socket.socket(socket.AF_UNIX)
        try:
            self.sock.bind(str(self.path))
            self.path.chmod(0o600)
            self.sock.listen()
        except OSError:
            self.sock.close()
            self.path.unlink(missing_ok=True)
            raise
        threading.Thread(target=self.serve, daemon=True).start()

    def serve(self):
        while True:
            try:
                conn, _ = self.sock.accept()
            except OSError:
                return
            with conn:
                conn.settimeout(3)
                try:
                    token = conn.recv(128).decode().strip()
                    with self.lock:
                        item = self.pending.pop(token, None)
                    if item and time.time() - item[0] < 60:
                        conn.sendall(json.dumps(item[1]).encode())
                except (OSError, ValueError):
                    pass

    def launch(self, profile):
        token = secrets.token_hex(32)
        with self.lock:
            self.pending = {k: v for k, v in self.pending.items() if time.time()-v[0] < 60}
            self.pending[token] = (time.time(), dict(profile))
        cmd = [sys.executable, SCRIPT, '--worker', str(self.path), token]
        try:
            subprocess.Popen(terminal_command(cmd), start_new_session=True,
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except (OSError, ValueError):
            with self.lock:
                self.pending.pop(token, None)
            raise

    def close(self):
        self.sock.close()
        self.path.unlink(missing_ok=True)
        self.pending.clear()


def receive(path, token):
    with socket.socket(socket.AF_UNIX) as s:
        s.settimeout(5)
        s.connect(path)
        s.sendall(token.encode())
        chunks = []
        while chunk := s.recv(65536):
            chunks.append(chunk)
    if not chunks:
        raise ValueError('Credential handoff expired. Open the connection again from SSH Desk.')
    return json.loads(b''.join(chunks))


def ssh_args(p, control, multiplex=False):
    args = ['ssh', '-p', str(p['port']), '-l', p['user'],
            '-o', 'ConnectTimeout=10', '-o', 'ServerAliveInterval=5',
            '-o', 'ServerAliveCountMax=3', '-o', 'StrictHostKeyChecking=yes',
            '-o', 'UserKnownHostsFile=' + str(DATA / 'known_hosts'),
            '-o', 'ControlPath=' + str(control)]
    args += ['-o', 'ControlMaster=no', '-o', 'BatchMode=yes', '-o', 'ProxyCommand=false'] if multiplex else ['-o', 'ControlMaster=yes', '-o', 'ControlPersist=no']
    if p.get('key'):
        args += ['-i', str(Path(p['key']).expanduser()), '-o', 'IdentitiesOnly=yes']
    return args


def trust_host(p):
    """Ask the user to verify and explicitly pin scanned public host keys."""
    known = DATA / 'known_hosts'
    config = subprocess.run(ssh_args(p, RUN / 'host-check.ctl') + ['-G', p['host']],
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10)
    if config.returncode:
        detail = config.stderr.decode(errors='replace').strip()
        raise ValueError('Unable to read SSH configuration: ' + (detail or 'ssh -G failed'))
    options = dict(line.split(None, 1) for line in config.stdout.decode(errors='replace').splitlines() if ' ' in line)
    hostname = options.get('hostname', p['host'])
    port = int(options.get('port', p['port']))
    alias = options.get('hostkeyalias')
    host = alias if alias and alias != 'none' else hostname if port == 22 else f'[{hostname}]:{port}'
    if known.exists() and subprocess.run(['ssh-keygen', '-F', host, '-f', str(known)], stdout=subprocess.DEVNULL).returncode == 0:
        return
    try:
        scan = subprocess.run(['ssh-keyscan', '-T', '8', '-p', str(port), '--', hostname],
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30)
    except subprocess.TimeoutExpired:
        raise ValueError(f'Host-key check timed out for {hostname}:{port}. Check the server, VPN and SSH port.') from None
    if not scan.stdout:
        detail = scan.stderr.decode(errors='replace').strip()
        message = f'Unable to obtain host keys from {hostname}:{port}.'
        if detail:
            message += '\n' + detail
        else:
            message += '\nNo SSH response. Check the server, VPN, firewall and SSH port.'
        if options.get('proxyjump', 'none') != 'none' or options.get('proxycommand', 'none') != 'none':
            message += '\nThis profile uses a proxy; the initial key scan currently requires direct access to the host.'
        raise ValueError(message)
    # HostKeyAlias overrides the name OpenSSH looks up in known_hosts.
    if alias and alias != 'none':
        scan.stdout = b''.join(host.encode()+b' '+line.split(b' ', 1)[1]+b'\n'
                               for line in scan.stdout.splitlines() if line and not line.startswith(b'#'))
    fingerprints = subprocess.run(['ssh-keygen', '-lf', '-'], input=scan.stdout, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if fingerprints.returncode:
        raise ValueError('Invalid host key response')
    print('\nFirst connection: verify these fingerprints with your server administrator:')
    print(fingerprints.stdout.decode())
    if input('Type yes to trust and save these host keys: ').strip() != 'yes':
        raise ValueError('Host was not trusted')
    # Serialize concurrent first-connection approvals.
    import fcntl
    fd = os.open(known, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
    with os.fdopen(fd, 'ab') as f:
        fcntl.flock(f, fcntl.LOCK_EX)
        f.write(scan.stdout)


PROBE = "LC_ALL=C; printf 'CPU '; head -n 1 /proc/stat; printf 'MEM '; awk '/MemTotal:/{t=$2} /MemAvailable:/{a=$2} END{print t,a}' /proc/meminfo; printf 'UP '; cut -d' ' -f1 /proc/uptime; printf 'HOST '; hostname"


def parse_metrics(output, previous=None):
    result = {}
    sample = None
    for line in output.splitlines():
        words = line.split()
        if words[:2] == ['CPU', 'cpu']:
            ticks = list(map(int, words[2:10]))
            sample = (sum(ticks), ticks[3] + ticks[4])
            if previous and sample[0] > previous[0]:
                result['cpu'] = round(100 * (1 - (sample[1]-previous[1])/(sample[0]-previous[0])), 1)
        elif words[:1] == ['MEM'] and len(words) == 3:
            total, available = map(int, words[1:])
            if total:
                result['ram'] = round(100 * (total-available)/total, 1)
        elif words[:1] == ['UP']:
            result['uptime'] = float(words[1])
        elif words[:1] == ['HOST']:
            result['hostname'] = ' '.join(words[1:])
    return result, sample


def credential_for_prompt(profile, prompt):
    prompt = prompt.lower()
    if 'passphrase' in prompt:
        return profile.get('key_password', '')
    if 'password' in prompt:
        return profile.get('password', '')
    return ''


def worker(path, token):
    p = receive(path, token)
    validate(p)
    private_dir(DATA)
    private_dir(RUN)
    ident = uuid.uuid4().hex
    status_path = RUN / (ident + '.json')
    control = RUN / (ident[:16] + '.ctl')
    stop_path = RUN / (ident + '.stop')
    stats = dict(profile=p['id'], name=p['name'], pid=os.getpid(), started=time.time(),
                 rx=0, tx=0, reconnects=0, state='connecting', connected_seconds=0)
    def publish(**fields):
        stats.update(fields)
        stats['updated'] = time.time()
        atomic(status_path, json.dumps(stats).encode())
    publish()
    child = None
    auth = None
    stopped = threading.Event()
    def halt(*_):
        stopped.set()
    signal.signal(signal.SIGTERM, halt)
    signal.signal(signal.SIGHUP, halt)
    try:
        trust_host(p)
        # Reusable password broker is private to this worker and lives in memory.
        auth_path = RUN / (ident[:16] + '.auth')
        auth = socket.socket(socket.AF_UNIX)
        auth.bind(str(auth_path))
        auth_path.chmod(0o600)
        auth.listen()
        auth.settimeout(1)
        def passwords():
            while not stopped.is_set():
                try:
                    c, _ = auth.accept()
                    with c:
                        c.settimeout(1)
                        prompt = c.recv(4096).decode(errors='replace').lower()
                        value = credential_for_prompt(p, prompt)
                        c.sendall(value.encode())
                except (OSError, TimeoutError):
                    continue
        threading.Thread(target=passwords, daemon=True).start()
        env = dict(os.environ, SSH_ASKPASS=str(ROOT / 'askpass'), SSH_ASKPASS_REQUIRE='force',
                   DISPLAY=os.environ.get('DISPLAY', ':0'), SSH_DESK_AUTH=str(auth_path),
                   SSH_DESK_PYTHON=sys.executable)
        attempt = 0
        while not stopped.is_set() and not stop_path.exists():
            control.unlink(missing_ok=True)
            publish(state='connecting', cpu=None, ram=None)
            print(f"\r\nConnecting to {p['user']}@{p['host']}:{p['port']} — Ctrl+] disconnects.\r\n", flush=True)
            master, slave = pty.openpty()
            size = os.get_terminal_size(sys.stdin.fileno())
            import fcntl, struct
            fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack('HHHH', size.lines, size.columns, 0, 0))
            child = subprocess.Popen(ssh_args(p, control) + ['-tt', p['host']], stdin=slave, stdout=slave, stderr=slave, env=env, start_new_session=True)
            os.close(slave)
            old = termios.tcgetattr(sys.stdin)
            tty.setraw(sys.stdin)
            connected_at = None
            next_probe = 0
            previous = None
            probe = None
            chunk_buffer = bytearray()
            error_tail = bytearray()
            probe_started = 0
            last_size = size
            try:
                while child.poll() is None and not stopped.is_set() and not stop_path.exists():
                    now = time.time()
                    if control.exists() and connected_at is None:
                        connected_at = now
                        attempt = 0
                        publish(state='connected')
                    new_size = os.get_terminal_size(sys.stdin.fileno())
                    if new_size != last_size:
                        fcntl.ioctl(master, termios.TIOCSWINSZ, struct.pack('HHHH', new_size.lines, new_size.columns, 0, 0))
                        last_size = new_size
                    read, write, _ = select.select([sys.stdin, master], [master] if chunk_buffer else [], [], .2)
                    if sys.stdin in read:
                        data = os.read(sys.stdin.fileno(), 8192)
                        if not data or b'\x1d' in data:
                            stopped.set()
                            break
                        chunk_buffer.extend(data)
                    if master in write:
                        try:
                            sent = os.write(master, chunk_buffer)
                            del chunk_buffer[:sent]
                            stats['tx'] += sent
                        except OSError:
                            break
                    if master in read:
                        try:
                            data = os.read(master, 65536)
                        except OSError:
                            break
                        if not data:
                            break
                        os.write(sys.stdout.fileno(), data)
                        stats['rx'] += len(data)
                        error_tail.extend(data)
                        del error_tail[:-8192]
                    if connected_at and probe is None and now >= next_probe:
                        probe = subprocess.Popen(ssh_args(p, control, True) + [p['host'], PROBE], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
                        probe_started = now
                        next_probe = now + 3
                    if probe and (probe.poll() is not None or now-probe_started > 5):
                        if probe.poll() is None:
                            probe.kill()
                        output = probe.communicate()[0].decode(errors='replace')
                        try:
                            metrics, previous = parse_metrics(output, previous)
                            publish(cpu=metrics.get('cpu'), ram=metrics.get('ram'), **{k:v for k,v in metrics.items() if k not in ('cpu','ram')}, metrics_state='available' if metrics else 'unavailable')
                        except (ValueError, IndexError):
                            publish(metrics_state='unavailable')
                        probe = None
                    publish(elapsed=int(now-stats['started']), connected_seconds=stats['connected_seconds'])
            finally:
                termios.tcsetattr(sys.stdin, termios.TCSADRAIN, old)
                if probe:
                    probe.kill()
                    probe.communicate()
                if child.poll() is None:
                    child.terminate()
                try:
                    code = child.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    child.kill()
                    code = child.wait()
                os.close(master)
                if connected_at:
                    stats['connected_seconds'] += time.time()-connected_at
            if stopped.is_set() or stop_path.exists() or code != 255:
                break
            tail = error_tail.decode(errors='replace').lower()
            if any(x in tail for x in ['permission denied', 'host key verification failed', 'remote host identification has changed', 'bad configuration option']):
                publish(state='error')
                print('\nAuthentication or host-key error. Fix the profile or verify the host key before retrying.')
                input('Press Enter to close…')
                break
            attempt += 1
            stats['reconnects'] += 1
            delay = min(30, 2 ** min(attempt, 5))
            publish(state=f'reconnecting ({delay}s)', cpu=None, ram=None)
            print(f'\r\nConnection lost. Reconnecting in {delay}s; Ctrl+C to stop.\r\n', flush=True)
            deadline = time.time() + delay
            next_heartbeat = 0
            while time.time() < deadline and not stopped.is_set() and not stop_path.exists():
                if time.time() >= next_heartbeat:
                    publish()
                    next_heartbeat = time.time()+1
                time.sleep(.2)
    except KeyboardInterrupt:
        pass
    except Exception as e:
        print(f'\nConnection stopped: {e}')
        publish(state='error')
        try:
            input('Press Enter to close…')
        except (EOFError, KeyboardInterrupt):
            pass
    finally:
        stopped.set()
        if child and child.poll() is None:
            child.terminate()
        if auth:
            auth.close()
        control.unlink(missing_ok=True)
        if 'auth_path' in locals():
            auth_path.unlink(missing_ok=True)
        stop_path.unlink(missing_ok=True)
        publish(state='closed' if stats['state'] != 'error' else 'error', cpu=None, ram=None)
        p.clear()


def set_cursor(visibility):
    try:
        curses.curs_set(visibility)
    except curses.error:
        pass  # Some classic terminal types cannot change cursor visibility.


def shortcut_rows(bindings, width):
    """Wrap whole shortcut labels only after the current row is full."""
    rows, row, used = [], [], 0
    for action, key in bindings:
        size = len(action)+1+len(key)
        gap = 3 if row else 0
        if row and used+gap+size > width:
            rows.append(row)
            row, used, gap = [], 0, 0
        row.append((action, key))
        used += gap+size
    if row:
        rows.append(row)
    return rows


def ascii_title():
    """Compact four-row ASCII lettering."""
    return " ___ ___ _  _   ___  ___ ___ _  __\n/ __/ __| || | |   \\| __/ __| |/ /\n\\__ \\__ \\ __ | | |) | _|\\__ \\ ' <\n|___/___/_||_| |___/|___|___/_|\\_\\".splitlines()


MONITOR_LOGO = (
    ' .----------. ',
    ' | .------. | ',
    ' | | >_   | | ',
    " | '------'o| ",
    " '----[]----' ",
)


def brand_parts(width):
    parts = [(row, 2, art, 'border') for row, art in enumerate(MONITOR_LOGO)]
    title = ascii_title()
    if width >= max(map(len, title))+19:
        parts += [(row, 17, art, 'title') for row, art in enumerate(title, 1)]
    else:
        parts.append((1, 18, 'SSH DESK', 'title'))
    return parts


def print_login_banner():
    width = shutil.get_terminal_size(fallback=(80, 24)).columns
    lines = [[' ']*max(1, width-1) for _ in MONITOR_LOGO]
    for row, x, art, _ in brand_parts(width):
        for offset, char in enumerate(art):
            if x+offset < len(lines[row]):
                lines[row][x+offset] = char
    print()
    for line in lines:
        print(''.join(line).rstrip())
    print()


class TerminalStyle:
    """Classic ANSI palette and clipped drawing for resizable terminals."""
    PALETTES = (
        ('PHOSPHOR', curses.COLOR_GREEN, curses.COLOR_CYAN, curses.COLOR_YELLOW),
        ('AMBER', curses.COLOR_YELLOW, curses.COLOR_WHITE, curses.COLOR_CYAN),
        ('ICE', curses.COLOR_CYAN, curses.COLOR_BLUE, curses.COLOR_WHITE),
        ('DOS', curses.COLOR_WHITE, curses.COLOR_BLUE, curses.COLOR_YELLOW),
        ('NEON', curses.COLOR_MAGENTA, curses.COLOR_CYAN, curses.COLOR_YELLOW),
        ('PAPER', curses.COLOR_WHITE, curses.COLOR_GREEN, curses.COLOR_CYAN),
    )

    def __init__(self, screen, palette=0):
        self.screen = screen
        self.palette = palette % len(self.PALETTES)
        self.name, ink, border, accent = self.PALETTES[self.palette]
        self.attrs = dict(text=0, border=curses.A_DIM, title=curses.A_BOLD,
                          muted=curses.A_DIM, selected=curses.A_REVERSE,
                          good=curses.A_BOLD, warn=curses.A_BOLD, error=curses.A_BOLD)
        if curses.has_colors():
            curses.start_color()
            background = curses.COLOR_BLACK
            try:
                curses.use_default_colors()
                background = -1
            except curses.error:
                pass
            colors = [('text', ink, background),
                      ('border', border, background),
                      ('title', ink, background),
                      ('muted', border, background),
                      ('selected', curses.COLOR_BLACK, ink),
                      ('good', curses.COLOR_GREEN, background),
                      ('warn', accent, background),
                      ('error', curses.COLOR_RED, background)]
            for pair, (role, fg, bg) in enumerate(colors, 1):
                if pair >= curses.COLOR_PAIRS:
                    break
                curses.init_pair(pair, fg, bg)
                self.attrs[role] = curses.color_pair(pair)
            for role in ('title', 'selected', 'good', 'warn', 'error'):
                self.attrs[role] |= curses.A_BOLD
        screen.bkgd(' ', self.attrs['text'])

    def text(self, y, x, text, role='text', width=None):
        h, w = self.screen.getmaxyx()
        room = w-x-1 if width is None else min(width, w-x-1)
        if 0 <= y < h and 0 <= x < w and room > 0:
            try:
                self.screen.addnstr(y, x, text, room, self.attrs[role])
            except curses.error:
                pass  # Resizing and wide glyphs can exhaust the available cells.

    def shortcuts(self, y, x, bindings, width):
        end = x+width
        for action, key in bindings:
            label = action+'='
            self.text(y, x, label, 'muted', end-x)
            x += len(label)
            self.text(y, x, key, 'warn', end-x)
            x += len(key)+3

    def box(self, y, x, height, width, title):
        if height < 3 or width < 6:
            return
        self.text(y, x, '+' + '-'*(width-2) + '+', 'border', width)
        for row in range(y+1, y+height-1):
            self.text(row, x, '|', 'border')
            self.text(row, x+width-1, '|', 'border')
        self.text(y+height-1, x, '+' + '-'*(width-2) + '+', 'border', width)
        self.text(y, x+2, ' ' + title + ' ', 'title', width-4)


def ask(screen, label, initial='', secret=False, style=None):
    style = style or TerminalStyle(screen)
    set_cursor(1)
    value = initial
    screen.timeout(-1)
    try:
        while True:
            screen.erase()
            h, w = screen.getmaxyx()
            if h >= 10 and w >= 24:
                width = min(w-2, 78)
                x, y = (w-width)//2, (h-9)//2
                style.box(y, x, 9, width, 'SSH DESK')
                style.text(y+2, x+2, label, 'title', width-4)
                shown = '*'*len(value) if secret else value
                room = width-5
                style.text(y+4, x+2, shown[-room:].ljust(room), 'selected', room)
                style.text(y+6, x+2, 'accept=Enter   cancel=Esc', 'muted', width-4)
                screen.move(y+4, x+2+min(len(shown), room-1))
            else:
                style.text(0, 0, label, 'title')
                shown = '*'*len(value) if secret else value
                style.text(1, 0, shown[-max(1, w-2):], 'selected')
                style.text(3, 0, 'accept=Enter  cancel=Esc', 'muted')
            screen.refresh()
            key = screen.get_wch()
            if key == '\x1b':
                return None
            if key in ('\n', '\r'):
                return value
            if key in (curses.KEY_BACKSPACE, '\x7f', '\b'):
                value = value[:-1]
            elif isinstance(key, str) and key.isprintable():
                value += key
    finally:
        set_cursor(0)
        screen.timeout(500)


def edit(screen, existing=None, style=None):
    p = dict(existing or {'id': uuid.uuid4().hex, 'port': 22})
    fields = [('name', 'Connection name'), ('host', 'Hostname or IP'), ('port', 'SSH port'),
              ('user', 'Username'), ('password', 'SSH password (blank for keys/agent)'),
              ('key', 'Private key path (optional)'), ('key_password', 'Private key passphrase (optional)')]
    for key, label in fields:
        value = ask(screen, label, str(p.get(key, '')), key in ('password', 'key_password'), style=style)
        if value is None:
            return None
        p[key] = value
    p['port'] = int(p['port'])
    validate(p)
    return p


def change_master_password(screen, vault, style):
    current = ask(screen, 'Current master password', secret=True, style=style)
    if current is None:
        return 'Master password change cancelled.'
    if not hmac.compare_digest(current.encode(), vault.phrase.encode()):
        raise ValueError('Current master password is incorrect.')
    replacement = ask(screen, 'New master password (12+ characters)', secret=True, style=style)
    if replacement is None:
        return 'Master password change cancelled.'
    confirmation = ask(screen, 'Confirm new master password', secret=True, style=style)
    if confirmation is None:
        return 'Master password change cancelled.'
    if replacement != confirmation:
        raise ValueError('New passwords do not match. Vault unchanged.')
    vault.change_phrase(current, replacement)
    return 'Master password changed. Use the new password next time.'


def sessions():
    result = []
    for file in RUN.glob('*.json'):
        try:
            d = json.loads(file.read_text())
            if not isinstance(d, dict) or not isinstance(d.get('state'), str):
                continue
            d['id'] = file.stem
            if d['state'] not in ('closed', 'error') and time.time()-d['updated'] > 20:
                d['state'] = 'unresponsive'
            if d['state'] in ('connected', 'connecting') or d['state'].startswith('reconnecting'):
                result.append(d)
        except (ValueError, OSError, KeyError, TypeError):
            pass
    return sorted(result, key=lambda d: d.get('started', 0), reverse=True)


def human_bytes(n):
    for unit in ['B', 'KiB', 'MiB', 'GiB']:
        if n < 1024 or unit == 'GiB':
            return f'{n:.1f}{unit}'
        n /= 1024


def duration(seconds):
    seconds = int(seconds)
    return f'{seconds//3600:02}:{seconds//60%60:02}:{seconds%60:02}'


def profile_columns(width):
    available = width-10  # Selection marker, three separators, and port.
    device = max(6, available//3)
    user = max(4, available//5)
    return device, user, available-device-user, 5


def profile_row(values, columns, marker=' '):
    return marker+' '+' '.join(str(value)[:size].ljust(size) for value, size in zip(values, columns))


def dashboard(screen, vault):
    set_cursor(0)
    screen.timeout(500)
    try:
        palette = int(json.loads((DATA / 'appearance.json').read_text())['palette'])
    except (OSError, ValueError, KeyError, TypeError):
        palette = 0
    style = TerminalStyle(screen, palette)
    broker = Broker()
    selected = 0
    session_selected = 0
    focus = 'profiles'
    message = 'Ready. Choose a profile or add=a.' if vault.profiles else 'Add a profile to begin: add=a.'
    try:
        while True:
            screen.erase()
            h, w = screen.getmaxyx()
            profiles = vault.profiles
            selected = max(0, min(selected, len(profiles)-1))
            active = sessions()
            session_selected = max(0, min(session_selected, len(active)-1))
            if h < 24 or w < 48:
                style.text(0, 1, 'SSH DESK', 'title')
                style.text(2, 1, 'Resize terminal to at least 48 x 24.', 'warn')
                style.text(4, 1, 'quit=q  add=a  open=Enter  theme=t', 'muted')
            else:
                width = w-3
                bindings = [('select', 'Up/Down'), ('focus', 'Tab'), ('add', 'a'), ('edit', 'e'),
                            ('delete', 'd'), ('open', 'Enter'), ('close', 'x'),
                            ('theme', 't'), ('quit', 'q'), ('master', 'm')]
                key_rows = shortcut_rows(bindings, width-4)
                for row, x, art, role in brand_parts(w):
                    style.text(row+1, x, art, role)
                keys_y = 6
                theme = f'{style.name}  {style.palette+1}/6'
                style.text(0, w-len(theme)-3, theme, 'muted')
                style.box(keys_y, 1, len(key_rows)+2, width, 'KEYS')
                for offset, bindings in enumerate(key_rows):
                    style.shortcuts(keys_y+1+offset, 3, bindings, width-4)
                profile_y = keys_y+2+len(key_rows)
                visible = max(1, min(8, (h-profile_y-11)//2))
                first = max(0, selected-visible+1)
                style.box(profile_y, 1, visible+4, width, f"{'>' if focus == 'profiles' else ' '} PROFILES [{len(profiles)}]")
                columns = profile_columns(width-4)
                style.text(profile_y+1, 3, profile_row(('Device', 'User', 'IP', 'Port'), columns), 'muted', width-4)
                style.text(profile_y+2, 1, '+' + '-'*(width-2) + '+', 'border', width)
                for offset, p in enumerate(profiles[first:first+visible]):
                    idx = first+offset
                    text = profile_row((p['name'], p['user'], p['host'], p['port']), columns, '>' if idx == selected else ' ')
                    style.text(profile_y+3+offset, 3, text.ljust(width-4),
                               'selected' if idx == selected and focus == 'profiles' else 'text', width-4)
                if not profiles:
                    style.text(profile_y+3, 3, 'No profiles yet. Press a to add a connection.', 'muted', width-4)
                base = profile_y+4+visible
                height = h-base-3
                style.box(base, 1, height, width, f"{'>' if focus == 'sessions' else ' '} SESSIONS [{len(active)}]" + (' / RX=received  TX=sent' if w >= 76 else ''))
                # Compact columns keep state and telemetry visible at 80 columns.
                wide = w >= 110
                name_width, state_width = (18, 20) if wide else (12, 12)
                header = f"{'Name':{name_width}} {'State':{state_width}} {'Time':8} {'RX':8} {'TX':8} {'CPU':6} {'RAM':6} Retry"
                if w < 76:
                    header = f"{'Name':12} {'State':12} Time"
                style.text(base+1, 3, header, 'muted', width-4)
                style.text(base+2, 1, '+' + '-'*(width-2) + '+', 'border', width)
                session_visible = max(0, height-4)
                session_first = max(0, session_selected-session_visible+1) if session_visible else 0
                for offset, session in enumerate(active[session_first:session_first+session_visible]):
                    state = session['state']
                    age = session.get('elapsed', 0)
                    if state not in ('closed', 'error'):
                        age = time.time()-session['started']
                    cpu = f"{session['cpu']}%" if session.get('cpu') is not None else '--'
                    ram = f"{session['ram']}%" if session.get('ram') is not None else '--'
                    text = (f"{session['name'][:name_width]:{name_width}} {state[:state_width]:{state_width}} "
                            f"{duration(age):8} {human_bytes(session['rx']):8} {human_bytes(session['tx']):8} "
                            f"{cpu:6} {ram:6} {session['reconnects']}")
                    if w < 76:
                        text = f"{session['name'][:12]:12} {state[:12]:12} {duration(age)}"
                    role = 'good' if state == 'connected' else 'error' if state in ('error', 'unresponsive') else 'muted' if state == 'closed' else 'warn'
                    if focus == 'sessions' and session_first+offset == session_selected:
                        role = 'selected'
                    style.text(base+3+offset, 3, text.ljust(width-4), role, width-4)
                if not active and height > 4:
                    style.text(base+3, 3, 'No active sessions. Select a profile and press Enter.', 'muted', width-4)
                style.box(h-3, 1, 3, width, 'STATUS')
                style.text(h-2, 3, message, 'warn', width-4)
            screen.refresh()
            key = screen.getch()
            try:
                if key == ord('q'):
                    break
                if key == 9:
                    focus = 'sessions' if focus == 'profiles' else 'profiles'
                    message = 'Sessions: select=Up/Down close=x.' if focus == 'sessions' else 'Profiles: open=Enter close=x (all sessions for profile).'
                elif key == curses.KEY_UP:
                    if focus == 'profiles':
                        selected -= 1
                    else:
                        session_selected -= 1
                elif key == curses.KEY_DOWN:
                    if focus == 'profiles':
                        selected += 1
                    else:
                        session_selected += 1
                elif key == ord('m'):
                    message = change_master_password(screen, vault, style)
                elif key == ord('t'):
                    style = TerminalStyle(screen, style.palette+1)
                    atomic(DATA / 'appearance.json', json.dumps({'palette': style.palette}).encode())
                    message = f'Palette: {style.name}. Press t to cycle through all six.'
                elif key == ord('a'):
                    if p := edit(screen, style=style):
                        profiles.append(p)
                        vault.save()
                        selected = len(profiles)-1
                        focus = 'profiles'
                        message = 'Profile saved in encrypted vault.'
                elif key == ord('e') and profiles and focus == 'profiles':
                    if p := edit(screen, profiles[selected], style=style):
                        profiles[selected] = p
                        vault.save()
                        message = 'Profile updated.'
                elif key == ord('d') and profiles and focus == 'profiles':
                    if ask(screen, 'Type DELETE to remove this saved profile', style=style) == 'DELETE':
                        profiles.pop(selected)
                        vault.save()
                        message = 'Profile removed. Existing connections continue.'
                elif key in (10, 13) and profiles and focus == 'profiles':
                    broker.launch(profiles[selected])
                    message = 'Opening terminal window… verify the host fingerprint on first connection.'
                elif key == ord('x'):
                    if focus == 'sessions':
                        chosen = active[session_selected] if active else None
                        matches = [chosen] if chosen and chosen['state'] not in ('closed', 'error') else []
                    else:
                        matches = [session for session in sessions() if profiles and session['profile'] == profiles[selected]['id'] and session['state'] not in ('closed', 'error')]
                    for session in matches:
                        atomic(RUN/(session['id']+'.stop'), b'')
                    message = f'Closing {len(matches)} session(s).' if matches else 'No open sessions to close.'
            except (ValueError, OSError) as e:
                message = str(e)
    finally:
        broker.close()


def prompt_vault():
    print('Ctrl+C to quit.\n')
    while True:
        phrase = getpass.getpass('Master passphrase: ')
        if not phrase or '\n' in phrase or len(phrase) > 1024:
            print('Use a nonempty passphrase, at most 1024 characters. Try again.\n')
            continue
        creating = not (DATA/'profiles.vault').exists()
        if creating:
            try:
                validate_new_phrase(phrase)
            except ValueError as e:
                print(str(e)+' Try again.\n')
                continue
            if getpass.getpass('Confirm master passphrase: ') != phrase:
                print('Passphrases do not match. Try again.\n')
                continue
        try:
            vault = Vault(phrase)
        except VaultUnlockError:
            print('Wrong master password or damaged vault. Please try again.\n')
            continue
        if creating:
            vault.save()
        return vault


def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--version', action='version', version='SSH Desk '+VERSION)
    parser.add_argument('--launch', action='store_true', help='Open the manager in a new terminal')
    parser.add_argument('--worker', nargs=2, metavar=('SOCKET', 'TOKEN'))
    parser.add_argument('--askpass', action='store_true')
    parser.add_argument('prompt', nargs='?', default='')
    args = parser.parse_args()
    if args.launch:
        try:
            subprocess.Popen(terminal_command([sys.executable, SCRIPT]), start_new_session=True)
        except (ValueError, OSError) as e:
            sys.exit(str(e))
        return
    if args.askpass:
        try:
            with socket.socket(socket.AF_UNIX) as s:
                s.settimeout(5)
                s.connect(os.environ['SSH_DESK_AUTH'])
                s.sendall(args.prompt.encode())
                print(s.recv(65536).decode())
        except (OSError, KeyError):
            sys.exit(1)
    elif args.worker:
        worker(*args.worker)
    else:
        try:
            check_requirements()
        except ValueError as e:
            sys.exit(str(e))
        private_dir(DATA)
        private_dir(RUN)
        import fcntl
        lock = open(DATA/'manager.lock', 'a')
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            sys.exit('SSH Desk is already open. Use the existing manager window.')
        print_login_banner()
        try:
            vault = prompt_vault()
            curses.wrapper(dashboard, vault)
        except (ValueError, OSError) as e:
            sys.exit(str(e))


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(130)
    except EOFError:
        sys.exit('Input closed. Run SSH Desk in an interactive terminal.')
