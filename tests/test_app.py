import json
import os
from pathlib import Path
import pty
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch, MagicMock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import ssh_desk as app


class VaultTests(unittest.TestCase):
    def test_encryption_unlock_tamper_and_permissions(self):
        with tempfile.TemporaryDirectory() as directory:
            with patch.object(app, 'DATA', Path(directory)):
                vault = app.Vault('a long testing passphrase')
                vault.profiles = [{'password': 'secret-do-not-store-plain', 'host': 'test.example'}]
                vault.save()
                content = vault.path.read_bytes()
                self.assertNotIn(b'secret-do-not-store-plain', content)
                self.assertNotIn(b'test.example', content)
                self.assertEqual(vault.path.stat().st_mode & 0o777, 0o600)
                self.assertEqual(app.Vault('a long testing passphrase').profiles, vault.profiles)
                with self.assertRaises(ValueError):
                    app.Vault('incorrect passphrase')
                damaged = bytearray(content)
                damaged[-12] ^= 1
                vault.path.write_bytes(damaged)
                with self.assertRaises(ValueError):
                    app.Vault('a long testing passphrase')

    def test_master_password_change_preserves_profiles_and_future_saves(self):
        with tempfile.TemporaryDirectory() as directory, patch.object(app, 'DATA', Path(directory)):
            vault = app.Vault('original master password')
            vault.profiles = [dict(name='demo', password='saved SSH secret')]
            vault.save()
            vault.change_phrase('original master password', 'replacement master password')
            self.assertEqual(app.Vault('replacement master password').profiles, vault.profiles)
            with self.assertRaises(ValueError):
                app.Vault('original master password')
            vault.profiles.append(dict(name='second'))
            vault.save()
            self.assertEqual(app.Vault('replacement master password').profiles, vault.profiles)
            self.assertEqual(vault.path.stat().st_mode & 0o777, 0o600)
            self.assertNotIn(b'saved SSH secret', vault.path.read_bytes())

    def test_master_password_rejections_and_write_failure_preserve_vault(self):
        with tempfile.TemporaryDirectory() as directory, patch.object(app, 'DATA', Path(directory)):
            vault = app.Vault('original master password')
            vault.save()
            original = vault.path.read_bytes()
            for current, replacement in [('wrong', 'replacement master password'),
                                         ('original master password', 'short')]:
                with self.assertRaises(ValueError):
                    vault.change_phrase(current, replacement)
            with patch.object(app, 'atomic', side_effect=OSError('write failed')):
                with self.assertRaises(OSError):
                    vault.change_phrase('original master password', 'replacement master password')
            self.assertEqual(vault.phrase, 'original master password')
            self.assertEqual(vault.path.read_bytes(), original)
            with patch.object(app, 'ask', side_effect=['original master password', 'replacement master password', 'mismatch']):
                with self.assertRaises(ValueError):
                    app.change_master_password(None, vault, None)
            with patch.object(app, 'ask', side_effect=['original master password', None]):
                self.assertIn('cancelled', app.change_master_password(None, vault, None))
            self.assertEqual(vault.path.read_bytes(), original)


class LoginTests(unittest.TestCase):
    def test_wrong_password_retries_without_changing_vault(self):
        with tempfile.TemporaryDirectory() as directory, patch.object(app, 'DATA', Path(directory)):
            vault = app.Vault('correct master password')
            vault.profiles = [dict(name='fixture', password='SSH secret')]
            vault.save()
            original = vault.path.read_bytes()
            with patch('getpass.getpass', side_effect=['wrong master password', 'correct master password']) as prompt, \
                 patch('builtins.print') as messages:
                unlocked = app.prompt_vault()
            self.assertEqual(unlocked.profiles, vault.profiles)
            self.assertEqual(prompt.call_count, 2)
            self.assertTrue(any('Wrong master password' in str(call) for call in messages.call_args_list))
            self.assertEqual(vault.path.read_bytes(), original)

    def test_creation_confirmation_mismatch_retries(self):
        with tempfile.TemporaryDirectory() as directory, patch.object(app, 'DATA', Path(directory)):
            with patch('getpass.getpass', side_effect=['first master password', 'mismatch',
                                                     'correct master password', 'correct master password']), \
                 patch('builtins.print') as messages:
                vault = app.prompt_vault()
            self.assertTrue(vault.path.exists())
            self.assertEqual(app.Vault('correct master password').profiles, [])
            self.assertTrue(any('do not match' in str(call) for call in messages.call_args_list))

    def test_file_errors_are_not_reported_as_wrong_password(self):
        with tempfile.TemporaryDirectory() as directory, patch.object(app, 'DATA', Path(directory)):
            (Path(directory)/'profiles.vault').touch()
            with patch('getpass.getpass', return_value='correct master password') as prompt, \
                 patch.object(app, 'Vault', side_effect=OSError('Cannot read vault')), patch('builtins.print'):
                with self.assertRaisesRegex(OSError, 'Cannot read vault'):
                    app.prompt_vault()
            self.assertEqual(prompt.call_count, 1)


class LogicTests(unittest.TestCase):
    def test_sessions_only_include_fresh_active_connections(self):
        with tempfile.TemporaryDirectory() as directory, patch.object(app, 'RUN', Path(directory)):
            now = time.time()
            for index, state in enumerate(['connected', 'connecting', 'reconnecting (2s)', 'closed', 'error', 'unresponsive']):
                (Path(directory)/f'{index}.json').write_text(json.dumps(dict(state=state, updated=now, started=now)))
            (Path(directory)/'stale.json').write_text(json.dumps(dict(state='connected', updated=now-30, started=now)))
            self.assertEqual({session['state'] for session in app.sessions()},
                             {'connected', 'connecting', 'reconnecting (2s)'})
            self.assertEqual(len(list(Path(directory).glob('*.json'))), 7)
            (Path(directory)/'malformed.json').write_text('[]')
            (Path(directory)/'wrong-types.json').write_text(json.dumps(dict(state=123)))
            self.assertEqual(len(app.sessions()), 3)

    def test_key_passphrase_takes_priority_over_password_in_filename(self):
        profile = dict(password='SSH secret', key_password='key secret')
        self.assertEqual(app.credential_for_prompt(profile, 'Enter passphrase for key password.pem:'), 'key secret')
        self.assertEqual(app.credential_for_prompt(profile, "tester@host's password:"), 'SSH secret')
        self.assertEqual(app.credential_for_prompt(profile, 'One-time code:'), '')

    def test_terminal_fallbacks_and_missing_terminal(self):
        for name, options in [('foot', ['-e']), ('kitty', ['-e']), ('gnome-terminal', ['--']), ('xterm', ['-e'])]:
            with self.subTest(name=name), patch('shutil.which', side_effect=lambda candidate: '/usr/bin/'+name if candidate == name else None):
                self.assertEqual(app.terminal_command(['python3', 'app.py']), ['/usr/bin/'+name]+options+['python3', 'app.py'])
        with patch('shutil.which', return_value=None):
            with self.assertRaisesRegex(ValueError, 'No supported terminal'):
                app.terminal_command(['app'])

    def test_failed_launch_discards_credentials(self):
        import threading
        broker = app.Broker.__new__(app.Broker)
        broker.lock, broker.pending, broker.path = threading.Lock(), {}, Path('/tmp/fixture.sock')
        with patch('shutil.which', return_value=None):
            with self.assertRaises(ValueError):
                broker.launch(dict(password='fixture secret'))
        self.assertEqual(broker.pending, {})

    def test_new_master_password_byte_limit_and_controls(self):
        app.validate_new_phrase('é'*511)
        for phrase in ['é'*512, 'a'*1024, 'valid password\r', 'valid password\n', 'short']:
            with self.subTest(phrase_length=len(phrase)), self.assertRaises(ValueError):
                app.validate_new_phrase(phrase)

    def test_metrics_cpu_delta_and_memory(self):
        first = 'CPU cpu 10 0 10 80 0 0 0 0 0 0\nMEM 1000 250\nUP 123.5\nHOST test-host\n'
        metrics, prev = app.parse_metrics(first)
        self.assertNotIn('cpu', metrics)
        self.assertEqual(metrics['ram'], 75)
        metrics, _ = app.parse_metrics(first.replace('10 0 10 80', '30 0 30 140'), prev)
        self.assertEqual(metrics['cpu'], 40)
        self.assertEqual(metrics['hostname'], 'test-host')

    def test_profile_validation(self):
        p = dict(name='demo', user='tester', host='localhost', port=22)
        app.validate(p)
        for host in ['-oProxyCommand=bad', 'example host', 'user@host', 'host\nother']:
            with self.assertRaises(ValueError):
                app.validate(dict(p, host=host))
        with self.assertRaises(ValueError):
            app.validate(dict(p, port=0))

    def test_password_not_in_ssh_arguments(self):
        p = dict(host='localhost', port=22, user='tester', password='topsecret')
        args = app.ssh_args(p, Path('/tmp/example'))
        self.assertNotIn('topsecret', ' '.join(args))
        self.assertIn('StrictHostKeyChecking=yes', args)

    def test_terminal_launcher_and_handoff_expiry(self):
        broker = app.Broker.__new__(app.Broker)
        import threading
        broker.lock = threading.Lock()
        broker.pending = {'old': (0, {'password': 'expired'})}
        broker.path = Path('/tmp/broker.sock')
        profile = dict(id='demo', password='topsecret')
        with patch('shutil.which', return_value='/usr/bin/xdg-terminal-exec'), patch('subprocess.Popen') as proc:
            broker.launch(profile)
        args = proc.call_args.args[0]
        self.assertEqual(args[0], '/usr/bin/xdg-terminal-exec')
        self.assertNotIn('topsecret', ' '.join(args))
        self.assertNotIn('old', broker.pending)
        self.assertEqual(len(broker.pending), 1)


class HostKeyTests(unittest.TestCase):
    def test_config_alias_scans_real_host_and_pins_only_after_confirmation(self):
        for alias in (None, 'server-key-name'):
            with self.subTest(alias=alias), tempfile.TemporaryDirectory() as directory:
                config = 'hostname 192.0.2.10\nport 2222\n'
                if alias:
                    config += 'hostkeyalias '+alias+'\n'
                calls = [subprocess.CompletedProcess([], 0, config.encode(), b''),
                         subprocess.CompletedProcess([], 0, b'[192.0.2.10]:2222 ssh-ed25519 fixture-key\n', b''),
                         subprocess.CompletedProcess([], 0, b'256 SHA256:fixture-key\n', b'')]
                profile = dict(host='lab-alias', port=2222, user='tester')
                with patch.object(app, 'DATA', Path(directory)), patch('subprocess.run', side_effect=calls) as run, \
                     patch('builtins.input', return_value='yes'), patch('builtins.print'):
                    app.trust_host(profile)
                self.assertEqual(run.call_args_list[1].args[0][-2:], ['--', '192.0.2.10'])
                content = (Path(directory)/'known_hosts').read_text()
                self.assertTrue(content.startswith((alias or '[192.0.2.10]:2222')+' '))
                self.assertEqual((Path(directory)/'known_hosts').stat().st_mode & 0o777, 0o600)

    def test_failed_scan_exposes_error_and_does_not_trust_host(self):
        with tempfile.TemporaryDirectory() as directory:
            calls = [subprocess.CompletedProcess([], 0, b'hostname actual.example\nport 22\n', b''),
                     subprocess.CompletedProcess([], 1, b'', b'Connection refused')]
            with patch.object(app, 'DATA', Path(directory)), patch('subprocess.run', side_effect=calls), \
                 patch('builtins.input') as prompt:
                with self.assertRaisesRegex(ValueError, 'actual.example:22.*\nConnection refused'):
                    app.trust_host(dict(host='alias', port=22, user='tester'))
            prompt.assert_not_called()
            self.assertFalse((Path(directory)/'known_hosts').exists())

    def test_cancelled_trust_does_not_pin_key(self):
        with tempfile.TemporaryDirectory() as directory:
            calls = [subprocess.CompletedProcess([], 0, b'hostname example\nport 22\n', b''),
                     subprocess.CompletedProcess([], 0, b'example ssh-ed25519 fixture-key\n', b''),
                     subprocess.CompletedProcess([], 0, b'256 SHA256:fixture-key\n', b'')]
            with patch.object(app, 'DATA', Path(directory)), patch('subprocess.run', side_effect=calls), \
                 patch('builtins.input', return_value='no'), patch('builtins.print'):
                with self.assertRaisesRegex(ValueError, 'not trusted'):
                    app.trust_host(dict(host='example', port=22, user='tester'))
            self.assertFalse((Path(directory)/'known_hosts').exists())


class WorkerTests(unittest.TestCase):
    def test_terminal_worker_reconnect_metrics_and_clean_exit(self):
        with tempfile.TemporaryDirectory() as directory:
            directory = Path(directory)
            fake = directory/'ssh'
            fake.write_text('''#!/usr/bin/env python3
import sys,time,os
from pathlib import Path
args=sys.argv[1:]
if 'ControlMaster=no' in args:
 print('CPU cpu 20 0 20 80 0 0 0 0')
 print('MEM 1000 500')
 print('UP 100')
 print('HOST fixture')
 sys.exit(0)
path=next(a.split('=',1)[1] for a in args if a.startswith('ControlPath='))
Path(path).touch()
counter=Path(os.environ['FIXTURE_COUNT'])
n=int(counter.read_text()) if counter.exists() else 0
counter.write_text(str(n+1))
print('Connected to fixture',flush=True)
time.sleep(1.2)
sys.exit(255 if n == 0 else 0)
''')
            fake.chmod(0o700)
            data = directory/'data'
            run = directory/'run'
            runner = directory/'runner.py'
            runner.write_text(f'''import sys
sys.path.insert(0,{str(ROOT)!r})
import ssh_desk as a
from pathlib import Path
a.DATA=Path({str(data)!r})
a.RUN=Path({str(run)!r})
a.receive=lambda *_: dict(id='fixture',name='Fixture',host='localhost',port=22,user='tester',password='secret')
a.trust_host=lambda _: None
class FakeSocket:
 def bind(self,path): Path(path).touch()
 def listen(self): pass
 def settimeout(self,*args): pass
 def accept(self):
  import time
  time.sleep(.2)
  raise TimeoutError()
 def close(self): pass
a.socket.socket=lambda *args:FakeSocket()
a.worker('unused','unused')
''')
            master, slave = pty.openpty()
            import fcntl, struct, termios
            fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack('HHHH', 30, 120, 0, 0))
            env = dict(os.environ, PATH=str(directory)+':'+os.environ['PATH'], FIXTURE_COUNT=str(directory/'count'))
            proc = subprocess.Popen([sys.executable, str(runner)], stdin=slave, stdout=slave, stderr=slave, env=env)
            os.close(slave)
            try:
                proc.wait(timeout=15)
                output = os.read(master, 65536).decode(errors='replace')
                self.assertEqual(proc.returncode, 0, output)
                self.assertIn('Reconnecting', output)
                self.assertEqual((directory/'count').read_text(), '2')
                state = json.loads(next(run.glob('*.json')).read_text())
                self.assertEqual(state['reconnects'], 1)
                self.assertEqual(state['state'], 'closed')
                self.assertGreater(state['rx'], 0)
                self.assertGreater(state['connected_seconds'], 1)
                self.assertEqual(state['hostname'], 'fixture')
                self.assertEqual(state['metrics_state'], 'available')
                self.assertNotIn('secret', json.dumps(state))
                self.assertFalse(list(run.glob('*.auth')))
            finally:
                if proc.poll() is None:
                    proc.kill()
                    proc.wait()
                os.close(master)

    def test_disconnect_escape(self):
        # A second integration fixture exercises the raw-terminal escape path.
        with tempfile.TemporaryDirectory() as directory:
            d = Path(directory)
            fake = d/'ssh'
            fake.write_text('#!/usr/bin/env python3\nimport time\ntime.sleep(30)\n')
            fake.chmod(0o700)
            runner = d/'run.py'
            runner.write_text(f"import sys\nsys.path.insert(0,{str(ROOT)!r})\nimport ssh_desk as a\nfrom pathlib import Path\na.DATA=Path({str(d/'data')!r})\na.RUN=Path({str(d/'state')!r})\na.receive=lambda *_: dict(id='f',name='f',host='localhost',port=22,user='tester')\na.trust_host=lambda _:None\nclass FakeSocket:\n def bind(self,path): Path(path).touch()\n def listen(self): pass\n def settimeout(self,*args): pass\n def accept(self):\n  import time\n  time.sleep(.2)\n  raise TimeoutError()\n def close(self): pass\na.socket.socket=lambda *args:FakeSocket()\na.worker('','')\n")
            master, slave = pty.openpty()
            import fcntl, struct, termios
            fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack('HHHH',30,100,0,0))
            proc = subprocess.Popen([sys.executable,str(runner)],stdin=slave,stdout=slave,stderr=slave,env=dict(os.environ,PATH=str(d)+':'+os.environ['PATH']))
            os.close(slave)
            try:
                time.sleep(.7)
                os.write(master,b'\x1d')
                proc.wait(timeout=5)
                self.assertEqual(proc.returncode,0)
                state=json.loads(next((d/'state').glob('*.json')).read_text())
                self.assertEqual(state['state'],'closed')
                self.assertEqual(state['reconnects'],0)
            finally:
                if proc.poll() is None:
                    proc.kill(); proc.wait()
                os.close(master)


class DashboardTests(unittest.TestCase):
    def test_close_selected_session_and_all_profile_sessions(self):
        states = [dict(id='first', profile='demo', name='one', state='connected', started=time.time(),
                       rx=0, tx=0, reconnects=0),
                  dict(id='second', profile='demo', name='two', state='connected', started=time.time(),
                       rx=0, tx=0, reconnects=0),
                  dict(id='other', profile='other', name='other', state='connected', started=time.time(),
                       rx=0, tx=0, reconnects=0)]
        for keys, expected in [([9, app.curses.KEY_DOWN, ord('x'), ord('q')], {'second.stop'}),
                               ([ord('x'), ord('q')], {'first.stop', 'second.stop'})]:
            with self.subTest(keys=keys), tempfile.TemporaryDirectory() as directory:
                screen = MagicMock()
                screen.getmaxyx.return_value = (35, 120)
                screen.getch.side_effect = keys
                vault = MagicMock()
                vault.profiles = [dict(id='demo', name='Device', user='tester', host='localhost', port=22)]
                style = MagicMock(palette=0, name='PHOSPHOR')
                with patch.object(app, 'RUN', Path(directory)), patch.object(app, 'DATA', Path(directory)), \
                     patch.object(app, 'sessions', return_value=states), patch.object(app, 'set_cursor'), \
                     patch.object(app, 'TerminalStyle', return_value=style), patch.object(app, 'Broker'):
                    app.dashboard(screen, vault)
                self.assertEqual({p.name for p in Path(directory).glob('*.stop')}, expected)
                rendered = [call.args[2] for call in style.text.call_args_list if len(call.args) >= 3]
                self.assertTrue(any(all(label in line for label in ('Device', 'User', 'IP', 'Port')) for line in rendered))

    def test_profile_entry_in_real_curses_terminal(self):
        with tempfile.TemporaryDirectory() as directory:
            d = Path(directory)
            runner = d/'ui.py'
            runner.write_text(f"""import sys,curses
sys.path.insert(0,{str(ROOT)!r})
import ssh_desk as a
from pathlib import Path
a.DATA=Path({str(d/'data')!r})
a.RUN=Path({str(d/'state')!r})
a.private_dir(a.RUN)
class Broker:
 def close(self):pass
a.Broker=Broker
v=a.Vault('a long testing passphrase')
curses.wrapper(a.dashboard,v)
""")
            master, slave = pty.openpty()
            import fcntl, struct, termios
            fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack('HHHH',35,140,0,0))
            proc=subprocess.Popen([sys.executable,str(runner)],stdin=slave,stdout=slave,stderr=slave,env=dict(os.environ,TERM='xterm-256color'))
            os.close(slave)
            try:
                time.sleep(.3)
                os.write(master,b'a')
                time.sleep(.2)
                os.write(master,b'Demo\nlocalhost\n\ntester\nsecretpassword\n\n\n')
                time.sleep(1.5)
                os.write(master,b'q')
                proc.wait(timeout=5)
                output=os.read(master,65536)
                self.assertEqual(proc.returncode,0,output.decode(errors='replace'))
                with patch.object(app,'DATA',d/'data'):
                    profiles=app.Vault('a long testing passphrase').profiles
                self.assertEqual(profiles[0]['name'],'Demo')
                self.assertEqual(profiles[0]['password'],'secretpassword')
                self.assertNotIn(b'secretpassword',(d/'data'/'profiles.vault').read_bytes())
                self.assertNotIn(b'secretpassword',output)
            finally:
                if proc.poll() is None:
                    proc.kill();proc.wait()
                os.close(master)


class InstallerTests(unittest.TestCase):
    def test_install_launch_and_uninstall_preserve_user_data(self):
        with tempfile.TemporaryDirectory() as directory:
            prefix = Path(directory)/"test prefix's files"
            installer = ROOT/'install.py'
            subprocess.run([sys.executable, str(installer), '--prefix', str(prefix)], check=True, capture_output=True)
            command = prefix/'bin/ssh-desk'
            result = subprocess.run([str(command), '--version'], check=True, capture_output=True, text=True)
            self.assertEqual(result.stdout.strip(), 'SSH Desk '+app.VERSION)
            self.assertTrue((prefix/'share/ssh-desk/askpass').stat().st_mode & 0o111)
            self.assertIn('--launch', (prefix/'share/applications/ssh-desk.desktop').read_text())
            data = prefix/'share/ssh-desk/profiles.vault'
            data.write_bytes(b'keep this data')
            subprocess.run([sys.executable, str(installer), '--prefix', str(prefix), '--uninstall'], check=True, capture_output=True)
            self.assertFalse(command.exists())
            self.assertFalse((prefix/'share/ssh-desk/ssh_desk.py').exists())
            self.assertEqual(data.read_bytes(), b'keep this data')


class SocketTests(unittest.TestCase):
    def test_real_one_use_credential_handoff(self):
        with tempfile.TemporaryDirectory() as directory, patch.object(app, 'RUN', Path(directory)):
            try:
                broker = app.Broker()
            except PermissionError:
                self.skipTest('Unix sockets are unavailable in this sandbox')
            try:
                token = 'a'*64
                broker.pending[token] = (time.time(), dict(password='fixture secret'))
                self.assertEqual(app.receive(str(broker.path), token), dict(password='fixture secret'))
                with self.assertRaisesRegex(ValueError, 'expired'):
                    app.receive(str(broker.path), token)
            finally:
                broker.close()


if __name__ == '__main__':
    unittest.main()
