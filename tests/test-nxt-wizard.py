#!/usr/bin/env python3
"""End-to-end NXT interactive -n/-ne wizard: clear and encrypted outputs."""
import errno
import os
from pathlib import Path
import pty
import re
import select
import subprocess
import sys
import tempfile
import time

BIN = str(Path(sys.argv[1]).resolve())
PLAINTEXT_ONLY = "--plaintext-only" in sys.argv[2:]
PASSWORD = "integration-only-test-secret-2026"
NICK = "wiztest"

class Terminal:
    def __init__(self, cwd, args):
        self.pid, self.fd = pty.fork()
        self.buf = b""
        if self.pid == 0:
            os.chdir(cwd)
            os.execv(BIN, [BIN, *args])

    def expect(self, needle, timeout=20):
        raw = needle.encode("utf-8")
        until = time.monotonic() + timeout
        while raw not in self.buf:
            if time.monotonic() > until:
                raise AssertionError(f"Prompt {needle!r} missing. Tail:\n{self.buf[-2800:].decode(errors='replace')}")
            ready, _, _ = select.select([self.fd], [], [], max(0.01, until - time.monotonic()))
            if ready:
                try:
                    chunk = os.read(self.fd, 8192)
                except OSError as e:
                    if e.errno == errno.EIO:
                        raise AssertionError(f"Wizard exited before {needle!r}. Output:\n{self.buf.decode(errors='replace')}")
                    raise
                if not chunk:
                    raise AssertionError(f"Wizard closed output before {needle!r}")
                self.buf += chunk
        pos = self.buf.index(raw) + len(raw)
        self.buf = self.buf[pos:]

    def send(self, value):
        os.write(self.fd, (value + "\n").encode("utf-8"))

    def respond(self, needle, reply):
        self.expect(needle)
        self.send(reply)

    def done(self):
        pid, status = os.waitpid(self.pid, 0)
        assert pid == self.pid
        assert os.waitstatus_to_exitcode(status) == 0, (status, self.buf.decode(errors="replace"))
        os.close(self.fd)

    def abort(self):
        try:
            os.kill(self.pid, 9)
        except ProcessLookupError:
            pass
        try:
            os.waitpid(self.pid, 0)
        except ChildProcessError:
            pass
        os.close(self.fd)

def create(mode, encrypted, base):
    with tempfile.TemporaryDirectory(prefix=f"nxt-wizard-{mode}-") as folder:
        tmp = Path(folder)
        t = Terminal(folder, mode.split())
        try:
            if mode in ("-n", "--new"):
                if not PLAINTEXT_ONLY:
                    t.respond("Encrypt config and userlist with NXTCRYPT?", "y" if encrypted else "")
                t.respond("nick?", NICK)
                t.respond("username?", NICK)
                t.respond("realname?", "wizard integration")
                t.respond("alternative nick?", "wizalt")
                t.respond("Which IPv4 or IPv6 address should be used", "")
                t.respond("Which IPv4 address should be used", "")
                t.respond("Your choice:", "0")
                t.respond("IP address (can be prefixed", "127.0.0.1")
                t.respond("Port number", "34567")
                t.respond('usage ("all"', "all")
                t.respond("Do you want to add more ports?", "")
                t.respond("ownerpass?", "owner-password-1234")
                t.respond("Do you want to add more ownerpasses?", "")
                t.respond("Do you want to add some servers?", "n")
                t.respond("Do you want to add some modules?", "n")
                t.respond("Do you want to switch to expert mode", "n")
            else:
                t.expect('set nick gay-psotnic')
                t.send(f"set nick {NICK}")
                t.send("set listen 127.0.0.1 34567 all")
                t.send("exit")
                if not PLAINTEXT_ONLY:
                    t.respond("Encrypt config and userlist with NXTCRYPT?", "y" if encrypted else "")

            t.respond("Where should the config file be saved?", "")
            if encrypted:
                t.respond("NXT password:", PASSWORD)
                t.respond("Confirm password:", PASSWORD)
            t.respond("Do you want to create the userlist?", "y")
            t.respond("username?", "ownerwiz")
            t.respond("password?", "ownerwiz-secret")
            t.expect("userlist saved as")
            if encrypted:
                t.expect("NXTCRYPT setup completed")
            t.done()
        except Exception:
            t.abort()
            raise

        suffix = ".nxt" if encrypted else ""
        cfg = tmp / f"{NICK}.cfg{suffix}"
        ul = tmp / f"{NICK}.ul{suffix}"
        assert cfg.exists(), list(tmp.iterdir())
        assert ul.exists(), list(tmp.iterdir())
        assert not (tmp/f"{NICK}.cfg").exists() if encrypted else cfg.exists()
        assert not (tmp/f"{NICK}.ul").exists() if encrypted else ul.exists()

        if encrypted:
            cfg_raw, ul_raw = cfg.read_bytes(), ul.read_bytes()
            assert cfg_raw.startswith(b"NXTCRYPT") and ul_raw.startswith(b"NXTCRYPT")
            assert cfg_raw[18:34] != ul_raw[18:34], "Config and userlist must have independent salts"
            assert cfg_raw[34:58] != ul_raw[34:58], "Config and userlist must have independent nonces"
            pw_file = tmp/"pw.txt"
            pw_file.write_text(PASSWORD + "\n")
            pw_file.chmod(0o600)
            recovered_cfg = tmp/"cfg.decrypted"
            recovered_ul = tmp/"ul.decrypted"
            for action, source, output in (("config",cfg,recovered_cfg),("userlist",ul,recovered_ul)):
                subprocess.run([BIN,action,"decrypt",str(source),"--output",str(output),
                               "--password-file",str(pw_file)], check=True,
                               capture_output=True, timeout=25)
            cfg_text = recovered_cfg.read_text()
            ul_text = recovered_ul.read_text()
            assert f"userlist {NICK}.ul.nxt" in cfg_text, cfg_text
            assert "ownerwiz" in ul_text, ul_text
        else:
            assert not cfg.read_bytes().startswith(b"NXTCRYPT")
            assert not ul.read_bytes().startswith(b"NXTCRYPT")
            cfg_text = cfg.read_text()
            assert f"{NICK}" in cfg_text
            assert "ownerwiz" in ul.read_text()
            if PLAINTEXT_ONLY:
                invalid = cfg_text.replace(f"userlist {NICK}.ul", "userlist absent.ul.nxt")
                assert invalid != cfg_text, "Missing userlist directive in generated config"
                invalid_cfg = tmp / "incompatible.cfg"
                invalid_cfg.write_text(invalid)
                result = subprocess.run([BIN, "-d", str(invalid_cfg)], capture_output=True,
                                        text=True, timeout=10)
                assert result.returncode != 0, "Incompatible NXT userlist accepted"
                assert "NXTCRYPT support was not compiled in" in result.stderr, result.stderr
                assert "userlist" in result.stderr, result.stderr
        print(f"NXT_WIZARD_OK mode={mode} encrypted={encrypted} files=2 same_pass=yes" ,flush=True)

for mode in ("-n", "-ne", "--new", "--new --expert"):
    for encrypted in ((False,) if PLAINTEXT_ONLY else (False, True)):
        create(mode, encrypted, None)
