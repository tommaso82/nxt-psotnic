#!/usr/bin/env python3
"""Integration assertions for NXT-Psotnic's compact ASCII startup banner."""
import os
import pty
import re
import subprocess
import sys

bot = sys.argv[1] if len(sys.argv) > 1 else "./bin/psotnic"
ansi = re.compile(rb"\x1b\[[0-9;]*m")

def run_plain(*args):
    result = subprocess.run([bot, *args], stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, check=True, timeout=10)
    return result.stdout

def run_tty(extra_env=None):
    master, slave = pty.openpty()
    env = os.environ.copy()
    env.pop("NO_COLOR", None)
    if extra_env:
        env.update(extra_env)
    try:
        proc = subprocess.Popen([bot, "-v"], stdout=slave, stderr=slave,
                                env=env)
        os.close(slave)
        slave = -1
        chunks = []
        while True:
            try:
                part = os.read(master, 4096)
                if not part:
                    break
                chunks.append(part)
            except OSError as e:
                # Linux PTY master reports EIO when the child closes the slave.
                if e.errno == 5:
                    break
                raise
        if proc.wait(timeout=10) != 0:
            raise AssertionError("TTY version command failed")
        return b"".join(chunks).replace(b"\r\n", b"\n")
    finally:
        os.close(master)
        if slave >= 0:
            os.close(slave)

expected = [
    ">>==[ NXT-Psotnic 0.1.0-dev ]==<<",
    " |-- based on gay-psotnic 0.1.1 (26-02-24)",
    " |-- IPv6 / rev: UNKNOWN / build: ",
    " |-- (C) 2003-2007 Grzegorz Rusin <grusin@gmail.com>",
    " `-- (C) 2009 psotnic.com development team",
]

plain = run_plain("-v")
assert not ansi.search(plain), "Redirected output must be ANSI-free"
assert plain == run_plain("--version"), "-v and --version should agree"
lines = plain.decode("ascii").splitlines()
assert len(lines) == 5, "Expected exactly five lines, got: %r" % lines
for i, (line, prefix) in enumerate(zip(lines, expected)):
    assert line.startswith(prefix), "Banner line %s mismatch: %r" % (i, line)
assert re.search(r"build: [A-Z][a-z]{2} +[ 0-9][0-9] 20[0-9]{2}$",
                 lines[2]), "Expected actual C/C++ __DATE__ build date"
assert not b"gay-psotnic, version" in plain

colored = run_tty()
assert ansi.search(colored), "ANSI cyan/gray is expected on a TTY"
assert ansi.sub(b"", colored) == plain, "Colored and plain text must be identical"
disabled = run_tty({"NO_COLOR": "1"})
assert not ansi.search(disabled), "NO_COLOR must disable ANSI codes"
assert disabled == plain, "NO_COLOR TTY output must match redirected version"
print("NXT_BANNER_OK lines=5 history=preserved ansi=tty-only no_color=honored")
