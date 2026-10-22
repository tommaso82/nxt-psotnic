#!/usr/bin/env python3
"""Integration assertions for NXT-Psotnic's minimal CLI startup banner."""
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

def run_tty(extra_env=None, args=("-v",)):
    master, slave = pty.openpty()
    env = os.environ.copy()
    env.pop("NO_COLOR", None)
    if extra_env:
        env.update(extra_env)
    try:
        proc = subprocess.Popen([bot, *args], stdout=slave, stderr=slave,
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
    "",
    ":: nxt-psotnic :: 0.1.0-dev",
    " |-- based on gay-psotnic 0.1.1 (26-02-24)",
    " |-- IPv6 / rev: UNKNOWN / build: ",
    " |-- (C) 2003-2007 Grzegorz Rusin <grusin@gmail.com>",
    " `-- (C) 2009 psotnic.com development team",
    "",
]

plain = run_plain("-v")
assert not ansi.search(plain), "Redirected output must be ANSI-free"
assert plain == run_plain("--version"), "-v and --version should agree"
lines = plain.decode("ascii").splitlines()
assert len(lines) == 7, "Expected five info lines plus surrounding blank lines, got: %r" % lines
assert plain.startswith(b"\n:: nxt-psotnic :: 0.1.0-dev\n"), "Version needs leading blank line"
assert plain.endswith(b"\n\n"), "Version needs trailing blank line"
for i, (line, prefix) in enumerate(zip(lines, expected)):
    assert line.startswith(prefix), "Banner line %s mismatch: %r" % (i, line)
assert re.search(r"build: [A-Z][a-z]{2} +[ 0-9][0-9] 20[0-9]{2}$",
                 lines[3]), "Expected actual C/C++ __DATE__ build date"
assert not b"gay-psotnic, version" in plain

quick = run_plain()
quick_lines = quick.decode("ascii").splitlines()
assert quick_lines[:3] == ["", lines[1], ""], "No-args needs the same title with blank lines"
assert "Quick start:" in quick_lines, "The no-args screen must remain a short guide"
assert len(quick_lines) <= 12, "The no-args screen must stay compact"
assert not ansi.search(quick), "Redirected quick help must not contain ANSI codes"

colored = run_tty()
assert ansi.search(colored), "ANSI cyan/gray is expected on a TTY"
assert colored.startswith(b"\n:: \x1b[36mnxt-psotnic\x1b[0m :: 0.1.0-dev\n"), "Only the bot name should be cyan"
assert ansi.sub(b"", colored) == plain, "Colored and plain text must be identical"
quick_tty = run_tty(args=())
assert ansi.search(quick_tty), "The short guide title should have TTY colors"
assert quick_tty.startswith(b"\n:: \x1b[36mnxt-psotnic\x1b[0m :: 0.1.0-dev\n"), "No-args title colors mismatch"
assert ansi.sub(b"", quick_tty) == quick, "TTY short guide must match plain output"
disabled = run_tty({"NO_COLOR": "1"})
assert not ansi.search(disabled), "NO_COLOR must disable ANSI codes"
assert disabled == plain, "NO_COLOR TTY output must match redirected version"
print("NXT_BANNER_OK lines=7 quick_title=same-as-version ansi=tty-only no_color=honored")
