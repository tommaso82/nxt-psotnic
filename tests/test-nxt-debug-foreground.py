#!/usr/bin/env python3
"""Real bot tests for -d in standard/debug builds and classic default daemon mode."""
import os
from pathlib import Path
import signal
import socket
import subprocess
import sys
import tempfile
import time

BIN = str(Path(sys.argv[1]).resolve())

def make_config(folder, port):
    (Path(folder) / "bot.cfg").write_text(
        "nick nxtbot\n"
        "ident nxtbot\n"
        "handle nxtbot\n"
        "hub 127.0.0.1 1 testingpass mainhub\n"
        f"server 127.0.0.1 {port}\n",
        encoding="ascii"
    )

def expect_irc_registration(listener):
    conn, _ = listener.accept()
    conn.settimeout(9)
    buf = bytearray()
    deadline = time.monotonic() + 9
    while time.monotonic() < deadline and b"USER " not in buf:
        chunk = conn.recv(4096)
        if not chunk:
            break
        buf.extend(chunk)
    registration = bytes(buf)
    assert b"CAP LS" in registration, registration
    assert b"NICK nxtbot" in registration, registration
    assert b"USER " in registration, registration
    return conn

def check_foreground(listener, folder):
    proc = subprocess.Popen(
        ["stdbuf", "-oL", "-eL", BIN, "-d", "bot.cfg"],
        cwd=folder, stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE
    )
    conn = None
    observed_returncode = None
    try:
        conn = expect_irc_registration(listener)
        time.sleep(0.3)
        observed_returncode = proc.poll()
    finally:
        if proc.poll() is None:
            proc.kill()
        out, err = proc.communicate(timeout=4)
        if conn is not None:
            conn.close()
    assert observed_returncode is None, (
        "-d incorrectly exited or forked (rc=%r)\nstdout:\n%s\nstderr:\n%s"
        % (observed_returncode, out.decode(errors="replace"), err.decode(errors="replace"))
    )
    assert b"-d: running in foreground" in out, out
    assert b"Config loaded" in out, (out, err)
    print("NXT_FOREGROUND_OK -d accepted, live IRC registration, process attached")

def check_daemon(listener, folder):
    parent = subprocess.Popen(
        [BIN, "bot.cfg"], cwd=folder, stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE
    )
    pid = None
    conn = None
    try:
        parent.wait(timeout=9)
        assert parent.returncode == 0, "Daemon parent returned nonzero"
        conn = expect_irc_registration(listener)
        pidfile = Path(folder) / "pid.nxtbot"
        deadline = time.monotonic() + 3
        while not pidfile.exists() and time.monotonic() < deadline:
            time.sleep(0.05)
        assert pidfile.exists(), "Daemon PID file missing"
        pid = int(pidfile.read_text().strip())
        assert pid != parent.pid, "Normal startup did not fork"
        os.kill(pid, 0)
        print("NXT_DAEMON_OK default startup forks, child performs IRC registration")
    finally:
        if conn is not None:
            conn.close()
        if parent.poll() is None:
            parent.kill()
        parent.communicate(timeout=4)
        if pid is not None:
            try:
                os.kill(pid, signal.SIGTERM)
            except ProcessLookupError:
                pass

def exercise(test, suffix):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        listener.settimeout(12)
        with tempfile.TemporaryDirectory(prefix="nxt-foreground-" + suffix + "-") as folder:
            make_config(folder, listener.getsockname()[1])
            test(listener, folder)

if __name__ == "__main__":
    exercise(check_foreground, "debug")
    exercise(check_daemon, "daemon")
