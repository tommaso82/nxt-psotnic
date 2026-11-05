#!/usr/bin/env python3
"""End-to-end IPv4/IPv6 MAIN-LEAF botnet authentication on real sockets."""
import shutil
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path

BIN = str(Path(sys.argv[1]).resolve())
COMMAND = ([shutil.which('stdbuf'), '-oL', '-eL'] if shutil.which('stdbuf') else []) + [BIN]
PASSWORD = "nxt-ipv6-botnet-test-secret"
# Psotnic uses a modified MD5 IV, not hashlib.md5 (RFC 1321).
PASSWORD_DIGEST = "ca61d593021ab048776dc28a37177b01"


def wait_for_listener(family, host, port, process):
    until = time.monotonic() + 12
    while time.monotonic() < until:
        if process.poll() is not None:
            raise AssertionError("MAIN exited before listening")
        try:
            with socket.socket(family, socket.SOCK_STREAM) as probe:
                probe.settimeout(0.4)
                probe.connect((host, port))
            return
        except OSError:
            time.sleep(0.12)
    raise AssertionError("MAIN never began listening")


def exercise(family, host, reject=False):
    with tempfile.TemporaryDirectory(prefix="nxt-botnet-ip-") as root:
        folder = Path(root)
        with socket.socket(family, socket.SOCK_STREAM) as probe:
            probe.bind((host, 0))
            port = probe.getsockname()[1]
        allowed = ("2001:db8::1" if family == socket.AF_INET6 else "192.0.2.1") if reject else host
        listener = "all" if reject else "bots"
        # Main's userlist is an existing on-disk database. The bot handles
        # and password hash use the classic botnet protocol, unchanged by NXT.
        (folder / "main.ul").write_text(
            "13 leafbot 1 1 0.0.0.0 integration\n"
            "19 leafbot +l\n"
            f"30 leafbot {PASSWORD_DIGEST}\n"
            f"80 leafbot {allowed}\n"
            "21 42\n82 1700000000\n"
        )
        (folder / "main.cfg").write_text(
            "nick mainhub\nident mainhub\nhandle mainhub\n"
            "dontfork ON\nuserlist main.ul\n"
            "server 127.0.0.1 65530\n"
            f"listen {host} {port} {listener}\n"
        )
        (folder / "leaf.cfg").write_text(
            "nick leafbot\nident leafbot\nhandle leafbot\n"
            "dontfork ON\nuserlist leaf.ul\nsave-userlist ON\n"
            "server 127.0.0.1 65530\n"
            f"hub {host} {port} {PASSWORD} mainhub\n"
        )
        with (folder / "main.log").open("wb") as main_log, (folder / "leaf.log").open("wb") as leaf_log:
            main = subprocess.Popen(COMMAND + ["-d", "main.cfg"], cwd=folder,
                                    stdin=subprocess.DEVNULL, stdout=main_log,
                                    stderr=subprocess.STDOUT)
            leaf = None
            try:
                wait_for_listener(family, host, port, main)
                leaf = subprocess.Popen(COMMAND + ["-d", "leaf.cfg"], cwd=folder,
                                       stdin=subprocess.DEVNULL, stdout=leaf_log,
                                       stderr=subprocess.STDOUT)
                until = time.monotonic() + (8 if reject else 15)
                while time.monotonic() < until:
                    if reject:
                        if "invalid botip" in (folder / "main.log").read_text(errors="replace"):
                            assert not (folder / "leaf.ul").exists(), "Unauthorized bot transferred userlist"
                            print(f"BOTNET_DENY_OK family={'IPv6' if family == socket.AF_INET6 else 'IPv4'} listener=all peer={host}", flush=True)
                            return
                        time.sleep(0.1)
                        continue
                    if leaf.poll() is not None or main.poll() is not None:
                        break
                    if (folder / "leaf.ul").exists():
                        data = (folder / "leaf.ul").read_bytes()
                        if b"21 42" in data:
                            break
                    time.sleep(0.1)
                else:
                    raise AssertionError("Missing bot-IP rejection" if reject else "Botnet link did not transfer the userlist")
                assert main.poll() is None and leaf.poll() is None, "Bot exited during link"
                assert b"21 42" in (folder / "leaf.ul").read_bytes(), "Botnet userlist not transferred"
                print(f"BOTNET_LINK_OK family={'IPv6' if family == socket.AF_INET6 else 'IPv4'}"
                      f" listener=bots peer={host} userlist_transferred=yes", flush=True)
            except BaseException:
                if shutil.which("ss"):
                    print("--- sockets ---", flush=True)
                    subprocess.run(["ss", "-tanp"], check=False)
                for name in ("main", "leaf"):
                    log = folder / (name + ".log")
                    if log.exists():
                        print(f"--- {name} log ---\n{log.read_text(errors='replace')[-6000:]}", flush=True)
                raise
            finally:
                for proc in (leaf, main):
                    if proc is not None and proc.poll() is None:
                        proc.terminate()
                        try:
                            proc.wait(timeout=3)
                        except subprocess.TimeoutExpired:
                            proc.kill()
                            proc.wait(timeout=3)


if __name__ == "__main__":
    negative = "--negative" in sys.argv[2:]
    exercise(socket.AF_INET, "127.0.0.1", reject=negative)
    exercise(socket.AF_INET6, "::1", reject=negative)
