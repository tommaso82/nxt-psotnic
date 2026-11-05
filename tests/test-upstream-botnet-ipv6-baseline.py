#!/usr/bin/env python3
"""Unmodified gay-psotnic IPv4/IPv6 baseline. Does not patch or mock upstream."""
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import time

BINARY = str(Path(sys.argv[1]).resolve())
PASS = "nxt-ipv6-botnet-test-secret"
HASH = "ca61d593021ab048776dc28a37177b01"

def run_case(family, address, listener, authorized):
    with tempfile.TemporaryDirectory(prefix="gay-ipv6-baseline-") as work:
        folder = Path(work)
        with socket.socket(family, socket.SOCK_STREAM) as probe:
            probe.bind((address, 0))
            port = probe.getsockname()[1]
        listed = address if authorized else ("2001:db8::123" if family == socket.AF_INET6 else "192.0.2.123")
        (folder / "main.ul").write_text(
            "13 leafbot 1 1 0.0.0.0 integration\n"
            "19 leafbot +l\n"
            f"30 leafbot {HASH}\n"
            f"80 leafbot {listed}\n"
            "21 42\n82 1700000000\n"
        )
        (folder / "main.cfg").write_text(
            "nick mainhub\nident mainhub\nhandle mainhub\n"
            "dontfork ON\nuserlist main.ul\n"
            "server 127.0.0.1 65530\n"
            f"listen {address} {port} {listener}\n"
        )
        (folder / "leaf.cfg").write_text(
            "nick leafbot\nident leafbot\nhandle leafbot\n"
            "dontfork ON\nuserlist leaf.ul\nsave-userlist ON\n"
            "server 127.0.0.1 65530\n"
            f"hub {address} {port} {PASS} mainhub\n"
        )
        logs = {}
        procs = []
        status = "UNKNOWN"
        try:
            for name, file in (("main", "main.cfg"), ("leaf", "leaf.cfg")):
                logs[name] = (folder / (name + ".log")).open("wb")
                procs.append(subprocess.Popen([BINARY, "-d", file],
                    cwd=folder, stdin=subprocess.DEVNULL,
                    stdout=logs[name], stderr=subprocess.STDOUT))
                if name == "main":
                    deadline = time.monotonic() + 10
                    while time.monotonic() < deadline:
                        if procs[0].poll() is not None:
                            status = "MAIN_EXIT"
                            break
                        try:
                            with socket.socket(family, socket.SOCK_STREAM) as probe:
                                probe.settimeout(0.3)
                                probe.connect((address, port))
                            break
                        except OSError:
                            time.sleep(0.1)
                    else:
                        status = "NO_LISTENER"
                    if status != "UNKNOWN":
                        break
            if status == "UNKNOWN":
                deadline = time.monotonic() + 8
                while time.monotonic() < deadline:
                    f = folder / "leaf.ul"
                    if f.exists() and b"21 42" in f.read_bytes():
                        status = "LINK_OK"
                        break
                    if any(p.poll() is not None for p in procs):
                        status = "PROCESS_EXIT"
                        break
                    time.sleep(0.1)
                else:
                    status = "NO_LINK"
        finally:
            for p in procs:
                if p.poll() is None:
                    p.terminate()
                    try: p.wait(timeout=2)
                    except subprocess.TimeoutExpired: p.kill(); p.wait()
            for log in logs.values():
                log.close()
        reason = "none"
        if status != "LINK_OK":
            mainlog = (folder / "main.log").read_text(errors="replace") if (folder / "main.log").exists() else ""
            for keyword in ("Rejecting connection", "invalid botip", "wrong botpass", "not a bot",
                            "error", "Cannot", "cannot"):
                if keyword in mainlog:
                    reason = keyword.replace(" ", "_")
                    break
            print(f"MAIN_LOG_TAIL family={family} listener={listener} authorized={authorized} "
                  f"{mainlog[-2000:]!r}", flush=True)
        expected = status == "LINK_OK" if authorized else status != "LINK_OK"
        label = "IPv6" if family == socket.AF_INET6 else "IPv4"
        print(f"BASELINE family={label} listener={listener} "
              f"listed_ip={'matching' if authorized else 'mismatching'} "
              f"result={status} reason={reason} "
              f"policy={'EXPECTED' if expected else 'UNEXPECTED'}", flush=True)
        return label, listener, authorized, status, expected

def main():
    results = []
    for access in ("all", "bots"):
        for family, host in ((socket.AF_INET, "127.0.0.1"), (socket.AF_INET6, "::1")):
            for authorized in (True, False):
                results.append(run_case(family, host, access, authorized))
    print("BASELINE_SUMMARY " + " ; ".join(
        f"{family}/{access}/{'allow' if authorized else 'deny'}={status}"
        for family, access, authorized, status, _ in results), flush=True)
    if any(status in ("MAIN_EXIT", "NO_LISTENER", "PROCESS_EXIT") for _,_,_,status,_ in results):
        sys.exit(2)

if __name__ == "__main__":
    main()
