#!/usr/bin/env python3
"""Live bot / fake SOCKS5 and HTTP CONNECT regression. Loopback only."""
import os
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path

BIN = str(Path(sys.argv[1]).resolve())

def exact(sock, count):
    data = b""
    while len(data) < count:
        part = sock.recv(count - len(data))
        if not part:
            raise AssertionError(f"unexpected EOF while reading {count} bytes; got {data!r}")
        data += part
    return data

def until(sock, needle, limit=8192):
    data = b""
    while needle not in data:
        data += sock.recv(1)
        if not data or len(data) > limit:
            raise AssertionError("missing delimiter")
    return data

def exercise(kind):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        listener.settimeout(12)
        port = listener.getsockname()[1]
        with tempfile.TemporaryDirectory(prefix="nxt-proxy-bot-") as folder:
            cfg=Path(folder)/"bot.cfg"
            cfg.write_text(
                "nick nxtbot\n"
                "ident nxtbot\n"
                "handle nxtbot\n"
                "dontfork ON\n"
                "hub 127.0.0.1 1 testingpass mainhub\n"
                "server irc.example.invalid 6667\n"
                f"proxy-type {kind}\n"
                "proxy-host 127.0.0.1\n"
                f"proxy-port {port}\n"
                "proxy-user testuser\n"
                "proxy-pass testpass\n"
                "proxy-scope irc\n"
            )
            proc = subprocess.Popen(
                [BIN, str(cfg)], cwd=folder,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                stdin=subprocess.DEVNULL
            )
            try:
                with listener.accept()[0] as conn:
                    conn.settimeout(9)
                    if kind=="socks5":
                        assert exact(conn, 3)==b"\x05\x01\x02", "wrong auth method"
                        conn.sendall(b"\x05\x02")
                        assert exact(conn,2)==b"\x01\x08", "incorrect RFC1929 header"
                        assert exact(conn,8)==b"testuser"
                        assert exact(conn,1)==b"\x08"
                        assert exact(conn,8)==b"testpass"
                        conn.sendall(b"\x01\x00")
                        assert exact(conn,4)==b"\x05\x01\x00\x03"
                        n=exact(conn,1)[0]
                        host=exact(conn,n).decode("ascii")
                        assert host=="irc.example.invalid", host
                        assert exact(conn,2)==b"\x1a\x0b"  # 6667
                        conn.sendall(b"\x05\x00\x00\x01\x7f\x00\x00\x01\x1a\x0b")
                    else:
                        request=until(conn,b"\r\n\r\n").decode("ascii")
                        assert request.startswith("CONNECT irc.example.invalid:6667 HTTP/1.1\r\n"),request
                        assert "Proxy-Authorization: Basic dGVzdHVzZXI6dGVzdHBhc3M=" in request,request
                        conn.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                    messages=until(conn,b"USER ",limit=4096)
                    assert b"CAP LS" in messages, messages
                    assert b"NICK nxtbot" in messages, messages
                    print(f"LIVE_PROXY_OK kind={kind} host=irc.example.invalid port=6667 "
                          f"registration_after_tunnel=yes", flush=True)
            except Exception:
                if proc.poll() is not None:
                    out, err=proc.communicate(timeout=2)
                    print("BOT STDERR:\n"+err.decode(errors="replace"),file=sys.stderr)
                    print("BOT STDOUT:\n"+out.decode(errors="replace"),file=sys.stderr)
                raise
            finally:
                proc.kill() if proc.poll() is None else None
                try: proc.communicate(timeout=4)
                except subprocess.TimeoutExpired: proc.kill();proc.wait()

if __name__=="__main__":
    exercise("socks5")
    exercise("http")
