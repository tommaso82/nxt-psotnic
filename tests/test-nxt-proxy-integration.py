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
            command=["stdbuf","-oL","-eL",BIN,str(cfg)]
            if os.environ.get("NXT_TRACE_PROXY"):
                command=["strace","-f","-tt","-s","160","-e","trace=network",
                         "-o",str(Path(folder)/"trace")]+command
            proc = subprocess.Popen(
                command, cwd=folder,
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
                if proc.poll() is None: proc.kill()
                out,err=proc.communicate(timeout=4)
                print("BOT STDERR:\n"+err.decode(errors="replace"),file=sys.stderr)
                print("BOT STDOUT:\n"+out.decode(errors="replace"),file=sys.stderr)
                trace=Path(folder)/"trace"
                if trace.exists():
                    print("TRACE:\n"+trace.read_text(errors="replace")[-16000:],file=sys.stderr)
                raise
            finally:
                if proc.poll() is None: proc.kill()
                try: proc.communicate(timeout=4)
                except subprocess.TimeoutExpired: proc.kill();proc.wait()


def exercise_both_channels():
    """IRC and hub must use separate concurrent state machines and one proxy."""
    import threading
    with socket.socket(socket.AF_INET,socket.SOCK_STREAM) as listener:
        listener.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
        listener.bind(("127.0.0.1",0))
        listener.listen(4)
        listener.settimeout(12)
        with tempfile.TemporaryDirectory(prefix="nxt-dual-proxy-") as folder:
            cfg=Path(folder)/"bot.cfg"
            cfg.write_text(
                "nick nxtbot\nident nxtbot\nhandle nxtbot\ndontfork ON\n"
                "hub 127.0.0.1 9001 testingpass mainhub\n"
                "server irc.example.invalid 6667\nproxy-type socks5\n"
                "proxy-host 127.0.0.1\n"
                f"proxy-port {listener.getsockname()[1]}\n"
                "proxy-user testuser\nproxy-pass testpass\nproxy-scope irc,hub\n"
            )
            results=[]
            failures=[]
            def serve(conn):
                try:
                    with conn:
                        conn.settimeout(9)
                        assert exact(conn,3)==b"\x05\x01\x02"
                        conn.sendall(b"\x05\x02")
                        assert exact(conn,2)==b"\x01\x08"
                        assert exact(conn,8)==b"testuser"
                        assert exact(conn,1)==b"\x08"
                        assert exact(conn,8)==b"testpass"
                        conn.sendall(b"\x01\x00")
                        assert exact(conn,3)==b"\x05\x01\x00"
                        typ=exact(conn,1)[0]
                        if typ==3:
                            n=exact(conn,1)[0]
                            host=exact(conn,n).decode("ascii")
                        elif typ==1:
                            host=socket.inet_ntop(socket.AF_INET,exact(conn,4))
                        else:
                            raise AssertionError(f"unexpected address type: {typ}")
                        port=int.from_bytes(exact(conn,2),"big")
                        assert (host,port) in [("irc.example.invalid",6667),("127.0.0.1",9001)]
                        conn.sendall(b"\x05\x00\x00\x01\x7f\x00\x00\x01\x1a\x0b")
                        line=until(conn,b"\n",limit=3000)
                        if port==6667:
                            assert line.startswith(b"CAP LS"),line
                        else:
                            assert b"Psotnic" in line,line
                        results.append((host,port))
                except Exception as exc:
                    failures.append(repr(exc))
            proc=subprocess.Popen(["stdbuf","-oL","-eL",BIN,str(cfg)],cwd=folder,stdin=subprocess.DEVNULL,
                                  stdout=subprocess.PIPE,stderr=subprocess.PIPE)
            threads=[]
            try:
                for _ in range(2):
                    conn,_=listener.accept()
                    worker=threading.Thread(target=serve,args=(conn,))
                    worker.start()
                    threads.append(worker)
                for thread in threads:
                    thread.join(timeout=10)
                    assert not thread.is_alive(),"proxy handshake stalled"
                assert not failures,failures
                assert set(results)=={("irc.example.invalid",6667),("127.0.0.1",9001)},results
                print("LIVE_PROXY_OK scope=irc,hub simultaneous_sessions=2 no_direct_hub=yes",flush=True)
            finally:
                if proc.poll() is None:proc.kill()
                out,err=proc.communicate(timeout=4)
                if failures or len(results)!=2:
                    print("BOT STDERR:\n"+err.decode(errors="replace"),file=sys.stderr)
                    print("BOT STDOUT:\n"+out.decode(errors="replace"),file=sys.stderr)

if __name__=="__main__":
    exercise("socks5")
    exercise("http")
    exercise_both_channels()
