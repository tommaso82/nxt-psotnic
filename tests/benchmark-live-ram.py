#!/usr/bin/env python3
"""Compare real, idle IRC bot processes, not CLI utilities or ul::save-only drivers.

All binaries use make debug. The original only supports plaintext config with
its historical -T debug switch. Both bot implementations use the same text
directives, plain userlist and local dummy IRC endpoint. Each invocation is
isolated in a new directory. Report VmRSS (resident), VmHWM (startup peak),
and Pss (proportional mapped memory, if available).
"""
import argparse
import json
import os
from pathlib import Path
import signal
import socket
import statistics
import subprocess
import tempfile
import time

parser=argparse.ArgumentParser()
parser.add_argument("--classic",required=True)
parser.add_argument("--nxt-min",required=True)
parser.add_argument("--nxt-crypt",required=True)
parser.add_argument("--classic-encrypt",required=True)
parser.add_argument("--repeats",type=int,default=5)
args=parser.parse_args()
binary={k:str(Path(v).resolve()) for k,v in {
    "classic":args.classic,"nxt_min":args.nxt_min,"nxt_crypt":args.nxt_crypt,
    "classic_encrypt":args.classic_encrypt}.items()}
assert args.repeats>=3
passphrase="local synthetic startup benchmark password 2026"

def snapshot(pid):
    result={}
    for line in Path("/proc/%d/status"%pid).read_text().splitlines():
        if line.startswith(("VmRSS:","VmHWM:")):
            k,v=line.split(":",1)
            result[k.lower()]=int(v.strip().split()[0])
    rollup=Path("/proc/%d/smaps_rollup"%pid)
    if rollup.exists():
        try:
            for line in rollup.read_text().splitlines():
                if line.startswith(("Pss:","Private_Clean:","Private_Dirty:")):
                    k,v=line.split(":",1)
                    result[k.lower()]=int(v.strip().split()[0])
        except PermissionError:
            pass
    return result

def one(label,roundno):
    with tempfile.TemporaryDirectory(prefix="nxt-live-ram-") as root:
        folder=Path(root)
        ul=folder/"bot.ul"
        ul.write_text("# userlist\n21 42\n82 1700000000\n")
        pw=folder/"pw.txt"
        pw.write_text(passphrase+"\n")
        pw.chmod(0o600)
        server=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
        server.bind(("127.0.0.1",0))
        server.listen(2)
        server.settimeout(8)
        port=server.getsockname()[1]
        # Identical functional configuration for every bot under test.
        content=("nick ramtest\nident ramtest\nhandle ramtest\n"
                 "realname Bench Real Bot\ndontfork ON\n"
                 "save-userlist ON\nuserlist bot.ul\n"
                 "hub 127.0.0.1 65531 hub-secret mainhub\n"
                 "server 127.0.0.1 %d\n"%port)
        plain=folder/"bot.cfg"
        plain.write_text(content)
        exe=binary["classic"] if label.startswith("classic") else binary[
            "nxt_min" if label=="nxt-plain" else "nxt_crypt"]
        if label=="classic-plain":
            cmd=[exe,"-d","-T","bot.cfg"]
        elif label=="classic-crypt":
            encrypted=folder/"bot-legacy.cfg"
            subprocess.run([binary["classic_encrypt"],str(plain),str(encrypted)],
                           check=True,capture_output=True,timeout=10)
            cmd=[exe,"-d",encrypted.name]
        elif label=="nxt-plain":
            cmd=[exe,"-d","bot.cfg"]
        elif label=="nxt-crypt":
            encrypted=folder/"bot.cfg.nxt"
            subprocess.run([exe,"config","encrypt",str(plain),"--output",str(encrypted),
                            "--password-file",str(pw)],
                           check=True,capture_output=True,timeout=15)
            cmd=[exe,"-d","--password-file",str(pw),encrypted.name]
        else:
            raise ValueError(label)

        process=subprocess.Popen(cmd,cwd=folder,stdin=subprocess.DEVNULL,
                                 stdout=subprocess.PIPE,stderr=subprocess.STDOUT)
        conn=None
        readings=[]
        try:
            conn,_=server.accept()
            conn.settimeout(6)
            registration=b""
            deadline=time.monotonic()+6
            while b"NICK " not in registration and time.monotonic()<deadline:
                chunk=conn.recv(4096)
                if not chunk:
                    raise RuntimeError("server connection closed during IRC registration")
                registration+=chunk
            if b"NICK " not in registration:
                raise RuntimeError("No real IRC NICK registration received: "+repr(registration[-400:]))
            # Capture peak while KDF/initialization is already completed;
            # VmHWM retains the earlier startup maximum.
            for _ in range(8):
                time.sleep(0.15)
                if process.poll() is not None:
                    raise RuntimeError("bot exited during idle sampling")
                readings.append(snapshot(process.pid))
            stable=readings[-5:]
            rss=int(statistics.median(x["vmrss"] for x in stable))
            hwm=max(x["vmhwm"] for x in readings)
            pss=int(statistics.median(x["pss"] for x in stable)) if all("pss" in x for x in stable) else None
            print("RAM_SAMPLE "+json.dumps(dict(label=label,round=roundno,rss_kib=rss,
                  hwm_kib=hwm,pss_kib=pss,real_irc_registration=True),sort_keys=True),flush=True)
            return dict(rss_kib=rss,hwm_kib=hwm,pss_kib=pss)
        except Exception as e:
            process.kill()
            output=process.communicate(timeout=5)[0].decode(errors="replace")
            raise RuntimeError("%s round=%d failed: %s; BOT_OUTPUT=%s"%
                               (label,roundno,e,output[-3000:])) from e
        finally:
            if conn:
                conn.close()
            server.close()
            if process.poll() is None:
                process.terminate()
            try:
                process.communicate(timeout=4)
            except subprocess.TimeoutExpired:
                process.kill()
                process.communicate(timeout=4)

groups={x:[] for x in ("classic-plain","nxt-plain","classic-crypt","nxt-crypt")}
order=list(groups)
for r in range(args.repeats):
    for label in (order if r%2==0 else list(reversed(order))):
        groups[label].append(one(label,r+1))

medians={}
for label,rows in groups.items():
    medians[label]={
        key:int(statistics.median(x[key] for x in rows))
        if all(x[key] is not None for x in rows) else None
        for key in ("rss_kib","hwm_kib","pss_kib")}
    print("RAM_MEDIAN "+json.dumps(dict(label=label,repeats=args.repeats,
          **medians[label]),sort_keys=True),flush=True)
for prefix,a,b in (("plain","classic-plain","nxt-plain"),
                   ("crypt","classic-crypt","nxt-crypt")):
    delta={key:medians[b][key]-medians[a][key] if medians[b][key] is not None and medians[a][key] is not None else None
           for key in medians[b]}
    print("RAM_COMPARE "+json.dumps(dict(mode=prefix,classic=a,nxt=b,
          delta_nxt_minus_classic_kib=delta),sort_keys=True),flush=True)
print("LIVE_REAL_BOT_RAM_BENCH_OK",flush=True)
