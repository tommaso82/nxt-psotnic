#!/usr/bin/env python3
"""Compare real, idle IRC bot processes, not CLI utilities or ul::save-only drivers.

All binaries use make debug. The original only supports plaintext config with
its historical -T debug switch. Both bot implementations use the same text
directives, equivalent userlist content and local dummy IRC endpoint. Each invocation is
isolated in a new directory. Report VmRSS (resident), VmHWM (startup peak),
and Pss (proportional mapped memory, if available).
"""
import argparse
import json
import os
import re
from pathlib import Path
import signal
import socket
import statistics
import subprocess
import tempfile
import time

parser=argparse.ArgumentParser()
parser.add_argument("--classic")
parser.add_argument("--nxt-min",required=True)
parser.add_argument("--nxt-crypt",required=True)
parser.add_argument("--classic-encrypt")
parser.add_argument("--nxt-only",action="store_true",help="Measure only the two NXT plaintext builds")
parser.add_argument("--repeats",type=int,default=5)
args=parser.parse_args()
binary={k:str(Path(v).resolve()) for k,v in {
    "classic":args.classic,"nxt_min":args.nxt_min,"nxt_crypt":args.nxt_crypt,
    "classic_encrypt":args.classic_encrypt}.items()}
assert args.repeats>=3
if not args.nxt_only and (not args.classic or not args.classic_encrypt):
    parser.error("--classic and --classic-encrypt are required without --nxt-only")
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


# Attribute memory to mapped ELF segments, libraries, heap and anonymous pages.
# PSS is more meaningful for shared library mappings than adding their RSS.
SMAPS_HEADER=re.compile(r"^[0-9a-f]+-[0-9a-f]+\s+\S+\s+[0-9a-f]+\s+\S+\s+\d+\s*(.*)$")
SMAPS_KEYS=("Rss","Pss","Private_Clean","Private_Dirty","Shared_Clean","Anonymous")
def smaps_groups(pid, exe):
    groups={}
    current=None
    for line in Path(f"/proc/{pid}/smaps").read_text().splitlines():
        match=SMAPS_HEADER.match(line)
        if match:
            path=match.group(1).strip().removesuffix(" (deleted)")
            if path==exe: category="nxt_executable"
            elif "libsodium.so" in path: category="libsodium"
            elif path=="[heap]": category="heap"
            elif path.startswith("[stack"): category="stack"
            elif path.startswith("[vdso") or path.startswith("[vvar") or path.startswith("[vsyscall"):
                category="kernel_special"
            elif not path or path.startswith("[anon"): category="anonymous"
            elif path.startswith("/"): category="other_files_and_libraries"
            else: category="other"
            current=groups.setdefault(category,{k:0 for k in SMAPS_KEYS})
            continue
        if current is None: continue
        field,sep,value=line.partition(":")
        if sep and field in SMAPS_KEYS:
            current[field]+=int(value.strip().split()[0])
    return groups

def one(label,roundno,profile):
    with tempfile.TemporaryDirectory(prefix="nxt-live-ram-") as root:
        folder=Path(root)
        ul=folder/"bot.ul"
        pw=folder/"pw.txt"
        pw.write_text(passphrase+"\n")
        pw.chmod(0o600)
        server=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
        server.bind(("127.0.0.1",0))
        server.listen(2)
        server.settimeout(8)
        port=server.getsockname()[1]
        # Same options and logical contents; only storage encoding differs.
        content=("nick ramtest\nident ramtest\nhandle ramtest\n"
                 "realname Bench Real Bot\ndontfork ON\n"
                 "save-userlist %s\nuserlist bot.ul\n"
                 "hub 127.0.0.1 65531 hub-secret mainhub\n"
                 "server 127.0.0.1 %d\n"%("ON" if profile=="with-ul" else "OFF",port))
        plain=folder/"bot.cfg"
        plain.write_text(content)
        exe=binary["classic"] if label.startswith("classic") else binary[
            "nxt_min" if label=="nxt-plain" else "nxt_crypt"]
        if profile=="with-ul":
            ul.write_text("# userlist\n21 42\n82 1700000000\n")
            if label.startswith("classic"):
                legacy_ul=folder/"bot-legacy.ul"
                subprocess.run([binary["classic_encrypt"],str(ul),str(legacy_ul),"ul"],
                               check=True,capture_output=True,timeout=10)
                legacy_ul.replace(ul)
            elif label=="nxt-crypt":
                encrypted_ul=folder/"bot.ul.nxt"
                subprocess.run([exe,"userlist","encrypt",str(ul),"--output",str(encrypted_ul),
                                "--password-file",str(pw)],
                               check=True,capture_output=True,timeout=15)
                encrypted_ul.replace(ul)
        if label=="classic-plain":
            cmd=[exe,"-d","-T","bot.cfg"]
        elif label=="classic-crypt":
            encrypted=folder/"bot-legacy.cfg"
            subprocess.run([binary["classic_encrypt"],str(plain),str(encrypted)],
                           check=True,capture_output=True,timeout=10)
            cmd=[exe,"-d",encrypted.name]
        elif label in ("nxt-plain","nxt-plain-with-crypto"):
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
            print("RAM_SAMPLE "+json.dumps(dict(label=label,profile=profile,round=roundno,rss_kib=rss,
                  hwm_kib=hwm,pss_kib=pss,real_irc_registration=True),sort_keys=True),flush=True)
            maps=smaps_groups(process.pid,exe) if args.nxt_only else {}
            if args.nxt_only:
                print("MEMORY_MAP_SAMPLE "+json.dumps(dict(profile=profile,label=label,round=roundno,
                      categories=maps),sort_keys=True),flush=True)
            return dict(rss_kib=rss,hwm_kib=hwm,pss_kib=pss,mappings=maps)
        except Exception as e:
            process.kill()
            output=process.communicate(timeout=5)[0].decode(errors="replace")
            raise RuntimeError("%s profile=%s round=%d failed: %s; BOT_OUTPUT=%s"%
                               (label,profile,roundno,e,output[-3000:])) from e
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

labels=(("nxt-plain","nxt-plain-with-crypto") if args.nxt_only else
        ("classic-plain","nxt-plain","nxt-plain-with-crypto","classic-crypt","nxt-crypt"))
profiles=("cfg-only","with-ul")
groups={(profile,label):[] for profile in profiles for label in labels}
for profile in profiles:
    for r in range(args.repeats):
        for label in (labels if r%2==0 else tuple(reversed(labels))):
            groups[(profile,label)].append(one(label,r+1,profile))

medians={}
for (profile,label),rows in groups.items():
    medians[(profile,label)]={
        key:int(statistics.median(x[key] for x in rows))
        if all(x[key] is not None for x in rows) else None
        for key in ("rss_kib","hwm_kib","pss_kib")}
    print("RAM_MEDIAN "+json.dumps(dict(profile=profile,label=label,repeats=args.repeats,
          **medians[(profile,label)]),sort_keys=True),flush=True)
for profile in profiles:
    pairs=(("compile_toggle","nxt-plain","nxt-plain-with-crypto"),) if args.nxt_only else (
        ("plain","classic-plain","nxt-plain"),
        ("plain_crypto_enabled","classic-plain","nxt-plain-with-crypto"),
        ("crypt","classic-crypt","nxt-crypt"),
        ("compile_toggle","nxt-plain","nxt-plain-with-crypto"))
    for mode,a,b in pairs:
        left,right=medians[(profile,a)],medians[(profile,b)]
        delta={key:right[key]-left[key] if left[key] is not None and right[key] is not None else None for key in right}
        print("RAM_COMPARE "+json.dumps(dict(profile=profile,mode=mode,classic=a,nxt=b,
              delta_nxt_minus_classic_kib=delta),sort_keys=True),flush=True)
if args.nxt_only:
    for profile in profiles:
        summaries={}
        for label in labels:
            rows=groups[(profile,label)]
            cats=sorted({cat for row in rows for cat in row["mappings"]})
            result={}
            for cat in cats:
                result[cat]={metric:int(statistics.median(
                    row["mappings"].get(cat,{}).get(metric,0) for row in rows))
                    for metric in SMAPS_KEYS}
            summaries[label]=result
            print("MEMORY_MAP_MEDIAN "+json.dumps(dict(profile=profile,label=label,
                  categories=result),sort_keys=True),flush=True)
        a,b=(summaries[x] for x in labels)
        delta={cat:{m:b.get(cat,{}).get(m,0)-a.get(cat,{}).get(m,0)
                    for m in SMAPS_KEYS} for cat in set(a)|set(b)}
        print("MEMORY_MAP_DELTA "+json.dumps(dict(profile=profile,
              delta_crypto_enabled_minus_minimal=delta),sort_keys=True),flush=True)
print("LIVE_REAL_BOT_RAM_BENCH_OK",flush=True)
