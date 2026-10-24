#!/usr/bin/env python3
"""Real-bot startup and idle RSS regression (no external IRC or hub)."""
from pathlib import Path
import subprocess
import sys
import tempfile
import time

BIN = str(Path(sys.argv[1]).resolve())
PASSWORD = "startup-memory-integration-secret"

def memory(pid):
    result = {}
    try:
        for line in Path(f"/proc/{pid}/status").read_text().splitlines():
            if line.startswith(("VmRSS:", "VmHWM:")):
                name, value = line.split(":", 1)
                result[name] = int(value.strip().split()[0])
    except (FileNotFoundError, ProcessLookupError):
        return {}
    return result

def execute(label, binary, role, storage, encrypted_cfg=False,
            encrypted_ul=False, existing=False, corrupted=False,
            cache=False, expected_alive=True):
    with tempfile.TemporaryDirectory(prefix="nxt-live-memory-") as tmp:
        directory = Path(tmp)
        dest = "bot.ul.nxt" if encrypted_ul else "bot.ul"
        lines = [
            "nick testbot", "ident testbot", "handle testbot",
            "realname memory-test", "dontfork ON",
            f"userlist {dest}", "server 127.0.0.1 65530",
        ]
        if role != "main":
            lines.append("hub 127.0.0.1 65531 integration-password mainhub")
        if role == "slave":
            lines.append("listen 127.0.0.1 35789 all")
        if role == "leaf" and storage:
            lines.append("save-userlist ON")
        cfg = directory / "bot.cfg"
        cfg.write_text("\n".join(lines)+"\n")
        pw = directory / "pw"
        pw.write_text(PASSWORD+"\n")
        pw.chmod(0o600)
        ul = directory / dest
        if existing:
            ul.write_text("# userlist\n21 42\n82 1700000000\n")
            if encrypted_ul:
                output = ul
                source = directory / "plainul"
                ul.rename(source)
                subprocess.run([BIN, "userlist", "encrypt", str(source),
                    "--output", str(output), "--password-file", str(pw)],
                    check=True, stdout=subprocess.DEVNULL)
        if corrupted:
            ul.write_bytes(b"corrupted NXTCRYPT file\x00\x01")
        config_path = cfg
        if encrypted_cfg:
            config_path = directory / "bot.cfg.nxt"
            subprocess.run([BIN, "config", "encrypt", str(cfg),
                "--output", str(config_path), "--password-file", str(pw)],
                check=True, stdout=subprocess.DEVNULL)
        argv = [binary]
        if encrypted_cfg or encrypted_ul:
            argv.extend(["--password-file", str(pw)])
            if cache:
                argv.append("--key-cache")
        argv.append(str(config_path))  # psotnic expects CFG as the final argument
        process = subprocess.Popen(argv, cwd=tmp, stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        rss, hwm = [], []
        for _ in range(8):
            time.sleep(0.12)
            if process.poll() is not None:
                break
            m = memory(process.pid)
            if "VmRSS" in m: rss.append(m["VmRSS"])
            if "VmHWM" in m: hwm.append(m["VmHWM"])
        alive = process.poll() is None
        if alive: process.terminate()
        try: out = process.communicate(timeout=3)[0].decode(errors="replace")
        except subprocess.TimeoutExpired:
            process.kill()
            out = process.communicate(timeout=3)[0].decode(errors="replace")
        print(f"LIVE_RSS case={label} role={role} storage={storage} cfg={'nxt' if encrypted_cfg else 'plain'} "
              f"ul={'nxt' if encrypted_ul else 'plain'} alive={int(alive)} "
              f"rss_idle_kib={rss[-1] if rss else -1} rss_high_kib={max(hwm) if hwm else -1}",
              flush=True)
        if alive != expected_alive:
            print("STARTUP_OUTPUT:", out[-2400:], flush=True)
            raise AssertionError(f"{label}: alive={alive}, expected={expected_alive}")
        if cache:
            assert (directory / "bot.key").exists(), (label, out)
            assert not ul.exists(), "Should not materialize a replica at first boot"
            # Ensure an actual second boot can use the cache without a password.
            new = [binary, str(config_path)]
            p2 = subprocess.Popen(new, cwd=tmp, stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
            time.sleep(0.5)
            alive2 = p2.poll() is None
            if alive2: p2.terminate()
            second = p2.communicate(timeout=3)[0]
            assert alive2, second[-1500:]
            assert not ul.exists()
            print(f"LIVE_KEY_CACHE_RESTART_OK case={label}", flush=True)

# Regressions on the actual binary, without a running external IRC server.
execute("slave-plain", BIN, "slave", True)
execute("leaf-off", BIN, "leaf", False)
execute("leaf-on-plain", BIN, "leaf", True)
execute("slave-nxt-missing", BIN, "slave", True,
        encrypted_cfg=True, encrypted_ul=True, cache=True)
execute("leaf-on-nxt-missing", BIN, "leaf", True,
        encrypted_cfg=True, encrypted_ul=True)
execute("leaf-off-nxt-path", BIN, "leaf", False,
        encrypted_cfg=True, encrypted_ul=True)
execute("slave-nxt-existing", BIN, "slave", True,
        encrypted_cfg=True, encrypted_ul=True, existing=True)
execute("main-plain-existing", BIN, "main", True, existing=True)
execute("main-nxt-existing", BIN, "main", True,
        encrypted_cfg=True, encrypted_ul=True, existing=True)
execute("main-nxt-missing", BIN, "main", True,
        encrypted_cfg=True, encrypted_ul=True, expected_alive=False)
execute("slave-nxt-corrupted", BIN, "slave", True,
        encrypted_cfg=True, encrypted_ul=True, corrupted=True,
        expected_alive=False)
print("LIVE_STARTUP_MATRIX_OK", flush=True)
