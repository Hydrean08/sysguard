#!/usr/bin/env python3
"""sysguard triage + break-glass control.

The break-glass operator console: a live "what's killing the box" snapshot and a
tiny whitelist of REVERSIBLE container actions the phone can trigger when the box
is thrashing too hard to use the desktop. Pure stdlib.

Why this can act directly (unlike web.py's proposal path, which waits for the
daemon's next cycle): the actions are `docker pause/unpause/restart/stop`, which
work over the Docker socket via the user's `docker` group membership — NO sudo,
NO cgroup-write privilege. `docker pause` is the freezer cgroup under the hood:
instant, non-destructive, reversible — the exact tourniquet that saved the box on
2026-07-07, but one tap from the phone instead of a shell.

Safety: only these four verbs, only on a container name that is actually present,
every action appended to an audit log. Destructive verbs (restart/stop) are
flagged so the UI can confirm; pause/unpause are safe (reversible).
"""
from __future__ import annotations

import glob
import json
import os
import subprocess
import time

HOME = os.path.expanduser("~")
AUDIT_LOG = os.path.join(HOME, ".local", "share", "sysguard", "control_audit.jsonl")

# The ONLY actions the console can take. pause/unpause are reversible & safe;
# restart/stop are flagged destructive so the UI confirms first. "freeze docker"
# (the whole daemon) is deliberately absent — too dangerous for one tap.
CONTROL_VERBS = {
    "pause":   {"argv": ["pause"],   "destructive": False, "desc": "freeze (reversible)"},
    "unpause": {"argv": ["unpause"], "destructive": False, "desc": "thaw"},
    "restart": {"argv": ["restart"], "destructive": True,  "desc": "restart"},
    "stop":    {"argv": ["stop"],    "destructive": True,  "desc": "stop"},
}


def _read_loadavg() -> list[float]:
    try:
        with open("/proc/loadavg") as f:
            p = f.read().split()
        return [float(p[0]), float(p[1]), float(p[2])]
    except (OSError, ValueError, IndexError):
        return [0.0, 0.0, 0.0]


def _read_meminfo() -> dict:
    """MemTotal/MemAvailable/Swap in MB, plus derived headroom, from /proc."""
    vals = {}
    try:
        with open("/proc/meminfo") as f:
            for line in f:
                k, _, rest = line.partition(":")
                vals[k] = float(rest.strip().split()[0]) / 1024.0  # kB -> MB
    except (OSError, ValueError, IndexError):
        return {}
    total = vals.get("MemTotal", 0.0)
    avail = vals.get("MemAvailable", 0.0)
    swap_total = vals.get("SwapTotal", 0.0)
    swap_free = vals.get("SwapFree", 0.0)
    return {
        "mem_total_mb": round(total),
        "mem_available_mb": round(avail),
        "mem_used_pct": round((total - avail) / total * 100, 1) if total else 0,
        "swap_total_mb": round(swap_total),
        "swap_used_mb": round(swap_total - swap_free),
        "swap_used_pct": round((swap_total - swap_free) / swap_total * 100, 1) if swap_total else 0,
    }


def _read_psi() -> dict:
    """Memory pressure (some/full avg10) — the 'is the box actually stalling' signal."""
    out = {"some_avg10": 0.0, "full_avg10": 0.0}
    try:
        with open("/proc/pressure/memory") as f:
            for line in f:
                parts = dict(kv.split("=") for kv in line.split()[1:] if "=" in kv)
                if line.startswith("some"):
                    out["some_avg10"] = float(parts.get("avg10", 0))
                elif line.startswith("full"):
                    out["full_avg10"] = float(parts.get("avg10", 0))
    except (OSError, ValueError):
        pass
    return out


def _top_consumers(field: str, n: int = 6) -> list[dict]:
    """Top-n processes by a /proc status field (VmRSS / VmSwap), as {name, mb, pid}."""
    prefix = field + ":"
    rows = []
    for status in glob.glob("/proc/[0-9]*/status"):
        try:
            name = kb = None
            with open(status) as f:
                for line in f:
                    if line.startswith("Name:"):
                        name = line.split(None, 1)[1].strip()
                    elif line.startswith(prefix):
                        kb = int(line.split()[1])
                        break
            if name and kb and kb > 0:
                rows.append((kb / 1024.0, name, status.split("/")[2]))
        except (OSError, ValueError, IndexError):
            continue
    rows.sort(reverse=True)
    return [{"name": nm, "mb": round(mb), "pid": pid} for mb, nm, pid in rows[:n]]


def _containers(timeout: float = 4.0) -> tuple[list[dict], str | None]:
    """Live container list with paused state + memory. Uses `docker ps` (user is in
    the docker group). Returns (rows, error) — degrades to ([], msg) if docker hangs
    under load rather than blocking the console."""
    try:
        r = subprocess.run(
            ["docker", "ps", "-a", "--no-trunc",
             "--format", "{{.Names}}\t{{.ID}}\t{{.State}}\t{{.Status}}"],
            capture_output=True, text=True, timeout=timeout,
        )
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError) as e:
        return [], f"docker unavailable: {e.__class__.__name__}"
    if r.returncode != 0:
        return [], (r.stderr.strip() or "docker error")[:120]
    rows = []
    for line in r.stdout.splitlines():
        parts = line.split("\t")
        if len(parts) < 3:
            continue
        name, cid, state = parts[0], parts[1], parts[2]
        rows.append({
            "name": name,
            "state": state,               # running | paused | exited | ...
            "paused": state == "paused",
            "mem_mb": _cgroup_mem_mb(cid),
        })
    rows.sort(key=lambda c: c["mem_mb"], reverse=True)
    return rows, None


def _cgroup_mem_mb(cid: str) -> int:
    """Container cgroup memory.current in MB (v2), 0 if unreadable. Cheap file read
    that works even when docker stats would hang."""
    for pat in (f"/sys/fs/cgroup/system.slice/docker-{cid}.scope/memory.current",
                f"/sys/fs/cgroup/system.slice/docker-{cid}*.scope/memory.current"):
        for path in glob.glob(pat):
            try:
                with open(path) as f:
                    return round(int(f.read().strip()) / 1024 / 1024)
            except (OSError, ValueError):
                continue
    return 0


def snapshot() -> dict:
    """The full live triage picture — everything the console needs in one cheap call."""
    containers, cerr = _containers()
    return {
        "ts": time.time(),
        "load": _read_loadavg(),
        "mem": _read_meminfo(),
        "psi": _read_psi(),
        "top_ram": _top_consumers("VmRSS"),
        "top_swap": _top_consumers("VmSwap"),
        "containers": containers,
        "containers_error": cerr,
        "verbs": {k: {"destructive": v["destructive"], "desc": v["desc"]}
                  for k, v in CONTROL_VERBS.items()},
    }


def _audit(entry: dict) -> None:
    try:
        os.makedirs(os.path.dirname(AUDIT_LOG), exist_ok=True)
        with open(AUDIT_LOG, "a") as f:
            f.write(json.dumps(entry) + "\n")
    except OSError:
        pass


def control(verb: str, target: str) -> tuple[bool, str]:
    """Run one whitelisted container action. Validates the verb and that `target` is
    a real container before touching anything; audit-logs the outcome. Returns
    (ok, message)."""
    spec = CONTROL_VERBS.get(verb)
    if not spec:
        return False, f"unknown action '{verb}'"
    if not target or "/" in target or any(c.isspace() for c in target):
        return False, "invalid target"
    live, _ = _containers(timeout=4.0)
    names = {c["name"] for c in live}
    if target not in names:
        return False, f"no such container '{target}'"
    now = time.time()
    try:
        r = subprocess.run(["docker", *spec["argv"], target],
                           capture_output=True, text=True, timeout=30)
        ok = r.returncode == 0
        msg = (r.stdout.strip() or r.stderr.strip() or ("done" if ok else "failed"))[:200]
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError) as e:
        ok, msg = False, f"{verb} error: {e.__class__.__name__}"
    _audit({"ts": now, "verb": verb, "target": target, "ok": ok, "msg": msg})
    return ok, msg
