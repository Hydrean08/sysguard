#!/usr/bin/env python3
"""sysguard — predictive memory health monitor with AI triage.

Samples per-systemd-unit RSS every N seconds, tracks growth slopes,
asks a local Ollama model to label suspicious units, and (when not in
dry-run) restarts or caps the unit via systemd. Hardcoded skip-list
protects Claude, sshd, plasma, ollama, etc.
"""
from __future__ import annotations

import json
import logging
import os
import signal
import socket
import sqlite3
import subprocess
import sys
import time
from collections import deque
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional
from urllib.error import URLError
from urllib.request import Request, urlopen

import psutil
import yaml

import ai_diagnose

ROOT = Path(__file__).resolve().parent
CONFIG_PATH = ROOT / "config.yaml"
STATE_DIR = Path.home() / ".local/share/sysguard"
STATE_FILE = STATE_DIR / "state.json"
ACTIONS_LOG = STATE_DIR / "actions.log"
DECISIONS_LOG = STATE_DIR / "decisions.jsonl"
HISTORY_DB = STATE_DIR / "history.db"

# Names that must NEVER be touched, even if config drops them.
# Mix of process comms and systemd unit substrings.
HARDCODED_SKIPS = {
    # Claude — per memory, killing Claude processes has burned the user twice
    "claude", "claude-code", "node",
    # SSH / login
    "sshd", "login", "systemd-logind",
    # systemd core
    "systemd", "systemd-journald", "systemd-oomd", "systemd-udevd",
    "systemd-resolved", "systemd-networkd", "systemd-timesyncd",
    # KDE Plasma desktop
    "plasmashell", "kwin_wayland", "kwin_x11", "kded5", "kded6",
    "ksmserver", "kglobalacceld", "krunner", "klauncher", "kactivitymanagerd",
    # Display server
    "Xorg", "Xwayland", "sddm",
    # Audio
    "pulseaudio", "pipewire", "pipewire-pulse", "wireplumber",
    # Networking / firewall
    "NetworkManager", "firewalld", "wpa_supplicant",
    # Container runtimes — too dangerous to restart broadly
    "dockerd", "containerd", "containerd-shim-runc-v2", "runc",
    # The brain we depend on
    "ollama",
    # sysguard itself
    "sysguard",
    # Prism — the Electron app that hosts the Claude Code session. Restarting it
    # kills the running session; a MemoryHigh cap can OOM the Electron renderer.
    # Its RSS is bursty (has flagged at 3.3× baseline), so without this it was one
    # model "restart"/"cap" verdict away from taking the session down in live mode.
    "prism",
}

# Substrings that match systemd unit names to skip
HARDCODED_SKIP_UNITS = {
    "user@", "session-", "init.scope", "system.slice",
    "sshd.service", "systemd-",
    "plasma-", "kde-",
    "docker.service", "containerd.service",
    "ollama.service",
    "sysguard.service",
    # Transient systemd-run jobs (run-rNNNN / run-pNNNN / run-uNNNN .service/.scope)
    # are ephemeral — gone by the next cycle. Tracking them produces churn and one
    # wasted a full Claude escalation timeout on a scope that had already vanished.
    "run-r", "run-p", "run-u",
}


@dataclass
class UnitSample:
    timestamp: float
    rss_mb: float


@dataclass
class UnitHistory:
    name: str
    samples: deque = field(default_factory=lambda: deque(maxlen=60))
    last_action_at: float = 0.0
    baseline_rss_mb: float = 0.0
    pending_verify: Optional[dict] = None

    def add(self, rss_mb: float, ts: float):
        self.samples.append(UnitSample(ts, rss_mb))
        # Startup-min seed: a provisional baseline for brand-new units with no
        # history yet. In median mode refresh_baselines() overwrites this with the
        # rolling median once enough samples exist in history.db (the `if not`
        # guard means we only seed once, then defer to the adaptive refresh).
        if not self.baseline_rss_mb and len(self.samples) >= 10:
            self.baseline_rss_mb = min(s.rss_mb for s in list(self.samples)[:10])

    def slope_mb_per_min(self, window_samples: int = 10) -> float:
        if len(self.samples) < 2:
            return 0.0
        recent = list(self.samples)[-window_samples:]
        if len(recent) < 2:
            return 0.0
        dt_min = (recent[-1].timestamp - recent[0].timestamp) / 60.0
        if dt_min <= 0:
            return 0.0
        return (recent[-1].rss_mb - recent[0].rss_mb) / dt_min

    def jump_mb(self) -> float:
        if len(self.samples) < 2:
            return 0.0
        return self.samples[-1].rss_mb - self.samples[-2].rss_mb

    def current_mb(self) -> float:
        return self.samples[-1].rss_mb if self.samples else 0.0


@dataclass
class SystemSample:
    total_mb: float
    available_mb: float
    used_mb: float
    swap_used_mb: float
    swap_total_mb: float
    pressure_some_avg10: float
    pressure_full_avg10: float
    disk_root_free_mb: float = 0.0
    disk_pool_free_mb: float = 0.0


class HistoryDB:
    """Durable per-unit RSS time-series sink.

    sysguard's live detection runs off the short in-memory UnitHistory window
    (history_window_samples). This class is a *passive recorder* that persists every
    sample to SQLite so long-term trends survive restarts and can be graphed or
    post-mortemed. It is never consulted in the kill/restart decision path, and a
    write failure here logs a warning but never interrupts a monitoring cycle.
    """

    def __init__(self, path: Path):
        self.conn = sqlite3.connect(str(path))
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.execute("PRAGMA synchronous=NORMAL")
        self.conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS unit_samples (
                ts     INTEGER NOT NULL,
                unit   TEXT    NOT NULL,
                rss_mb REAL    NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_unit_samples_unit_ts ON unit_samples(unit, ts);
            CREATE INDEX IF NOT EXISTS idx_unit_samples_ts ON unit_samples(ts);
            CREATE TABLE IF NOT EXISTS system_samples (
                ts                INTEGER PRIMARY KEY,
                available_mb      REAL,
                used_mb           REAL,
                swap_used_mb      REAL,
                psi_some_avg10    REAL,
                psi_full_avg10    REAL,
                disk_root_free_mb REAL,
                disk_pool_free_mb REAL
            );
            """
        )
        self.conn.commit()

    def record(self, ts: int, sysm: SystemSample,
               unit_rows: list[tuple[int, str, float]]):
        try:
            with self.conn:
                if unit_rows:
                    self.conn.executemany(
                        "INSERT INTO unit_samples(ts, unit, rss_mb) VALUES (?, ?, ?)",
                        unit_rows,
                    )
                self.conn.execute(
                    "INSERT OR REPLACE INTO system_samples"
                    "(ts, available_mb, used_mb, swap_used_mb, psi_some_avg10,"
                    " psi_full_avg10, disk_root_free_mb, disk_pool_free_mb)"
                    " VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                    (ts, sysm.available_mb, sysm.used_mb, sysm.swap_used_mb,
                     sysm.pressure_some_avg10, sysm.pressure_full_avg10,
                     sysm.disk_root_free_mb, sysm.disk_pool_free_mb),
                )
        except sqlite3.Error as e:
            logging.warning("history: write failed: %s", e)

    def unit_medians(self, window_hours: float, min_samples: int) -> dict[str, float]:
        """Median RSS per unit over the trailing window — the adaptive baseline.

        Read-only (stays a passive recorder). Median, not mean, so transient
        spikes don't skew it. Units with fewer than min_samples in the window
        are omitted so a barely-seen unit keeps its startup-min fallback.
        """
        cutoff = int(time.time()) - int(window_hours * 3600)
        out: dict[str, float] = {}
        try:
            rows = self.conn.execute(
                "SELECT unit, COUNT(*) FROM unit_samples WHERE ts > ? "
                "GROUP BY unit HAVING COUNT(*) >= ?",
                (cutoff, min_samples),
            ).fetchall()
            for unit, cnt in rows:
                # True median via the middle ordered row (lower-middle for even
                # counts — close enough; avoids averaging two queries).
                row = self.conn.execute(
                    "SELECT rss_mb FROM unit_samples WHERE unit = ? AND ts > ? "
                    "ORDER BY rss_mb LIMIT 1 OFFSET ?",
                    (unit, cutoff, (cnt - 1) // 2),
                ).fetchone()
                if row:
                    out[unit] = row[0]
        except sqlite3.Error as e:
            logging.warning("baseline: median query failed: %s", e)
        return out

    def prune(self, retention_days: int):
        cutoff = int(time.time()) - retention_days * 86400
        try:
            with self.conn:
                self.conn.execute("DELETE FROM unit_samples WHERE ts < ?", (cutoff,))
                self.conn.execute("DELETE FROM system_samples WHERE ts < ?", (cutoff,))
        except sqlite3.Error as e:
            logging.warning("history: prune failed: %s", e)

    def close(self):
        try:
            self.conn.close()
        except sqlite3.Error:
            pass


def setup_logging(level_name: str):
    level = getattr(logging, level_name.upper(), logging.INFO)
    logging.basicConfig(
        level=level,
        format="%(asctime)s %(levelname)s %(message)s",
        handlers=[
            logging.StreamHandler(sys.stdout),
            logging.FileHandler(ACTIONS_LOG),
        ],
    )


def load_config() -> dict:
    with open(CONFIG_PATH) as f:
        return yaml.safe_load(f)


def read_pressure() -> tuple[float, float]:
    """Read /proc/pressure/memory — PSI avg10 for some/full stalls."""
    try:
        with open("/proc/pressure/memory") as f:
            lines = f.read().splitlines()
        some_avg10 = 0.0
        full_avg10 = 0.0
        for line in lines:
            parts = dict(p.split("=") for p in line.split()[1:] if "=" in p)
            if line.startswith("some"):
                some_avg10 = float(parts.get("avg10", 0))
            elif line.startswith("full"):
                full_avg10 = float(parts.get("avg10", 0))
        return some_avg10, full_avg10
    except (OSError, ValueError):
        return 0.0, 0.0


def sample_system() -> SystemSample:
    vm = psutil.virtual_memory()
    sm = psutil.swap_memory()
    some, full = read_pressure()
    try:
        disk_root_free_mb = psutil.disk_usage("/").free / 1024 / 1024
    except OSError:
        disk_root_free_mb = 0.0
    try:
        disk_pool_free_mb = psutil.disk_usage("/mnt/docker-pool").free / 1024 / 1024
    except OSError:
        disk_pool_free_mb = 0.0
    return SystemSample(
        total_mb=vm.total / 1024 / 1024,
        available_mb=vm.available / 1024 / 1024,
        used_mb=vm.used / 1024 / 1024,
        swap_used_mb=sm.used / 1024 / 1024,
        swap_total_mb=sm.total / 1024 / 1024,
        pressure_some_avg10=some,
        pressure_full_avg10=full,
        disk_root_free_mb=disk_root_free_mb,
        disk_pool_free_mb=disk_pool_free_mb,
    )


def docker_name_map() -> dict[str, str]:
    """Map `docker-<id>.scope` -> friendly container name. Empty dict if docker absent."""
    try:
        r = subprocess.run(
            ["docker", "ps", "--no-trunc", "--format", "{{.ID}}\t{{.Names}}"],
            capture_output=True, text=True, timeout=5,
        )
        if r.returncode != 0:
            return {}
        out = {}
        for line in r.stdout.splitlines():
            if "\t" not in line:
                continue
            cid, name = line.split("\t", 1)
            out[f"docker-{cid.strip()}.scope"] = name.strip()
        return out
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return {}


def list_systemd_units() -> list[tuple[str, str, str]]:
    """Return [(unit_id, friendly_name, kind)] for active services AND container scopes.

    kind is one of: 'system_service', 'user_service', 'docker'.
    friendly_name is the container name for docker scopes, else equals unit_id.
    """
    docker_names = docker_name_map()
    units: list[tuple[str, str, str]] = []

    for scope_flag, kind in (("--system", "system_service"), ("--user", "user_service")):
        try:
            r = subprocess.run(
                ["systemctl", scope_flag, "list-units", "--type=service",
                 "--state=running", "--no-legend", "--no-pager", "--plain"],
                capture_output=True, text=True, timeout=10,
            )
            for line in r.stdout.splitlines():
                parts = line.split()
                if parts and parts[0].endswith(".service"):
                    units.append((parts[0], parts[0], kind))
        except (subprocess.TimeoutExpired, FileNotFoundError):
            continue

    # System scopes — picks up docker, podman, user sessions, etc.
    try:
        r = subprocess.run(
            ["systemctl", "--system", "list-units", "--type=scope",
             "--state=running", "--no-legend", "--no-pager", "--plain"],
            capture_output=True, text=True, timeout=10,
        )
        for line in r.stdout.splitlines():
            parts = line.split()
            if not parts or not parts[0].endswith(".scope"):
                continue
            unit_id = parts[0]
            if unit_id.startswith("docker-") and unit_id in docker_names:
                units.append((unit_id, f"docker:{docker_names[unit_id]}", "docker"))
            # Skip non-docker scopes (user sessions, etc.) — covered by skip-list anyway
    except (subprocess.TimeoutExpired, FileNotFoundError):
        pass

    return units


def _systemctl_scope_flag(kind: str) -> str:
    """Map our 'kind' label to systemctl --user/--system flag."""
    return "--user" if kind == "user_service" else "--system"


def get_unit_memory_mb(unit: str, kind: str) -> Optional[float]:
    """Return MemoryCurrent in MB via systemctl show, or None."""
    try:
        r = subprocess.run(
            ["systemctl", _systemctl_scope_flag(kind), "show", unit,
             "-p", "MemoryCurrent", "--value"],
            capture_output=True, text=True, timeout=5,
        )
        v = r.stdout.strip()
        if not v or v == "[not set]":
            return None
        n = int(v)
        # systemd reports a huge sentinel when unset
        if n > 10**15:
            return None
        return n / 1024 / 1024
    except (subprocess.TimeoutExpired, ValueError, FileNotFoundError):
        return None


def is_skipped(unit_or_proc: str, extra_units: list[str], extra_procs: list[str]) -> bool:
    name = unit_or_proc.lower()
    # comm match
    for s in HARDCODED_SKIPS:
        if s.lower() == name or name.startswith(s.lower() + "."):
            return True
    # unit substring match
    for s in HARDCODED_SKIP_UNITS:
        if s.lower() in name:
            return True
    for s in extra_units + extra_procs:
        if s and s.lower() in name:
            return True
    return False


def call_ollama(url: str, model: str, prompt: str, timeout: int, num_thread: int = 4) -> Optional[dict]:
    """POST to /api/generate, expect JSON object back in response."""
    payload = {
        "model": model,
        "prompt": prompt,
        "stream": False,
        "format": "json",
        "options": {"temperature": 0.1, "num_predict": 200, "num_thread": num_thread},
    }
    body = json.dumps(payload).encode()
    req = Request(
        f"{url.rstrip('/')}/api/generate",
        data=body,
        headers={"Content-Type": "application/json"},
    )
    try:
        with urlopen(req, timeout=timeout) as resp:
            data = json.loads(resp.read())
        raw = data.get("response", "")
        return json.loads(raw)
    except (URLError, socket.timeout, json.JSONDecodeError, ValueError) as e:
        logging.warning("ollama call failed model=%s err=%s", model, e)
        return None


def build_prompt(friendly: str, kind: str, hist: UnitHistory, sysm: SystemSample,
                 journal_tail: str, extra_context: str = "") -> str:
    samples = list(hist.samples)
    rss_now = samples[-1].rss_mb
    rss_5min_ago = samples[max(0, len(samples) - 10)].rss_mb
    extra_section = f"\nLive stats:\n{extra_context}\n" if extra_context else ""
    return f"""You are a Linux system health analyst on a Fedora 44 box with 32GB RAM.
Decide ONE action for the unit below. Return JSON only.

Unit: {friendly} ({kind})
Current RSS: {rss_now:.0f} MB
RSS ~5 min ago: {rss_5min_ago:.0f} MB
Growth slope: {hist.slope_mb_per_min():.1f} MB/min (last 5 min)
Last-sample jump: {hist.jump_mb():+.0f} MB
Baseline (adaptive median, normal size for this unit): {hist.baseline_rss_mb:.0f} MB
Samples held: {len(samples)}

System: available={sysm.available_mb:.0f}MB, swap_used={sysm.swap_used_mb:.0f}/{sysm.swap_total_mb:.0f}MB
PSI memory some_avg10={sysm.pressure_some_avg10:.1f} full_avg10={sysm.pressure_full_avg10:.1f}
Disk: root={sysm.disk_root_free_mb / 1024:.1f}GB free, docker-pool={sysm.disk_pool_free_mb / 1024:.1f}GB free
{extra_section}
Recent journal (last 25 lines):
{journal_tail or "(none)"}

Pick ONE action:
- "ignore"      — normal behavior for this workload
- "restart"     — leak or runaway; restarting the unit will recover memory cleanly
- "cap"         — apply systemd MemoryHigh to bound future growth without restart
- "investigate" — pattern is novel; escalate to a stronger model

Output JSON: {{"action": "ignore|restart|cap|investigate", "reason": "one short sentence", "root_cause": "what is driving the growth — active workload, memory leak, or unknown"}}
"""


def journal_tail(unit_id: str, friendly: str, kind: str, lines: int = 25) -> str:
    """Tail recent log lines. Uses docker logs for containers, journalctl otherwise."""
    if kind == "docker":
        container = friendly.split(":", 1)[1] if friendly.startswith("docker:") else friendly
        try:
            r = subprocess.run(
                ["docker", "logs", "--tail", str(lines), container],
                capture_output=True, text=True, timeout=5,
            )
            return (r.stdout + r.stderr).strip()[-2000:]
        except (subprocess.TimeoutExpired, FileNotFoundError):
            return ""
    args = ["journalctl"]
    if kind == "user_service":
        args.append("--user")
    args += ["-u", unit_id, "-n", str(lines), "--no-pager", "-o", "short"]
    try:
        r = subprocess.run(args, capture_output=True, text=True, timeout=5)
        return r.stdout.strip()
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return ""


def notify_kde(title: str, body: str):
    try:
        subprocess.Popen(
            ["notify-send", "-a", "sysguard", "-u", "normal", title, body],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
    except FileNotFoundError:
        pass


def notify_ntfy(cfg: dict, title: str, body: str, priority: int = 3):
    """Send a push notification via ntfy. priority: 1=min 2=low 3=default 4=high 5=max.
    No-ops if ntfy_topic is empty or priority is below ntfy_min_priority."""
    topic = cfg.get("ntfy_topic", "")
    if not topic:
        return
    if priority < cfg.get("ntfy_min_priority", 1):
        return
    url = cfg.get("ntfy_url", "https://ntfy.sh").rstrip("/") + "/" + topic
    headers = {"Title": title, "Priority": str(priority), "Tags": "computer"}
    token = cfg.get("ntfy_token", "")
    if token:
        headers["Authorization"] = f"Bearer {token}"
    req = Request(url, data=body.encode(), headers=headers, method="POST")
    try:
        with urlopen(req, timeout=10):
            pass
    except Exception as e:
        logging.warning("ntfy notification failed: %s", e)


# Disk alerting is EDGE-triggered: notify once when a mount drops into warn/crit,
# again only if it worsens (warn->crit) or a full day passes while still low, and
# log — not push — a recovery. Hysteresis (must climb back above threshold*factor)
# stops boundary flapping. The old level-triggered version re-pushed every 15 min
# forever, spamming the phone for a static "disk a bit full" that needs cleanup, not
# 96 notifications a day. Severity order: ok < warn < crit.
_disk_state: dict[str, dict] = {}
_DISK_REMIND_SEC = 86400          # at most one reminder/day while a mount stays low
_DISK_RECOVER_FACTOR = 1.15       # must climb 15% above a threshold to clear it


def check_disk(sysm: SystemSample, cfg: dict, now: float):
    """Alert when disk is low. A full root partition once crashed the box with no
    visibility — this closes that blind spot without spamming for a steady-state
    'pool a bit full' condition."""
    remind = cfg.get("disk_remind_sec", _DISK_REMIND_SEC)
    rank = {"ok": 0, "warn": 1, "crit": 2}

    def evaluate(mount: str, free_mb: float, warn_mb: float, crit_mb: float, label: str):
        if free_mb <= 0:
            return
        st = _disk_state.setdefault(mount, {"sev": "ok", "last_alert": 0.0})
        prev = st["sev"]
        if crit_mb and free_mb < crit_mb:
            sev = "crit"
        elif free_mb < warn_mb:
            sev = "warn"
        elif prev != "ok" and free_mb < warn_mb * _DISK_RECOVER_FACTOR:
            sev = prev            # inside hysteresis band — hold, don't re-alert
        else:
            sev = "ok"
        st["sev"] = sev
        if sev == "ok":
            if prev != "ok":
                logging.info("disk recovered: %s %.1f GB free", label, free_mb / 1024)
            return
        worsened = rank[sev] > rank[prev]
        stale = (now - st["last_alert"]) >= remind
        if not (worsened or stale):
            return                # same bad state, reminder not due — stay quiet
        st["last_alert"] = now
        crit = sev == "crit"
        # For the docker pool, RECOMMEND a concrete one-tap reclaim (safe prunes)
        # rather than just nagging. If a proposal was created/pending it sends its
        # own richer notification, so suppress the bare alert.
        if mount == "pool":
            try:
                if ai_diagnose.propose_disk_reclaim(mount, free_mb, cfg, notify_ntfy):
                    logging.warning("disk %s: %s [reclaim proposed — approve on phone]", sev, label)
                    return
            except Exception as e:      # a proposal hiccup must never mute the alert
                logging.warning("disk reclaim proposal failed: %s", e)
        title = "sysguard: DISK CRITICAL" if crit else f"sysguard: {label} low"
        msg = f"{label} {free_mb / 1024:.1f} GB free" + (" — disk-full crash imminent" if crit else "")
        (logging.error if crit else logging.warning)("disk %s: %s", sev, msg)
        if cfg.get("kde_notify"):
            notify_kde(title, msg)
        notify_ntfy(cfg, title, msg, 5 if crit else 3)

    evaluate("root", sysm.disk_root_free_mb,
             cfg.get("disk_root_warn_mb", 20480), cfg.get("disk_root_crit_mb", 10240), "root")
    evaluate("pool", sysm.disk_pool_free_mb,
             cfg.get("disk_pool_warn_mb", 30720), cfg.get("disk_pool_crit_mb", 10240), "docker-pool")


_swap_alert_last: dict[str, float] = {}
_SWAP_ALERT_COOLDOWN = 900  # 15 min between repeated swap alerts


def check_swap(sysm: SystemSample, cfg: dict, now: float):
    """Alert on swap saturation — the blind spot in the available_mb-only checks.

    available_mb counts reclaimable page cache, so the box can sit at 99% swap
    (one spike from OOM) while every other signal reads healthy. This surfaces it.
    Alert-only, like check_disk — never actuates.
    """
    total = sysm.swap_total_mb
    if total <= 0:
        return
    pct = 100.0 * sysm.swap_used_mb / total
    warn = cfg.get("swap_used_pct_warn", 85)
    crit = cfg.get("swap_used_pct_crit", 95)

    def _alert(key: str, level: str, title: str, msg: str, priority: int):
        if now - _swap_alert_last.get(key, 0) < _SWAP_ALERT_COOLDOWN:
            return
        _swap_alert_last[key] = now
        (logging.error if level == "crit" else logging.warning)("%s", msg)
        if cfg["kde_notify"]:
            notify_kde(title, msg)
        notify_ntfy(cfg, title, msg, priority)

    used_gb, total_gb = sysm.swap_used_mb / 1024, total / 1024
    if pct >= crit:
        _alert("swap_crit", "crit", "sysguard: SWAP CRITICAL",
               f"swap {pct:.0f}% full ({used_gb:.1f}/{total_gb:.1f}GB) — OOM risk "
               f"(available RAM masks this)", priority=5)
    elif pct >= warn:
        _alert("swap_warn", "warn", "sysguard: swap high",
               f"swap {pct:.0f}% full ({used_gb:.1f}/{total_gb:.1f}GB)", priority=4)


_headroom_hist: deque = deque(maxlen=20)  # (ts, headroom_mb) — memory + free swap
_oom_forecast_last: float = 0.0
_OOM_FORECAST_COOLDOWN = 600  # 10 min between forecast alerts


def check_oom_forecast(sysm: SystemSample, cfg: dict, now: float):
    """Predictive early-warning: least-squares fit the memory+swap headroom trend
    and, if it's shrinking, extrapolate to exhaustion. Alert when the ETA drops
    under oom_forecast_warn_min. This is the "predict before it dies" piece — it
    fires with lead time, unlike the reactive slope/jump flags. Alert-only."""
    global _oom_forecast_last
    swap_free = max(0.0, sysm.swap_total_mb - sysm.swap_used_mb)
    headroom = sysm.available_mb + swap_free
    _headroom_hist.append((now, headroom))
    if len(_headroom_hist) < 5:
        return

    t0 = _headroom_hist[0][0]
    xs = [(t - t0) / 60.0 for t, _ in _headroom_hist]  # minutes
    ys = [h for _, h in _headroom_hist]
    n = len(xs)
    sx, sy = sum(xs), sum(ys)
    sxx = sum(x * x for x in xs)
    sxy = sum(x * y for x, y in zip(xs, ys))
    denom = n * sxx - sx * sx
    if denom == 0:
        return
    slope = (n * sxy - sx * sy) / denom  # MB/min; negative = shrinking
    if slope >= -1.0:  # flat or growing — no OOM on the horizon
        return
    eta_min = ys[-1] / (-slope)
    warn = cfg.get("oom_forecast_warn_min", 30)
    if eta_min > warn:
        return
    if now - _oom_forecast_last < _OOM_FORECAST_COOLDOWN:
        return
    _oom_forecast_last = now
    priority = 5 if eta_min < 10 else 4
    msg = (f"memory+swap headroom {ys[-1] / 1024:.1f}GB falling {-slope:.0f}MB/min "
           f"→ OOM in ~{eta_min:.0f} min at this rate")
    logging.error("OOM FORECAST: %s", msg)
    if cfg["kde_notify"]:
        notify_kde("sysguard: OOM predicted", msg)
    notify_ntfy(cfg, "sysguard: OOM predicted", msg, priority=priority)


def gather_extra_context(friendly: str, kind: str) -> str:
    """Pull live docker stats for containers so the AI sees CPU/IO alongside RSS
    and can distinguish normal-workload growth from a pathological leak."""
    if kind != "docker":
        return ""
    container = friendly.split(":", 1)[1] if friendly.startswith("docker:") else friendly
    try:
        r = subprocess.run(
            ["docker", "stats", "--no-stream", "--format",
             "CPU={{.CPUPerc}} MEM={{.MemUsage}} NET={{.NetIO}} BLOCK={{.BlockIO}}",
             container],
            capture_output=True, text=True, timeout=5,
        )
        return r.stdout.strip()
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return ""


def _planned_cap_mb(hist: UnitHistory, cfg: dict) -> int:
    """Cap floor: max(baseline*1.5, current*0.9, 1GB) — avoids flap loops."""
    base = hist.baseline_rss_mb or hist.current_mb()
    return cfg.get("default_cap_mb", 0) or max(
        int(base * 1.5), int(hist.current_mb() * 0.9), 1024
    )


def check_unit_active(unit_id: str, friendly: str, kind: str) -> bool:
    """Return True if the unit is currently running."""
    if kind == "docker":
        container = friendly.split(":", 1)[1] if friendly.startswith("docker:") else friendly
        try:
            r = subprocess.run(
                ["docker", "inspect", "--format", "{{.State.Status}}", container],
                capture_output=True, text=True, timeout=5,
            )
            return r.stdout.strip() == "running"
        except (subprocess.TimeoutExpired, FileNotFoundError):
            return False
    scope_flag = _systemctl_scope_flag(kind)
    try:
        r = subprocess.run(
            ["systemctl", scope_flag, "is-active", unit_id],
            capture_output=True, text=True, timeout=5,
        )
        return r.returncode == 0
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return False


def lift_cap(unit_id: str, friendly: str, kind: str) -> tuple[bool, str]:
    """Remove a memory cap previously applied by sysguard."""
    if kind == "docker":
        container = friendly.split(":", 1)[1] if friendly.startswith("docker:") else friendly
        try:
            r = subprocess.run(
                ["docker", "update", "--memory=0", "--memory-swap=0", container],
                capture_output=True, text=True, timeout=15,
            )
            return r.returncode == 0, r.stderr.strip() or f"cap lifted on {container}"
        except subprocess.TimeoutExpired:
            return False, "timeout lifting cap"
    scope_flag = _systemctl_scope_flag(kind)
    try:
        r = subprocess.run(
            ["systemctl", scope_flag, "set-property", unit_id, "MemoryHigh=infinity"],
            capture_output=True, text=True, timeout=10,
        )
        return r.returncode == 0, r.stderr.strip() or f"cap lifted on {unit_id}"
    except subprocess.TimeoutExpired:
        return False, "timeout lifting cap"


def run_verifications(units: dict[str, UnitHistory], cfg: dict, now: float):
    """For each unit we recently capped or restarted, confirm it is still running
    and the intervention had the intended effect. If a cap OOM-killed the service,
    auto-lift it and alert so the user knows the band-aid made things worse."""
    for friendly, hist in list(units.items()):
        pv = hist.pending_verify
        if not pv or now < pv["check_after"]:
            continue

        hist.pending_verify = None
        unit_id = pv["unit_id"]
        kind = pv["kind"]
        action = pv["action"]
        pre_rss = pv["pre_rss_mb"]
        cur_rss = hist.current_mb()
        is_active = check_unit_active(unit_id, friendly, kind)
        verdict = ""
        extra = ""

        if not is_active:
            verdict = "service_down"
            logging.error("verify FAIL: %s is DOWN after %s", friendly, action)
            if cfg["kde_notify"]:
                notify_kde(f"sysguard: {friendly} DOWN",
                           f"Went down after {action} — check logs")
            notify_ntfy(cfg, f"sysguard: {friendly} DOWN",
                        f"Went down after {action} — check logs", priority=5)
            if action == "cap":
                ok, lift_msg = lift_cap(unit_id, friendly, kind)
                extra = f"auto-lifted cap: {lift_msg}"
                logging.warning("  %s", extra)
        elif action == "restart":
            if cur_rss < pre_rss * 0.6:
                verdict = "restart_ok"
                logging.info("verify OK: %s restarted cleanly, RSS %d→%d MB",
                             friendly, pre_rss, cur_rss)
            else:
                verdict = "restart_rss_unchanged"
                logging.warning("verify WARN: %s RSS unchanged after restart (%d MB)",
                                friendly, cur_rss)
        elif action == "cap":
            cap_mb = pv.get("cap_mb", 0)
            if cap_mb and cur_rss > cap_mb * 1.2:
                verdict = "cap_ineffective"
                logging.warning("verify WARN: %s RSS %d MB still above cap %d MB",
                                friendly, cur_rss, cap_mb)
                if cfg["kde_notify"]:
                    notify_kde(f"sysguard: cap ineffective — {friendly}",
                               f"RSS {cur_rss:.0f} MB > cap {cap_mb} MB; may need restart instead")
                notify_ntfy(cfg, f"sysguard: cap ineffective — {friendly}",
                            f"RSS {cur_rss:.0f} MB > cap {cap_mb} MB; may need restart instead",
                            priority=4)
            else:
                verdict = "cap_stable"
                logging.info("verify OK: %s stable at %d MB after cap", friendly, cur_rss)

        log_decision({
            "ts": now, "type": "verify",
            "unit_id": unit_id, "friendly": friendly, "kind": kind,
            "action": action, "verdict": verdict,
            "pre_rss_mb": pre_rss, "post_rss_mb": cur_rss,
            "service_active": is_active, "extra": extra,
        })


def execute_action(unit_id: str, friendly: str, kind: str, action: str,
                   cfg: dict, hist: UnitHistory) -> tuple[bool, str]:
    """Returns (success, message). Respects dry_run and allowed_actions."""
    if cfg["dry_run"]:
        return True, f"DRY RUN: would {action} {friendly} ({kind})"
    if action not in cfg["allowed_actions"]:
        return False, f"action {action} not in allowed_actions"

    # cap_mb is only used by the cap action; guard so a caller without a live
    # UnitHistory (e.g. the AI approve→execute path passing hist=None for a
    # restart) doesn't crash computing a size it never uses.
    cap_mb = _planned_cap_mb(hist, cfg) if hist is not None else 0

    if kind == "docker":
        container = friendly.split(":", 1)[1] if friendly.startswith("docker:") else friendly
        if action == "restart":
            try:
                r = subprocess.run(
                    ["docker", "restart", container],
                    capture_output=True, text=True, timeout=60,
                )
                if r.returncode == 0:
                    return True, f"restarted docker container {container}"
                return False, f"docker restart failed: {r.stderr.strip()}"
            except subprocess.TimeoutExpired:
                return False, "docker restart timeout"
        if action == "cap":
            try:
                r = subprocess.run(
                    ["docker", "update", f"--memory={cap_mb}m",
                     f"--memory-swap={cap_mb}m", container],
                    capture_output=True, text=True, timeout=15,
                )
                if r.returncode == 0:
                    return True, f"capped docker {container} memory={cap_mb}MB"
                return False, f"docker update failed: {r.stderr.strip()}"
            except subprocess.TimeoutExpired:
                return False, "docker update timeout"
        return False, f"unknown action {action}"

    scope_flag = _systemctl_scope_flag(kind)
    if action == "restart":
        try:
            r = subprocess.run(
                ["systemctl", scope_flag, "restart", unit_id],
                capture_output=True, text=True, timeout=30,
            )
            if r.returncode == 0:
                return True, f"restarted {unit_id}"
            return False, f"restart failed: {r.stderr.strip()}"
        except subprocess.TimeoutExpired:
            return False, "restart timeout"

    if action == "cap":
        try:
            r = subprocess.run(
                ["systemctl", scope_flag, "set-property", unit_id,
                 f"MemoryHigh={cap_mb}M"],
                capture_output=True, text=True, timeout=10,
            )
            if r.returncode == 0:
                return True, f"capped {unit_id} MemoryHigh={cap_mb}M"
            return False, f"cap failed: {r.stderr.strip()}"
        except subprocess.TimeoutExpired:
            return False, "cap timeout"

    return False, f"unknown action {action}"


def log_decision(record: dict):
    with open(DECISIONS_LOG, "a") as f:
        f.write(json.dumps(record) + "\n")


def save_state(units: dict[str, UnitHistory]):
    serializable = {}
    for name, h in units.items():
        serializable[name] = {
            "baseline_rss_mb": h.baseline_rss_mb,
            "last_action_at": h.last_action_at,
            "pending_verify": h.pending_verify,
            "samples": [(s.timestamp, s.rss_mb) for s in h.samples],
        }
    tmp = STATE_FILE.with_suffix(".json.tmp")
    with open(tmp, "w") as f:
        json.dump(serializable, f)
    tmp.replace(STATE_FILE)


def load_state() -> dict[str, UnitHistory]:
    if not STATE_FILE.exists():
        return {}
    try:
        with open(STATE_FILE) as f:
            data = json.load(f)
    except (json.JSONDecodeError, OSError):
        return {}
    out: dict[str, UnitHistory] = {}
    for name, blob in data.items():
        h = UnitHistory(name=name)
        h.baseline_rss_mb = blob.get("baseline_rss_mb", 0.0)
        h.last_action_at = blob.get("last_action_at", 0.0)
        h.pending_verify = blob.get("pending_verify")
        for ts, rss in blob.get("samples", [])[-60:]:
            h.samples.append(UnitSample(ts, rss))
        out[name] = h
    return out


def pick_model(cfg: dict, sysm: SystemSample) -> str:
    """Drop to fallback when memory is critical so we don't make the crisis worse."""
    if sysm.available_mb < cfg["system_critical_available_mb"]:
        return cfg["fallback_model"]
    return cfg["primary_model"]


def should_flag(hist: UnitHistory, sysm: SystemSample, cfg: dict) -> Optional[str]:
    """Return a reason string if the unit should be triaged, else None.

    Adaptive baseline: once enough samples are collected we compare against the
    unit's own learned baseline (N× multiplier) instead of the global absolute
    threshold. This means high-but-stable services like Jellyfin self-calibrate
    within ~10 min and stop producing false positives without manual skip-listing.
    New containers are auto-discovered every cycle and follow the same path.
    """
    cur = hist.current_mb()
    # Per-unit floor: units with legitimately large/spiky working sets (e.g. a
    # FUSE daemon whose read-ahead buffers swing up to ~1.5GB) are ignored below
    # their own floor, so normal buffer churn doesn't trip the global jump/slope
    # thresholds. Anything not listed uses the 200MB default.
    # Most-specific (longest) matching pattern wins, so "orionfs" (4500) beats
    # "orion" (2000) for the orionfs unit regardless of config key order — the
    # old first-match-and-break was silently order-dependent.
    floor = 200
    best_pat = ""
    for pat, mb in (cfg.get("unit_rss_floor_mb") or {}).items():
        if pat in hist.name and len(pat) > len(best_pat):
            best_pat, floor = pat, mb
    if cur < floor:
        return None
    slope = hist.slope_mb_per_min()
    jump = hist.jump_mb()

    if slope >= cfg["rss_growth_mb_per_min"]:
        return f"growth slope {slope:.1f}MB/min exceeds {cfg['rss_growth_mb_per_min']}MB/min"
    # Don't flag startup spikes for brand-new units — first few samples are always jumpy
    if jump >= cfg["rss_jump_mb"] and len(hist.samples) >= cfg.get("rss_jump_min_samples", 5):
        return f"single-sample jump {jump:.0f}MB exceeds {cfg['rss_jump_mb']}MB"

    baseline_mult = cfg.get("baseline_multiplier", 2.0)
    min_samples = cfg.get("baseline_min_samples", 20)
    baseline_ready = (
        baseline_mult > 0
        and hist.baseline_rss_mb > 0
        and len(hist.samples) >= min_samples
    )

    if baseline_ready:
        # Use learned baseline — only flag if unit has genuinely doubled from normal
        threshold = hist.baseline_rss_mb * baseline_mult
        if cur >= threshold and slope > 5:
            return (
                f"RSS {cur:.0f}MB is {cur/hist.baseline_rss_mb:.1f}× above learned baseline "
                f"{hist.baseline_rss_mb:.0f}MB (slope={slope:.1f}MB/min)"
            )
    else:
        # No baseline yet (new unit) — fall back to global absolute threshold
        if cur >= cfg["rss_absolute_mb"] and (slope > 5 or sysm.available_mb < cfg["system_available_mb_floor"]):
            return (f"RSS {cur:.0f}MB exceeds {cfg['rss_absolute_mb']}MB "
                    f"with slope={slope:.1f}MB/min and {sysm.available_mb:.0f}MB free")

    if sysm.available_mb < cfg["system_available_mb_floor"] and cur >= 1024:
        return f"system low ({sysm.available_mb:.0f}MB free) and unit holds {cur:.0f}MB"

    # Swap saturation: available_mb can read healthy (reclaimable cache) while
    # swap is nearly full and the box is one spike from OOM. Triage the largest
    # holders — but ONLY when saturation coincides with real memory stalls
    # (PSI full > 0). Swap can sit high-but-stable (no thrashing) for legit
    # reasons; acting then would be an action storm. check_swap() still alerts
    # on saturation alone so the user is warned before it tips into thrashing.
    swap_floor = cfg.get("system_swap_pct_floor", 90)
    psi_min = cfg.get("system_swap_psi_full_min", 5.0)
    if sysm.swap_total_mb > 0 and cur >= 1024:
        swap_pct = 100.0 * sysm.swap_used_mb / sysm.swap_total_mb
        if swap_pct >= swap_floor and sysm.pressure_full_avg10 >= psi_min:
            return (f"swap {swap_pct:.0f}% full with memory stalls "
                    f"(PSI full={sysm.pressure_full_avg10:.0f}), unit holds {cur:.0f}MB")
    return None


def can_act_on(hist: UnitHistory, cfg: dict, now: float) -> bool:
    if now - hist.last_action_at < 3600 / cfg["max_actions_per_unit_per_hour"]:
        return False
    return True


def has_memory_cap(unit_id: str, friendly: str, kind: str) -> bool:
    """True if the OS already bounds this unit's memory (systemd MemoryMax/High or
    a docker --memory limit). Such units OOM-recycle on their own, so sysguard
    acting on them is redundant and was the source of most false-positive caps
    (chatterbox, crafty, jellyfin…). Fails safe to False (unknown → don't treat as
    capped; the confidence/grace gates still apply)."""
    try:
        if kind == "docker":
            container = friendly.split(":", 1)[1] if friendly.startswith("docker:") else friendly
            # Absolute path: the systemd user unit doesn't propagate /usr/bin in
            # PATH, so relative `docker` fails to spawn (as noted at collectHomelab).
            r = subprocess.run(
                ["/usr/bin/docker", "inspect", "-f", "{{.HostConfig.Memory}}", container],
                capture_output=True, text=True, timeout=5,
            )
            return r.returncode == 0 and r.stdout.strip().isdigit() and int(r.stdout.strip()) > 0
        scope_flag = _systemctl_scope_flag(kind)
        r = subprocess.run(
            ["systemctl", scope_flag, "show", unit_id, "-p", "MemoryMax", "-p", "MemoryHigh", "--value"],
            capture_output=True, text=True, timeout=5,
        )
        for line in r.stdout.split("\n"):
            v = line.strip()
            if v and v != "infinity" and v.isdigit() and int(v) < 10**15:
                return True
    except (subprocess.TimeoutExpired, FileNotFoundError, ValueError):
        pass
    return False


def count_signals(hist: UnitHistory, sysm: SystemSample, cfg: dict) -> tuple[int, float]:
    """Return (number of independent thresholds tripped, peak severity ratio).

    Used by the action gate to distinguish an obvious runaway (many signals, or one
    signal far over its threshold) from a lone marginal reading. MUST mirror the
    thresholds in should_flag() — kept parallel rather than merged to leave the
    battle-tested should_flag() untouched.
    """
    cur = hist.current_mb()
    slope = hist.slope_mb_per_min()
    jump = hist.jump_mb()
    ratios: list[float] = []

    g = cfg["rss_growth_mb_per_min"]
    if slope >= g and g > 0:
        ratios.append(slope / g)
    j = cfg["rss_jump_mb"]
    if jump >= j and j > 0 and len(hist.samples) >= cfg.get("rss_jump_min_samples", 5):
        ratios.append(jump / j)

    baseline_mult = cfg.get("baseline_multiplier", 2.0)
    baseline_ready = (baseline_mult > 0 and hist.baseline_rss_mb > 0
                      and len(hist.samples) >= cfg.get("baseline_min_samples", 20))
    if baseline_ready:
        threshold = hist.baseline_rss_mb * baseline_mult
        if cur >= threshold and slope > 5:
            ratios.append(cur / threshold)
    else:
        if cur >= cfg["rss_absolute_mb"] and (slope > 5 or sysm.available_mb < cfg["system_available_mb_floor"]):
            ratios.append(cur / cfg["rss_absolute_mb"])

    if sysm.available_mb < cfg["system_available_mb_floor"] and cur >= 1024:
        ratios.append(cfg["system_available_mb_floor"] / max(1.0, sysm.available_mb))

    return len(ratios), (max(ratios) if ratios else 0.0)


def gate_action(unit_id: str, friendly: str, kind: str, hist: UnitHistory,
                sysm: SystemSample, cfg: dict, has_override: bool) -> Optional[str]:
    """Decide whether a destructive restart/cap should EXECUTE. Returns None to
    proceed, or a short reason string to HOLD (alert-only). Explicit
    unit_action_overrides bypass every gate (the user asked for that action).

    The gates, in order: (1) the OS already caps this unit; (2) it's too new to
    judge and the system isn't critical (protects freshly-added programs); (3) the
    evidence is a single marginal signal (not an obvious runaway) and the system
    isn't critical.
    """
    if has_override:
        return None
    critical = sysm.available_mb < cfg["system_critical_available_mb"]

    if cfg.get("skip_os_capped_units", True) and has_memory_cap(unit_id, friendly, kind):
        return "OS already memory-limits this unit (systemd/docker owns its OOM)"

    grace = cfg.get("action_grace_samples", 20)
    if len(hist.samples) < grace and not critical:
        return f"unit too new ({len(hist.samples)}/{grace} samples) — grace period, system not critical"

    nsig, peak = count_signals(hist, sysm, cfg)
    strong = peak >= cfg.get("strong_signal_ratio", 2.0)
    if not (critical or strong or nsig >= cfg.get("min_signals_to_act", 2)):
        return f"low confidence ({nsig} signal(s), peak {peak:.1f}×) — alert only"
    return None


def cycle(cfg: dict, units: dict[str, UnitHistory],
          hist_db: Optional[HistoryDB] = None):
    now = time.time()
    sysm = sample_system()
    logging.info(
        "system: avail=%.0fMB swap=%.0f/%.0fMB psi_some=%.1f psi_full=%.1f",
        sysm.available_mb, sysm.swap_used_mb, sysm.swap_total_mb,
        sysm.pressure_some_avg10, sysm.pressure_full_avg10,
    )
    logging.info("disk: root=%.0fGB free, pool=%.0fGB free",
                 sysm.disk_root_free_mb / 1024, sysm.disk_pool_free_mb / 1024)
    check_disk(sysm, cfg, now)
    check_swap(sysm, cfg, now)
    check_oom_forecast(sysm, cfg, now)
    # Merge the AI's self-tuned floors on top of the config.yaml floors (config
    # wins ties only if larger — a human floor is never lowered by auto-tuning).
    auto_floors = ai_diagnose.load_auto_floors()
    if auto_floors:
        merged = dict(cfg.get("unit_rss_floor_mb") or {})
        for unit, mb in auto_floors.items():
            merged[unit] = max(merged.get(unit, 0), mb)
        cfg["unit_rss_floor_mb"] = merged
    run_verifications(units, cfg, now)
    # Execute any proposals the phone approved (via sysguard's own action machinery
    # — never arbitrary shell). Cheap no-op when none are approved. Runs when either
    # the AI escalation OR deterministic disk-reclaim proposals can be produced.
    if cfg.get("ai_diagnose_enabled", False) or cfg.get("disk_reclaim_enabled", True):
        ai_diagnose.execute_approved(cfg, execute_action, lift_cap, notify_ntfy)

    extra_units = cfg.get("extra_skip_units") or []
    extra_procs = cfg.get("extra_skip_processes") or []

    discovered = list_systemd_units()
    seen = set()
    cycle_rows: list[tuple[int, str, float]] = []
    for unit_id, friendly, kind in discovered:
        # is_skipped checks both unit_id and friendly so docker:<name> matches
        # user skip-list entries like "jellyfin"
        if is_skipped(unit_id, extra_units, extra_procs) or \
           is_skipped(friendly, extra_units, extra_procs):
            continue
        mem = get_unit_memory_mb(unit_id, kind)
        if mem is None or mem < 50:  # don't track <50MB units
            continue
        seen.add(friendly)
        hist = units.get(friendly) or UnitHistory(name=friendly)
        hist.add(mem, now)
        units[friendly] = hist
        cycle_rows.append((int(now), friendly, mem))

        reason = should_flag(hist, sysm, cfg)
        if not reason:
            continue

        logging.warning("flagging %s (%s): %s", friendly, kind, reason)
        if not can_act_on(hist, cfg, now):
            logging.info("  rate-limited, skipping triage for %s", friendly)
            continue

        model = pick_model(cfg, sysm)
        extra_ctx = gather_extra_context(friendly, kind)
        jtail = journal_tail(unit_id, friendly, kind)
        prompt = build_prompt(friendly, kind, hist, sysm, jtail, extra_ctx)
        result = call_ollama(cfg["ollama_url"], model, prompt, cfg["ollama_timeout_seconds"],
                             cfg.get("ollama_num_threads", 4))
        if not result:
            continue
        action = result.get("action", "ignore")
        ai_reason = result.get("reason", "")
        root_cause = result.get("root_cause", "")

        if action == "investigate":
            esc_min = cfg.get("escalation_min_available_mb", 8192)
            if sysm.available_mb >= esc_min:
                esc = call_ollama(cfg["ollama_url"], cfg["escalation_model"],
                                  prompt, cfg["ollama_timeout_seconds"],
                                  cfg.get("ollama_num_threads", 4))
                if esc:
                    action = esc.get("action", "investigate")
                    ai_reason = f"[escalated to {cfg['escalation_model']}] {esc.get('reason', '')}"
                    root_cause = esc.get("root_cause", root_cause)
            else:
                logging.info(
                    "  skipping escalation for %s: only %.0fMB free (need %dMB)",
                    friendly, sysm.available_mb, esc_min,
                )
                # Don't set ignore yet — let the override check below apply first.
                # A unit with a known fix should act even when escalation is skipped.
                action = "investigate"
                ai_reason = f"[escalation skipped: low mem] {ai_reason}"

        # Per-unit override: for units with a known-correct fix, force it over the
        # model's pick. Also fires when escalation was skipped (investigate) so that
        # units with a forced override don't stall indefinitely waiting for a larger model.
        overridden_from = None
        if action in ("restart", "cap", "investigate"):
            # Most-specific (longest) matching override key wins — order-independent.
            best_key = ""
            best_forced = None
            for key, forced in (cfg.get("unit_action_overrides") or {}).items():
                if key.lower() in friendly.lower() and len(key) > len(best_key):
                    best_key, best_forced = key, forced
            if best_forced and best_forced != action:
                overridden_from = action
                action = best_forced
                ai_reason = f"[override {overridden_from}->{best_forced}] {ai_reason}"
        # Explicitly-listed units bypass the safety gate below — the user asked for
        # that action (e.g. orionfs: restart), even if it's a young or capped unit.
        has_override = any(k.lower() in friendly.lower()
                           for k in (cfg.get("unit_action_overrides") or {}))

        decision = {
            "ts": now, "unit_id": unit_id, "friendly": friendly, "kind": kind,
            "trigger": reason, "model": model, "action": action,
            "overridden_from": overridden_from,
            "ai_reason": ai_reason, "root_cause": root_cause,
            "rss_mb": hist.current_mb(),
            "slope_mb_per_min": hist.slope_mb_per_min(),
            "baseline_mb": hist.baseline_rss_mb,
            "dry_run": cfg["dry_run"],
        }

        # Safety gate: a flagged unit is triaged + logged, but a destructive
        # restart/cap only EXECUTES when it clears the gate (OS-uncapped, past its
        # grace period, and backed by strong/multi-signal evidence — or the system
        # is genuinely critical). Held actions are logged (visible on the dashboard)
        # but do NOT execute or notify — this is what stops sysguard from becoming
        # the thing that disrupts services on every marginal flag.
        held = gate_action(unit_id, friendly, kind, hist, sysm, cfg, has_override) \
            if action in ("restart", "cap") else None
        if held:
            decision["held"] = True
            decision["hold_reason"] = held
            decision["execution_ok"] = False
            decision["execution_msg"] = f"HELD: {held}"
            hist.last_action_at = now  # respect the 1/hr re-eval cadence; don't re-triage every 30s
            logging.warning("  -> HELD %s on %s: %s", action, friendly, held)
            log_decision(decision)
            continue

        if action in ("restart", "cap"):
            ok, msg = execute_action(unit_id, friendly, kind, action, cfg, hist)
            decision["execution_ok"] = ok
            decision["execution_msg"] = msg
            # Stamp always — on success AND failure — so a hung service that times
            # out on restart doesn't get retried every 30s until it responds.
            hist.last_action_at = now
            if ok and not cfg["dry_run"]:
                hist.pending_verify = {
                    "unit_id": unit_id, "kind": kind, "action": action,
                    "taken_at": now, "pre_rss_mb": hist.current_mb(),
                    "cap_mb": _planned_cap_mb(hist, cfg) if action == "cap" else 0,
                    "check_after": now + (90 if action == "restart" else 180),
                }
            logging.warning("  -> %s: %s", action, msg)
            if cfg["kde_notify"]:
                if cfg["dry_run"] and not cfg["notify_on_dry_run"]:
                    pass
                else:
                    notify_kde(
                        f"sysguard: {friendly}",
                        f"{action} ({'dry-run' if cfg['dry_run'] else 'live'}): {ai_reason}",
                    )
            if not cfg["dry_run"]:
                notify_ntfy(cfg, f"sysguard: {friendly}",
                            f"{action}: {ai_reason}", priority=3)
        else:
            logging.info("  -> %s: %s", action, ai_reason)
            # Terminal "investigate": the local models (phi4→glm4) are stumped and
            # there's no known fix. Escalate to headless Claude for a real
            # root-cause diagnosis (no-tools reasoning over the evidence we already
            # have). Fire-and-forget; ai_diagnose enforces its own enable switch,
            # memory floor, per-unit cooldown, and daily cap.
            if action == "investigate":
                evidence = (
                    f"Unit: {friendly} ({kind})\n"
                    f"RSS now {hist.current_mb():.0f}MB, baseline {hist.baseline_rss_mb:.0f}MB, "
                    f"slope {hist.slope_mb_per_min():.1f}MB/min, last jump {hist.jump_mb():+.0f}MB, "
                    f"{len(hist.samples)} samples\n"
                    f"System: available {sysm.available_mb:.0f}MB, "
                    f"swap {sysm.swap_used_mb:.0f}/{sysm.swap_total_mb:.0f}MB, "
                    f"PSI mem some_avg10={sysm.pressure_some_avg10:.1f} full_avg10={sysm.pressure_full_avg10:.1f}\n"
                    f"Local model said: {ai_reason}\n"
                    f"Live docker stats: {extra_ctx or '(n/a)'}\n"
                    f"Recent journal:\n{jtail or '(none)'}"
                )
                ai_diagnose.escalate(unit_id, friendly, kind, evidence,
                                     sysm.available_mb, cfg, notify_ntfy)

        log_decision(decision)

    # Persist this cycle's samples to the durable time-series. Passive — never in
    # the decision path; HistoryDB.record swallows its own errors so a write
    # failure can't interrupt monitoring.
    if hist_db is not None:
        hist_db.record(int(now), sysm, cycle_rows)

    # GC units we haven't seen in a while
    stale = [n for n, h in units.items() if n not in seen and
             (not h.samples or now - h.samples[-1].timestamp > 3600)]
    for n in stale:
        del units[n]


def refresh_baselines(units: dict, hist_db: Optional[HistoryDB], cfg: dict) -> None:
    """Update each unit's baseline to its median RSS over the rolling window.

    No-op in startup_min mode or without a history DB (units keep the frozen
    min-of-first-10 baseline from UnitHistory.add). This is what makes detection
    ADAPT: the baseline tracks each unit's real steady-state instead of the value
    it happened to have at startup.
    """
    if hist_db is None or cfg.get("baseline_mode", "median") != "median":
        return
    window = cfg.get("baseline_window_hours", 72)
    min_samples = cfg.get("baseline_min_samples", 20)
    medians = hist_db.unit_medians(window, min_samples)
    updated = 0
    for name, h in units.items():
        m = medians.get(name)
        if m and m > 0 and abs(m - h.baseline_rss_mb) >= 1.0:
            h.baseline_rss_mb = m
            updated += 1
    if updated:
        logging.info("baseline: refreshed %d unit medians over %dh window", updated, window)


def main():
    cfg = load_config()
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    setup_logging(cfg.get("log_level", "INFO"))

    logging.info("sysguard starting (dry_run=%s, interval=%ds)",
                 cfg["dry_run"], cfg["sample_interval_seconds"])
    logging.info("primary=%s escalation=%s fallback=%s",
                 cfg["primary_model"], cfg["escalation_model"], cfg["fallback_model"])

    # Pre-warm the primary model so the first real flag doesn't hit cold-start
    # (cold load can be 30-45s; subsequent calls are sub-second).
    logging.info("pre-warming %s ...", cfg["primary_model"])
    warm = call_ollama(cfg["ollama_url"], cfg["primary_model"],
                       '{"action":"ignore","reason":"warmup"}',
                       cfg["ollama_timeout_seconds"],
                       cfg.get("ollama_num_threads", 4))
    logging.info("pre-warm result: %s", "ok" if warm else "FAILED — first triage may time out")

    units = load_state()
    logging.info("loaded %d unit histories from state", len(units))

    hist_db: Optional[HistoryDB] = None
    if cfg.get("history_db_enabled", True):
        try:
            hist_db = HistoryDB(HISTORY_DB)
            logging.info("history: recording to %s (retention %dd)",
                         HISTORY_DB, cfg.get("history_retention_days", 30))
        except sqlite3.Error as e:
            logging.warning("history: disabled, could not open db: %s", e)
            hist_db = None

    # Seed adaptive baselines from history immediately so a restart doesn't fall
    # back to startup-min values for units that already have a known steady-state.
    refresh_baselines(units, hist_db, cfg)

    stop = False

    def _stop(*_):
        nonlocal stop
        stop = True
        logging.info("shutdown signal received")

    signal.signal(signal.SIGTERM, _stop)
    signal.signal(signal.SIGINT, _stop)

    interval = cfg["sample_interval_seconds"]
    last_save = 0.0
    last_prune = 0.0
    last_baseline = time.time()  # initial seed already done above
    prune_every = cfg.get("history_prune_interval_seconds", 3600)
    baseline_every = cfg.get("baseline_refresh_interval_seconds", 3600)
    retention_days = cfg.get("history_retention_days", 30)
    while not stop:
        try:
            cycle(cfg, units, hist_db)
        except Exception as e:
            logging.exception("cycle error: %s", e)
        now = time.time()
        if now - last_save > 60:
            save_state(units)
            last_save = now
        if hist_db is not None and now - last_prune > prune_every:
            hist_db.prune(retention_days)
            last_prune = now
        if hist_db is not None and now - last_baseline > baseline_every:
            refresh_baselines(units, hist_db, cfg)
            last_baseline = now
        # sleep but wake on signal
        for _ in range(interval):
            if stop:
                break
            time.sleep(1)

    save_state(units)
    if hist_db is not None:
        hist_db.close()
    logging.info("sysguard stopped cleanly")


if __name__ == "__main__":
    main()
