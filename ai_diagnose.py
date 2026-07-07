"""AI root-cause escalation for sysguard.

When the local triage models (phi4/glm4) are stumped — the terminal "investigate"
verdict — sysguard escalates to headless Claude Code for a real root-cause
diagnosis. Claude reasons over evidence sysguard ALREADY gathered (RSS trend,
system memory/swap/PSI, container cgroup limits, journal tail); it is given NO
tools, so it can never touch the system — it only produces a structured
diagnosis + recommended fix, which is logged and pushed to the phone.

Design constraints (validated 2026-07-04):
  * No-tools reasoning mode: safe (read-only), cheap (~$0.27), fast (~30s), and
    can't hang on a streaming command (the failure mode a tool-enabled agent hit).
  * Hard guards: disabled by default off-switch, a system-memory floor (never
    spawn a ~400MB Claude process when the box is already tight), a per-unit
    cooldown, and a global daily cap — this is expensive and must stay rare.
  * Fully detached: runs in a worker thread; never blocks the monitor loop.
  * Diagnosis only. Execution stays with the human (the fix command is in the
    push). A gated one-tap-execute path is a separate, later step.
"""
from __future__ import annotations

import json
import logging
import re
import subprocess
import threading
import time
from datetime import date
from pathlib import Path

STATE_DIR = Path.home() / ".local/share/sysguard"
PROPOSALS_LOG = STATE_DIR / "ai_proposals.jsonl"     # immutable audit trail
PROPOSALS_STORE = STATE_DIR / "ai_proposals.json"    # mutable {id: proposal} for approve/execute
DECISIONS_LOG = STATE_DIR / "decisions.jsonl"        # the feed the web/phone UI renders
AI_STATE_FILE = STATE_DIR / "ai_diagnose_state.json"
# Machine-managed tuning overrides sysguard merges on top of config.yaml, so the
# AI's self-corrections never touch (or strip comments from) the hand-tuned config.
AUTO_TUNING_FILE = STATE_DIR / "auto_tuning.json"

_DEFAULT_CLAUDE_BIN = str(Path.home() / ".nvm/versions/node/v24.15.0/bin/claude")

# Service-touching actions — human-gated: a one-tap phone approval executes them
# via sysguard's existing guarded machinery (never arbitrary shell).
APPROVE_ACTIONS = {"restart_unit", "lift_cap", "reclaim_disk"}

# Disk reclaim maps a plan KEY to a HARDCODED, safe docker command. A proposal may
# only reference these keys — execution never runs an arbitrary string. Deliberately
# EXCLUDES `volume prune`: external volumes (Romm/Nextcloud) look unused when their
# container is stopped, and pruning them destroys data. build cache is regenerable;
# `image prune` here is dangling-only (-f, not -a) so it can't remove a tagged
# rollback image.
_RECLAIM_OPS = {
    "build_cache":     ["builder", "prune", "-af"],
    "dangling_images": ["image", "prune", "-f"],
}
_DOCKER_BIN = "/usr/bin/docker"
# Self-tuning actions — safe to AUTO-apply: they only make sysguard LESS
# trigger-happy on a confirmed false positive (raise a unit's floor). Bounded so a
# real leak toward the unit's cap still trips. Can't harm the box.
AUTO_ACTIONS = {"raise_floor"}

_lock = threading.Lock()
_store_lock = threading.Lock()
_tuning_lock = threading.Lock()


def load_auto_floors() -> dict:
    """Per-unit RSS floors the AI has auto-applied. sysguard merges these over the
    config.yaml floors each cycle. Read-only for sysguard; written only here."""
    try:
        return json.loads(AUTO_TUNING_FILE.read_text()).get("unit_rss_floor_mb", {})
    except (OSError, ValueError):
        return {}


def _apply_floor(friendly: str, floor_mb: int, cfg: dict) -> tuple[bool, str]:
    """Raise a unit's RSS floor so a confirmed false positive stops flagging.
    BOUNDED: never above `ai_autotune_max_floor_frac` of the unit's cgroup cap (so a
    genuine leak toward the cap still trips), never below the current floor, and
    capped by ai_autotune_max_floor_mb for non-capped units."""
    hard_max = int(cfg.get("ai_autotune_max_floor_mb", 8192))
    if friendly.startswith("docker:"):
        cap_mb = _container_cap_mb(friendly)
        if cap_mb > 0:
            hard_max = min(hard_max, int(cap_mb * cfg.get("ai_autotune_max_floor_frac", 0.8)))
    current = load_auto_floors().get(friendly, 0)
    # Clamp to the hard ceiling, then only apply if it strictly RAISES the floor —
    # a request at/below the current auto-floor (or above the cap) is a no-op.
    new_floor = min(int(floor_mb), hard_max)
    if new_floor <= current:
        return False, f"requested {floor_mb}MB not above current floor {current}MB (ceiling {hard_max}MB)"
    with _tuning_lock:
        try:
            data = json.loads(AUTO_TUNING_FILE.read_text()) if AUTO_TUNING_FILE.exists() else {}
        except (OSError, ValueError):
            data = {}
        data.setdefault("unit_rss_floor_mb", {})[friendly] = new_floor
        try:
            tmp = AUTO_TUNING_FILE.with_suffix(".json.tmp")
            tmp.write_text(json.dumps(data))
            tmp.replace(AUTO_TUNING_FILE)
        except OSError as e:
            return False, f"write failed: {e}"
    return True, f"floor set to {new_floor}MB (capped at {hard_max}MB)"


def _container_cap_mb(friendly: str) -> float:
    container = friendly.split(":", 1)[1]
    try:
        r = subprocess.run(
            ["/usr/bin/docker", "inspect", "-f", "{{.HostConfig.Memory}}", container],
            capture_output=True, text=True, timeout=10,
        )
        v = r.stdout.strip()
        return int(v) / 1024 / 1024 if v.isdigit() and int(v) > 0 else 0.0
    except (subprocess.TimeoutExpired, FileNotFoundError, ValueError):
        return 0.0


def _load_store() -> dict:
    try:
        return json.loads(PROPOSALS_STORE.read_text())
    except (OSError, ValueError):
        return {}


def _save_store(store: dict) -> None:
    try:
        tmp = PROPOSALS_STORE.with_suffix(".json.tmp")
        tmp.write_text(json.dumps(store))
        tmp.replace(PROPOSALS_STORE)
    except OSError as e:
        logging.warning("ai_diagnose: store save failed: %s", e)


def list_pending() -> list[dict]:
    """Proposals awaiting a phone decision (for the dashboard/phone), newest first."""
    store = _load_store()
    out = [p for p in store.values() if p.get("status") == "pending"]
    out.sort(key=lambda p: p.get("ts", 0), reverse=True)
    return out


def set_status(proposal_id: str, status: str) -> bool:
    """Flip a proposal's status (approve/reject from the phone). Returns True if found."""
    with _store_lock:
        store = _load_store()
        p = store.get(proposal_id)
        if not p:
            return False
        p["status"] = status
        _save_store(store)
        return True


def _load_state() -> dict:
    try:
        return json.loads(AI_STATE_FILE.read_text())
    except (OSError, ValueError):
        return {}


def _save_state(state: dict) -> None:
    try:
        AI_STATE_FILE.write_text(json.dumps(state))
    except OSError as e:
        logging.warning("ai_diagnose: state save failed: %s", e)


# A cheap phone page must NEVER be gated by the expensive AI diagnosis. When the
# LLM path is suppressed (cooldown/cap/low-mem floor) but the box is genuinely in
# trouble, sysguard still pages — on its own short cooldown so a sustained fire
# keeps pinging instead of going dark for the full AI cooldown. This is the exact
# gap that let a Nextcloud storm run silently for hours (2026-07-07): the 6h
# per-unit AI cooldown suppressed the page, and when avail fell below the floor
# escalate() returned without notifying at all.
_FALLBACK_PAGE_COOLDOWN = 900  # 15 min between fallback pages for the same unit


def _fallback_page(friendly: str, evidence: str, available_mb: float, why: str,
                   cfg: dict, notify_fn, now: float) -> None:
    """Send a lightweight page (no AI diagnosis) when escalation was suppressed but
    the box is in real trouble. Own 15-min per-unit cooldown, separate from the AI
    cooldown, so a worsening incident is never silenced by diagnosis rate limits."""
    with _lock:
        state = _load_state()
        last = (state.get("last_page_by_unit") or {}).get(friendly, 0)
        if now - last < _FALLBACK_PAGE_COOLDOWN:
            return
        state.setdefault("last_page_by_unit", {})[friendly] = now
        _save_state(state)
    headline = evidence.strip().split("\n", 1)[0][:160]
    body = (f"{headline}\n(AI diagnosis {why}; paging anyway — box in trouble, "
            f"avail {available_mb:.0f}MB)")
    try:
        notify_fn(cfg, f"sysguard: {friendly} — needs eyes", body, 5)
    except Exception as e:  # noqa: BLE001 — a page must never crash the monitor
        logging.warning("ai_diagnose: fallback page failed: %s", e)


def _rate_ok(friendly: str, cfg: dict, now: float) -> tuple[bool, str]:
    """Enforce per-unit cooldown + global daily cap. Returns (ok, reason_if_not)."""
    cooldown_h = cfg.get("ai_per_unit_cooldown_hours", 6)
    max_per_day = cfg.get("ai_max_per_day", 8)
    today = date.today().isoformat()
    with _lock:
        state = _load_state()
        if state.get("day") != today:
            state["day"] = today
            state["count"] = 0
            state["last_by_unit"] = {}
        if state.get("count", 0) >= max_per_day:
            return False, f"daily cap reached ({max_per_day})"
        last = (state.get("last_by_unit") or {}).get(friendly, 0)
        if now - last < cooldown_h * 3600:
            return False, f"per-unit cooldown ({cooldown_h}h)"
        # Reserve the slot now so concurrent escalations can't overrun the caps.
        state["count"] = state.get("count", 0) + 1
        state.setdefault("last_by_unit", {})[friendly] = now
        _save_state(state)
        return True, ""


def _enrich_docker(friendly: str, claude_bin_dir: str) -> str:
    """Read the container's enforced cgroup memory/swap limits — the signal that
    exposed the chatterbox swap leak (compose declared a cap the live cgroup
    didn't honour). Read-only; best-effort."""
    if not friendly.startswith("docker:"):
        return ""
    container = friendly.split(":", 1)[1]
    try:
        cid = subprocess.run(
            ["/usr/bin/docker", "inspect", "-f", "{{.Id}}", container],
            capture_output=True, text=True, timeout=10,
        ).stdout.strip()
        if not cid:
            return ""
        cg = Path(f"/sys/fs/cgroup/system.slice/docker-{cid}.scope")
        vals = {}
        for f in ("memory.max", "memory.swap.max", "memory.swap.current", "memory.current"):
            try:
                vals[f] = (cg / f).read_text().strip()
            except OSError:
                vals[f] = "?"
        return ("Container cgroup (enforced): "
                + " ".join(f"{k}={v}" for k, v in vals.items()))
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return ""


def _build_prompt(evidence: str) -> str:
    return (
        "You are a Linux memory-health diagnostician for a Fedora 44 homelab "
        "(32GB RAM). sysguard flagged the unit below and its local triage models "
        "could not determine a fix. Reason over ONLY the read-only evidence "
        "provided — do NOT run commands. Identify the ROOT CAUSE (distinguish a "
        "real application leak from host-level/config causes), then give a "
        "specific, safe recommended fix. Output ONLY a JSON object with keys: "
        "root_cause, confidence (high|medium|low), recommended_fix (specific "
        "command or action), risk (what could go wrong), urgency (low|medium|high), "
        "and structured_action — ONE of: \"restart_unit\" (restart this exact unit "
        "cleanly reclaims the memory), \"lift_cap\" (a prior memory cap is "
        "starving it), \"raise_floor\" (this is a FALSE POSITIVE — the unit's "
        "learned baseline/threshold is too low for its legitimate working set, so "
        "sysguard should stop flagging it; also set floor_mb to a value above the "
        "unit's normal peak but well below its cgroup cap), or \"none\" (needs a "
        "human). Prefer raise_floor when you conclude it's a false positive and no "
        "real remediation is needed; restart_unit/lift_cap only when they genuinely "
        "and safely fix a real problem on THIS unit; otherwise \"none\". Include "
        "floor_mb (integer MB) only for raise_floor."
        "\n\nEVIDENCE:\n" + evidence
    )


def _build_swap_prompt(evidence: str) -> str:
    return (
        "You are a Linux memory/swap diagnostician for a Fedora 44 homelab (32GB RAM, "
        "24GB swap). sysguard detected SWAP SATURATION / imminent OOM. The unit below "
        "is the largest RESTARTABLE swap consumer; the evidence lists all top swap "
        "consumers. Reason over ONLY the read-only evidence — do NOT run commands. "
        "Decide whether restarting THIS unit is the right, safe way to relieve the "
        "pressure (restarting frees the swap it holds and it reloads cleanly), or "
        "whether a human/different action is needed. Output ONLY a JSON object with "
        "keys: root_cause, confidence (high|medium|low), recommended_fix (specific, "
        "e.g. 'restart ollama to reclaim ~1.8GB of idle model swap'), risk (what "
        "restarting interrupts), urgency (low|medium|high), and structured_action — "
        "\"restart_unit\" (restarting THIS unit safely relieves swap) or \"none\" "
        "(unsafe to auto-restart, or a different consumer/human action is needed — "
        "state it in recommended_fix). Choose restart_unit only when this unit is "
        "genuinely holding reclaimable swap and restarts without data loss."
        "\n\nEVIDENCE:\n" + evidence
    )


def _parse_result(raw: str) -> dict | None:
    """Extract the JSON diagnosis from Claude's result text (may be fenced)."""
    s = raw.strip()
    if s.startswith("```"):
        s = s.split("```", 2)[1]
        if s.startswith("json"):
            s = s[4:]
        s = s.strip()
    try:
        obj = json.loads(s)
        return obj if isinstance(obj, dict) else None
    except ValueError:
        # Fall back to the first {...} block.
        i, j = s.find("{"), s.rfind("}")
        if 0 <= i < j:
            try:
                obj = json.loads(s[i:j + 1])
                return obj if isinstance(obj, dict) else None
            except ValueError:
                return None
        return None


def _run_claude(prompt: str, cfg: dict) -> tuple[dict | None, float]:
    """Invoke headless Claude in no-tools reasoning mode. Returns (diagnosis, cost)."""
    claude_bin = cfg.get("claude_bin", _DEFAULT_CLAUDE_BIN)
    timeout = cfg.get("ai_timeout_seconds", 150)
    model = cfg.get("ai_model", "opus")  # Max subscription — use the strongest brain
    try:
        r = subprocess.run(
            [claude_bin, "-p", prompt, "--model", model, "--output-format", "json"],
            capture_output=True, text=True, timeout=timeout,
            stdin=subprocess.DEVNULL,  # else the CLI waits 3s for piped stdin
        )
    except subprocess.TimeoutExpired:
        logging.warning("ai_diagnose: claude timed out after %ss", timeout)
        return None, 0.0
    except FileNotFoundError:
        logging.warning("ai_diagnose: claude binary not found at %s", claude_bin)
        return None, 0.0
    if r.returncode != 0:
        logging.warning("ai_diagnose: claude exit %s: %s", r.returncode, r.stderr[:200])
        return None, 0.0
    try:
        outer = json.loads(r.stdout)
    except ValueError:
        return None, 0.0
    return _parse_result(outer.get("result", "")), float(outer.get("total_cost_usd", 0.0) or 0.0)


def _worker(unit_id: str, friendly: str, kind: str, evidence: str, cfg: dict, notify_fn,
            context: str = "memory") -> None:
    now = time.time()
    evidence_full = evidence
    extra = _enrich_docker(friendly, cfg.get("claude_bin", _DEFAULT_CLAUDE_BIN))
    if extra:
        evidence_full += "\n" + extra
    prompt = _build_swap_prompt(evidence_full) if context == "swap" else _build_prompt(evidence_full)
    diag, cost = _run_claude(prompt, cfg)
    proposal_id = f"{int(now)}-{friendly[:24]}"
    action = str((diag or {}).get("structured_action", "none")).strip().lower()
    if action not in (APPROVE_ACTIONS | AUTO_ACTIONS):
        action = "none"

    # Self-tuning: a confirmed false positive auto-corrects (raise this unit's
    # floor, bounded) with NO human approval — it can only make sysguard quieter
    # on this unit, never touches a running service. Everything service-touching
    # still waits for a phone tap.
    autotune_msg = None
    status = "advisory"
    if action == "raise_floor":
        if cfg.get("ai_autotune_enabled", True):
            floor_mb = int((diag or {}).get("floor_mb", 0) or 0)
            if floor_mb > 0:
                ok, autotune_msg = _apply_floor(friendly, floor_mb, cfg)
                status = "auto_tuned" if ok else "advisory"
            else:
                autotune_msg = "raise_floor without a floor_mb — left advisory"
        else:
            status = "advisory"  # autotune off → treat as advisory
    elif action in APPROVE_ACTIONS:
        status = "pending"

    record = {
        "id": proposal_id, "ts": now, "unit_id": unit_id, "friendly": friendly, "kind": kind,
        "cost_usd": round(cost, 4), "diagnosis": diag, "structured_action": action,
        "status": status, "autotune_result": autotune_msg,
    }
    # Immutable audit trail + the mutable store the phone/daemon act on.
    try:
        with open(PROPOSALS_LOG, "a") as f:
            f.write(json.dumps(record) + "\n")
    except OSError as e:
        logging.warning("ai_diagnose: audit log write failed: %s", e)
    with _store_lock:
        store = _load_store()
        store[proposal_id] = record
        # Keep the store bounded — drop the oldest resolved entries past 50.
        if len(store) > 50:
            resolved = sorted((p for p in store.values()
                               if p.get("status") in ("executed", "rejected", "failed", "advisory")),
                              key=lambda p: p.get("ts", 0))
            for p in resolved[:len(store) - 50]:
                store.pop(p["id"], None)
        _save_store(store)

    if not diag:
        # The LLM was reached but produced nothing usable — usually a timeout
        # because the box is too saturated to answer (the 2026-07-07 incident).
        # That's the worst moment to stay silent: page with the raw evidence we
        # already have, so a stuck diagnosis never means the human hears nothing.
        logging.warning("ai_diagnose: no usable diagnosis for %s (cost $%.3f)", friendly, cost)
        headline = evidence.strip().split("\n", 1)[0][:160]
        try:
            notify_fn(cfg, f"sysguard: {friendly} — needs eyes",
                      f"{headline}\n(AI diagnosis failed/timed out — paging with raw signal)", 5)
        except Exception as e:  # noqa: BLE001 — a page must never crash the worker
            logging.warning("ai_diagnose: fallback notify failed: %s", e)
        return
    root = str(diag.get("root_cause", ""))[:280]
    fix = str(diag.get("recommended_fix", ""))[:280]
    urgency = str(diag.get("urgency", "medium")).lower()
    if status == "auto_tuned":
        suffix = f"\n\n✓ Auto-tuned: {autotune_msg}"
    elif status == "pending":
        suffix = " [approve on phone to apply]"
    else:
        suffix = ""
    logging.warning("ai_diagnose[%s]: %s | fix: %s [%s]%s (cost $%.3f)",
                    friendly, root, fix, status, autotune_msg or "", cost)
    priority = {"high": 5, "medium": 4, "low": 3}.get(urgency, 4)
    try:
        notify_fn(cfg, f"sysguard AI: {friendly}", f"{root}\n\nFix: {fix}{suffix}", priority)
    except Exception as e:  # notify must never break the worker
        logging.warning("ai_diagnose: notify failed: %s", e)


def _parse_size_mb(s: str) -> float:
    """Parse a docker size string like '44.87GB' / '512.3MB' / '0B' into MB."""
    s = (s or "").strip()
    m = re.match(r"([\d.]+)\s*([KMGT]?)i?B", s, re.IGNORECASE)
    if not m:
        return 0.0
    val = float(m.group(1))
    mult = {"": 1 / 1024 / 1024, "K": 1 / 1024, "M": 1, "G": 1024, "T": 1024 * 1024}
    return val * mult[m.group(2).upper()]


def _docker_reclaimable_mb(cfg: dict) -> float:
    """CONSERVATIVE MB the safe plan will free, from `docker system df`. Counts only
    build-cache reclaimable — the reliable floor. Dangling-image cleanup in the plan
    frees more on top, so this under-promises (we report the real total after). NOT
    total unused images, which are mostly tagged rollback images the plan won't touch.
    Read-only; 0.0 if docker is unreachable."""
    try:
        r = subprocess.run([_DOCKER_BIN, "system", "df", "--format", "{{.Type}}\t{{.Reclaimable}}"],
                           capture_output=True, text=True, timeout=15, stdin=subprocess.DEVNULL)
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        return 0.0
    total = 0.0
    for line in r.stdout.splitlines():
        parts = line.split("\t")
        if len(parts) != 2:
            continue
        typ, recl = parts[0].strip().lower(), parts[1].split("(")[0].strip()
        if typ == "build cache":
            total += _parse_size_mb(recl)
    return total


def _log_disk_decision(p: dict, action: str, trigger: str, cfg: dict) -> None:
    """Append a disk event to the decisions feed so it shows in the web/phone UI —
    disk activity used to be push-only and never appeared there. Best-effort."""
    try:
        with open(DECISIONS_LOG, "a") as f:
            f.write(json.dumps({
                "ts": time.time(), "unit_id": p.get("unit_id", "disk"),
                "friendly": p.get("friendly", "disk"), "kind": "disk",
                "trigger": str(trigger)[:120], "action": action,
                "root_cause": (p.get("diagnosis") or {}).get("root_cause", ""),
                "dry_run": cfg.get("dry_run", False),
            }) + "\n")
    except OSError as e:
        logging.warning("ai_diagnose: disk decision log failed: %s", e)


def propose_disk_reclaim(mount: str, free_mb: float, cfg: dict, notify_fn) -> bool:
    """Instead of nagging that a disk is low, create a ONE-TAP reclaim proposal
    (safe docker prunes) that the phone can approve. Returns True if a proposal was
    created or one is already pending for this mount (so the caller suppresses the
    bare alert). Deterministic — no LLM cost."""
    if not cfg.get("disk_reclaim_enabled", True):
        return False
    # Don't stack proposals: if one is already pending for this mount, leave it.
    for p in list_pending():
        if p.get("structured_action") == "reclaim_disk" and p.get("unit_id") == f"disk:{mount}":
            return True
    reclaim_mb = _docker_reclaimable_mb(cfg)
    if reclaim_mb < cfg.get("disk_reclaim_min_mb", 2048):
        return False   # nothing worth proposing — let the plain alert fire
    now = time.time()
    est_gb = reclaim_mb / 1024
    pid = f"{int(now)}-disk-{mount}"
    root = f"{mount} low ({free_mb / 1024:.1f} GB free); >={est_gb:.0f} GB safely reclaimable from Docker."
    fix = f"Prune Docker build cache (~{est_gb:.0f} GB) + dangling images. Safe/regenerable; leaves volumes untouched."
    record = {
        "id": pid, "ts": now, "unit_id": f"disk:{mount}", "friendly": f"{mount} disk",
        "kind": "disk", "cost_usd": 0.0,
        "diagnosis": {"root_cause": root, "recommended_fix": fix, "urgency": "medium"},
        "structured_action": "reclaim_disk", "status": "pending",
        "reclaim_plan": ["build_cache", "dangling_images"], "est_reclaim_mb": round(reclaim_mb),
        "mount": mount, "free_mb": round(free_mb),
    }
    try:
        with open(PROPOSALS_LOG, "a") as f:
            f.write(json.dumps(record) + "\n")
    except OSError as e:
        logging.warning("ai_diagnose: disk audit write failed: %s", e)
    with _store_lock:
        store = _load_store()
        store[pid] = record
        _save_store(store)
    _log_disk_decision(record, "propose_reclaim", f"{free_mb / 1024:.1f}GB free", cfg)
    logging.warning("ai_diagnose[disk]: %s | fix: %s [pending — approve on phone]", root, fix)
    try:
        notify_fn(cfg, f"sysguard: {mount} disk low",
                  f"{root}\n\nProposed: {fix}\n[approve on phone to free space]", 3)
    except Exception as e:
        logging.warning("ai_diagnose: disk notify failed: %s", e)
    return True


def _run_disk_reclaim(p: dict, cfg: dict) -> tuple[int, int, str]:
    """Execute an APPROVED reclaim via the fixed safe op map. Returns
    (freed_ops, failed_ops, msg). Never runs an arbitrary command. The timeout is
    generous because `docker builder prune` on a large cache is slow — and it runs
    server-side, so a short client timeout reports a FALSE failure while the daemon
    finishes anyway (the bug that made a working prune look 'timed out')."""
    timeout = int(cfg.get("disk_reclaim_timeout_sec", 1200))
    msgs, freed, failed = [], 0, 0
    for op in (p.get("reclaim_plan") or []):
        args = _RECLAIM_OPS.get(op)
        if not args:
            msgs.append(f"{op}: skipped (unknown)")
            continue
        try:
            r = subprocess.run([_DOCKER_BIN, *args], capture_output=True, text=True,
                               timeout=timeout, stdin=subprocess.DEVNULL)
        except (subprocess.TimeoutExpired, FileNotFoundError, OSError) as e:
            failed += 1
            msgs.append(f"{op}: error {type(e).__name__}")
            continue
        if r.returncode == 0:
            freed += 1
            line = next((l for l in r.stdout.splitlines() if "reclaimed" in l.lower()), "done")
            msgs.append(f"{op}: {line}")
        else:
            failed += 1
            msgs.append(f"{op}: failed ({r.stderr.strip()[:80]})")
    return freed, failed, "; ".join(msgs) or "nothing to do"


def _reclaim_worker(pid: str, p: dict, cfg: dict, notify_fn) -> None:
    """Run the reclaim DETACHED so a multi-minute prune never blocks the monitor
    loop. Reports honestly: executed (all ops freed), partial (some failed), or
    failed (nothing freed)."""
    freed, failed, msg = _run_disk_reclaim(p, cfg)
    status = "executed" if freed and not failed else ("partial" if freed else "failed")
    _finish(pid, status, msg)
    _log_disk_decision(p, f"reclaimed:{status}", msg, cfg)
    logging.warning("ai_diagnose: reclaim_disk %s -> %s: %s", p.get("friendly"), status, msg)
    try:
        mark = {"executed": "✓", "partial": "⚠", "failed": "✗"}[status]
        notify_fn(cfg, f"sysguard: {p.get('friendly')} reclaim", f"{mark} {msg[:250]}",
                  4 if freed else 5)
    except Exception:
        pass


def execute_approved(cfg: dict, execute_action_fn, lift_cap_fn, notify_fn) -> None:
    """Run any proposals the phone APPROVED, via sysguard's existing action
    machinery (never arbitrary shell). Called once per monitor cycle. Each
    approval executes at most once — status flips to executed/failed immediately.
    """
    store = _load_store()
    approved = [p for p in store.values() if p.get("status") == "approved"]
    for p in approved:
        pid = p["id"]
        action = p.get("structured_action")
        unit_id, friendly, kind = p["unit_id"], p["friendly"], p["kind"]
        # Re-validate against the approve allowlist at execution time (defense in
        # depth — never trust the stored value; auto-actions must never land here).
        if action not in APPROVE_ACTIONS:
            _finish(pid, "failed", f"action {action} not executable")
            continue
        # Disk reclaim can run for minutes (a big `builder prune`) — run it DETACHED
        # so it never blocks the monitor loop. Flip to "executing" first so the next
        # cycle won't pick it up again; the worker flips to executed/partial/failed.
        if action == "reclaim_disk":
            _finish(pid, "executing", "reclaim running (may take a few minutes)")
            logging.warning("ai_diagnose: reclaim_disk %s started (detached)", friendly)
            threading.Thread(target=_reclaim_worker, args=(pid, p, cfg, notify_fn),
                             daemon=True).start()
            continue
        logging.warning("ai_diagnose: executing approved %s on %s (%s)", action, friendly, pid)
        try:
            if action == "restart_unit":
                ok, msg = execute_action_fn(unit_id, friendly, kind, "restart", cfg, None)
            elif action == "lift_cap":
                ok, msg = lift_cap_fn(unit_id, friendly, kind)
            else:
                ok, msg = False, "unhandled action"
        except Exception as e:  # execution must never crash the cycle
            ok, msg = False, f"exception: {e}"
        _finish(pid, "executed" if ok else "failed", msg)
        logging.warning("ai_diagnose: %s %s -> %s: %s", action, friendly,
                        "OK" if ok else "FAILED", msg)
        try:
            notify_fn(cfg, f"sysguard AI: {friendly}",
                      f"{'✓ applied' if ok else '✗ failed'} {action}: {msg[:200]}",
                      5 if not ok else 4)
        except Exception:
            pass


def _finish(proposal_id: str, status: str, result_msg: str) -> None:
    with _store_lock:
        store = _load_store()
        p = store.get(proposal_id)
        if p:
            p["status"] = status
            p["execution_result"] = result_msg
            p["executed_ts"] = time.time()
            _save_store(store)


def escalate(unit_id: str, friendly: str, kind: str, evidence: str,
             available_mb: float, cfg: dict, notify_fn, context: str = "memory") -> None:
    """Fire-and-forget AI root-cause escalation. Guarded by an enable switch, a
    system-memory floor, a per-unit cooldown, and a daily cap; runs detached so
    it never blocks the monitor loop."""
    if not cfg.get("ai_diagnose_enabled", False):
        return
    now = time.time()
    # "Box in real trouble" — the threshold below which a suppressed AI diagnosis
    # must still produce a page. 2x the AI floor: covers the low-mem-floor skip and
    # a cooldown/cap skip that lands while memory is genuinely tight (the incident
    # had ~3GB free when the 6h cooldown silenced it).
    floor = cfg.get("ai_min_available_mb", 2048)
    page_below = cfg.get("ai_fallback_page_below_mb", floor * 2)
    if available_mb < floor:
        # Don't add a ~400MB Claude process while the box is already tight — that's
        # when the fast local path + the human should handle it, not a heavy LLM.
        # But DO page: this is precisely when the human needs to know.
        logging.info("ai_diagnose: skipping %s — only %.0fMB free (need %d)",
                     friendly, available_mb, floor)
        _fallback_page(friendly, evidence, available_mb, "skipped: low mem", cfg, notify_fn, now)
        return
    ok, why = _rate_ok(friendly, cfg, now)
    if not ok:
        logging.info("ai_diagnose: skipping %s — %s", friendly, why)
        # A repeat while the box is fine stays quiet; a repeat while memory is
        # tight means the earlier fix didn't hold — page so it can't run silent.
        if available_mb < page_below:
            _fallback_page(friendly, evidence, available_mb, why, cfg, notify_fn, now)
        return
    logging.warning("ai_diagnose: escalating %s to Claude for root-cause diagnosis", friendly)
    threading.Thread(
        target=_worker, args=(unit_id, friendly, kind, evidence, cfg, notify_fn, context),
        daemon=True, name=f"ai-diagnose-{friendly[:20]}",
    ).start()
