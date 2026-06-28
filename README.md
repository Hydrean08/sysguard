# sysguard

**Predictive memory-health monitor for Linux servers, with local-LLM triage.**

sysguard samples per-unit RSS (systemd services *and* Docker containers) every 30
seconds, tracks each unit's growth slope and learned baseline, and when something
starts misbehaving it asks a **local Ollama model** to decide what to do — ignore,
restart, cap, or escalate. It's built to catch the slow leak *before* it OOMs the
box, instead of triaging the storm afterward by hand.

It runs as an unprivileged `systemd --user` service, capped at 512 MB / 20% CPU so
it can never become part of the problem, and ships in **dry-run** so it watches and
explains for as long as you want before it's allowed to touch anything.

## Why

Long-running homelab boxes accumulate slow leaks — a FUSE cache that creeps,
a service that grows ~2 GB a day, an ML process that balloons and crashes the host.
Static thresholds either fire constantly or miss the slow ones. sysguard watches the
*trajectory* per unit and brings a small local model in to make the judgment call,
with hard safety rails around what it's allowed to do.

## How it works

1. **Sample** — every cycle, read RSS for each systemd unit and Docker container.
2. **Flag** — a unit is flagged if it crosses any of: absolute size, growth slope
   (MB/min), single-sample jump, or N× its own learned baseline; thresholds tighten
   automatically as free memory drops.
3. **Triage** — a flagged unit's recent history + journal tail is handed to a local
   Ollama model, which returns `ignore | restart | cap | investigate`. `investigate`
   escalates to a larger model when there's enough free RAM.
4. **Act** (only when `dry_run: false`) — `restart` or `cap` via systemd / `docker
   update`, rate-limited to one action per unit per hour to prevent flap loops.
   Every decision is logged to `decisions.jsonl`.
5. **Record** — a passive SQLite sink persists every sample for long-term trend
   graphs and post-mortems, independent of the live detection window.

A hardcoded skip-list protects critical processes (your shell, sshd, the desktop
session, container runtimes, Ollama, and sysguard itself) regardless of config.

## Requirements

- Linux with systemd and Python 3.10+
- [`psutil`](https://pypi.org/project/psutil/), [`PyYAML`](https://pypi.org/project/PyYAML/)
- [Ollama](https://ollama.com/) running locally with the models named in your config
  (defaults: `phi4-mini:3.8b`, `glm4:9b`, `qwen3:1.7b`)
- Docker (optional — only if you want container monitoring)

## Install

```bash
git clone https://github.com/Hydrean08/sysguard.git ~/sysguard
cd ~/sysguard
pip install --user psutil pyyaml
cp config.example.yaml config.yaml      # then edit to taste
./install.sh                            # installs + enables the systemd --user service
systemctl --user start sysguard
```

Watch it think (it starts in dry-run):

```bash
journalctl --user -u sysguard -f          # live logs
tail -f ~/.local/share/sysguard/decisions.jsonl   # what it WOULD do
```

When you trust it, set `dry_run: false` in `config.yaml` and restart.

## Configuration

Everything lives in `config.yaml` (see `config.example.yaml` for the fully
commented template): sample interval, detection thresholds, adaptive baselines,
the Ollama models, per-unit action overrides and RSS floors, disk-space alerts,
and notifications (KDE + [ntfy](https://ntfy.sh) for your phone).

## Safety

- **Dry-run by default** — no action is taken until you opt in.
- **Resource-capped** — runs under `MemoryMax=512M`, `CPUQuota=20%`, with a
  start-limit so a crash can't become a respawn storm.
- **Rate-limited** — at most one action per unit per hour.
- **No hard kills** — only `restart` and `cap` are allowed; `kill` is excluded.
- **Protected processes** — a hardcoded skip-list can't be configured away.

## Querying the history DB

```bash
sqlite3 ~/.local/share/sysguard/history.db \
  "SELECT unit, round(rss_mb,1), datetime(ts,'unixepoch','localtime')
   FROM unit_samples ORDER BY ts DESC LIMIT 20;"
```

## License

MIT — see [LICENSE](LICENSE).
