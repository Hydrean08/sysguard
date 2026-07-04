#!/usr/bin/env python3
"""sysguard-web — read-only dashboard for sysguard.

Serves system + per-unit memory history and the AI decision log over HTTP.
It NEVER writes to sysguard's data: the SQLite connection is opened query-only
and the JSONL/state files are read-only. Pure stdlib — no Flask/FastAPI, no CDN,
self-contained inline charts — so it can't add a dependency that breaks the box.

Run:  python3 ~/sysguard/web.py   (or via the sysguard-web.service user unit)
"""
import hmac
import json
import os
import sqlite3
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

try:
    import yaml
except ImportError:  # config view degrades gracefully without PyYAML
    yaml = None

HOME = os.path.expanduser("~")
DATA = os.path.join(HOME, ".local", "share", "sysguard")
DB = os.path.join(DATA, "history.db")
DECISIONS = os.path.join(DATA, "decisions.jsonl")
STATE = os.path.join(DATA, "state.json")
CONFIG = os.path.join(HOME, "sysguard", "config.yaml")
PORT = int(os.environ.get("SYSGUARD_WEB_PORT", "18900"))
HOST = os.environ.get("SYSGUARD_WEB_HOST", "0.0.0.0")
# Optional shared secret. When SYSGUARD_WEB_TOKEN is set, every request must
# present it via the `X-Sysguard-Token` header or `?token=` query param, else
# 401. Unset = open (back-compat). The dashboard exposes the full unit
# inventory + decision log, so a token is what makes binding 0.0.0.0 (needed for
# the phone to reach it over LAN) safe, and closes it if the port is ever tunneled.
AUTH_TOKEN = os.environ.get("SYSGUARD_WEB_TOKEN", "")
LIVE_WINDOW_S = 120  # latest system sample newer than this => sysguard is "live"


def db():
    """Read-only SQLite handle. query_only guarantees we can never write, and a
    plain (not mode=ro) connection reads WAL databases without shm hassles."""
    con = sqlite3.connect(DB, timeout=5)
    con.row_factory = sqlite3.Row
    con.execute("PRAGMA query_only=ON")
    return con


def load_config():
    if not yaml or not os.path.exists(CONFIG):
        return {}
    try:
        with open(CONFIG) as f:
            return yaml.safe_load(f) or {}
    except Exception:
        return {}


def load_state():
    try:
        with open(STATE) as f:
            return json.load(f)
    except Exception:
        return {}


def slope_mb_per_min(samples):
    """Least-squares slope over the last ~10 samples, MB/min."""
    pts = samples[-10:]
    if len(pts) < 2:
        return 0.0
    t0 = pts[0][0]
    xs = [(t - t0) for t, _ in pts]
    ys = [v for _, v in pts]
    n = len(pts)
    sx, sy = sum(xs), sum(ys)
    sxx = sum(x * x for x in xs)
    sxy = sum(x * y for x, y in zip(xs, ys))
    denom = n * sxx - sx * sx
    if denom == 0:
        return 0.0
    slope_per_s = (n * sxy - sx * sy) / denom
    return slope_per_s * 60.0


def overview():
    cfg = load_config()
    state = load_state()
    con = db()
    sysrow = con.execute(
        "SELECT * FROM system_samples ORDER BY ts DESC LIMIT 1"
    ).fetchone()
    con.close()
    sysd = dict(sysrow) if sysrow else {}

    now = time.time()
    live = bool(sysd) and (now - sysd.get("ts", 0) < LIVE_WINDOW_S)

    mult = float(cfg.get("baseline_multiplier", 2.0) or 0)
    units = []
    for name, u in state.items():
        if not isinstance(u, dict):
            continue
        samples = u.get("samples") or []
        cur = samples[-1][1] if samples else 0.0
        base = float(u.get("baseline_rss_mb") or 0)
        x = (cur / base) if base else 0
        units.append({
            "name": name,
            "rss_mb": round(cur, 1),
            "baseline_mb": round(base, 1),
            "x_baseline": round(x, 2),
            "slope": round(slope_mb_per_min(samples), 1),
            "last_action_at": u.get("last_action_at") or 0,
            "pending_verify": bool(u.get("pending_verify")),
            "over": bool(mult and base and cur >= base * mult),
            "samples": len(samples),
        })
    units.sort(key=lambda d: d["x_baseline"], reverse=True)

    # action tallies over the last 24h from the decision log
    cutoff = now - 86400
    tally = {"cap": 0, "restart": 0, "investigate": 0, "ignore": 0}
    flags24 = 0
    if os.path.exists(DECISIONS):
        with open(DECISIONS) as f:
            for line in f:
                try:
                    o = json.loads(line)
                except Exception:
                    continue
                if o.get("type") == "verify":
                    continue
                if o.get("ts", 0) < cutoff:
                    continue
                flags24 += 1
                a = o.get("action")
                if a in tally:
                    tally[a] += 1

    return {
        "live": live,
        "system": sysd,
        "now": now,
        "dry_run": bool(cfg.get("dry_run", False)),
        "thresholds": {
            "rss_growth_mb_per_min": cfg.get("rss_growth_mb_per_min"),
            "rss_jump_mb": cfg.get("rss_jump_mb"),
            "rss_absolute_mb": cfg.get("rss_absolute_mb"),
            "baseline_multiplier": cfg.get("baseline_multiplier"),
            "system_available_mb_floor": cfg.get("system_available_mb_floor"),
            "sample_interval_seconds": cfg.get("sample_interval_seconds"),
        },
        "actions_24h": tally,
        "flags_24h": flags24,
        "units": units,
    }


def _bucket(hours, target=320):
    span = max(1, int(hours * 3600))
    return max(30, span // target)


def sys_series(hours):
    since = time.time() - hours * 3600
    b = _bucket(hours)
    con = db()
    rows = con.execute(
        """
        SELECT (ts/?)*? AS bts,
               avg(available_mb) av, avg(used_mb) us, avg(swap_used_mb) sw,
               max(psi_some_avg10) ps, max(psi_full_avg10) pf,
               min(disk_root_free_mb) dr, min(disk_pool_free_mb) dp
        FROM system_samples WHERE ts > ?
        GROUP BY ts/? ORDER BY bts
        """,
        (b, b, since, b),
    ).fetchall()
    con.close()
    return [
        {"ts": r["bts"], "available_mb": r["av"], "used_mb": r["us"],
         "swap_used_mb": r["sw"], "psi_some": r["ps"], "psi_full": r["pf"],
         "disk_root_gb": (r["dr"] or 0) / 1024, "disk_pool_gb": (r["dp"] or 0) / 1024}
        for r in rows
    ]


def unit_series(name, hours):
    since = time.time() - hours * 3600
    b = _bucket(hours)
    con = db()
    rows = con.execute(
        "SELECT (ts/?)*? AS bts, avg(rss_mb) rss, max(rss_mb) peak "
        "FROM unit_samples WHERE unit=? AND ts > ? GROUP BY ts/? ORDER BY bts",
        (b, b, name, since, b),
    ).fetchall()
    con.close()
    state = load_state().get(name, {})
    return {
        "name": name,
        "baseline_mb": state.get("baseline_rss_mb"),
        "points": [{"ts": r["bts"], "rss": r["rss"], "peak": r["peak"]} for r in rows],
    }


def decisions_feed(limit):
    if not os.path.exists(DECISIONS):
        return []
    with open(DECISIONS) as f:
        lines = f.readlines()
    out = []
    for line in reversed(lines):
        if len(out) >= limit:
            break
        try:
            o = json.loads(line)
        except Exception:
            continue
        out.append(o)
    return out


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):  # quiet — journald already timestamps
        pass

    def _send(self, code, body, ctype):
        data = body.encode() if isinstance(body, str) else body
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _json(self, obj):
        self._send(200, json.dumps(obj), "application/json")

    def _authorized(self, q: dict) -> bool:
        if not AUTH_TOKEN:
            return True  # open mode (no token configured)
        provided = self.headers.get("X-Sysguard-Token") or (q.get("token", [""])[0])
        # hmac.compare_digest avoids leaking the token length/prefix via timing.
        return hmac.compare_digest(provided or "", AUTH_TOKEN)

    def do_GET(self):
        u = urlparse(self.path)
        q = parse_qs(u.query)
        if not self._authorized(q):
            self._send(401, json.dumps({"error": "unauthorized"}), "application/json")
            return
        try:
            if u.path == "/":
                self._send(200, PAGE, "text/html; charset=utf-8")
            elif u.path == "/api/overview":
                self._json(overview())
            elif u.path == "/api/sys":
                self._json(sys_series(float(q.get("hours", ["24"])[0])))
            elif u.path == "/api/unit":
                name = q.get("name", [""])[0]
                self._json(unit_series(name, float(q.get("hours", ["24"])[0])))
            elif u.path == "/api/decisions":
                self._json(decisions_feed(int(q.get("limit", ["80"])[0])))
            elif u.path == "/api/proposals":
                # AI diagnoses awaiting a phone decision (v2 approve→execute).
                try:
                    import ai_diagnose
                    self._json(ai_diagnose.list_pending())
                except Exception:
                    self._json([])
            else:
                self._send(404, "not found", "text/plain")
        except Exception as e:
            self._send(500, json.dumps({"error": str(e)}), "application/json")

    def do_POST(self):
        u = urlparse(self.path)
        q = parse_qs(u.query)
        if not self._authorized(q):
            self._send(401, json.dumps({"error": "unauthorized"}), "application/json")
            return
        # Flip a proposal's status; the sysguard DAEMON executes approved ones next
        # cycle via its own guarded action machinery. web.py never runs system
        # changes itself — it only records the human's decision.
        if u.path in ("/api/proposal/approve", "/api/proposal/reject"):
            try:
                length = int(self.headers.get("Content-Length", "0") or "0")
                body = json.loads(self.rfile.read(length) or b"{}")
                pid = str(body.get("id", ""))
            except (ValueError, OSError):
                self._send(400, json.dumps({"error": "bad request"}), "application/json")
                return
            status = "approved" if u.path.endswith("approve") else "rejected"
            try:
                import ai_diagnose
                ok = ai_diagnose.set_status(pid, status)
            except Exception as e:
                self._send(500, json.dumps({"error": str(e)}), "application/json")
                return
            if not ok:
                self._send(404, json.dumps({"error": "proposal not found"}), "application/json")
                return
            self._json({"ok": True, "id": pid, "status": status})
        else:
            self._send(404, "not found", "text/plain")


PAGE = r"""<!doctype html>
<html lang="en"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>sysguard</title>
<style>
:root{--bg:#0d1117;--panel:#161b22;--panel2:#1c2330;--line:#2a3340;--fg:#e6edf3;
--mut:#8b98a6;--accent:#3fb6f0;--ok:#3fb950;--warn:#d29922;--crit:#f85149;
--cap:#d29922;--restart:#f85149;--investigate:#a371f7;--ignore:#6e7681;}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--fg);
font:14px/1.5 system-ui,-apple-system,Segoe UI,Roboto,sans-serif}
header{display:flex;align-items:center;gap:14px;padding:14px 20px;
background:var(--panel);border-bottom:1px solid var(--line);position:sticky;top:0;z-index:5}
header h1{font-size:18px;margin:0;letter-spacing:.5px}
header h1 .g{color:var(--accent)}
.dot{width:10px;height:10px;border-radius:50%;display:inline-block}
.dot.live{background:var(--ok);box-shadow:0 0 8px var(--ok)}
.dot.stale{background:var(--crit);box-shadow:0 0 8px var(--crit)}
.pill{font-size:12px;padding:2px 9px;border-radius:20px;border:1px solid var(--line);color:var(--mut)}
.pill.enforce{color:var(--crit);border-color:var(--crit)}
.pill.audit{color:var(--warn);border-color:var(--warn)}
.spacer{flex:1}
#updated{color:var(--mut);font-size:12px}
.wrap{padding:18px 20px;max-width:1280px;margin:0 auto}
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:12px;margin-bottom:18px}
.card{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:13px 15px}
.card .k{color:var(--mut);font-size:12px;text-transform:uppercase;letter-spacing:.5px}
.card .v{font-size:24px;font-weight:600;margin-top:3px}
.card .v small{font-size:13px;color:var(--mut);font-weight:400}
.card .sub{font-size:12px;color:var(--mut);margin-top:2px}
.v.ok{color:var(--ok)}.v.warn{color:var(--warn)}.v.crit{color:var(--crit)}
.panel{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:16px;margin-bottom:18px}
.panel h2{margin:0 0 12px;font-size:14px;font-weight:600;color:var(--mut);
text-transform:uppercase;letter-spacing:.6px;display:flex;align-items:center;gap:10px}
.ranges{margin-left:auto;display:flex;gap:6px}
.ranges button,.tbtn{background:var(--panel2);color:var(--mut);border:1px solid var(--line);
border-radius:6px;padding:3px 10px;font-size:12px;cursor:pointer}
.ranges button.on{color:var(--fg);border-color:var(--accent)}
canvas{width:100%;height:220px;display:block}
.legend{display:flex;gap:16px;flex-wrap:wrap;margin-top:8px;font-size:12px;color:var(--mut)}
.legend span{display:inline-flex;align-items:center;gap:6px}
.legend i{width:11px;height:3px;border-radius:2px;display:inline-block}
table{width:100%;border-collapse:collapse;font-size:13px}
th,td{text-align:left;padding:7px 10px;border-bottom:1px solid var(--line)}
th{color:var(--mut);font-weight:600;font-size:11px;text-transform:uppercase;letter-spacing:.5px;cursor:pointer;user-select:none}
tbody tr{cursor:pointer}
tbody tr:hover{background:var(--panel2)}
td.num{text-align:right;font-variant-numeric:tabular-nums}
.bar{height:6px;border-radius:3px;background:var(--line);overflow:hidden;min-width:60px}
.bar>i{display:block;height:100%;background:var(--accent)}
.tag{font-size:11px;padding:1px 7px;border-radius:5px;font-weight:600}
.tag.over{background:rgba(248,81,73,.15);color:var(--crit)}
.tag.okk{background:rgba(63,185,80,.13);color:var(--ok)}
.feed{display:flex;flex-direction:column;gap:0}
.ev{display:grid;grid-template-columns:130px 1fr;gap:12px;padding:10px 4px;border-bottom:1px solid var(--line)}
.ev:last-child{border-bottom:0}
.ev .when{color:var(--mut);font-size:12px}
.ev .who{font-weight:600}
.ev .act{font-size:11px;padding:1px 7px;border-radius:5px;font-weight:700;text-transform:uppercase;margin-left:8px}
.act.cap{background:rgba(210,153,34,.18);color:var(--cap)}
.act.restart{background:rgba(248,81,73,.18);color:var(--restart)}
.act.investigate{background:rgba(163,113,247,.18);color:var(--investigate)}
.act.ignore{background:rgba(110,118,129,.18);color:var(--ignore)}
.act.verify{background:rgba(63,182,240,.16);color:var(--accent)}
.ev .why{color:var(--mut);font-size:12.5px;margin-top:3px}
.ev .trig{color:#aeb9c4;font-size:12px;margin-top:2px}
.muted{color:var(--mut)}
.dry{font-size:11px;color:var(--warn);margin-left:6px}
#unitTitle{color:var(--fg);text-transform:none;letter-spacing:0;font-weight:600}
.hint{font-size:12px;color:var(--mut);font-weight:400;text-transform:none;letter-spacing:0}
@media(max-width:600px){.ev{grid-template-columns:1fr}.ev .when{order:2}}
</style></head>
<body>
<header>
  <h1><span class="g">sys</span>guard</h1>
  <span id="status"><span class="dot stale"></span> <span id="statusTxt">connecting…</span></span>
  <span id="mode" class="pill"></span>
  <div class="spacer"></div>
  <span id="updated"></span>
</header>
<div class="wrap">
  <div class="cards" id="cards"></div>

  <div class="panel">
    <h2>System memory <div class="ranges" id="sysRanges"></div></h2>
    <canvas id="sysChart"></canvas>
    <div class="legend">
      <span><i style="background:#3fb950"></i>available</span>
      <span><i style="background:#3fb6f0"></i>used</span>
      <span><i style="background:#d29922"></i>swap used</span>
    </div>
  </div>

  <div class="panel">
    <h2><span id="unitTitle">Unit memory</span> <span class="hint">— click a row below</span>
      <div class="ranges" id="unitRanges"></div></h2>
    <canvas id="unitChart"></canvas>
    <div class="legend">
      <span><i style="background:#3fb6f0"></i>RSS</span>
      <span><i style="background:#6e7681"></i>baseline</span>
    </div>
  </div>

  <div class="panel">
    <h2>Tracked units <span class="hint" id="unitCount"></span></h2>
    <table id="unitsTable">
      <thead><tr>
        <th data-k="name">unit</th>
        <th data-k="rss_mb" class="num">RSS (MB)</th>
        <th data-k="baseline_mb" class="num">baseline</th>
        <th data-k="x_baseline" class="num">×base</th>
        <th data-k="slope" class="num">slope MB/min</th>
        <th>state</th>
      </tr></thead>
      <tbody></tbody>
    </table>
  </div>

  <div class="panel">
    <h2>Recent decisions <span class="hint">— newest first</span></h2>
    <div class="feed" id="feed"></div>
  </div>
</div>

<script>
const $=s=>document.querySelector(s);
const fmtMB=v=>v>=1024?(v/1024).toFixed(1)+' GB':Math.round(v)+' MB';
const ago=s=>{const d=Date.now()/1000-s;if(d<60)return Math.round(d)+'s ago';
 if(d<3600)return Math.round(d/60)+'m ago';if(d<86400)return Math.round(d/3600)+'h ago';
 return Math.round(d/86400)+'d ago';};
const clock=ts=>new Date(ts*1000).toLocaleString([], {month:'short',day:'numeric',hour:'2-digit',minute:'2-digit'});

let sysHours=24, unitHours=24, curUnit=null, units=[], sortK='x_baseline', sortDir=-1;

// ---- minimal canvas line chart (no deps) ----
function draw(canvas, series, opts={}){
  const dpr=window.devicePixelRatio||1;
  const W=canvas.clientWidth, H=canvas.clientHeight;
  canvas.width=W*dpr; canvas.height=H*dpr;
  const c=canvas.getContext('2d'); c.scale(dpr,dpr);
  c.clearRect(0,0,W,H);
  const padL=52,padR=12,padT=10,padB=22;
  const plotW=W-padL-padR, plotH=H-padT-padB;
  let all=[].concat(...series.map(s=>s.data.map(p=>p.y))).filter(v=>v!=null);
  if(!all.length){c.fillStyle='#8b98a6';c.font='13px system-ui';c.fillText('no data in range',padL,H/2);return;}
  let lo=Math.min(...all), hi=Math.max(...all);
  if(opts.zero)lo=Math.min(lo,0);
  if(hi===lo)hi=lo+1; const pad=(hi-lo)*0.08; lo-=pad; hi+=pad;
  const xs=series[0].data.map(p=>p.x);
  const xmin=Math.min(...xs), xmax=Math.max(...xs)||xmin+1;
  const X=x=>padL+((x-xmin)/(xmax-xmin||1))*plotW;
  const Y=y=>padT+(1-(y-lo)/(hi-lo))*plotH;
  // grid + y labels
  c.strokeStyle='#2a3340';c.fillStyle='#8b98a6';c.font='11px system-ui';c.lineWidth=1;
  for(let i=0;i<=4;i++){const y=padT+plotH*i/4, val=hi-(hi-lo)*i/4;
    c.beginPath();c.moveTo(padL,y);c.lineTo(W-padR,y);c.stroke();
    c.fillText(opts.fmt?opts.fmt(val):Math.round(val),6,y+3);}
  // x labels (start / mid / end)
  [0,.5,1].forEach(f=>{const t=xmin+(xmax-xmin)*f;const x=X(t);
    c.fillStyle='#8b98a6';c.textAlign=f===0?'left':(f===1?'right':'center');
    c.fillText(clock(t),Math.min(Math.max(x,padL),W-padR),H-6);});
  c.textAlign='left';
  // series
  series.forEach(s=>{
    c.beginPath();c.lineWidth=s.dash?1.5:2;c.strokeStyle=s.color;
    if(s.dash)c.setLineDash([5,4]);else c.setLineDash([]);
    let started=false;
    s.data.forEach(p=>{if(p.y==null){started=false;return;}
      const x=X(p.x),y=Y(p.y);if(!started){c.moveTo(x,y);started=true;}else c.lineTo(x,y);});
    c.stroke();
    if(s.fill){c.lineTo(X(s.data[s.data.length-1].x),Y(lo));c.lineTo(X(s.data[0].x),Y(lo));
      c.closePath();c.globalAlpha=.08;c.fillStyle=s.color;c.fill();c.globalAlpha=1;}
  });
  c.setLineDash([]);
}

async function loadOverview(){
  const o=await (await fetch('/api/overview')).json();
  // status
  $('#status').innerHTML='<span class="dot '+(o.live?'live':'stale')+'"></span> '+
    (o.live?'live':'stale');
  $('#mode').textContent=o.dry_run?'AUDIT (dry-run)':'ENFORCING';
  $('#mode').className='pill '+(o.dry_run?'audit':'enforce');
  $('#updated').textContent='system sampled '+ago(o.system.ts||0)+' · refreshed '+new Date().toLocaleTimeString();
  // cards
  const s=o.system, totalRam=(s.available_mb+s.used_mb);
  const availPct=totalRam?s.available_mb/totalRam:0;
  const swapTotal=24576; // box swap; display only
  const cls=v=>v<0.08?'crit':v<0.18?'warn':'ok';
  const t=o.actions_24h||{};
  $('#cards').innerHTML=[
    card('Available RAM',fmtMB(s.available_mb),Math.round(availPct*100)+'% free',cls(availPct)),
    card('Used RAM',fmtMB(s.used_mb),'of '+fmtMB(totalRam),''),
    card('Swap used',fmtMB(s.swap_used_mb||0),(((s.swap_used_mb||0)/swapTotal*100).toFixed(0))+'% of 24 GB',
        (s.swap_used_mb/swapTotal)>0.8?'warn':''),
    card('Mem pressure',(s.psi_some_avg10??0).toFixed(1),'PSI some · full '+(s.psi_full_avg10??0).toFixed(1),
        (s.psi_some_avg10>10)?'warn':''),
    card('Disk root',((s.disk_root_free_mb||0)/1024).toFixed(0)+' GB','free',''),
    card('Actions 24h','<small>cap</small> '+(t.cap||0)+'  <small>restart</small> '+(t.restart||0),
        (o.flags_24h||0)+' flags · '+(t.investigate||0)+' invest.',''),
  ].join('');
  units=o.units;
  $('#unitCount').textContent='— '+units.length+' tracked';
  renderUnits();
  if(!curUnit && units.length) selectUnit(units[0].name);
}
function card(k,v,sub,cl){return '<div class="card"><div class="k">'+k+'</div>'+
  '<div class="v '+(cl||'')+'">'+v+'</div><div class="sub">'+(sub||'')+'</div></div>';}

function renderUnits(){
  const tb=$('#unitsTable tbody');
  const arr=[...units].sort((a,b)=>{let x=a[sortK],y=b[sortK];
    if(typeof x==='string')return sortDir*x.localeCompare(y);return sortDir*((x||0)-(y||0));});
  const maxX=Math.max(1,...arr.map(u=>u.x_baseline||0));
  tb.innerHTML=arr.map(u=>{
    const xw=Math.min(100,(u.x_baseline/maxX)*100);
    const st=u.over?'<span class="tag over">over ×base</span>':'<span class="tag okk">ok</span>';
    const pv=u.pending_verify?' <span class="tag over">verifying</span>':'';
    return '<tr data-u="'+encodeURIComponent(u.name)+'">'+
      '<td>'+u.name+(u.last_action_at?' <span class="dry">acted '+ago(u.last_action_at)+'</span>':'')+'</td>'+
      '<td class="num">'+Math.round(u.rss_mb)+'</td>'+
      '<td class="num muted">'+Math.round(u.baseline_mb)+'</td>'+
      '<td class="num">'+(u.x_baseline||0).toFixed(2)+'<div class="bar"><i style="width:'+xw+'%"></i></div></td>'+
      '<td class="num '+(u.slope>20?'':'muted')+'">'+(u.slope>0?'+':'')+u.slope+'</td>'+
      '<td>'+st+pv+'</td></tr>';
  }).join('');
  tb.querySelectorAll('tr').forEach(tr=>tr.onclick=()=>selectUnit(decodeURIComponent(tr.dataset.u)));
}
$('#unitsTable thead').addEventListener('click',e=>{
  const k=e.target.dataset.k;if(!k)return;
  if(sortK===k)sortDir*=-1;else{sortK=k;sortDir=(k==='name')?1:-1;}renderUnits();});

async function selectUnit(name){
  curUnit=name; $('#unitTitle').textContent=name;
  const d=await (await fetch('/api/unit?name='+encodeURIComponent(name)+'&hours='+unitHours)).json();
  const pts=d.points.map(p=>({x:p.ts,y:p.rss}));
  const series=[{color:'#3fb6f0',fill:true,data:pts}];
  if(d.baseline_mb&&pts.length)series.push({color:'#6e7681',dash:true,
    data:[{x:pts[0].x,y:d.baseline_mb},{x:pts[pts.length-1].x,y:d.baseline_mb}]});
  draw($('#unitChart'),series,{zero:true,fmt:v=>Math.round(v)});
}

async function loadSys(){
  const d=await (await fetch('/api/sys?hours='+sysHours)).json();
  draw($('#sysChart'),[
    {color:'#3fb950',data:d.map(p=>({x:p.ts,y:p.available_mb}))},
    {color:'#3fb6f0',data:d.map(p=>({x:p.ts,y:p.used_mb}))},
    {color:'#d29922',data:d.map(p=>({x:p.ts,y:p.swap_used_mb}))},
  ],{zero:true,fmt:v=>v>=1024?(v/1024).toFixed(0)+'G':Math.round(v)});
}

async function loadFeed(){
  const evs=await (await fetch('/api/decisions?limit=80')).json();
  $('#feed').innerHTML=evs.map(e=>{
    const who='<span class="who">'+(e.friendly||e.unit_id||'?')+'</span>';
    if(e.type==='verify'){
      const delta=Math.round((e.post_rss_mb||0)-(e.pre_rss_mb||0));
      return ev(e.ts,who+'<span class="act verify">verify</span>',
        '<span class="why">'+e.verdict+' — '+Math.round(e.pre_rss_mb)+'→'+Math.round(e.post_rss_mb)+
        ' MB ('+(delta>0?'+':'')+delta+'), service '+(e.service_active?'up':'DOWN')+'</span>');
    }
    const a=(e.action||'ignore');
    let body='<span class="trig">'+(e.trigger||'')+'</span>';
    if(e.ai_reason)body+='<span class="why">'+(e.model?('['+e.model+'] '):'')+e.ai_reason+
      (e.root_cause?' · <i>'+e.root_cause+'</i>':'')+'</span>';
    return ev(e.ts,who+'<span class="act '+a+'">'+a+'</span>'+
      (e.dry_run?'<span class="dry">dry-run</span>':''),body);
  }).join('');
}
function ev(ts,head,body){return '<div class="ev"><div class="when">'+clock(ts)+'<br>'+ago(ts)+
  '</div><div>'+head+body+'</div></div>';}

function ranges(elId,vals,cur,cb){
  $(elId).innerHTML=vals.map(v=>'<button data-h="'+v.h+'" class="'+(v.h===cur?'on':'')+'">'+v.l+'</button>').join('');
  $(elId).querySelectorAll('button').forEach(b=>b.onclick=()=>{
    $(elId).querySelectorAll('button').forEach(x=>x.classList.remove('on'));
    b.classList.add('on');cb(parseFloat(b.dataset.h));});
}
const RANGES=[{h:1,l:'1h'},{h:6,l:'6h'},{h:24,l:'24h'},{h:72,l:'3d'},{h:168,l:'7d'}];
ranges('#sysRanges',RANGES,sysHours,h=>{sysHours=h;loadSys();});
ranges('#unitRanges',RANGES,unitHours,h=>{unitHours=h;if(curUnit)selectUnit(curUnit);});

async function refresh(){await Promise.all([loadOverview(),loadSys(),loadFeed()]);}
refresh();
setInterval(refresh,15000);
window.addEventListener('resize',()=>{loadSys();if(curUnit)selectUnit(curUnit);});
</script>
</body></html>"""


def main():
    srv = ThreadingHTTPServer((HOST, PORT), Handler)
    print(f"sysguard-web on http://{HOST}:{PORT}  (db={DB})")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        srv.shutdown()


if __name__ == "__main__":
    main()
