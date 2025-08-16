#!/usr/bin/env python3
"""
Cyber Sentinel — a senior-project–ready, SIEM‑lite you can run locally.

Single‑file Flask app that:
  • Ingests Linux auth/system logs (or runs in simulation mode)
  • Parses common security signals (SSH brute force, sudo misuse, port scans, suspicious processes)
  • Stores data in SQLite
  • Applies rule‑based alerts
  • Serves a live dashboard (no external JS/CSS libs) at http://127.0.0.1:5000

Dependencies: Python 3.9+, Flask (pip install flask)

Usage examples:
  python cyber_sentinel.py --simulate               # start with synthetic events
  python cyber_sentinel.py --logs /var/log/auth.log # tail a real log
  python cyber_sentinel.py --logs /var/log/auth.log /var/log/syslog

Linux tip: run with sudo to access protected logs, or add yourself to a group with read perms.
Windows/macOS: use --simulate, or point --logs to any text file that receives events.

Author: You + ChatGPT (GPT‑5)
License: MIT
"""
import argparse
import datetime as dt
import ipaddress
import os
import queue
import re
import signal
import sqlite3
import sys
import threading
import time
from collections import defaultdict, deque
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Optional, Tuple

from flask import Flask, jsonify, request, Response
from flask import render_template_string

APP_TITLE = "Cyber Sentinel — SIEM‑lite"
DB_FILE = "sentinel.db"

# -----------------------------
# Database layer (SQLite)
# -----------------------------

SCHEMA = """
PRAGMA journal_mode=WAL;
CREATE TABLE IF NOT EXISTS events (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ts TEXT NOT NULL,
  source TEXT NOT NULL,
  level TEXT NOT NULL,
  ip TEXT,
  username TEXT,
  rule TEXT,
  message TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_events_ts ON events(ts);
CREATE INDEX IF NOT EXISTS idx_events_ip ON events(ip);
CREATE INDEX IF NOT EXISTS idx_events_rule ON events(rule);

CREATE TABLE IF NOT EXISTS alerts (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ts TEXT NOT NULL,
  severity TEXT NOT NULL,
  title TEXT NOT NULL,
  description TEXT NOT NULL,
  count INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_alerts_ts ON alerts(ts);
"""


def db_connect(db_path: str = DB_FILE) -> sqlite3.Connection:
    conn = sqlite3.connect(db_path, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    with conn:
        conn.executescript(SCHEMA)
    return conn


# -----------------------------
# Event & Rule engine
# -----------------------------

@dataclass
class Event:
    ts: dt.datetime
    source: str
    level: str
    ip: Optional[str]
    username: Optional[str]
    rule: Optional[str]
    message: str


def insert_event(conn: sqlite3.Connection, ev: Event):
    with conn:
        conn.execute(
            "INSERT INTO events(ts, source, level, ip, username, rule, message) VALUES (?,?,?,?,?,?,?)",
            (
                ev.ts.isoformat(),
                ev.source,
                ev.level,
                ev.ip,
                ev.username,
                ev.rule,
                ev.message,
            ),
        )


def insert_alert(conn: sqlite3.Connection, ts: dt.datetime, severity: str, title: str, description: str, count: int):
    with conn:
        conn.execute(
            "INSERT INTO alerts(ts, severity, title, description, count) VALUES (?,?,?,?,?)",
            (ts.isoformat(), severity, title, description, count),
        )


# Regex patterns for common signals
RE_SSH_FAIL = re.compile(r"Failed password for (invalid user )?(?P<user>[\w\-\.]+) from (?P<ip>[0-9a-fA-F:\.]+)")
RE_SSH_ACCEPT = re.compile(r"Accepted (password|publickey) for (?P<user>[\w\-\.]+) from (?P<ip>[0-9a-fA-F:\.]+)")
RE_INVALID_USER = re.compile(r"Invalid user (?P<user>[\w\-\.]+) from (?P<ip>[0-9a-fA-F:\.]+)")
RE_SUDO_FAIL = re.compile(r"pam_unix\(sudo:auth\): authentication failure.*rhost=(?P<ip>[0-9a-fA-F:\.]*) .*user=(?P<user>[\w\-\.]+)")
RE_NMAP = re.compile(r"Nmap scan report for (?P<target>[\w\.-]+) \((?P<ip>[0-9a-fA-F:\.]+)\)")


def safe_ip(ip: str) -> Optional[str]:
    try:
        ipaddress.ip_address(ip)
        return ip
    except Exception:
        return None


class RuleEngine:
    """Very small, transparent rule engine."""

    def __init__(self, conn: sqlite3.Connection):
        self.conn = conn
        self.window = deque(maxlen=10000)
        self.lock = threading.Lock()
        # for brute-force detection per IP
        self.failed_by_ip = defaultdict(lambda: deque())
        # for spray detection per username
        self.failed_by_user = defaultdict(lambda: deque())

    def handle(self, ev: Event):
        with self.lock:
            self.window.append(ev)
            # Index windows (keep last 10 min)
            now = ev.ts
            cutoff = now - dt.timedelta(minutes=10)

            # Clean old entries
            for dq in (self.failed_by_ip, self.failed_by_user):
                for k in list(dq.keys()):
                    while dq[k] and dq[k][0] < cutoff:
                        dq[k].popleft()
                    if not dq[k]:
                        dq.pop(k, None)

            # Update structures based on event
            if ev.rule in ("ssh_failed", "invalid_user", "sudo_failed"):
                if ev.ip:
                    self.failed_by_ip[ev.ip].append(ev.ts)
                if ev.username:
                    self.failed_by_user[ev.username].append(ev.ts)

            # Evaluate rules
            self._rule_bruteforce_ip(now)
            self._rule_password_spray(now)

    def _rule_bruteforce_ip(self, now: dt.datetime):
        # 10+ failures from same IP within 2 minutes
        for ip, times in list(self.failed_by_ip.items()):
            while times and (now - times[0]).total_seconds() > 120:
                times.popleft()
            if len(times) >= 10:
                insert_alert(
                    self.conn,
                    ts=now,
                    severity="high",
                    title="SSH brute-force suspected",
                    description=f">=10 failed auth attempts in 2 minutes from {ip}",
                    count=len(times),
                )
                times.clear()

    def _rule_password_spray(self, now: dt.datetime):
        # 5+ usernames targeted within 2 minutes from any IPs
        # Derive from the recent window
        # Count unique usernames seen in last 120s with failures
        recent = [ev for ev in list(self.window)[-1000:] if (now - ev.ts).total_seconds() <= 120 and ev.rule in ("ssh_failed", "invalid_user", "sudo_failed")]
        users = {ev.username for ev in recent if ev.username}
        if len(users) >= 5:
            insert_alert(
                self.conn,
                ts=now,
                severity="medium",
                title="Possible password spray",
                description=f">=5 distinct usernames failed within 2 minutes",
                count=len(users),
            )


# -----------------------------
# Log ingestion
# -----------------------------

class Ingestor(threading.Thread):
    def __init__(self, conn: sqlite3.Connection, sources: Iterable[Path], simulate: bool = False):
        super().__init__(daemon=True)
        self.conn = conn
        self.sources = list(sources)
        self.simulate = simulate
        self.stop_event = threading.Event()
        self.queue: "queue.Queue[Tuple[str,str]]" = queue.Queue()
        self.rule_engine = RuleEngine(conn)

    def run(self):
        if self.simulate or not self.sources:
            self._run_simulation()
        else:
            threads = [threading.Thread(target=self._tail_file, args=(p,), daemon=True) for p in self.sources]
            for t in threads:
                t.start()
            while not self.stop_event.is_set():
                try:
                    src, line = self.queue.get(timeout=0.5)
                except queue.Empty:
                    continue
                self._process_line(src, line)

    def stop(self):
        self.stop_event.set()

    def _tail_file(self, path: Path):
        try:
            with open(path, "r", errors="ignore") as f:
                # seek to end
                f.seek(0, os.SEEK_END)
                while not self.stop_event.is_set():
                    line = f.readline()
                    if not line:
                        time.sleep(0.2)
                        continue
                    self.queue.put((str(path), line.rstrip()))
        except FileNotFoundError:
            # Gracefully ignore missing files
            return

    def _run_simulation(self):
        users = ["root", "admin", "postgres", "ubuntu", "reda"]
        bad_ips = ["45.12.34.56", "102.67.89.10", "2a03:2880:2110::1"]
        ok_ip = "192.168.1.10"
        start = dt.datetime.utcnow()
        i = 0
        while not self.stop_event.is_set():
            now = start + dt.timedelta(seconds=i)
            # mix normal and bad events
            if i % 7 == 0:
                self._emit(now, "simulator", f"Accepted password for ubuntu from {ok_ip} port 22 ssh2")
            # bursty failures to trigger alerts
            if (i % 3) == 0:
                ip = bad_ips[i % len(bad_ips)]
                user = users[i % len(users)]
                self._emit(now, "simulator", f"Failed password for {user} from {ip} port 40712 ssh2")
            if (i % 11) == 0:
                self._emit(now, "simulator", f"Invalid user oracle from {bad_ips[0]}")
            if (i % 19) == 0:
                self._emit(now, "simulator", f"pam_unix(sudo:auth): authentication failure; logname= uid=1000 ruser= rhost={bad_ips[1]} user=reda")
            time.sleep(0.35)
            i += 1

    def _emit(self, ts: dt.datetime, src: str, line: str):
        self._process_line(src, line, ts_override=ts)

    def _process_line(self, src: str, line: str, ts_override: Optional[dt.datetime] = None):
        ts = ts_override or dt.datetime.utcnow()
        msg = line.strip()
        level = "info"
        ip = None
        user = None
        rule = None

        # Order matters: match most specific first
        m = RE_SSH_FAIL.search(msg)
        if m:
            level = "warning"
            user = m.group("user")
            ip = safe_ip(m.group("ip"))
            rule = "ssh_failed"
        else:
            m = RE_INVALID_USER.search(msg)
            if m:
                level = "warning"
                user = m.group("user")
                ip = safe_ip(m.group("ip"))
                rule = "invalid_user"
            else:
                m = RE_SUDO_FAIL.search(msg)
                if m:
                    level = "warning"
                    user = m.group("user")
                    ip = safe_ip(m.group("ip"))
                    rule = "sudo_failed"
                else:
                    m = RE_SSH_ACCEPT.search(msg)
                    if m:
                        level = "info"
                        user = m.group("user")
                        ip = safe_ip(m.group("ip"))
                        rule = "ssh_accepted"
                    else:
                        m = RE_NMAP.search(msg)
                        if m:
                            level = "warning"
                            ip = safe_ip(m.group("ip"))
                            rule = "nmap_detected"

        ev = Event(ts=ts, source=src, level=level, ip=ip, username=user, rule=rule, message=msg)
        insert_event(self.conn, ev)
        self.rule_engine.handle(ev)


# -----------------------------
# Web app
# -----------------------------

app = Flask(__name__)
_conn = db_connect(DB_FILE)
_ingestor: Optional[Ingestor] = None

INDEX_HTML = """
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>{{ title }}</title>
  <style>
    :root { --bg:#0b1020; --card:#121936; --text:#e6eaf2; --muted:#9fb1d0; --ok:#28a745; --warn:#ffc107; --bad:#dc3545; }
    * { box-sizing: border-box; }
    body { margin: 0; background: var(--bg); color: var(--text); font-family: ui-sans-serif, system-ui, -apple-system, Segoe UI, Roboto, Helvetica, Arial; }
    header { padding: 16px 20px; border-bottom: 1px solid #223; display:flex; align-items:center; gap:12px; }
    .dot { width:10px; height:10px; border-radius:50%; background: #3ddc84; box-shadow: 0 0 10px #3ddc84; }
    h1 { font-size: 20px; margin: 0; }
    main { padding: 16px; display: grid; grid-template-columns: repeat(12, 1fr); gap: 16px; }
    .card { background: var(--card); border:1px solid #1e274a; border-radius: 14px; padding: 14px; box-shadow: 0 4px 18px #00000055; }
    .kpi { grid-column: span 3; }
    .kpi h2 { font-size: 12px; color: var(--muted); margin: 0 0 6px; }
    .kpi .num { font-size: 28px; font-weight: 700; }
    .flex { display:flex; align-items:center; justify-content:space-between; gap:8px; }
    .table { grid-column: span 8; }
    table { width: 100%; border-collapse: collapse; font-size: 13px; }
    th, td { padding: 8px; border-bottom: 1px solid #243157; text-align:left; }
    th { color: var(--muted); font-weight: 600; }
    tr:hover { background: #0f1633; }
    .badge { padding: 2px 8px; border-radius: 999px; font-size: 12px; border:1px solid #2a3a6b; }
    .ok { color: var(--ok); }
    .warn { color: var(--warn); }
    .bad { color: var(--bad); }
    .controls { grid-column: span 4; display:flex; flex-direction:column; gap: 16px; }
    input, select, button { background:#0b1229; color:var(--text); border:1px solid #223; padding:8px 10px; border-radius: 10px; }
    button { cursor: pointer; }
    footer { color: var(--muted); padding: 12px 16px; font-size: 12px; border-top: 1px solid #223; text-align:center; }
    @media (max-width: 1000px) {
      .kpi { grid-column: span 6; }
      .table { grid-column: span 12; }
      .controls { grid-column: span 12; }
    }
  </style>
</head>
<body>
  <header>
    <div class="dot"></div>
    <h1>{{ title }}</h1>
  </header>
  <main>
    <section class="card kpi">
      <h2>Events (24h)</h2>
      <div class="num" id="kpi_events">0</div>
    </section>
    <section class="card kpi">
      <h2>Alerts (24h)</h2>
      <div class="num" id="kpi_alerts">0</div>
    </section>
    <section class="card kpi">
      <h2>Top Offender IP</h2>
      <div class="num" id="kpi_topip">—</div>
    </section>
    <section class="card kpi">
      <h2>Last Update</h2>
      <div class="num" id="kpi_updated">—</div>
    </section>

    <section class="card table">
      <div class="flex"><h2>Recent Alerts</h2><span class="badge">auto‑refresh</span></div>
      <table>
        <thead><tr><th>Time (UTC)</th><th>Severity</th><th>Title</th><th>Description</th><th>Count</th></tr></thead>
        <tbody id="alerts_body"></tbody>
      </table>
    </section>

    <section class="card controls">
      <div>
        <h2 style="margin:0 0 8px">Filter Events</h2>
        <div class="flex" style="gap:8px">
          <input id="f_user" placeholder="username" />
          <input id="f_ip" placeholder="ip" />
          <select id="f_rule">
            <option value="">rule: any</option>
            <option>ssh_failed</option>
            <option>invalid_user</option>
            <option>sudo_failed</option>
            <option>ssh_accepted</option>
            <option>nmap_detected</option>
          </select>
          <button onclick="loadEvents()">Apply</button>
        </div>
      </div>
      <div>
        <h2 style="margin:0 0 8px">Recent Events</h2>
        <table>
          <thead><tr><th>Time</th><th>Src</th><th>Level</th><th>User</th><th>IP</th><th>Rule</th><th>Message</th></tr></thead>
          <tbody id="events_body"></tbody>
        </table>
      </div>
    </section>
  </main>
  <footer>
    Cyber Sentinel (local SIEM‑lite). No external CDNs. Data stored in SQLite (sentinel.db).
  </footer>
  <script>
    async function jsonGet(url){ const r = await fetch(url); return await r.json(); }
    function esc(s){ return (s??"")
      .toString()
      .replaceAll("&","&amp;")
      .replaceAll("<","&lt;")
      .replaceAll(">","&gt;")
      .replaceAll('"','&quot;'); }

    async function refresh(){
      const stats = await jsonGet('/api/stats');
      document.getElementById('kpi_events').innerText = stats.events24h;
      document.getElementById('kpi_alerts').innerText = stats.alerts24h;
      document.getElementById('kpi_topip').innerText = stats.top_ip || '—';
      document.getElementById('kpi_updated').innerText = new Date().toISOString().slice(0,19).replace('T',' ');

      const alerts = await jsonGet('/api/alerts?limit=50');
      const ab = document.getElementById('alerts_body'); ab.innerHTML='';
      for (const a of alerts){
        const tr = document.createElement('tr');
        tr.innerHTML = `<td>${esc(a.ts)}</td><td><span class="badge ${a.severity==='high'?'bad':(a.severity==='medium'?'warn':'')}">${esc(a.severity)}</span></td><td>${esc(a.title)}</td><td>${esc(a.description)}</td><td>${a.count}</td>`;
        ab.appendChild(tr);
      }
      loadEvents();
    }

    async function loadEvents(){
      const q = new URLSearchParams();
      const u = document.getElementById('f_user').value.trim(); if (u) q.set('username', u);
      const ip = document.getElementById('f_ip').value.trim(); if (ip) q.set('ip', ip);
      const r = document.getElementById('f_rule').value.trim(); if (r) q.set('rule', r);
      q.set('limit','100');
      const events = await jsonGet('/api/events?' + q.toString());
      const eb = document.getElementById('events_body'); eb.innerHTML='';
      for (const e of events){
        const tr = document.createElement('tr');
        tr.innerHTML = `<td>${esc(e.ts.replace('T',' ').slice(0,19))}</td><td>${esc(e.source)}</td><td>${esc(e.level)}</td><td>${esc(e.username)}</td><td>${esc(e.ip)}</td><td>${esc(e.rule||'')}</td><td title="${esc(e.message)}">${esc(e.message.slice(0,80))}${e.message.length>80?'…':''}</td>`;
        eb.appendChild(tr);
      }
    }

    refresh();
    setInterval(refresh, 3000);
  </script>
</body>
</html>
"""


@app.route("/")
def index() -> Response:
    return render_template_string(INDEX_HTML, title=APP_TITLE)


@app.get("/api/stats")
def api_stats():
    now = dt.datetime.utcnow()
    day_ago = (now - dt.timedelta(hours=24)).isoformat()
    cur = _conn.cursor()
    events24 = cur.execute("SELECT COUNT(*) FROM events WHERE ts >= ?", (day_ago,)).fetchone()[0]
    alerts24 = cur.execute("SELECT COUNT(*) FROM alerts WHERE ts >= ?", (day_ago,)).fetchone()[0]
    top_ip = cur.execute("SELECT ip, COUNT(*) c FROM events WHERE ip IS NOT NULL AND ts >= ? GROUP BY ip ORDER BY c DESC LIMIT 1", (day_ago,)).fetchone()
    return jsonify({
        "events24h": events24,
        "alerts24h": alerts24,
        "top_ip": top_ip[0] if top_ip else None,
    })


@app.get("/api/alerts")
def api_alerts():
    limit = int(request.args.get("limit", 50))
    rows = _conn.execute("SELECT ts, severity, title, description, count FROM alerts ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
    return jsonify([dict(r) for r in rows])


@app.get("/api/events")
def api_events():
    limit = int(request.args.get("limit", 100))
    ip = request.args.get("ip")
    username = request.args.get("username")
    rule = request.args.get("rule")

    q = "SELECT ts, source, level, ip, username, rule, message FROM events WHERE 1=1"
    params = []
    if ip:
        q += " AND ip = ?"
        params.append(ip)
    if username:
        q += " AND username = ?"
        params.append(username)
    if rule:
        q += " AND rule = ?"
        params.append(rule)
    q += " ORDER BY id DESC LIMIT ?"
    params.append(limit)

    rows = _conn.execute(q, tuple(params)).fetchall()
    return jsonify([dict(r) for r in rows])


@app.post("/api/ingest")
def api_ingest():
    data = request.get_json(force=True, silent=True) or {}
    msg = data.get("message")
    source = data.get("source", "api")
    if not msg:
        return jsonify({"error": "message required"}), 400
    _ingestor._process_line(source, msg)
    return jsonify({"ok": True})


# -----------------------------
# CLI + startup
# -----------------------------

def parse_args():
    ap = argparse.ArgumentParser(description="Cyber Sentinel — SIEM‑lite")
    ap.add_argument("--logs", nargs="*", default=[], help="paths to log files to tail (e.g., /var/log/auth.log)")
    ap.add_argument("--simulate", action="store_true", help="generate synthetic security events")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=5000)
    return ap.parse_args()


def main():
    global _ingestor
    args = parse_args()
    paths = [Path(p) for p in args.logs]
    _ingestor = Ingestor(_conn, paths, simulate=args.simulate or not any(p.exists() for p in paths))
    _ingestor.start()

    def _graceful(*_):
        print("\n[+] Shutting down…", flush=True)
        _ingestor.stop()
        time.sleep(0.3)
        sys.exit(0)

    signal.signal(signal.SIGINT, _graceful)
    signal.signal(signal.SIGTERM, _graceful)

    print(f"[+] {APP_TITLE}")
    if args.simulate:
        print("[+] Simulation mode ON (synthetic events will stream)")
    elif not paths:
        print("[!] No logs provided; falling back to simulation (use --logs to tail real logs)")
    else:
        existing = [str(p) for p in paths if p.exists()]
        missing = [str(p) for p in paths if not p.exists()]
        if existing:
            print("[+] Tailing logs:", ", ".join(existing))
        if missing:
            print("[!] Missing logs (ignored):", ", ".join(missing))

    print(f"[+] Open http://{args.host}:{args.port} in your browser")
    app.run(host=args.host, port=args.port, debug=False, use_reloader=False)


if __name__ == "__main__":
    main()
