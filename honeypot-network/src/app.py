"""
app.py
------
A read-only dashboard over the honeypot database.

    python -m src.app          # http://127.0.0.1:5000

READ-ONLY IS A SECURITY PROPERTY, NOT A LIMITATION
--------------------------------------------------
Every value shown here was typed by an attacker. The dashboard therefore does
two things carefully:

  1. It only READS the database. There is no endpoint that writes, so a
     malicious record cannot trigger a state change.
  2. It escapes attacker-controlled text before rendering. Jinja2's
     autoescaping is on, and it is the only thing standing between "an
     attacker sent an XSS payload as a username" and "the XSS ran in the
     operator's browser." That would be a bitterly ironic way to be owned by
     your own honeypot, so there is a test for it.
"""

from __future__ import annotations

import json

from flask import Flask, render_template_string, request

from .honeypot import severity
from .services import SERVICES
from .store import Store

app = Flask(__name__)
DB_PATH = "logs/honeypot.db"


def store() -> Store:
    return Store(DB_PATH)


PAGE = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Honeypot Console</title>
<style>
  :root {
    --bg:#0b0e13; --card:#141a22; --line:#232c38; --text:#e6edf3;
    --muted:#8b98a5; --low:#3b82f6; --medium:#d29922; --high:#e8833a; --critical:#e5534b;
    --accent:#2f9e6e;
  }
  *{box-sizing:border-box}
  body{margin:0;padding:26px 16px;background:var(--bg);color:var(--text);
       font:14px/1.5 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif}
  .wrap{max-width:1120px;margin:0 auto}
  h1{font-size:21px;margin:0 0 3px}
  .sub{color:var(--muted);font-size:13px;margin:0 0 22px}
  .tiles{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px;margin-bottom:22px}
  .tile{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:14px 16px}
  .tile .n{font-size:26px;font-weight:700}
  .tile .l{font-size:11px;text-transform:uppercase;letter-spacing:.06em;color:var(--muted);margin-top:2px}
  .grid{display:grid;grid-template-columns:1fr 1fr;gap:18px}
  @media(max-width:880px){.grid{grid-template-columns:1fr}}
  .panel{background:var(--card);border:1px solid var(--line);border-radius:10px;overflow:hidden;margin-bottom:18px}
  .panel h2{font-size:12px;text-transform:uppercase;letter-spacing:.07em;color:var(--muted);
            margin:0;padding:12px 16px;border-bottom:1px solid var(--line)}
  table{width:100%;border-collapse:collapse;font-size:13px}
  th,td{padding:8px 16px;text-align:left;border-bottom:1px solid var(--line);vertical-align:top}
  th{color:var(--muted);font-weight:500;font-size:11px;text-transform:uppercase;letter-spacing:.04em}
  tr:last-child td{border-bottom:0}
  code{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:12px;
       background:#0b1219;padding:1px 5px;border-radius:4px;word-break:break-all}
  .pill{display:inline-block;padding:1px 8px;border-radius:20px;font-size:11px;font-weight:600}
  .low{background:rgba(59,130,246,.15);color:var(--low)}
  .medium{background:rgba(210,153,34,.15);color:var(--medium)}
  .high{background:rgba(232,131,58,.15);color:var(--high)}
  .critical{background:rgba(229,83,75,.15);color:var(--critical)}
  .flag{color:var(--critical);font-weight:600}
  .bar{height:7px;border-radius:4px;background:#0b1219;overflow:hidden}
  .bar>div{height:100%;background:var(--accent)}
  .num{text-align:right;font-family:ui-monospace,SFMono-Regular,Menlo,monospace}
  .empty{padding:26px 16px;color:var(--muted);text-align:center}
  a{color:var(--accent);text-decoration:none}
</style>
</head>
<body>
<div class="wrap">
  <h1>Honeypot Console</h1>
  <p class="sub">Read-only view of recorded attacker activity. Every value below was typed by an attacker &mdash; and is escaped before display.</p>

  <div class="tiles">
    <div class="tile"><div class="n">{{ s.sessions }}</div><div class="l">Sessions</div></div>
    <div class="tile"><div class="n">{{ s.attackers }}</div><div class="l">Distinct sources</div></div>
    <div class="tile"><div class="n" style="color:var(--critical)">{{ s.credential_attempts }}</div><div class="l">Login attempts</div></div>
    <div class="tile"><div class="n">{{ s.interactions }}</div><div class="l">Interactions</div></div>
    <div class="tile"><div class="n">{{ '{:,}'.format(s.bytes_in) }}</div><div class="l">Bytes received</div></div>
  </div>

  {% if s.sessions == 0 %}
  <div class="panel"><div class="empty">
    No activity yet. Generate some with:<br><br>
    <code>python -m src.cli demo</code>
  </div></div>
  {% else %}

  <div class="grid">
    <div class="panel">
      <h2>Top credentials tried</h2>
      <table>
        <tr><th>Attempts</th><th>Username</th><th>Password</th></tr>
        {% for u, p, n in credentials %}
        <tr><td class="num">{{ n }}</td><td><code>{{ u }}</code></td><td><code>{{ p }}</code></td></tr>
        {% endfor %}
      </table>
    </div>
    <div class="panel">
      <h2>What attackers tried</h2>
      <table>
        {% for label, n in payloads %}
        <tr><td class="num" style="width:60px">{{ n }}</td><td>{{ label }}</td></tr>
        {% endfor %}
      </table>
    </div>
  </div>

  <div class="grid">
    <div class="panel">
      <h2>Services probed</h2>
      <table>
        {% for row in services %}
        <tr>
          <td style="width:80px">{{ row.service }}</td>
          <td>{{ row.sessions }} sessions
            <div class="bar"><div style="width:{{ (100 * row.sessions / peak) | round }}%"></div></div>
          </td>
        </tr>
        {% endfor %}
      </table>
    </div>
    <div class="panel">
      <h2>Top sources by threat</h2>
      <table>
        <tr><th>Source</th><th>Threat</th><th class="num">Sessions</th></tr>
        {% for row in attackers %}
        <tr>
          <td><code>{{ row.source_ip }}</code></td>
          <td><span class="pill {{ sev(row.threat) }}">{{ row.threat }} {{ sev(row.threat) }}</span></td>
          <td class="num">{{ row.sessions }}</td>
        </tr>
        {% endfor %}
      </table>
    </div>
  </div>

  <div class="panel">
    <h2>Recent activity</h2>
    <table>
      <tr><th>Time</th><th>Source</th><th>Service</th><th>Kind</th><th>Detail</th></tr>
      {% for row in recent %}
      <tr>
        <td style="white-space:nowrap;color:var(--muted)">{{ row.when }}</td>
        <td><code>{{ row.source_ip }}</code></td>
        <td>{{ row.service }}</td>
        <td>{{ row.kind }}</td>
        <td>
          <code>{{ row.summary }}</code>
          {% if row.flag %}<span class="flag">&larr; {{ row.flag }}</span>{% endif %}
        </td>
      </tr>
      {% endfor %}
    </table>
  </div>
  {% endif %}
</div>
</body>
</html>
"""


@app.route("/")
def index():
    database = store()
    try:
        summary = database.summary()
        services = database.service_counts()
        peak = max((row["sessions"] for row in services), default=1)

        recent = []
        for row in database.interactions(limit=60):
            detail = json.loads(row["detail"])
            if row["kind"] == "auth":
                summary_text = f"{detail.get('username','')} / {detail.get('password','')}"
            elif row["kind"] == "request":
                summary_text = f"{detail.get('method','')} {detail.get('path','')}"
            elif row["kind"] == "command":
                summary_text = detail.get("command", "")
            else:
                summary_text = detail.get("client_version", "")
            tool = detail.get("tool", "")
            flag = (detail.get("payload") or detail.get("exploit")
                    or (tool if ("botnet" in tool or "scanner" in tool) else ""))
            import time as _time
            recent.append({
                "when": _time.strftime("%H:%M:%S", _time.localtime(row["at"])),
                "source_ip": row["source_ip"], "service": row["service"],
                "kind": row["kind"], "summary": summary_text, "flag": flag,
            })

        return render_template_string(
            PAGE, s=summary, services=services, peak=peak,
            credentials=database.credentials(12),
            payloads=database.payload_counts(12),
            attackers=database.top_attackers(10),
            recent=recent, sev=severity)
    finally:
        database.close()


@app.route("/api/summary")
def api_summary():
    database = store()
    try:
        from flask import jsonify
        return jsonify(database.summary())
    finally:
        database.close()


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)
