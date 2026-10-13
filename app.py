"""Local-only academic demonstration of login lockouts and honeypot accounts."""
import csv
import hashlib
import hmac
import json
import os
import secrets
import threading
import time
from pathlib import Path
from flask import Flask, render_template_string, request, jsonify, has_request_context
from collections import Counter
from datetime import datetime
from detection import assess

BASE = Path(__file__).resolve().parent
DATA = BASE / 'runtime_data'
DATA.mkdir(exist_ok=True)
USERS_FILE = DATA / 'users.json'
CSV_FILE = DATA / 'timeline.csv'
LOCK = threading.Lock()
MAX_FAILED = 3
BASE_LOCK_SECONDS = 10
HONEYPOT_LOCK_SECONDS = 600
app = Flask(__name__)


def password_hash(password, salt=None):
    salt = salt or secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac('sha256', password.encode(), bytes.fromhex(salt), 200_000)
    return {'salt': salt, 'password_hash': digest.hex()}


def verify_password(password, user):
    expected = bytes.fromhex(user['password_hash'])
    candidate = hashlib.pbkdf2_hmac('sha256', password.encode(), bytes.fromhex(user['salt']), 200_000)
    return hmac.compare_digest(expected, candidate)


def initial_users():
    # Deliberately public demonstration credentials; never reuse real passwords.
    return {
        'alice': dict(password_hash('DemoPass123!'), failed=0, locked_until=0, honeypot=False),
        'admin_test': dict(password_hash('HoneyDemo123!'), failed=0, locked_until=0, honeypot=True),
        'root_local': dict(password_hash('HoneyRoot123!'), failed=0, locked_until=0, honeypot=True),
    }


def load_users():
    if not USERS_FILE.exists():
        users = initial_users()
        save_users(users)
        return users
    return json.loads(USERS_FILE.read_text(encoding='utf-8'))


def save_users(users):
    temp = USERS_FILE.with_suffix('.tmp')
    temp.write_text(json.dumps(users, indent=2), encoding='utf-8')
    temp.replace(USERS_FILE)


def record_attempt(username, success, reason):
    new_file = not CSV_FILE.exists() or CSV_FILE.stat().st_size == 0
    with CSV_FILE.open('a', newline='', encoding='utf-8') as handle:
        writer = csv.writer(handle)
        if new_file:
            writer.writerow(['ts', 'username', 'success', 'reason', 'time', 'scenario'])
        ts = time.time()
        writer.writerow([ts, username[:80], success, reason, time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(ts)), (request.headers.get('X-Demo-Scenario', '')[:30] if has_request_context() else '')])


def check_login(username, password, now=None):
    now = time.time() if now is None else now
    with LOCK:
        users = load_users()
        user = users.get(username)
        if user is None:
            record_attempt(username, False, 'unknown_user')
            return 'Invalid credentials'
        if user['locked_until'] > now:
            record_attempt(username, False, 'locked')
            return 'Account locked. Please try again later.'
        # Honeypots never permit login, even with their published demo password.
        if user['honeypot']:
            user['failed'] += 1
            user['locked_until'] = now + HONEYPOT_LOCK_SECONDS
            save_users(users)
            record_attempt(username, False, 'honeypot_triggered')
            return 'Account locked. Please try again later.'
        if verify_password(password, user):
            user['failed'] = 0
            user['locked_until'] = 0
            save_users(users)
            record_attempt(username, True, 'success')
            return 'Login successful (demo only)'
        user['failed'] += 1
        if user['failed'] >= MAX_FAILED:
            user['locked_until'] = now + BASE_LOCK_SECONDS
            user['failed'] = 0
            reason = 'locked_due_failed_attempts'
            message = 'Account locked. Please try again later.'
        else:
            reason = 'invalid'
            message = 'Invalid credentials'
        save_users(users)
        record_attempt(username, False, reason)
        return message


PAGE = '''<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Login Protection Simulator</title>
<style>body{font:16px system-ui;background:#f2f4f8;min-height:100vh;display:grid;place-items:center;margin:0;color:#172033}main{background:white;padding:2rem;border-radius:14px;box-shadow:0 8px 28px #17203322;width:min(90vw,390px)}h1{font-size:1.45rem}label{display:block;margin:1rem 0 .35rem}input{width:100%;padding:.7rem;box-sizing:border-box;border:1px solid #aeb8c5;border-radius:7px}button{margin-top:1.3rem;padding:.75rem;background:#5145a5;color:white;border:0;border-radius:7px;width:100%;cursor:pointer}.notice{padding:.8rem;background:#edf0ff;border-radius:7px;margin-top:1rem}small{color:#536176}</style></head><body><main><h1>Login Protection Simulator</h1><p>Local academic demonstration of account lockouts and honeypot detection.</p><form method="post"><label for="username">Username</label><input id="username" name="username" maxlength="80" required autocomplete="username"><label for="password">Password</label><input id="password" type="password" name="password" required autocomplete="off"><button>Try login</button></form>{% if message %}<div class="notice" role="status">{{ message }}</div>{% endif %}<p><a href="/dashboard">View live security dashboard →</a></p><p><small>Use only demo accounts. No real authentication or session is created.</small></p></main></body></html>'''




def dashboard_data():
    # Aggregate events without passwords
    with LOCK:
        if not CSV_FILE.exists():
            rows = []
        else:
            with CSV_FILE.open(newline='', encoding='utf-8') as handle:
                rows = list(csv.DictReader(handle))
        users = load_users()
    reasons = Counter(row['reason'] for row in rows)
    total = len(rows)
    successful = sum(row['success'].lower() == 'true' for row in rows)
    current = time.time()
    buckets = Counter(datetime.fromtimestamp(float(row['ts'])).strftime('%H:%M:%S') for row in rows)
    recent = [{'time': row['time'], 'username': row['username'], 'reason': row['reason']} for row in rows[-12:][::-1]]
    risk = assess(rows, current)
    scenario_counts = Counter(row.get('scenario', '') for row in rows if row.get('scenario'))
    return {'risk': risk, 'scenarios': dict(scenario_counts), 'total': total, 'successful': successful, 'failed': total-successful,
            'lockout_events': reasons['locked_due_failed_attempts'] + reasons['locked'],
            'honeypot_events': reasons['honeypot_triggered'],
            'active_locks': sum(u['locked_until'] > current for u in users.values()),
            'reasons': dict(reasons),
            'timeline': [{'time': k, 'attempts': v} for k, v in sorted(buckets.items())[-20:]],
            'recent': recent}


DASHBOARD = '''<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Security Monitor | Login Simulator</title>
<style>body{margin:0;background:#0b1220;color:#e6eefb;font:15px system-ui}header{padding:22px max(20px,calc((100vw - 1080px)/2));background:#111c30;border-bottom:1px solid #26364e}header h1{margin:0;font-size:25px}header p{color:#a8bad1;margin:7px 0}main{max-width:1080px;margin:auto;padding:22px}.metrics{display:grid;grid-template-columns:repeat(auto-fit,minmax(155px,1fr));gap:13px}.tile,.panel{background:#15233a;border:1px solid #2b3d56;border-radius:12px;padding:17px}.tile small{display:block;color:#b0c4db}.tile strong{display:block;font-size:32px;margin-top:8px}.panels{display:grid;grid-template-columns:1fr 1fr;gap:15px;margin-top:18px}h2{font-size:17px;margin:0 0 15px}a{color:#8bc8ff}table{width:100%;border-collapse:collapse;font-size:13px}td,th{text-align:left;border-bottom:1px solid #30415a;padding:9px 5px;overflow-wrap:anywhere}th{color:#a8bad1}.bar{background:#263950;border-radius:5px;overflow:hidden;height:13px;margin:6px 0 13px}.bar>div{height:100%;background:#4db5ff}.chart{display:flex;align-items:end;gap:4px;height:145px;border-bottom:1px solid #657b93}.chart div{flex:1;min-width:4px;background:#60a5fa;border-radius:3px 3px 0 0}.muted{color:#a8bad1}.pill{display:inline-block;background:#233a53;padding:6px 10px;border-radius:20px}@media(max-width:700px){.panels{grid-template-columns:1fr}}</style></head><body><header><h1>🛡 Login Security Monitor</h1><p>Local-only academic brute-force protection demonstration · <a href="/">Manual login</a></p></header><main><p class="muted">Auto-refresh every 2 seconds. Run <code>python attacker.py --attempts 30</code> in a second terminal.</p><section class="metrics"><div class="tile"><small>Total attempts</small><strong id="total">0</strong></div><div class="tile"><small>Failed attempts</small><strong id="failed">0</strong></div><div class="tile"><small>Successful logins</small><strong id="successful">0</strong></div><div class="tile"><small>Lockout events</small><strong id="lockout_events">0</strong></div><div class="tile"><small>Honeypot alerts</small><strong id="honeypot_events">0</strong></div><div class="tile"><small>Accounts currently locked</small><strong id="active_locks">0</strong></div></section><section class="panel" style="margin-top:18px"><h2>Explainable rolling-window detection (last 60 seconds)</h2><p><strong id="risk_score">0</strong>/100 · <span id="risk_level">low</span> risk · <span id="risk_pattern">insufficient evidence</span></p><p class="muted" id="risk_signals">No recent events</p><p class="muted">Heuristic classification, not proof of attack type. Existing account lockouts and honeypots remain the prevention controls.</p></section><section class="panels"><div class="panel"><h2>Attempts over time</h2><div id="chart" class="chart" aria-label="Login attempts timeline"></div><p class="muted" id="chartNote">No activity yet</p></div><div class="panel"><h2>Protection outcomes</h2><div id="reasons"></div></div><div class="panel" style="grid-column:1/-1"><h2>Recent security events</h2><div style="overflow-x:auto"><table><thead><tr><th>Time</th><th>Demo account</th><th>Outcome</th></tr></thead><tbody id="events"></tbody></table></div></div></section><p class="muted">Synthetic localhost traffic only. This monitor is for teaching, not production deployment. Generated data remains on your computer.</p></main>
<script>async function refresh(){try{const response=await fetch('/api/stats',{cache:'no-store'});if(!response.ok)throw Error('Unavailable');const d=await response.json();for(const id of ['total','failed','successful','lockout_events','honeypot_events','active_locks'])document.getElementById(id).textContent=d[id];document.getElementById('risk_score').textContent=d.risk.score;document.getElementById('risk_level').textContent=d.risk.level;document.getElementById('risk_pattern').textContent=d.risk.pattern;document.getElementById('risk_signals').textContent=JSON.stringify(d.risk.signals);const chart=document.getElementById('chart');chart.replaceChildren();const max=Math.max(1,...d.timeline.map(x=>x.attempts));for(const item of d.timeline){const bar=document.createElement('div');bar.style.height=(item.attempts/max*100)+'%';bar.title=item.time+': '+item.attempts+' attempts';chart.append(bar)}document.getElementById('chartNote').textContent=d.timeline.length?'Last '+d.timeline.length+' active seconds':'No activity yet';const reasons=document.getElementById('reasons');reasons.replaceChildren();for(const [key,value] of Object.entries(d.reasons).sort((a,b)=>b[1]-a[1])){const label=document.createElement('div');label.textContent=key.replaceAll('_',' ')+': '+value;const bar=document.createElement('div');bar.className='bar';const fill=document.createElement('div');fill.style.width=(value/Math.max(1,d.total)*100)+'%';bar.append(fill);reasons.append(label,bar)}const events=document.getElementById('events');events.replaceChildren();for(const e of d.recent){const tr=document.createElement('tr');for(const value of [e.time,e.username,e.reason.replaceAll('_',' ')]){const td=document.createElement('td');td.textContent=value;tr.append(td)}events.append(tr)}}catch(err){document.getElementById('chartNote').textContent='Unable to fetch events — check server.'}}refresh();setInterval(refresh,2000)</script></body></html>'''


@app.get('/dashboard')
def dashboard():
    return render_template_string(DASHBOARD)


@app.get('/api/stats')
def stats():
    response = jsonify(dashboard_data())
    response.headers['Cache-Control'] = 'no-store'
    return response

@app.route('/', methods=['GET', 'POST'])
def login():
    message = ''
    if request.method == 'POST':
        message = check_login(request.form.get('username', '').strip()[:80], request.form.get('password', ''))
    return render_template_string(PAGE, message=message)


if __name__ == '__main__':
    app.run(host='127.0.0.1', port=5000, debug=False)
