"""30 synthetic Python files, each with ONE planted semantic bug mapped to a distinct --check-bank item, plus 30 clean twins
(same job, bug fixed). Files get neutral shuffled names (module_NN.py) so the path does not leak the answer."""
import json, random, sys
from pathlib import Path

P = {}  # item id -> (buggy, clean)

P["BANK-SEC-001"] = ("""from flask import Flask, jsonify
app = Flask(__name__)

@app.route('/admin/users/<int:uid>', methods=['DELETE'])
def delete_user(uid):
    db.execute('DELETE FROM users WHERE id = ?', (uid,))
    return jsonify(ok=True)
""", """from flask import Flask, jsonify, abort
from auth import current_user
app = Flask(__name__)

@app.route('/admin/users/<int:uid>', methods=['DELETE'])
def delete_user(uid):
    if not current_user().is_admin:
        abort(403)
    db.execute('DELETE FROM users WHERE id = ?', (uid,))
    return jsonify(ok=True)
""")
P["BANK-SEC-002"] = ("""from flask import Flask, jsonify, request
app = Flask(__name__)

@app.get('/invoices/<int:invoice_id>')
def get_invoice(invoice_id):
    row = db.query_one('SELECT * FROM invoices WHERE id = ?', (invoice_id,))
    return jsonify(row)
""", """from flask import Flask, jsonify, abort
from auth import current_user
app = Flask(__name__)

@app.get('/invoices/<int:invoice_id>')
def get_invoice(invoice_id):
    row = db.query_one('SELECT * FROM invoices WHERE id = ? AND owner_id = ?', (invoice_id, current_user().id))
    if row is None:
        abort(404)
    return jsonify(row)
""")
P["BANK-SEC-003"] = ("""from flask import Flask, request, jsonify
app = Flask(__name__)

@app.post('/profile/update')
def update_profile():
    data = request.get_json()
    uid = data['user_id']
    db.execute('UPDATE profiles SET bio = ? WHERE user_id = ?', (data['bio'], uid))
    return jsonify(ok=True)
""", """from flask import Flask, request, jsonify, session
app = Flask(__name__)

@app.post('/profile/update')
def update_profile():
    data = request.get_json()
    uid = session['user_id']
    db.execute('UPDATE profiles SET bio = ? WHERE user_id = ?', (data['bio'], uid))
    return jsonify(ok=True)
""")
P["BANK-SEC-005"] = ("""import logging
log = logging.getLogger(__name__)

def login(user, password, api_key):
    log.info('login attempt user=%s password=%s api_key=%s', user, password, api_key)
    return auth_backend.check(user, password)
""", """import logging
log = logging.getLogger(__name__)

def login(user, password, api_key):
    log.info('login attempt user=%s', user)
    return auth_backend.check(user, password)
""")
P["BANK-SEC-006"] = ("""def connect(db_url, password):
    try:
        return driver.connect(db_url, password=password)
    except driver.Error as e:
        raise RuntimeError(f'cannot connect to {db_url} with password {password}: {e}')
""", """def connect(db_url, password):
    try:
        return driver.connect(db_url, password=password)
    except driver.Error as e:
        raise RuntimeError(f'cannot connect to {db_url}: {e.__class__.__name__}') from None
""")
P["BANK-SEC-010"] = ("""from flask import Flask, request, send_file
app = Flask(__name__)
BASE = '/srv/reports'

@app.get('/download')
def download():
    name = request.args['file']
    return send_file(BASE + '/' + name)
""", """import os
from flask import Flask, request, send_from_directory
app = Flask(__name__)
BASE = '/srv/reports'

@app.get('/download')
def download():
    name = os.path.basename(request.args['file'])
    return send_from_directory(BASE, name)
""")
P["BANK-SEC-011"] = ("""import os
from flask import Flask, request
app = Flask(__name__)

@app.get('/ping')
def ping():
    host = request.args['host']
    return os.popen('ping -c 1 ' + host).read()
""", """import subprocess, re
from flask import Flask, request, abort
app = Flask(__name__)

@app.get('/ping')
def ping():
    host = request.args['host']
    if not re.fullmatch(r'[A-Za-z0-9.-]{1,253}', host):
        abort(400)
    return subprocess.run(['ping', '-c', '1', host], capture_output=True, text=True, timeout=5).stdout
""")
P["BANK-SEC-013"] = ("""from flask import Flask, request, render_template_string
app = Flask(__name__)

@app.get('/greet')
def greet():
    tpl = '<h1>Hello ' + request.args.get('name', 'guest') + '</h1>'
    return render_template_string(tpl)
""", """from flask import Flask, request, render_template_string
app = Flask(__name__)

@app.get('/greet')
def greet():
    return render_template_string('<h1>Hello {{ name }}</h1>', name=request.args.get('name', 'guest'))
""")
P["BANK-SEC-015"] = ("""from flask import Flask, request, redirect
app = Flask(__name__)

@app.get('/login/done')
def done():
    return redirect(request.args.get('next', '/'))
""", """from urllib.parse import urlparse
from flask import Flask, request, redirect
app = Flask(__name__)

@app.get('/login/done')
def done():
    nxt = request.args.get('next', '/')
    if urlparse(nxt).netloc:
        nxt = '/'
    return redirect(nxt)
""")
P["BANK-SEC-016"] = ("""import requests
from flask import Flask, request
app = Flask(__name__)

@app.get('/preview')
def preview():
    url = request.args['url']
    return requests.get(url, timeout=5).text[:500]
""", """import ipaddress, socket, requests
from urllib.parse import urlparse
from flask import Flask, request, abort
app = Flask(__name__)
ALLOWED = {'images.example.com', 'cdn.example.com'}

@app.get('/preview')
def preview():
    url = request.args['url']
    if urlparse(url).hostname not in ALLOWED:
        abort(400)
    return requests.get(url, timeout=5).text[:500]
""")
P["BANK-SEC-018"] = ("""import random, string

def new_reset_token():
    alphabet = string.ascii_letters + string.digits
    return ''.join(random.choice(alphabet) for _ in range(24))
""", """import secrets

def new_reset_token():
    return secrets.token_urlsafe(24)
""")
P["BANK-SEC-023"] = ("""import jwt

def user_from_token(token):
    claims = jwt.decode(token, options={'verify_signature': False})
    return claims['sub']
""", """import jwt

def user_from_token(token, key):
    claims = jwt.decode(token, key, algorithms=['HS256'], options={'require': ['exp', 'sub']})
    return claims['sub']
""")
P["BANK-SEC-026"] = ("""def check_webhook(request, expected_signature):
    sig = request.headers.get('X-Signature', '')
    if sig == expected_signature:
        return True
    return False
""", """import hmac

def check_webhook(request, expected_signature):
    sig = request.headers.get('X-Signature', '')
    return hmac.compare_digest(sig, expected_signature)
""")
P["BANK-RELIAB-005"] = ("""import time, requests

def fetch(url):
    for attempt in range(5):
        try:
            return requests.get(url, timeout=3)
        except requests.RequestException:
            time.sleep(1)
    raise RuntimeError('gave up')
""", """import time, random, requests

def fetch(url):
    for attempt in range(5):
        try:
            return requests.get(url, timeout=3)
        except requests.RequestException:
            time.sleep(min(30, 2 ** attempt) * random.uniform(0.5, 1.5))
    raise RuntimeError('gave up')
""")
P["BANK-RELIAB-006"] = ("""import time

def wait_for_service(client):
    while True:
        try:
            return client.ping()
        except ConnectionError:
            time.sleep(0.5)
""", """import time

def wait_for_service(client, deadline_s=60):
    end = time.monotonic() + deadline_s
    while time.monotonic() < end:
        try:
            return client.ping()
        except ConnectionError:
            time.sleep(0.5)
    raise TimeoutError('service did not come up')
""")
P["BANK-RELIAB-011"] = ("""import os

def claim_job(path, worker):
    if not os.path.exists(path):
        with open(path, 'w') as f:
            f.write(worker)
        return True
    return False
""", """import os

def claim_job(path, worker):
    try:
        fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
    except FileExistsError:
        return False
    with os.fdopen(fd, 'w') as f:
        f.write(worker)
    return True
""")
P["BANK-RELIAB-012"] = ("""import threading

counts = {}

def record(event):
    counts[event] = counts.get(event, 0) + 1

def start(events):
    ts = [threading.Thread(target=record, args=(e,)) for e in events]
    for t in ts: t.start()
    for t in ts: t.join()
""", """import threading

counts = {}
_lock = threading.Lock()

def record(event):
    with _lock:
        counts[event] = counts.get(event, 0) + 1

def start(events):
    ts = [threading.Thread(target=record, args=(e,)) for e in events]
    for t in ts: t.start()
    for t in ts: t.join()
""")
P["BANK-RELIAB-013"] = ("""import json

def save_state(path, state):
    with open(path, 'w') as f:
        json.dump(state, f)
""", """import json, os, tempfile

def save_state(path, state):
    fd, tmp = tempfile.mkstemp(dir=os.path.dirname(path) or '.')
    with os.fdopen(fd, 'w') as f:
        json.dump(state, f)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, path)
""")
P["BANK-RELIAB-016"] = ("""def load_lines(path):
    f = open(path)
    lines = [l.strip() for l in f]
    return lines
""", """def load_lines(path):
    with open(path) as f:
        return [l.strip() for l in f]
""")
P["BANK-RELIAB-019"] = ("""import queue, threading

jobs = queue.Queue()

def producer(source):
    for item in source:
        jobs.put(item)

def worker():
    while True:
        handle(jobs.get())
""", """import queue, threading

jobs = queue.Queue(maxsize=1000)

def producer(source):
    for item in source:
        jobs.put(item)

def worker():
    while True:
        handle(jobs.get())
""")
P["BANK-RELIAB-020"] = ("""_cache = {}

def get_profile(user_id):
    if user_id not in _cache:
        _cache[user_id] = load_profile_from_db(user_id)
    return _cache[user_id]
""", """from functools import lru_cache

@lru_cache(maxsize=10_000)
def get_profile(user_id):
    return load_profile_from_db(user_id)
""")
P["BANK-RELIAB-033"] = ("""import time

_cache = {}
TTL = 60

def get_rates():
    hit = _cache.get('rates')
    if hit and time.time() - hit[0] < TTL:
        return hit[1]
    value = expensive_rates_query()
    _cache['rates'] = (time.time(), value)
    return value
""", """import time, threading

_cache = {}
_lock = threading.Lock()
TTL = 60

def get_rates():
    hit = _cache.get('rates')
    if hit and time.monotonic() - hit[0] < TTL:
        return hit[1]
    with _lock:
        hit = _cache.get('rates')
        if hit and time.monotonic() - hit[0] < TTL:
            return hit[1]
        value = expensive_rates_query()
        _cache['rates'] = (time.monotonic(), value)
        return value
""")
P["BANK-RELIAB-034"] = ("""import time

def run_with_budget(task, seconds):
    start = time.time()
    while time.time() - start < seconds:
        if task.step():
            return True
    return False
""", """import time

def run_with_budget(task, seconds):
    start = time.monotonic()
    while time.monotonic() - start < seconds:
        if task.step():
            return True
    return False
""")
P["BANK-RELIAB-040"] = ("""def transfer(conn, src, dst, amount):
    cur = conn.cursor()
    cur.execute('UPDATE accounts SET balance = balance - ? WHERE id = ?', (amount, src))
    cur.execute('UPDATE accounts SET balance = balance + ? WHERE id = ?', (amount, dst))
    conn.commit()
""", """def transfer(conn, src, dst, amount):
    cur = conn.cursor()
    try:
        cur.execute('UPDATE accounts SET balance = balance - ? WHERE id = ?', (amount, src))
        cur.execute('UPDATE accounts SET balance = balance + ? WHERE id = ?', (amount, dst))
        conn.commit()
    except Exception:
        conn.rollback()
        raise
""")
P["BANK-RELIAB-041"] = ("""import subprocess

def convert(src, dst):
    subprocess.run(['ffmpeg', '-i', src, dst])
    return dst
""", """import subprocess

def convert(src, dst):
    subprocess.run(['ffmpeg', '-i', src, dst], check=True, timeout=300)
    return dst
""")
P["BANK-RELIAB-001"] = ("""def sync_all(items, client):
    for it in items:
        try:
            client.push(it)
        except Exception:
            pass
""", """import logging
log = logging.getLogger(__name__)

def sync_all(items, client):
    failed = []
    for it in items:
        try:
            client.push(it)
        except ConnectionError:
            log.exception('push failed for %s', it)
            failed.append(it)
    return failed
""")
P["API-002"] = ("""def add_tag(tag, tags=[]):
    tags.append(tag)
    return tags
""", """def add_tag(tag, tags=None):
    tags = [] if tags is None else tags
    tags.append(tag)
    return tags
""")
P["BANK-ARCH-018"] = ("""def order_total(items):
    total = 0.0
    for price, qty in items:
        total += price * qty * 1.2
    return total

def charge(card, items):
    return card.charge(order_total(items))
""", """from decimal import Decimal

def order_total(items):
    total = Decimal('0')
    for price, qty in items:
        total += Decimal(price) * qty * Decimal('1.2')
    return total.quantize(Decimal('0.01'))

def charge(card, items):
    return card.charge(order_total(items))
""")
P["BANK-ARCH-037"] = ("""import threading, time

def start_worker(job):
    t = threading.Thread(target=job.run)
    t.start()
    time.sleep(5)
    return job.result
""", """import threading

def start_worker(job):
    t = threading.Thread(target=job.run)
    t.start()
    t.join(timeout=30)
    return job.result
""")
P["PERF-GEN-003"] = ("""import requests

def get_weather(city):
    r = requests.get('https://api.weather.example/v1/' + city)
    r.raise_for_status()
    return r.json()
""", """import requests

def get_weather(city):
    r = requests.get('https://api.weather.example/v1/' + city, timeout=(3, 10))
    r.raise_for_status()
    return r.json()
""")


def main(out: Path):
    d = out / "bank" / "proj"; d.mkdir(parents=True, exist_ok=True)
    assert len(P) == 30, len(P)
    entries = [(k, "bug", b) for k, (b, c) in P.items()] + [(k, "clean", c) for k, (b, c) in P.items()]
    rng = random.Random(3); rng.shuffle(entries)
    truth = {}
    for n, (item, kind, src) in enumerate(entries, 1):
        fn = f"module_{n:02d}.py"
        (d / fn).write_text(src)
        truth[fn] = {"item": item, "kind": kind}
    (out / "bank" / "truth.json").write_text(json.dumps(truth, indent=1))


if __name__ == "__main__":
    main(Path(sys.argv[1]))
