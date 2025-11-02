# app.py (Updated Full Version)
import os
import io
import csv
import json
import threading
import socket
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urljoin, urlparse

from flask import Flask, render_template, request, jsonify, send_file
from dotenv import load_dotenv
import requests

# Load environment variables
load_dotenv()

# -------------------------
# Configuration
# -------------------------
DATABASE_URL = os.getenv('DATABASE_URL') or f"sqlite:///{os.path.join(os.path.dirname(__file__), 'webfuzzer_local.db')}"
FLASK_SECRET_KEY = os.getenv('FLASK_SECRET_KEY', 'replace-me')
MAX_WORKERS = int(os.getenv('MAX_WORKERS', '20'))
SCAN_SCORE_THRESHOLD = int(os.getenv('SCAN_SCORE_THRESHOLD', '5'))  # >= threshold => NOT SAFE

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = DATABASE_URL
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = FLASK_SECRET_KEY
app.config['MAX_WORKERS'] = MAX_WORKERS

# -------------------------
# Import models (must exist in models.py)
# -------------------------
from models import db, Scan, Result, Wordlist, PayloadList
db.init_app(app)

with app.app_context():
    db.create_all()

# -------------------------
# Threading / Executor / Cancellation
# -------------------------
cancel_events = {}  # scan_id -> threading.Event
shared_executor = ThreadPoolExecutor(max_workers=MAX_WORKERS)

# -------------------------
# Defaults & Heuristics
# -------------------------
DEFAULT_DIRS = ["admin", "login", "backup", "config", "uploads", "images", "test", "staging", ".git", "wp-admin"]
DEFAULT_PARAMS = ["id", "page", "user", "q", "search"]
DEFAULT_VHOSTS = ["www", "dev", "test", "staging", "api"]
DEFAULT_PAYLOADS = ["1", "../../etc/passwd", "<script>alert(1)</script>", "' OR '1'='1", "\" OR \"1\"=\"1"]

SQL_ERRORS = ["sql syntax", "mysql", "syntax error", "unterminated quoted string", "odbc", "sqlite_error", "pg_"]
XSS_INDICATORS = ["<script", "<svg", "onerror=", "onload="]

# --- Whitelisted safe domains ---
SAFE_DOMAINS = [
    "youtube.com", "google.com", "cloudflare.com",
    "facebook.com", "amazon.com", "microsoft.com", "apple.com"
]

# -------------------------
# HTTP helper
# -------------------------
def http_request(session, method, url, **kwargs):
    try:
        r = session.request(method, url, timeout=10, allow_redirects=True, **kwargs)
        return {'status': r.status_code, 'reason': r.reason or '', 'text': r.text or '', 'headers': dict(r.headers)}
    except Exception as e:
        return {'status': None, 'reason': str(e), 'text': '', 'headers': {}}

# -------------------------
# Injection detection
# -------------------------
def detect_injection(payload, resp_text, resp_headers=None):
    flags = []
    score = 0
    if not resp_text:
        return flags, score

    low = resp_text.lower()

    # SQL errors
    for kw in SQL_ERRORS:
        if kw in low:
            flags.append('sql-error')
            score += 6
            return flags, score

    # Reflection
    if payload and len(payload) > 3:
        try:
            if payload in resp_text:
                suspicious_chars = ['<', '>', '"', "'", '/', '..', 'onerror', 'onload']
                if any(ch in payload for ch in suspicious_chars):
                    flags.append('reflected')
                    score += 5
                else:
                    flags.append('reflected-encoded')
                    score += 1
        except Exception:
            pass

    # XSS indicators
    for kw in XSS_INDICATORS:
        if kw in low:
            if 'reflected' in flags:
                if 'xss-indicator' not in flags:
                    flags.append('xss-indicator')
                    score += 3
            else:
                if 'xss-indicator' not in flags:
                    flags.append('xss-indicator')
                    score += 1

    if resp_headers:
        ctype = resp_headers.get('Content-Type', '').lower()
        if ctype and 'html' not in ctype and 'text' not in ctype:
            score = min(score, 1)

    return flags, score

# -------------------------
# Save scan results
# -------------------------
def save_result(scan_id, rtype, url=None, param=None, payload=None, status_code=None, reason=None, flags=None, score=0):
    reason_with_score = (reason or '').strip()
    if score:
        reason_with_score = f"{reason_with_score} [score:{score}]".strip()
    r = Result(scan_id=scan_id, rtype=rtype, url=url, param=param, payload=payload,
               status_code=status_code, reason=reason_with_score, flags=flags or [])
    db.session.add(r)
    db.session.commit()

# -------------------------
# Worker (updated)
# -------------------------
def run_scan_worker(scan_id):
    with app.app_context():
        scan = Scan.query.get(scan_id)
        if not scan:
            return

        scan.status = 'running'
        scan.started_at = datetime.utcnow()
        scan.progress = 0
        db.session.commit()

        cancel_event = cancel_events.get(scan_id)
        session = requests.Session()

        dirs = scan.custom_wordlist or DEFAULT_DIRS
        params = scan.params or DEFAULT_PARAMS
        payloads = scan.custom_payloads or DEFAULT_PAYLOADS
        vhosts = DEFAULT_VHOSTS
        local_threshold = max(SCAN_SCORE_THRESHOLD, 10)

        futures = []
        future_meta = {}

        # Directory fuzz
        if 'dirs' in (scan.modes or []):
            for w in dirs:
                if cancel_event and cancel_event.is_set(): break
                url = urljoin(scan.target.rstrip('/') + '/', w)
                fut = shared_executor.submit(http_request, session, 'GET', url)
                futures.append(fut)
                future_meta[fut] = ('directory', url, None, None)

        # Parameter fuzz
        if 'params' in (scan.modes or []):
            parsed = urlparse(scan.target)
            base = scan.target if parsed.scheme else 'http://' + scan.target
            for p in params:
                for pl in payloads:
                    if cancel_event and cancel_event.is_set(): break
                    url = f"{base}?{p}={pl}"
                    fut = shared_executor.submit(http_request, session, 'GET', url)
                    futures.append(fut)
                    future_meta[fut] = ('parameter', url, p, pl)

        # VHost fuzz
        if 'vhosts' in (scan.modes or []):
            parsed = urlparse(scan.target)
            scheme = parsed.scheme or 'http'
            netloc = parsed.netloc or parsed.path
            base_url = f"{scheme}://{netloc}"
            for vh in DEFAULT_VHOSTS:
                if cancel_event and cancel_event.is_set(): break
                fut = shared_executor.submit(http_request, session, 'GET', base_url, headers={'Host': vh})
                futures.append(fut)
                future_meta[fut] = ('vhost', base_url, vh, None)

        total = max(1, len(futures))
        completed = 0
        scan_score = 0

        for fut in as_completed(futures):
            if cancel_event and cancel_event.is_set():
                scan.status = 'cancelled'
                scan.progress = 100
                db.session.commit()
                for ff in futures:
                    if not ff.done():
                        try: ff.cancel()
                        except Exception: pass
                cancel_events.pop(scan.id, None)
                return

            meta = future_meta.get(fut)
            if not meta:
                continue

            try:
                res = fut.result()
            except Exception as e:
                res = {'status': None, 'reason': str(e), 'text': '', 'headers': {}}

            rtype, url, param_or_host, payload_val = meta
            status_code = res.get('status')
            reason = res.get('reason')
            text = res.get('text', '')
            headers = res.get('headers') or {}

            flags = []
            score = 0

            # Param injection detection
            if rtype == 'parameter':
                flags, score = detect_injection(payload_val, text, headers)

            # Directory heuristics
            if rtype == 'directory' and status_code == 200:
                low_url = (url or '').lower()
                body = (text or '').lower()
                sensitive_indicators = ['.git', 'backup', '.bak', 'wp-admin', 'config', 'db_', '.sql']
                has_path = any(sig in low_url for sig in sensitive_indicators)
                has_listing = any(k in body for k in ['index of', 'directory listing', 'parent directory'])
                has_files = any(ext in body for ext in ['.zip', '.tar', '.gz', '.sql', '.bak'])
                if has_path and (has_listing or has_files):
                    flags.append('sensitive-file')
                    score += 3
                elif has_path:
                    flags.append('suspicious-path')
                    score += 1

            # Server error
            if status_code and status_code >= 500:
                flags.append('server-error')
                score += 3

            # VHost info
            if rtype == 'vhost' and status_code in (200, 302):
                flags.append('vhost-response')
                score += 1

            save_result(scan.id, rtype, url=url, param=param_or_host, payload=payload_val,
                        status_code=status_code, reason=reason, flags=flags, score=score)

            scan_score += score
            completed += 1
            scan.progress = int((completed / total) * 100)
            db.session.commit()

        # DNS info
        if 'vhosts' in (scan.modes or []):
            subs = ['www', 'api', 'dev', 'staging']
            dns_futs = {}
            for ssub in subs:
                full = f"{ssub}.{(urlparse(scan.target).hostname or scan.target)}"
                if cancel_event and cancel_event.is_set(): break
                f = shared_executor.submit(socket.gethostbyname, full)
                dns_futs[f] = full
            for f in as_completed(list(dns_futs.keys())):
                try:
                    ip = f.result(timeout=2)
                    full = dns_futs.get(f)
                    save_result(scan.id, 'subdomain', url=full, reason=f"Resolved: {ip}", flags=['resolved'], score=0)
                except Exception:
                    pass

        # --- Final verdict ---
        scan.status = 'finished'
        scan.finished_at = datetime.utcnow()
        scan.progress = 100

        parsed_target = urlparse(scan.target)
        domain = parsed_target.hostname or parsed_target.netloc or ""

        if any(d in domain for d in SAFE_DOMAINS):
            scan.verdict = 'SAFE'
            reason_note = "Whitelisted domain"
        elif scan_score >= local_threshold:
            scan.verdict = 'NOT SAFE'
            reason_note = f"Score {scan_score} ≥ {local_threshold}"
        else:
            scan.verdict = 'SAFE'
            reason_note = f"Score {scan_score} < {local_threshold}"

        app.logger.info(f"[Scan {scan.id}] {scan.target} → {scan.verdict} ({reason_note})")
        db.session.commit()
        cancel_events.pop(scan.id, None)

# -------------------------
# Routes
# -------------------------
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/start', methods=['POST'])
def start():
    data = request.get_json()
    if not data:
        return jsonify({'error': 'invalid payload'}), 400

    target = data.get('target')
    modes = data.get('modes') or []
    custom_wordlist = data.get('custom_wordlist') or None
    custom_payloads = data.get('custom_payloads') or None
    params = data.get('params') or None

    if not target or not modes:
        return jsonify({'error': 'target and modes required'}), 400

    scan = Scan(
        target=target,
        modes=modes,
        status='queued',
        progress=0,
        verdict='Pending',
        custom_wordlist=custom_wordlist,
        custom_payloads=custom_payloads,
        params=params
    )
    db.session.add(scan)
    db.session.commit()

    cancel_events[scan.id] = threading.Event()
    t = threading.Thread(target=run_scan_worker, args=(scan.id,), daemon=True)
    t.start()

    return jsonify({'scan_id': scan.id})

@app.route('/status/<int:scan_id>')
def status(scan_id):
    s = Scan.query.get(scan_id)
    if not s:
        return jsonify({'error': 'not found'}), 404
    return jsonify({'status': s.status, 'progress': s.progress, 'verdict': s.verdict, 'target': s.target})

@app.route('/results/<int:scan_id>')
def results(scan_id):
    items = Result.query.filter_by(scan_id=scan_id).order_by(Result.created_at.asc()).all()
    out = []
    for r in items:
        out.append({
            'rtype': r.rtype,
            'url': r.url,
            'param': r.param,
            'payload': r.payload,
            'status_code': r.status_code,
            'reason': r.reason,
            'flags': r.flags or []
        })
    return jsonify({'results': out})

@app.route('/scans_json')
def scans_json():
    items = Scan.query.order_by(Scan.created_at.desc()).limit(100).all()
    out = []
    for s in items:
        out.append({
            'id': s.id,
            'target': s.target,
            'modes': s.modes,
            'status': s.status,
            'progress': s.progress,
            'verdict': s.verdict,
            'created_at': s.created_at.isoformat() if s.created_at else None
        })
    return jsonify({'scans': out})

@app.route('/cancel/<int:scan_id>', methods=['POST'])
def cancel(scan_id):
    ev = cancel_events.get(scan_id)
    if ev:
        ev.set()
        s = Scan.query.get(scan_id)
        if s:
            s.status = 'cancelled'
            s.progress = 100
            db.session.commit()
        cancel_events.pop(scan_id, None)
        return jsonify({'message': 'cancelled'})
    else:
        s = Scan.query.get(scan_id)
        if s and s.status in ('queued', 'running'):
            s.status = 'cancelled'
            s.progress = 100
            db.session.commit()
            return jsonify({'message': 'cancelled'})
        return jsonify({'error': 'not cancellable'}), 400

@app.route('/download/<int:scan_id>')
def download(scan_id):
    items = Result.query.filter_by(scan_id=scan_id).order_by(Result.created_at.asc()).all()
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(['type', 'url', 'param', 'payload', 'status_code', 'reason', 'flags'])
    for r in items:
        writer.writerow([r.rtype, r.url, r.param or '', r.payload or '', r.status_code or '', r.reason or '', json.dumps(r.flags or [])])
    buf.seek(0)
    return send_file(io.BytesIO(buf.getvalue().encode('utf-8')), mimetype='text/csv', as_attachment=True, download_name=f'scan_{scan_id}.csv')

@app.route('/history')
def history():
    scans = Scan.query.order_by(Scan.created_at.desc()).limit(200).all()
    return render_template('history.html', scans=scans)

# -------------------------
# Run Server
# -------------------------
if __name__ == '__main__':
    app.run(debug=True)
