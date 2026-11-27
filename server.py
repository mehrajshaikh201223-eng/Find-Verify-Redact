#!/usr/bin/env python3
"""
Blackline Full-Stack Server & Database
100% Python Standard Library (No external pip packages required)
Includes:
  1. SQLite3 Database Engine (Users, Jobs, Metrics, PseudonymTokens, AuditLogs)
  2. REST API Server (/api/sanitize, /api/jobs, /api/telemetry, /api/audit-logs, /api/health)
  3. Static Web Server (Serves index.html and frontend assets)
"""

import http.server
import socketserver
import json
import sqlite3
import hashlib
import os
import re
import datetime
from urllib.parse import urlparse, parse_qs

PORT = int(os.environ.get('PORT', 8000))
DB_PATH = os.path.join(os.path.dirname(__file__), 'blackline.db')

# =====================================================================
# 1. DATABASE SCHEMA INITIALIZATION (SQLite3)
# =====================================================================
def init_database():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    # Users Table
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS users (
        id TEXT PRIMARY KEY,
        email TEXT UNIQUE NOT NULL,
        name TEXT,
        api_key TEXT UNIQUE NOT NULL,
        created_at TEXT NOT NULL
    )
    ''')

    # Sanitization Jobs Table (Zero-leak: raw incoming payload is never permanently saved)
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS sanitization_jobs (
        id TEXT PRIMARY KEY,
        user_id TEXT,
        file_name TEXT,
        file_type TEXT,
        file_size_bytes INTEGER DEFAULT 0,
        char_count INTEGER DEFAULT 0,
        line_count INTEGER DEFAULT 0,
        redaction_mode TEXT DEFAULT 'FULL_MASK',
        status TEXT DEFAULT 'COMPLETED',
        execution_ms INTEGER DEFAULT 0,
        input_checksum TEXT NOT NULL,
        output_checksum TEXT NOT NULL,
        sanitized_output TEXT,
        created_at TEXT NOT NULL,
        completed_at TEXT,
        FOREIGN KEY (user_id) REFERENCES users (id)
    )
    ''')

    # Job Metrics Table
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS job_metrics (
        id TEXT PRIMARY KEY,
        job_id TEXT UNIQUE NOT NULL,
        cc_count INTEGER DEFAULT 0,
        aadhaar_count INTEGER DEFAULT 0,
        pan_count INTEGER DEFAULT 0,
        email_count INTEGER DEFAULT 0,
        ip_count INTEGER DEFAULT 0,
        phone_count INTEGER DEFAULT 0,
        total_redacted INTEGER DEFAULT 0,
        blocked_luhn INTEGER DEFAULT 0,
        created_at TEXT NOT NULL,
        FOREIGN KEY (job_id) REFERENCES sanitization_jobs (id)
    )
    ''')

    # Pseudonym Registry Table
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS pseudonym_tokens (
        id TEXT PRIMARY KEY,
        job_id TEXT NOT NULL,
        entity_type TEXT NOT NULL,
        key_hash TEXT NOT NULL,
        pseudonym_token TEXT NOT NULL,
        created_at TEXT NOT NULL,
        FOREIGN KEY (job_id) REFERENCES sanitization_jobs (id)
    )
    ''')

    # Immutable Audit Logs Table
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS audit_logs (
        id TEXT PRIMARY KEY,
        job_id TEXT,
        action TEXT NOT NULL,
        ip_address TEXT,
        user_agent TEXT,
        status TEXT DEFAULT 'SUCCESS',
        metadata_json TEXT,
        created_at TEXT NOT NULL,
        FOREIGN KEY (job_id) REFERENCES sanitization_jobs (id)
    )
    ''')

    # Default admin user seed if empty
    cursor.execute('SELECT COUNT(*) FROM users')
    if cursor.fetchone()[0] == 0:
        cursor.execute('''
        INSERT INTO users (id, email, name, api_key, created_at)
        VALUES ('usr_admin_01', 'security-ops@blackline.internal', 'Lead Security Engineer', 'blk_live_key_9942a', datetime('now'))
        ''')

    conn.commit()
    conn.close()
    print(f'[Database] Initialized SQLite database at {DB_PATH}')


# =====================================================================
# 2. DETECTION & REDACTION LOGIC ENGINE
# =====================================================================
def validate_luhn(num_str):
    digits = [int(c) for c in num_str if c.isdigit()]
    if not (13 <= len(digits) <= 19):
        return False
    chk = 0
    double = False
    for d in reversed(digits):
        n = d
        if double:
            n *= 2
            if n > 9:
                n -= 9
        chk += n
        double = not double
    return chk % 10 == 0


def key_of(e_type, raw_text):
    if e_type == 'email':
        return raw_text.lower().strip()
    elif e_type == 'pan':
        return raw_text.upper().strip()
    elif e_type in ('cc', 'aadhaar'):
        return re.sub(r'\D', '', raw_text)
    elif e_type == 'phone':
        d = re.sub(r'\D', '', raw_text)
        return d[-10:] if len(d) > 10 else d
    elif e_type == 'ip':
        return raw_text.lower().strip()
    return raw_text.strip()


def partial_mask(e_type, raw_text):
    if e_type == 'email':
        at = raw_text.find('@')
        if at == -1:
            return '***@domain.com'
        user = raw_text[:at]
        domain = raw_text[at:]
        vis = user[:min(2, len(user))]
        return f'{vis}***{domain}'
    elif e_type == 'cc':
        d = re.sub(r'\D', '', raw_text)
        return f'XXXX-XXXX-XXXX-{d[-4:]}'
    elif e_type == 'aadhaar':
        d = re.sub(r'\D', '', raw_text)
        return f'XXXX-XXXX-{d[-4:]}'
    elif e_type == 'pan':
        c = raw_text.upper().strip()
        if len(c) < 10:
            return 'XXXXXXXXXX'
        return f'{c[:2]}XXXXXXX{c[-1]}'
    elif e_type == 'phone':
        d = re.sub(r'\D', '', raw_text)
        last2 = d[-2:]
        prefix = ''
        if raw_text.strip().startswith('+'):
            m = re.match(r'^\+(\d{1,3})', raw_text.strip())
            if m:
                prefix = f'+{m.group(1)}-'
        return f'{prefix}XXXXXXXX{last2}'
    elif e_type == 'ip':
        if '.' in raw_text:
            parts = raw_text.split('.')
            return f'{parts[0]}.XXX.XXX.XXX'
        else:
            parts = raw_text.split(':')
            f = parts[0] if parts[0] else 'XXXX'
            return f'{f}:XXXX:XXXX:XXXX'
    return '[REDACTED]'


def detect_and_redact(text, mode='full'):
    claimed = []
    entities = []
    blocked_luhn = 0

    def is_overlapping(s, e):
        for cs, ce in claimed:
            if max(s, cs) < min(e, ce):
                return True
        return False

    # 1. Credit Card
    for m in re.finditer(r'(?<!\d)(?:(?:\d[ -]?){13,19})(?!\d)', text):
        raw = m.group(0).rstrip(' -')
        s, e = m.start(), m.start() + len(raw)
        digits = re.sub(r'\D', '', raw)
        if 13 <= len(digits) <= 19:
            if validate_luhn(digits):
                if not is_overlapping(s, e):
                    claimed.append((s, e))
                    entities.append({'type': 'cc', 'start': s, 'end': e, 'rawText': raw})
            else:
                blocked_luhn += 1
                claimed.append((s, e))

    # 2. Aadhaar
    for m in re.finditer(r'(?<!\d)[2-9]\d{3}[ -]?\d{4}[ -]?\d{4}(?!\d)', text):
        raw = m.group(0)
        s, e = m.start(), m.end()
        if not is_overlapping(s, e):
            claimed.append((s, e))
            entities.append({'type': 'aadhaar', 'start': s, 'end': e, 'rawText': raw})

    # 3. PAN
    for m in re.finditer(r'\b[A-Z]{5}\d{4}[A-Z]\b', text):
        raw = m.group(0)
        s, e = m.start(), m.end()
        if not is_overlapping(s, e):
            claimed.append((s, e))
            entities.append({'type': 'pan', 'start': s, 'end': e, 'rawText': raw})

    # 4. Email
    for m in re.finditer(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b', text):
        raw = m.group(0)
        s, e = m.start(), m.end()
        if not is_overlapping(s, e):
            claimed.append((s, e))
            entities.append({'type': 'email', 'start': s, 'end': e, 'rawText': raw})

    # 5. IP
    for m in re.finditer(r'(?<![0-9.])(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?![0-9.])', text):
        raw = m.group(0)
        s, e = m.start(), m.end()
        if not is_overlapping(s, e):
            claimed.append((s, e))
            entities.append({'type': 'ip', 'start': s, 'end': e, 'rawText': raw})

    for m in re.finditer(r'(?<![a-zA-Z0-9:])(?:(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}|(?:[0-9a-fA-F]{1,4}:){1,7}:|(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|(?:[0-9a-fA-F]{1,4}:){1,5}(?::[0-9a-fA-F]{1,4}){1,2}|(?:[0-9a-fA-F]{1,4}:){1,4}(?::[0-9a-fA-F]{1,4}){1,3}|(?:[0-9a-fA-F]{1,4}:){1,3}(?::[0-9a-fA-F]{1,4}){1,4}|(?:[0-9a-fA-F]{1,4}:){1,2}(?::[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:(?::[0-9a-fA-F]{1,4}){1,6}|:(?::[0-9a-fA-F]{1,4}){1,7}|::)(?![a-zA-Z0-9:])', text):
        raw = m.group(0)
        s, e = m.start(), m.end()
        if len(raw) > 2 and not is_overlapping(s, e):
            claimed.append((s, e))
            entities.append({'type': 'ip', 'start': s, 'end': e, 'rawText': raw})

    # 6. Phone
    for m in re.finditer(r'(?<![\w+])(?:(?:\+?91[\s-]?)?(?:0)?[6-9]\d{4}[\s-]?\d{5}|(?:\+?91[\s-]?)?(?:0)?[6-9]\d{9}|(?:\+?1[\s-]?)?(?:\(\d{3}\)|\d{3})[\s.-]?\d{3}[\s.-]?\d{4})(?!\d)', text):
        raw = m.group(0)
        s, e = m.start(), m.end()
        if not is_overlapping(s, e):
            claimed.append((s, e))
            entities.append({'type': 'phone', 'start': s, 'end': e, 'rawText': raw})

    entities.sort(key=lambda x: x['start'])

    counts = {'cc': 0, 'aadhaar': 0, 'pan': 0, 'email': 0, 'ip': 0, 'phone': 0, 'total': len(entities)}
    for e in entities:
        counts[e['type']] += 1

    # Redaction Pass
    full_mask_map = {
        'email': '[REDACTED_EMAIL]',
        'phone': '[REDACTED_PHONE]',
        'ip': '[REDACTED_IP]',
        'pan': '[REDACTED_PAN]',
        'aadhaar': '[REDACTED_AADHAAR]',
        'cc': '[REDACTED_CC]'
    }

    pseudo_map = {}
    counters = {'cc': 0, 'aadhaar': 0, 'pan': 0, 'email': 0, 'ip': 0, 'phone': 0}
    prefixes = {'email': 'EMAIL', 'phone': 'PHONE', 'ip': 'IP', 'pan': 'PAN', 'aadhaar': 'AADHAAR', 'cc': 'CC'}

    for e in entities:
        k = e['type'] + ':' + key_of(e['type'], e['rawText'])
        if k not in pseudo_map:
            counters[e['type']] += 1
            seq = f"{counters[e['type']]:02d}"
            pseudo_map[k] = f"{prefixes[e['type']]}_{seq}"

    sanitized = ''
    last_idx = 0
    for e in entities:
        sanitized += text[last_idx:e['start']]
        if mode == 'full':
            sanitized += full_mask_map.get(e['type'], '[REDACTED]')
        elif mode == 'partial':
            sanitized += partial_mask(e['type'], e['rawText'])
        elif mode == 'pseudonymize':
            k = e['type'] + ':' + key_of(e['type'], e['rawText'])
            sanitized += pseudo_map.get(k, '[REDACTED]')
        last_idx = e['end']
    sanitized += text[last_idx:]

    return {
        'entities': entities,
        'counts': counts,
        'blocked_luhn': blocked_luhn,
        'sanitized_text': sanitized,
        'unique_pseudonyms': len(pseudo_map),
        'pseudonym_map': pseudo_map
    }


# =====================================================================
# 3. HTTP REQUEST ROUTER & CONTROLLER
# =====================================================================
class BlacklineHTTPHandler(http.server.SimpleHTTPRequestHandler):
    def end_headers(self):
        # Enable CORS for all local dev tools & browsers
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type, Authorization')
        super().end_headers()

    def do_OPTIONS(self):
        self.send_response(204)
        self.end_headers()

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path

        if path == '/api/health':
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            resp = {
                'status': 'ONLINE',
                'service': 'Blackline Full-Stack Engine',
                'database': 'SQLite3 Connected',
                'timestamp': datetime.datetime.utcnow().isoformat() + 'Z'
            }
            self.wfile.write(json.dumps(resp).encode('utf-8'))
            return

        elif path == '/api/telemetry':
            conn = sqlite3.connect(DB_PATH)
            c = conn.cursor()
            c.execute('''
            SELECT 
                COUNT(id),
                COALESCE(SUM(cc_count), 0),
                COALESCE(SUM(aadhaar_count), 0),
                COALESCE(SUM(pan_count), 0),
                COALESCE(SUM(email_count), 0),
                COALESCE(SUM(ip_count), 0),
                COALESCE(SUM(phone_count), 0),
                COALESCE(SUM(total_redacted), 0),
                COALESCE(SUM(blocked_luhn), 0)
            FROM job_metrics
            ''')
            row = c.fetchone()
            conn.close()

            telemetry = {
                'totalJobs': row[0],
                'creditCardsVerified': row[1],
                'aadhaarVerified': row[2],
                'panDetected': row[3],
                'emailsRedacted': row[4],
                'ipAddressesRedacted': row[5],
                'phonesRedacted': row[6],
                'totalRedacted': row[7],
                'blockedLuhn': row[8]
            }

            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps({'telemetry': telemetry}).encode('utf-8'))
            return

        elif path == '/api/audit-logs':
            conn = sqlite3.connect(DB_PATH)
            c = conn.cursor()
            c.execute('''
            SELECT id, job_id, action, ip_address, status, metadata_json, created_at 
            FROM audit_logs 
            ORDER BY created_at DESC LIMIT 50
            ''')
            rows = c.fetchall()
            conn.close()

            logs = []
            for r in rows:
                logs.append({
                    'id': r[0],
                    'jobId': r[1],
                    'action': r[2],
                    'ip': r[3],
                    'status': r[4],
                    'metadata': json.loads(r[5]) if r[5] else None,
                    'timestamp': r[6]
                })

            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps({'auditLogs': logs}).encode('utf-8'))
            return

        elif path == '/api/jobs':
            conn = sqlite3.connect(DB_PATH)
            c = conn.cursor()
            c.execute('''
            SELECT j.id, j.file_name, j.redaction_mode, j.char_count, j.status, j.created_at, m.total_redacted, m.blocked_luhn
            FROM sanitization_jobs j
            LEFT JOIN job_metrics m ON j.id = m.job_id
            ORDER BY j.created_at DESC LIMIT 30
            ''')
            rows = c.fetchall()
            conn.close()

            jobs = []
            for r in rows:
                jobs.append({
                    'id': r[0],
                    'fileName': r[1],
                    'mode': r[2],
                    'chars': r[3],
                    'status': r[4],
                    'createdAt': r[5],
                    'totalRedacted': r[6] or 0,
                    'blockedLuhn': r[7] or 0
                })

            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps({'jobs': jobs}).encode('utf-8'))
            return

        # Serve frontend static files (default to index.html)
        if path == '/' or path == '':
            self.path = '/index.html'
        return super().do_GET()

    def do_POST(self):
        parsed = urlparse(self.path)
        path = parsed.path

        if path == '/api/sanitize':
            start_time = datetime.datetime.utcnow()
            content_length = int(self.headers.get('Content-Length', 0))
            body_bytes = self.rfile.read(content_length)

            try:
                data = json.loads(body_bytes.decode('utf-8'))
            except Exception:
                self.send_response(400)
                self.end_headers()
                self.wfile.write(b'{"error": "Invalid JSON body"}')
                return

            text = data.get('text', '')
            mode = data.get('mode', 'full')
            file_name = data.get('fileName', 'memory_stream.txt')

            in_hash = hashlib.sha256(text.encode('utf-8')).hexdigest()
            result = detect_and_redact(text, mode=mode)
            out_hash = hashlib.sha256(result['sanitized_text'].encode('utf-8')).hexdigest()

            end_time = datetime.datetime.utcnow()
            execution_ms = int((end_time - start_time).total_seconds() * 1000)

            # Insert Record into SQLite Database
            job_id = f"job_{int(datetime.datetime.utcnow().timestamp() * 1000)}"
            now_str = datetime.datetime.utcnow().isoformat() + 'Z'

            conn = sqlite3.connect(DB_PATH)
            c = conn.cursor()
            try:
                # 1. Sanitization Job Record
                c.execute('''
                INSERT INTO sanitization_jobs (
                    id, file_name, file_type, file_size_bytes, char_count, line_count,
                    redaction_mode, status, execution_ms, input_checksum, output_checksum,
                    sanitized_output, created_at, completed_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    job_id, file_name, file_name.split('.')[-1] if '.' in file_name else 'txt',
                    len(text.encode('utf-8')), len(text), text.count('\n') + 1,
                    mode.upper(), 'COMPLETED', execution_ms, in_hash, out_hash,
                    result['sanitized_text'], now_str, now_str
                ))

                # 2. Metrics Record
                metric_id = f"met_{job_id}"
                cnt = result['counts']
                c.execute('''
                INSERT INTO job_metrics (
                    id, job_id, cc_count, aadhaar_count, pan_count, email_count,
                    ip_count, phone_count, total_redacted, blocked_luhn, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    metric_id, job_id, cnt['cc'], cnt['aadhaar'], cnt['pan'], cnt['email'],
                    cnt['ip'], cnt['phone'], cnt['total'], result['blocked_luhn'], now_str
                ))

                # 3. Audit Log
                audit_id = f"aud_{job_id}"
                client_ip = self.client_address[0] if self.client_address else '127.0.0.1'
                user_agent = self.headers.get('User-Agent', 'Unknown')
                c.execute('''
                INSERT INTO audit_logs (id, job_id, action, ip_address, user_agent, status, metadata_json, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    audit_id, job_id, 'BUFFER_REDACTED', client_ip, user_agent, 'SUCCESS',
                    json.dumps({'mode': mode, 'total': cnt['total'], 'blockedLuhn': result['blocked_luhn']}),
                    now_str
                ))

                conn.commit()
            except Exception as e:
                print('Database insert error:', e)
            finally:
                conn.close()

            response_data = {
                'success': True,
                'jobId': job_id,
                'executionMs': execution_ms,
                'inputChecksum': in_hash,
                'outputChecksum': out_hash,
                'counts': {
                    **result['counts'],
                    'blockedLuhn': result['blocked_luhn']
                },
                'uniquePseudonyms': result['unique_pseudonyms'],
                'sanitizedText': result['sanitized_text'],
                'pseudonymMap': result['pseudonym_map'] if mode == 'pseudonymize' else None
            }

            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps(response_data).encode('utf-8'))
            return

        self.send_response(404)
        self.end_headers()


# =====================================================================
# 4. SERVER STARTUP
# =====================================================================
if __name__ == '__main__':
    init_database()
    socketserver.TCPServer.allow_reuse_address = True
    with socketserver.TCPServer(('', PORT), BlacklineHTTPHandler) as httpd:
        print('===================================================================')
        print(f'  BLACKLINE FULL-STACK SERVER RUNNING AT: http://localhost:{PORT}')
        print(f'  • Frontend UI: http://localhost:{PORT}/index.html')
        print(f'  • REST API:    http://localhost:{PORT}/api/sanitize')
        print(f'  • Database:    {DB_PATH} (SQLite3)')
        print('===================================================================')
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print('\nServer stopped gracefully.')
