"""
NetGuard - Flask Application
Integrates Security Audit Engine + ML Engine + Remediation
"""
from flask import Flask, render_template, jsonify, send_from_directory, send_file, request, Response, stream_with_context
from pdf_report import generate_pdf_report
from email_alerts import load_settings, save_settings, send_email, send_critical_alerts, send_scan_report, get_recipients, build_html_report
from database import (get_all_devices, get_config_versions, get_config_by_id,
                       diff_configs, get_db_stats, get_latest_config, init_db)
import os, json, threading
from harvest import run_harvest
from security_audit import audit_all_devices, get_audit_summary, AUDIT_CHECKS
from ml_engine import analyze_all_devices, ensure_model_trained, train_model
from monitor import (start_monitor, stop_monitor, get_status_cache,
                     update_config, monitor_event_queue, MONITOR_CONFIG)
from remediation import generate_device_remediation, save_remediation_file, generate_and_save_all

app = Flask(__name__)
from flask_httpauth import HTTPBasicAuth
from werkzeug.security import generate_password_hash, check_password_hash

auth = HTTPBasicAuth()

USERS = {
    "suhail": generate_password_hash("suhail")#change this.......
}

@auth.verify_password
def verify(username, password):
    if username in USERS and check_password_hash(USERS[username], password):
        return username



# Pre-train ML model at startup (background, non-blocking)
# Auto-start live monitor
threading.Thread(target=start_monitor, daemon=True).start()
# Pre-train ML model at startup (background, non-blocking)
threading.Thread(target=lambda: ensure_model_trained(verbose=True), daemon=True).start()

# ── Static Topology ──────────────────────────────────────────────────────────
@app.route('/static/topology.json')
def serve_topology():
    return send_from_directory('.', 'topology.json')

# ── Discovery Scan ───────────────────────────────────────────────────────────
is_scanning = False

@app.route('/scan', methods=['POST'])
def trigger_scan():
    global is_scanning
    if is_scanning:
        return jsonify({"status": "already_running"}), 400

    def _bg():
        global is_scanning
        is_scanning = True
        try:
            run_harvest()
        finally:
            is_scanning = False

    threading.Thread(target=_bg).start()
    return jsonify({"status": "started"})


# ── Security Audit API ───────────────────────────────────────────────────────
@app.route('/api/security_audit')
def security_audit():
    try:
        results  = audit_all_devices()
        summary  = get_audit_summary(results)
        return jsonify({
            "status":  "ok",
            "summary": summary,
            "devices": results,
        })
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


@app.route('/api/audit_checks')
def list_checks():
    checks = [{
        "id":          c["id"],
        "category":    c["category"],
        "title":       c["title"],
        "description": c["description"],
        "severity":    c["severity"],
        "cve":         c.get("cve", "—"),
        "cis":         c.get("cis", "—"),
        "fix":         c["fix"],
    } for c in AUDIT_CHECKS]
    return jsonify({"checks": checks, "total": len(checks)})


# ── ML Analysis API ──────────────────────────────────────────────────────────
@app.route('/api/ml_analysis')
def ml_analysis():
    try:
        results  = analyze_all_devices()
        rem_map  = generate_and_save_all(results)
        devices  = []
        for r in results:
            device   = r['device']
            rem_data = rem_map.get(device, {})
            devices.append({
                'device':       device,
                'score':        r['score'],
                'level':        r['level'],
                'counts':       r['counts'],
                'total_lines':  r['total_lines'],
                'flagged':      r['flagged'],
                'notable':      r['notable'],
                'remediations': rem_data.get('remediations', []),
                'issue_count':  rem_data.get('issue_count', 0),
            })
        return jsonify({'status': 'ok', 'devices': devices})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500



# ── ML Enhanced Routes ────────────────────────────────────────────────────────

_trend_cache = {}  # hostname → list of points
_trend_cache_time = 0

@app.route('/api/ml_trend')
def ml_trend():
    import time as _time
    global _trend_cache, _trend_cache_time
    # Return cached result if less than 5 minutes old
    if _trend_cache and (_time.time() - _trend_cache_time) < 300:
        return jsonify({'status': 'ok', 'trend': _trend_cache})
    # Load model once at start
    from ml_engine import ensure_model_trained
    try:
        _model = ensure_model_trained(verbose=False)
    except Exception as ex:
        return jsonify({'status': 'error', 'message': f'Model load failed: {ex}'}), 500
    """
    Risk score history per device — used for trend line chart.
    Reads config_history from DB, re-runs ML on each saved snapshot.
    """
    import sqlite3 as _sq
    from ml_engine import analyze_config, compute_risk_score, ensure_model_trained
    db_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'netguard.db')
    if not os.path.exists(db_path):
        return jsonify({'status': 'error', 'message': 'No database found'}), 404
    try:
        conn  = _sq.connect(db_path)
        conn.row_factory = _sq.Row
        # Get last 10 snapshots per device
        rows = conn.execute("""
            SELECT hostname, config_text, harvested_at, changed, config_hash
            FROM config_history
            ORDER BY hostname, harvested_at ASC
        """).fetchall()
        conn.close()

        # Group by device
        from collections import defaultdict
        device_snapshots = defaultdict(list)
        for r in rows:
            device_snapshots[r['hostname']].append(dict(r))

        trend_data = {}
        for hostname, snaps in device_snapshots.items():
            # Keep max last 8 snapshots
            snaps = snaps[-5:]
            points = []
            seen_hashes = set()
            for s in snaps:
                if not s.get('config_text'):
                    continue
                # Skip duplicate configs (same hash = same config = same score)
                h = s.get('config_hash', '')
                if h and h in seen_hashes:
                    # Reuse last point's score with updated timestamp
                    if points:
                        last = dict(points[-1])
                        last['time']    = s['harvested_at'][:16]
                        last['changed'] = bool(s['changed'])
                        points.append(last)
                    continue
                if h:
                    seen_hashes.add(h)
                analysis  = analyze_config(s['config_text'], _model)
                risk_data = compute_risk_score(analysis)
                points.append({
                    'time':    s['harvested_at'][:16],   # "YYYY-MM-DD HH:MM"
                    'score':   risk_data['score'],
                    'level':   risk_data['level'],
                    'changed': bool(s['changed']),
                    'critical': risk_data['counts'].get('CRITICAL', 0),
                    'high':     risk_data['counts'].get('HIGH', 0),
                })
            if points:
                trend_data[hostname] = points

        _trend_cache = trend_data
        _trend_cache_time = __import__('time').time()
        return jsonify({'status': 'ok', 'trend': trend_data})
    except Exception as ex:
        return jsonify({'status': 'error', 'message': str(ex)}), 500


@app.route('/api/ml_missing')
def ml_missing():
    """
    Missing Hardening Detection.
    Checks each device config for absence of required security commands.
    Flags what SHOULD be there but isn't — more powerful than flagging bad lines.
    """
    import glob
    config_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'network_configs')

    # Required hardening commands with metadata
    REQUIRED = [
        {'cmd': 'service password-encryption',     'sev': 'CRITICAL', 'title': 'Password Encryption',        'fix': 'service password-encryption'},
        {'cmd': 'enable secret',                    'sev': 'CRITICAL', 'title': 'Enable Secret (Hashed)',      'fix': 'enable secret 9 <strong-password>'},
        {'cmd': 'no ip http server',                'sev': 'CRITICAL', 'title': 'HTTP Server Disabled',        'fix': 'no ip http server'},
        {'cmd': 'no ip source-route',               'sev': 'CRITICAL', 'title': 'Source Routing Disabled',     'fix': 'no ip source-route'},
        {'cmd': 'no service tcp-small-servers',     'sev': 'CRITICAL', 'title': 'TCP Small Servers Off',       'fix': 'no service tcp-small-servers'},
        {'cmd': 'no service udp-small-servers',     'sev': 'CRITICAL', 'title': 'UDP Small Servers Off',       'fix': 'no service udp-small-servers'},
        {'cmd': 'ip ssh version 2',                 'sev': 'HIGH',     'title': 'SSH Version 2',               'fix': 'ip ssh version 2'},
        {'cmd': 'transport input ssh',              'sev': 'HIGH',     'title': 'SSH-Only VTY Access',         'fix': 'line vty 0 4\n transport input ssh'},
        {'cmd': 'aaa new-model',                    'sev': 'HIGH',     'title': 'AAA Authentication',          'fix': 'aaa new-model'},
        {'cmd': 'logging buffered',                 'sev': 'HIGH',     'title': 'Logging Enabled',             'fix': 'logging buffered 16384'},
        {'cmd': 'service timestamps log datetime',  'sev': 'HIGH',     'title': 'Log Timestamps',              'fix': 'service timestamps log datetime msec'},
        {'cmd': 'no ip proxy-arp',                  'sev': 'HIGH',     'title': 'Proxy ARP Disabled',          'fix': 'no ip proxy-arp'},
        {'cmd': 'ntp server',                       'sev': 'MEDIUM',   'title': 'NTP Server Configured',       'fix': 'ntp server <ntp-ip>'},
        {'cmd': 'banner motd',                      'sev': 'MEDIUM',   'title': 'Login Banner Set',            'fix': 'banner motd # Authorized Access Only #'},
        {'cmd': 'no cdp run',                       'sev': 'MEDIUM',   'title': 'CDP Disabled Globally',       'fix': 'no cdp run'},
        {'cmd': 'no ip redirects',                  'sev': 'MEDIUM',   'title': 'ICMP Redirects Disabled',     'fix': 'no ip redirects'},
        {'cmd': 'no ip unreachables',               'sev': 'MEDIUM',   'title': 'ICMP Unreachables Disabled',  'fix': 'no ip unreachables'},
        {'cmd': 'login block-for',                  'sev': 'MEDIUM',   'title': 'Login Rate Limiting',         'fix': 'login block-for 120 attempts 5 within 60'},
        {'cmd': 'crypto key generate rsa',          'sev': 'MEDIUM',   'title': 'RSA Key Generated',           'fix': 'crypto key generate rsa modulus 2048'},
        {'cmd': 'ip tcp intercept',                 'sev': 'LOW',      'title': 'TCP Intercept (DoS protect)', 'fix': 'ip tcp intercept list <acl>'},
    ]

    results = {}
    if not os.path.exists(config_dir):
        return jsonify({'status': 'ok', 'missing': {}})

    for fpath in sorted(glob.glob(os.path.join(config_dir, '*_config.txt'))):
        device = os.path.basename(fpath).replace('_config.txt', '')
        try:
            with open(fpath, encoding='utf-8', errors='ignore') as _cf:
                cfg = _cf.read()
        except Exception:
            continue

        missing = []
        for req in REQUIRED:
            if req['cmd'].lower() not in cfg:
                missing.append({
                    'title': req['title'],
                    'sev':   req['sev'],
                    'fix':   req['fix'],
                    'cmd':   req['cmd'],
                })
        # Sort by severity
        sev_order = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3}
        missing.sort(key=lambda x: sev_order.get(x['sev'], 9))
        results[device] = {
            'missing': missing,
            'score':   len(missing),
            'critical_missing': sum(1 for m in missing if m['sev'] == 'CRITICAL'),
            'total_checked': len(REQUIRED),
        }

    return jsonify({'status': 'ok', 'missing': results})


@app.route('/api/ml_correlation')
def ml_correlation():
    from ml_engine import ensure_model_trained
    try:
        _model = ensure_model_trained(verbose=False)
    except Exception as ex:
        return jsonify({'status': 'error', 'message': f'Model load failed: {ex}'}), 500
    """
    Cross-Device Correlation.
    Finds vulnerability patterns present on MULTIPLE devices simultaneously.
    Shows network-wide attack surface — same as Cisco DNA Center threat correlation.
    """
    import glob
    from collections import defaultdict
    from ml_engine import analyze_config, ensure_model_trained

    config_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'network_configs')
    if not os.path.exists(config_dir):
        return jsonify({'status': 'ok', 'correlations': []})

    try:
        # Map: normalised_vuln_line → list of devices
        vuln_map = defaultdict(list)

        files = sorted(glob.glob(os.path.join(config_dir, '*_config.txt')))
        device_count = len(files)

        for fpath in files:
            device = os.path.basename(fpath).replace('_config.txt', '')
            try:
                with open(fpath, encoding='utf-8', errors='ignore') as _cf:
                    cfg = _cf.read()
            except Exception:
                continue

            analysis = analyze_config(cfg, _model)
            for item in analysis:
                if item['risk'] in ('CRITICAL', 'HIGH'):
                    # Normalise line for grouping
                    norm = item['line'].strip().lower()
                    # Skip very long lines and pure noise
                    if len(norm) < 5 or len(norm) > 120:
                        continue
                    vuln_map[(norm, item['risk'])].append(device)

        # Only keep patterns seen on 2+ devices
        correlations = []
        seen_patterns = set()
        for (line, risk), devices in vuln_map.items():
            unique_devs = list(dict.fromkeys(devices))  # preserve order, deduplicate
            if len(unique_devs) < 2:
                continue
            # Deduplicate by normalised line
            key = line[:60]
            if key in seen_patterns:
                continue
            seen_patterns.add(key)
            correlations.append({
                'line':        line,
                'risk':        risk,
                'devices':     unique_devs,
                'device_count': len(unique_devs),
                'spread':      round(len(unique_devs) / device_count * 100) if device_count else 0,
            })

        # Sort by device_count desc, then severity
        sev_order = {'CRITICAL': 0, 'HIGH': 1}
        correlations.sort(key=lambda x: (-x['device_count'], sev_order.get(x['risk'], 9)))

        return jsonify({
            'status':       'ok',
            'correlations': correlations[:30],   # top 30
            'device_count': device_count,
        })
    except Exception as ex:
        return jsonify({'status': 'error', 'message': str(ex)}), 500

@app.route('/api/retrain_model', methods=['POST'])
def retrain_model():
    try:
        _, acc = train_model(verbose=False)
        return jsonify({'status': 'ok', 'accuracy': round(acc * 100, 1)})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500


@app.route('/api/download_remediation/<device_name>')
def download_remediation(device_name):
    filename = f"{device_name}_remediation.txt"
    filepath = os.path.join('network_configs', filename)
    if not os.path.exists(filepath):
        return jsonify({'error': 'Not generated yet'}), 404
    return send_file(filepath, as_attachment=True,
                     download_name=filename, mimetype='text/plain')



# ── Devices API ──────────────────────────────────────────────────────────────
@app.route('/api/devices')
def api_devices():
    import glob, re as _re
    from datetime import datetime
    devices = []
    config_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'network_configs')

    if not os.path.exists(config_dir):
        return jsonify({'status': 'ok', 'devices': []})

    for fpath in sorted(glob.glob(os.path.join(config_dir, '*.txt'))):
        fname = os.path.basename(fpath)
        name  = fname.replace('.txt', '')

        # Skip PC and unknown-device entries — they have no full config
        if name.startswith('PC-') or name.startswith('Device-'):
            continue

        try:
            with open(fpath, 'r', encoding='utf-8', errors='ignore') as f:
                config = f.read()
        except Exception:
            config = ''

        # Device type detection
        h = name.upper()
        if any(x in h for x in ('SW','SWITCH','DIST','ACCESS','CORE')):
            dev_type = 'switch'
        elif any(x in h for x in ('FW','FIREWALL','ASA','PFSENSE','VYOS','PA-','FGT','FORTINET')):
            dev_type = 'firewall'
        else:
            dev_type = 'router'

        # Extract first usable IP from config
        ip = '—'
        for m in _re.finditer(r'ip address (\d+\.\d+\.\d+\.\d+)', config):
            candidate = m.group(1)
            if not candidate.startswith(('127.','0.')):
                ip = candidate
                break

        # Config line count (exclude blank + comment lines)
        total_lines   = len(config.splitlines())
        active_lines  = sum(1 for l in config.splitlines()
                            if l.strip() and not l.strip().startswith('!'))

        mtime     = os.path.getmtime(fpath)
        last_seen = datetime.fromtimestamp(mtime).strftime('%b %d %Y  %H:%M')

        devices.append({
            'hostname':     name,
            'ip':           ip,
            'type':         dev_type,
            'score':        None,
            'level':        'UNKNOWN',
            'last_seen':    last_seen,
            'config':       config,
            'total_lines':  total_lines,
            'active_lines': active_lines,
        })

    return jsonify({'status': 'ok', 'devices': devices})


# ── Database Stats API ───────────────────────────────────────────────────────
@app.route('/api/db_stats')
def db_stats():
    try:
        return jsonify({'status': 'ok', 'stats': get_db_stats()})
    except Exception as ex:
        return jsonify({'status': 'error', 'message': str(ex)}), 500


# ── Config History API ───────────────────────────────────────────────────────
@app.route('/api/config_history/<hostname>')
def config_history(hostname):
    """Return all saved config versions for a device."""
    try:
        versions = get_config_versions(hostname, limit=50)
        return jsonify({'status': 'ok', 'hostname': hostname, 'versions': versions})
    except Exception as ex:
        return jsonify({'status': 'error', 'message': str(ex)}), 500


@app.route('/api/config_version/<int:config_id>')
def config_version(config_id):
    """Return full config text for a specific version."""
    try:
        row = get_config_by_id(config_id)
        if not row:
            return jsonify({'status': 'error', 'message': 'Version not found'}), 404
        return jsonify({'status': 'ok', 'version': row})
    except Exception as ex:
        return jsonify({'status': 'error', 'message': str(ex)}), 500


@app.route('/api/config_diff/<int:id_old>/<int:id_new>')
def config_diff(id_old, id_new):
    """Compare two config versions — shows added and removed lines."""
    try:
        result = diff_configs(id_old, id_new)
        return jsonify({'status': 'ok', 'diff': result})
    except Exception as ex:
        return jsonify({'status': 'error', 'message': str(ex)}), 500


# ── DB-backed Devices API ────────────────────────────────────────────────────
@app.route('/api/devices_db')
def api_devices_db():
    """Return devices from SQLite — richer data than file-based scan."""
    try:
        import glob, re as _re
        from datetime import datetime
        db_devs = get_all_devices()

        # Enrich with config text from files (for inline viewer)
        config_dir = os.path.join(
            os.path.dirname(os.path.abspath(__file__)), 'network_configs')

        for d in db_devs:
            cfg_path = os.path.join(config_dir, f"{d['hostname']}_config.txt")
            if os.path.exists(cfg_path):
                try:
                    with open(cfg_path, 'r', encoding='utf-8', errors='ignore') as f:
                        d['config'] = f.read()
                except Exception:
                    d['config'] = ''
            else:
                row = get_latest_config(d['hostname'])
                d['config'] = row['config_text'] if row else ''

            lines = d['config'].splitlines()
            d['total_lines']  = len(lines)
            d['active_lines'] = sum(
                1 for l in lines if l.strip() and not l.strip().startswith('!'))
            d['score'] = None
            d['level'] = 'UNKNOWN'

        return jsonify({'status': 'ok', 'devices': db_devs})
    except Exception as ex:
        return jsonify({'status': 'error', 'message': str(ex)}), 500


# ── Re-Scan SSE Stream ────────────────────────────────────────────────────────
# Server-Sent Events: streams live log lines to the browser during re-scan
# Browser reads each line and appends to the live terminal panel in real-time
import queue as _queue
_scan_queue   = _queue.Queue()
_scan_running = False

@app.route('/api/rescan', methods=['POST'])
def trigger_rescan():
    """Start a background re-scan. Returns immediately."""
    global _scan_running
    if _scan_running:
        return jsonify({'status': 'busy', 'message': 'Scan already running'}), 400
    import threading as _th
    _th.Thread(target=_run_rescan_pipeline, daemon=True).start()
    return jsonify({'status': 'started'})


ACTIVITY_LOG = os.path.expanduser('~/netguard_activity.log')

def _run_rescan_pipeline():
    """
    Runs harvest.py as a real subprocess — identical to pressing Start NetGuard.
    SSH works correctly because it runs in its own process, not a Flask thread.
    Safe: only replaces network_configs if harvest actually found devices.
    """
    global _scan_running
    _scan_running = True

    import datetime as _dt
    import subprocess as _sp
    import shutil as _sh
    import sys as _sys

    HOME        = os.path.expanduser('~')
    VENV_PY     = os.path.join(HOME, 'venv', 'bin', 'python3')
    HARVEST_PY  = os.path.join(HOME, 'harvest.py')
    REAL_CFG    = os.path.join(HOME, 'network_configs')
    BACKUP_CFG  = os.path.join(HOME, 'network_configs_bak')
    TOPO_FILE   = os.path.join(HOME, 'topology.json')
    TOPO_BAK    = os.path.join(HOME, 'topology.json.bak')

    def emit(msg, tag='info'):
        ts = _dt.datetime.now().strftime('%H:%M:%S')
        line = f"[{ts}] {msg}||{tag}"
        _scan_queue.put(line)
        try:
            with open(ACTIVITY_LOG, 'a') as lf:
                lf.write(line + '\n')
        except Exception:
            pass

    try:
        # Clear activity log
        try:
            open(ACTIVITY_LOG, 'w').close()
        except Exception:
            pass

        emit('🚀 NetGuard Re-Scan starting...', 'info')
        emit('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━', 'dim')

        # ── Backup existing data ───────────────────────────────────────────
        if os.path.exists(REAL_CFG):
            if os.path.exists(BACKUP_CFG):
                _sh.rmtree(BACKUP_CFG)
            _sh.copytree(REAL_CFG, BACKUP_CFG)
            emit('📦 Previous configs backed up', 'dim')

        if os.path.exists(TOPO_FILE):
            import shutil
            shutil.copy2(TOPO_FILE, TOPO_BAK)

        # ── Wipe for fresh scan ────────────────────────────────────────────
        if os.path.exists(REAL_CFG):
            _sh.rmtree(REAL_CFG)
        os.makedirs(REAL_CFG)
        if os.path.exists(TOPO_FILE):
            os.remove(TOPO_FILE)
        emit('🧹 Clean slate — starting fresh harvest', 'dim')
        emit('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━', 'dim')

        # ── Run harvest.py as subprocess (same as main.py does) ───────────
        emit('📡 STEP 1 — Network Discovery (harvest.py)', 'blue')
        emit('   Running as subprocess with full SSH environment', 'dim')

        proc = _sp.Popen(
            [VENV_PY, HARVEST_PY],
            cwd=HOME,
            stdout=_sp.PIPE,
            stderr=_sp.STDOUT,
            text=True,
            bufsize=1,
            env=dict(os.environ, HOME=HOME)
        )

        for raw_line in proc.stdout:
            line = raw_line.rstrip()
            if not line:
                continue
            # Colour code
            tag = 'info'
            if '✅' in line or 'Harvesting' in line or 'ROUTER' in line:
                tag = 'green'
            elif '❌' in line or 'error' in line.lower():
                tag = 'red'
            elif '⚠️' in line or 'failed' in line.lower() or 'warning' in line.lower():
                tag = 'orange'
            elif '🖥️' in line or 'PC' in line:
                tag = 'cyan'
            elif '📡' in line or '🔌' in line or 'SWITCH' in line:
                tag = 'blue'
            elif '━' in line or '═' in line or '===' in line:
                tag = 'dim'
            emit(line, tag)

        proc.wait()
        ret = proc.returncode
        emit(f'   Harvest process exited (code {ret})', 'dim' if ret == 0 else 'orange')

        # ── Count what harvest wrote ───────────────────────────────────────
        device_configs = []
        if os.path.exists(REAL_CFG):
            device_configs = [
                f for f in os.listdir(REAL_CFG)
                if f.endswith('.txt')
                and not f.startswith('PC-')
                and not f.startswith('Device-')
                and 'remediation' not in f
            ]

        n = len(device_configs)
        emit('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━', 'dim')

        if n > 0:
            # Great — clean up backup
            emit(f'✅ {n} device config(s) harvested', 'green')
            if os.path.exists(BACKUP_CFG):
                _sh.rmtree(BACKUP_CFG)
            if os.path.exists(TOPO_BAK):
                os.remove(TOPO_BAK)
        else:
            # Nothing harvested — restore previous data
            emit('⚠️  0 device configs written — restoring previous data', 'orange')
            emit('   (Ensure GNS3 routers are ON and SSH is responding)', 'dim')
            if os.path.exists(REAL_CFG):
                _sh.rmtree(REAL_CFG)
            if os.path.exists(BACKUP_CFG):
                _sh.move(BACKUP_CFG, REAL_CFG)
                emit('✅ Previous data restored', 'green')
            if os.path.exists(TOPO_BAK) and not os.path.exists(TOPO_FILE):
                import shutil
                shutil.copy2(TOPO_BAK, TOPO_FILE)
                os.remove(TOPO_BAK)

        # ── Step 2: Security Audit ─────────────────────────────────────────
        emit('🛡️  STEP 2 — Security Audit (40 checks)', 'blue')
        try:
            results = audit_all_devices()
            summary = get_audit_summary(results)
            c = summary.get('total_critical', 0)
            h = summary.get('total_high', 0)
            m = summary.get('total_medium', 0)
            l = summary.get('total_low', 0)
            emit(f'   Devices audited : {len(results)}', 'info')
            emit(f'   CRITICAL        : {c}', 'red'    if c else 'dim')
            emit(f'   HIGH            : {h}', 'orange' if h else 'dim')
            emit(f'   MEDIUM          : {m}', 'yellow' if m else 'dim')
            emit(f'   LOW             : {l}', 'cyan'   if l else 'dim')
            emit('✅ Audit complete', 'green')

            # ── Auto-email: send critical alerts + full report ──────
            try:
                _adata = {'status': 'ok', 'summary': summary, 'devices': results}
                send_critical_alerts(_adata)
                import sqlite3 as _sq2
                _db2 = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'netguard.db')
                _hist2 = []
                if os.path.exists(_db2):
                    _c2 = _sq2.connect(_db2)
                    _c2.row_factory = _sq2.Row
                    _hist2 = [dict(r) for r in _c2.execute(
                        'SELECT * FROM config_history ORDER BY harvested_at DESC LIMIT 100'
                    ).fetchall()]
                    _c2.close()
                send_scan_report(_adata, _hist2)
                emit('📧 Email report sent', 'green')
            except Exception as _me:
                emit(f'📧 Email skipped: {_me}', 'dim')

        except Exception as ae:
            emit(f'⚠️  Audit error: {ae}', 'orange')

        emit('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━', 'dim')
        emit('🎉 ALL DONE — Re-Scan complete!', 'green')
        _scan_queue.put('__DONE__')

    except Exception as ex:
        emit(f'❌ Pipeline error: {ex}', 'red')
        _scan_queue.put('__DONE__')
    finally:
        _scan_running = False


@app.route('/api/rescan_stream')
def rescan_stream():
    """SSE endpoint — browser connects here to receive live log lines."""

    def generate():
        yield "data: __CONNECTED__\n\n"
        while True:
            try:
                msg = _scan_queue.get(timeout=600)
                if msg == '__DONE__':
                    yield "data: __DONE__\n\n"
                    break
                yield f"data: {msg}\n\n"
            except _queue.Empty:
                yield "data: __TIMEOUT__\n\n"
                break

    return Response(
        stream_with_context(generate()),
        mimetype='text/event-stream',
        headers={
            'Cache-Control': 'no-cache',
            'X-Accel-Buffering': 'no',
        }
    )


@app.route('/api/scan_status')
def scan_status():
    return jsonify({'running': _scan_running})


# ── Full DB dump (for Database dashboard page) ────────────────────────────────
@app.route('/api/db_full')
def db_full():
    """Return all DB tables as JSON for the Database dashboard page."""
    import sqlite3, os
    db_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'netguard.db')
    if not os.path.exists(db_path):
        return jsonify({'status': 'error', 'message': 'Database not found — run a scan first'}), 404
    try:
        conn = sqlite3.connect(db_path)
        conn.row_factory = sqlite3.Row

        def q(sql, params=()):
            return [dict(r) for r in conn.execute(sql, params).fetchall()]

        devices   = q("SELECT * FROM devices ORDER BY last_seen DESC")
        history   = q("""
            SELECT id, hostname, config_hash, total_lines, active_lines,
                   harvested_at, changed
            FROM config_history ORDER BY harvested_at DESC LIMIT 200
        """)
        topology  = q("SELECT * FROM topology_links ORDER BY recorded_at DESC LIMIT 200")

        # Stats
        db_size   = os.path.getsize(db_path)
        total_cfg = conn.execute("SELECT COUNT(*) FROM config_history").fetchone()[0]
        changed   = conn.execute("SELECT COUNT(*) FROM config_history WHERE changed=1").fetchone()[0]
        conn.close()

        return jsonify({
            'status':   'ok',
            'stats': {
                'db_size_kb':    round(db_size / 1024, 1),
                'total_devices': len(devices),
                'total_configs': total_cfg,
                'total_changes': changed,
                'topology_links':len(topology),
            },
            'devices':  devices,
            'history':  history,
            'topology': topology,
        })
    except Exception as ex:
        return jsonify({'status': 'error', 'message': str(ex)}), 500


@app.route('/api/db_clear', methods=['POST'])
def db_clear():
    """Clear old config history — keep latest 12 per device."""
    try:
        from database import cleanup_all_devices
        result = cleanup_all_devices(keep=12)
        return jsonify({'status': 'ok', **result})
    except Exception as ex:
        return jsonify({'status': 'error', 'message': str(ex)}), 500


@app.route('/api/db_clear_last', methods=['POST'])
def db_clear_last():
    """Keep ONLY the last harvest record per device — maximum cleanup."""
    try:
        from database import keep_only_last_harvest
        result = keep_only_last_harvest()
        return jsonify({'status': 'ok', **result})
    except Exception as ex:
        return jsonify({'status': 'error', 'message': str(ex)}), 500


@app.route('/api/db_storage_stats')
def db_storage_stats():
    """Return detailed storage statistics."""
    try:
        from database import get_storage_stats
        return jsonify({'status': 'ok', 'stats': get_storage_stats()})
    except Exception as ex:
        return jsonify({'status': 'error', 'message': str(ex)}), 500


@app.route('/api/rebuild_topology')
def rebuild_topology():
    """
    Rebuild topology.json from database topology_links table.
    Called after auto-harvest discovers new devices.
    """
    try:
        import sqlite3 as _sq
        db_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'netguard.db')
        conn = _sq.connect(db_path)
        conn.row_factory = _sq.Row
        rows = conn.execute(
            "SELECT source, target, link_type FROM topology_links ORDER BY recorded_at DESC"
        ).fetchall()
        conn.close()

        # Build Cytoscape format
        seen = set()
        links = []
        for r in rows:
            key = tuple(sorted([r['source'], r['target']]))
            if key not in seen:
                seen.add(key)
                links.append({
                    "data": {
                        "source": r['source'],
                        "target": r['target'],
                        "type":   r['link_type']
                    }
                })

        if links:
            with open('topology.json', 'w') as f:
                json.dump(links, f, indent=4)

        # Count device types from devices table
        conn2 = _sq.connect(db_path)
        conn2.row_factory = _sq.Row
        devs = [dict(r) for r in conn2.execute("SELECT type FROM devices").fetchall()]
        conn2.close()

        counts = {
            'routers':   sum(1 for d in devs if d['type'] == 'router'),
            'switches':  sum(1 for d in devs if d['type'] == 'switch'),
            'firewalls': sum(1 for d in devs if d['type'] == 'firewall'),
            'total':     len(devs),
        }

        # Count PCs from topology.json nodes (PCs not in DB — no SSH)
        pc_count = 0
        try:
            all_nodes = set()
            for lk in links:
                all_nodes.add(lk['data']['source'])
                all_nodes.add(lk['data']['target'])
            pc_count = sum(1 for n in all_nodes
                          if 'PC-' in n.upper() or n.upper().startswith('PC'))
        except Exception:
            pass
        counts['pcs'] = pc_count
        counts['total'] = len(devs) + pc_count

        return jsonify({
            'status': 'ok',
            'links':  len(links),
            'counts': counts,
        })
    except Exception as ex:
        return jsonify({'status': 'error', 'message': str(ex)}), 500


@app.route('/api/db_query', methods=['POST'])
def db_query():
    """Run a safe SELECT query against netguard.db (for professor demo)."""
    import sqlite3, os
    data = request.get_json(silent=True) or {}
    sql  = (data.get('sql') or '').strip()
    if not sql.upper().startswith('SELECT'):
        return jsonify({'status': 'error', 'message': 'Only SELECT queries allowed'}), 400
    db_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'netguard.db')
    try:
        conn = sqlite3.connect(db_path)
        conn.row_factory = sqlite3.Row
        cur  = conn.execute(sql)
        cols = [d[0] for d in cur.description]
        rows = [list(r) for r in cur.fetchall()]
        conn.close()
        return jsonify({'status': 'ok', 'columns': cols, 'rows': rows, 'count': len(rows)})
    except Exception as ex:
        return jsonify({'status': 'error', 'message': str(ex)}), 400


# ── Email Settings Routes ─────────────────────────────────────────────────────
@app.route('/api/email_settings', methods=['GET'])
def get_email_settings():
    s = load_settings()
    # Never send password back to frontend
    safe = {k: v for k, v in s.items() if k != 'password'}
    safe['has_password'] = bool(s.get('password'))
    return jsonify({'status': 'ok', 'settings': safe})


@app.route('/api/email_settings', methods=['POST'])
def set_email_settings():
    data = request.get_json(silent=True) or {}
    current = load_settings()
    # Only update password if a new one was provided
    if not data.get('password') and current.get('password'):
        data['password'] = current['password']
    save_settings(data)
    return jsonify({'status': 'ok', 'message': 'Settings saved'})


@app.route('/api/email_test', methods=['POST'])
def email_test():
    """Send a test email to verify settings work."""
    import datetime
    s = load_settings()
    recipients = get_recipients(s)
    if not recipients:
        return jsonify({'status': 'error', 'message': 'No recipients configured'}), 400
    if not s.get('sender') or not s.get('password'):
        return jsonify({'status': 'error', 'message': 'Sender or password missing'}), 400

    now = datetime.datetime.now().strftime('%b %d %Y  %H:%M:%S')
    body = f"""
    <div style="background:#080d14;color:#cdd9e8;font-family:Arial,sans-serif;padding:24px;max-width:600px;margin:0 auto">
      <div style="background:#111c2b;border:1px solid #1a2d45;border-top:3px solid #00e07a;border-radius:10px;padding:20px">
        <div style="font-size:.7rem;font-weight:700;letter-spacing:.2em;color:#00e07a;margin-bottom:8px">✅ NETGUARD TEST EMAIL</div>
        <div style="font-size:1.2rem;font-weight:800;color:#fff">Email alerts are working!</div>
        <div style="color:#5a7a9a;font-size:.8rem;margin-top:8px;font-family:monospace">
          Sent at: {now}<br>
          Recipients: {', '.join(recipients)}<br>
          System: NetGuard v4.0
        </div>
      </div>
      <div style="margin-top:12px;font-size:.72rem;color:#5a7a9a;font-family:monospace;text-align:center">
        NetGuard v4.0 · BY: Suhail · Shamha · Hiqmi
      </div>
    </div>"""

    ok, err = send_email(
        subject=f"✅ [NetGuard] Test Email — {now}",
        body_html=body,
        recipients=recipients,
        sender=s['sender'],
        password=s['password']
    )
    if ok:
        return jsonify({'status': 'ok', 'message': f'Test email sent to {", ".join(recipients)}'})
    else:
        return jsonify({'status': 'error', 'message': err}), 500


@app.route('/api/email_send_report', methods=['POST'])
def email_send_report_now():
    """Manually send the report right now."""
    try:
        results = audit_all_devices()
        summary = get_audit_summary(results)
        audit_data = {'status': 'ok', 'summary': summary, 'devices': results}
        import sqlite3 as _sq, os as _os
        db_path = _os.path.join(_os.path.dirname(_os.path.abspath(__file__)), 'netguard.db')
        history = []
        if _os.path.exists(db_path):
            conn = _sq.connect(db_path)
            conn.row_factory = _sq.Row
            history = [dict(r) for r in conn.execute(
                "SELECT * FROM config_history ORDER BY harvested_at DESC LIMIT 100"
            ).fetchall()]
            conn.close()
        send_scan_report(audit_data, history)
        return jsonify({'status': 'ok', 'message': 'Report sent'})
    except Exception as ex:
        return jsonify({'status': 'error', 'message': str(ex)}), 500

@app.route('/api/download_pdf')
def download_pdf():
    try:
        results = audit_all_devices()
        summary = get_audit_summary(results)
        pdf_bytes = generate_pdf_report({'summary': summary, 'devices': results})
        from flask import send_file
        from io import BytesIO
        return send_file(BytesIO(pdf_bytes), as_attachment=True,
                         download_name='NetGuard_Report.pdf',
                         mimetype='application/pdf')
    except Exception as ex:
        return jsonify({'status': 'error', 'message': str(ex)}), 500


# ── Live Monitor Routes ───────────────────────────────────────────────────────

@app.route('/api/device_status')
def api_device_status():
    """Return current live status of all monitored devices."""
    try:
        from database import get_all_device_status, get_monitor_stats
        devices = get_all_device_status()
        stats   = get_monitor_stats()
        return jsonify({
            'status':  'ok',
            'devices': devices,
            'stats':   stats,
            'monitor_running': MONITOR_CONFIG.get('enabled', False),
            'interval': MONITOR_CONFIG.get('interval', 60),
        })
    except Exception as ex:
        return jsonify({'status': 'error', 'message': str(ex)}), 500


@app.route('/api/monitor_stream')
def monitor_stream():
    """SSE endpoint — pushes live device status events to browser."""
    import queue as _q

    def generate():
        yield "data: __CONNECTED__\n\n"
        while True:
            try:
                event = monitor_event_queue.get(timeout=30)
                yield f"data: {event}\n\n"
            except _q.Empty:
                # Heartbeat to keep connection alive
                yield "data: __HEARTBEAT__\n\n"

    return Response(
        stream_with_context(generate()),
        mimetype='text/event-stream',
        headers={
            'Cache-Control': 'no-cache',
            'X-Accel-Buffering': 'no',
            'Connection': 'keep-alive',
        }
    )


@app.route('/api/alerts')
def api_alerts():
    """Return alert history."""
    try:
        from database import get_alerts
        limit    = int(request.args.get('limit', 100))
        unack    = request.args.get('unack', 'false').lower() == 'true'
        alerts   = get_alerts(limit=limit, unack_only=unack)
        return jsonify({'status': 'ok', 'alerts': alerts})
    except Exception as ex:
        return jsonify({'status': 'error', 'message': str(ex)}), 500


@app.route('/api/alerts/ack/<int:alert_id>', methods=['POST'])
def ack_alert_route(alert_id):
    """Acknowledge an alert."""
    try:
        from database import ack_alert
        ack_alert(alert_id)
        return jsonify({'status': 'ok'})
    except Exception as ex:
        return jsonify({'status': 'error', 'message': str(ex)}), 500


@app.route('/api/monitor/config', methods=['GET', 'POST'])
def monitor_config():
    """Get or update monitor configuration."""
    if request.method == 'GET':
        return jsonify({'status': 'ok', 'config': MONITOR_CONFIG})
    data = request.get_json(silent=True) or {}
    update_config(data)
    return jsonify({'status': 'ok', 'config': MONITOR_CONFIG})


@app.route('/api/monitor/start', methods=['POST'])
def monitor_start():
    start_monitor()
    MONITOR_CONFIG['enabled'] = True
    return jsonify({'status': 'ok', 'message': 'Monitor started'})


@app.route('/api/monitor/stop', methods=['POST'])
def monitor_stop():
    MONITOR_CONFIG['enabled'] = False
    return jsonify({'status': 'ok', 'message': 'Monitor paused'})



@app.route('/api/remediate_r4', methods=['POST'])
def remediate_r4():
    import time as _time
    data     = request.get_json(silent=True) or {}
    fix_cmds = data.get('commands', '')
    check_id = data.get('check_id', '')
    title    = data.get('title', '')

    R4_IP   = '10.10.4.2'
    R4_USER = 'admin'
    R4_PASS = 'cisco'
    R4_ENA  = 'cisco'

    if not fix_cmds:
        return jsonify({'status': 'error', 'message': 'No commands provided'}), 400

    try:
        from netmiko import ConnectHandler

        conn = ConnectHandler(
            device_type='cisco_ios_telnet',
            host=R4_IP,
            username=R4_USER,
            password=R4_PASS,
            secret=R4_ENA,
            conn_timeout=30,
            read_timeout_override=120,
            global_delay_factor=3,
            fast_cli=False,
        )
        conn.enable()
        conn.send_command('terminal length 0', read_timeout=15)

        lines = [l.strip() for l in fix_cmds.splitlines()
                 if l.strip() and not l.strip().startswith('!')]

        needs_conf = any(
            l.startswith(('no ', 'service ', 'ip ', 'username ', 'crypto ',
                          'line ', 'logging ', 'ntp ', 'banner ', 'snmp',
                          'spanning', 'interface', 'router ', 'enable secret',
                          'aaa ', 'login '))
            for l in lines
        )

        # Filter out wrapper lines - send only real IOS commands
        config_lines = [
            l for l in lines
            if l not in ('configure terminal', 'conf t', 'end', 'write memory')
            and not l.startswith('!')
        ]

        output = ''
        if needs_conf and config_lines:
            # Use send_config_set - handles banner motd and all config commands
            try:
                output = conn.send_config_set(
                    config_lines,
                    cmd_verify=False,
                    read_timeout=60,
                    delay_factor=3,
                )
            except Exception as ce:
                # Fallback: send line by line with timing
                conn.config_mode()
                for line in config_lines:
                    out = conn.send_command_timing(
                        line,
                        delay_factor=3,
                        read_timeout=30,
                    )
                    output += line + "\n" + out + "\n"
                conn.exit_config_mode()
        elif config_lines:
            for line in config_lines:
                out = conn.send_command(line, read_timeout=30)
                output += line + "\n" + out + "\n"

        conn.send_command_timing('write memory', delay_factor=3)

        new_config = conn.send_command('show running-config', read_timeout=120)
        conn.disconnect()

        try:
            cfg_path = os.path.join(
                os.path.dirname(os.path.abspath(__file__)),
                'network_configs', 'R4_config.txt'
            )
            with open(cfg_path, 'w') as f:
                f.write(new_config)
            from database import upsert_device, save_config
            upsert_device('R4', R4_IP, 'router')
            save_config('R4', new_config)
        except Exception as dbe:
            print(f"DB save warning: {dbe}")

        _time.sleep(2)
        after_score    = None
        after_critical = None
        try:
            from security_audit import audit_all_devices
            results   = audit_all_devices()
            r4_result = next((r for r in results if r['device'] == 'R4'), None)
            if r4_result:
                after_score    = r4_result['score']
                after_critical = r4_result['counts'].get('CRITICAL', 0)
        except Exception:
            pass

        try:
            from email_alerts import load_settings, send_email, get_recipients
            import datetime as _dt
            s = load_settings()
            if s.get('enabled') and s.get('sender'):
                recipients = get_recipients(s)
                if recipients:
                    now     = _dt.datetime.now().strftime('%b %d %Y  %H:%M:%S')
                    subject = f"[NetGuard] Remediation Applied - R4 - {title} - {now}"
                    body    = f"""<div style="background:#080d14;color:#cdd9e8;font-family:Arial,sans-serif;padding:24px;max-width:700px;margin:0 auto">
                      <div style="background:#111c2b;border:1px solid #1a2d45;border-top:3px solid #00e07a;border-radius:10px;padding:20px">
                        <div style="font-size:.7rem;font-weight:700;letter-spacing:.2em;color:#00e07a;margin-bottom:6px">REMEDIATION APPLIED</div>
                        <div style="font-size:1.2rem;font-weight:800;color:#fff">R4 - {title}</div>
                        <div style="color:#5a7a9a;font-size:.8rem;margin-top:8px;font-family:monospace">
                          Device: R4 ({R4_IP})<br>Check: {check_id}<br>Applied: {now}<br>
                          {"New Score: " + str(after_score) + " | Critical: " + str(after_critical) if after_score is not None else ""}
                        </div>
                        <div style="margin-top:12px;background:#030608;border:1px solid #1a2d45;border-radius:8px;padding:12px;font-family:monospace;font-size:.75rem;color:#7dd3fc">
                          {fix_cmds.replace(chr(10),"<br>")}
                        </div>
                      </div>
                    </div>"""
                    send_email(subject, body, recipients, s['sender'], s['password'])
        except Exception as me:
            print(f"Email error: {me}")

        return jsonify({
            'status':         'ok',
            'message':        'Fix applied to R4 successfully',
            'check_id':       check_id,
            'output':         output[:500],
            'after_score':    after_score,
            'after_critical': after_critical,
        })

    except Exception as ex:
        return jsonify({'status': 'error', 'message': str(ex)}), 500


# ── Main Dashboard ───────────────────────────────────────────────────────────
@app.route('/')
@auth.login_required
def index():
    stats      = {'routers': 0, 'switches': 0, 'firewalls': 0, 'pcs': 0, 'other': 0}
    nodes      = []
    unique_ids = set()

    if os.path.exists('topology.json'):
        try:
            with open('topology.json', 'r') as f:
                for link in json.load(f):
                    unique_ids.add(link['data']['source'])
                    unique_ids.add(link['data']['target'])
        except Exception as e:
            print(f"Topology error: {e}")

    for node_id in unique_ids:
        n = node_id.upper()
        if any(n.startswith(x) for x in ('FW','ASA','PA-','FGT','FORTINET','FIREWALL')):
            stats['firewalls'] += 1
            nodes.append({'data': {'id': node_id, 'label': node_id}, 'classes': 'firewall'})
        elif any(n.startswith(x) for x in ('SW','DIST','ACCESS')) or 'SWITCH' in n:
            stats['switches'] += 1
            nodes.append({'data': {'id': node_id, 'label': node_id}, 'classes': 'switch'})
        elif n.startswith('R') or any(n.startswith(x) for x in ('RTR','ROUTER','GW')):
            stats['routers'] += 1
            nodes.append({'data': {'id': node_id, 'label': node_id}, 'classes': 'router'})
        elif 'PC-' in n:
            stats['pcs'] += 1
            nodes.append({'data': {'id': node_id, 'label': node_id}, 'classes': 'pc'})
        elif n in ('INTERNET', 'CLOUD'):
            nodes.append({'data': {'id': node_id, 'label': node_id}, 'classes': 'cloud'})
        else:
            stats['other'] += 1
            nodes.append({'data': {'id': node_id, 'label': node_id}, 'classes': 'generic'})

    if 'Cloud' not in unique_ids and 'Internet' not in unique_ids:
        nodes.append({'data': {'id': 'Cloud', 'label': 'INTERNET'}, 'classes': 'cloud'})

    return render_template('index.html', stats=stats, dynamic_nodes=nodes)


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=False, use_reloader=False)
