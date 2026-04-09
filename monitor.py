"""
NetGuard Live Monitor Engine — 2026
=====================================
4-Layer detection per device:
  Layer 1: ICMP ping (icmplib)
  Layer 2: TCP port check (22/23)
  Layer 3: SNMP sysUptime poll (pysnmp)
  Layer 4: SSH show version (paramiko/netmiko)

Runs as a background thread inside Flask.
Pushes events to SSE queue for real-time browser updates.
Supports ANY network — reads devices from SQLite automatically.
"""

import os, re, time, socket, threading, datetime, json
import queue as _queue
from database import (get_all_devices, upsert_device_status,
                      get_all_device_status, add_alert,
                      resolve_alert, get_monitor_stats, init_db)

# ── Global state ──────────────────────────────────────────────────────────────
_monitor_thread  = None
_monitor_running = False
_monitor_lock    = threading.Lock()

# SSE event queue — browser subscribes to this
monitor_event_queue = _queue.Queue(maxsize=500)

# In-memory status cache (hostname → status dict)
_status_cache = {}
_cache_lock   = threading.Lock()

# Monitor configuration
MONITOR_CONFIG = {
    'interval':         60,     # seconds between checks
    'ping_timeout':     4,      # ICMP timeout seconds
    'tcp_timeout':      6,      # TCP connect timeout
    'snmp_community':   'netguard',
    'snmp_timeout':     3,
    'ssh_timeout':      30,
    'fail_threshold':   2,      # consecutive failures before OFFLINE alert
    'ping_warn_ms':     300,    # ping above this = DEGRADED
    'enabled':          True,
    'harvest_interval': 420,    # auto-harvest every 7 minutes
}

# Device IP map — built from database + known static IPs
# These are fallback IPs if device not in DB yet
STATIC_IPS = {
    'FW1': '192.168.214.3',
    'R1':  '10.10.0.2',
}


# ─────────────────────────────────────────────────────────────────────────────
#  LAYER 1 — ICMP PING
# ─────────────────────────────────────────────────────────────────────────────
def _ping(ip, timeout=2):
    """
    Ping an IP using subprocess /bin/ping — works without root.
    Returns (reachable: bool, rtt_ms: float).
    """
    import subprocess
    try:
        r = subprocess.run(
            ['/bin/ping', '-c', '2', '-W', str(timeout), ip],
            capture_output=True,
            timeout=timeout * 2 + 4
        )
        if r.returncode == 0:
            out = r.stdout.decode('utf-8', errors='ignore')
            m = re.search(r'rtt min/avg/max.*?=\s*[\d.]+/([\d.]+)/', out)
            rtt = float(m.group(1)) if m else 1.0
            return True, round(rtt, 1)
        return False, -1
    except subprocess.TimeoutExpired:
        return False, -1
    except Exception as ex:
        print(f"Ping error for {ip}: {ex}")
        return False, -1


# ─────────────────────────────────────────────────────────────────────────────
#  LAYER 2 — TCP PORT CHECK
# ─────────────────────────────────────────────────────────────────────────────
def _tcp_check(ip, ports=(22, 23), timeout=3):
    """
    Check if any management port is open.
    Returns (open: bool, port: int).
    """
    for port in ports:
        try:
            with socket.create_connection((ip, port), timeout=timeout):
                return True, port
        except Exception:
            continue
    return False, -1


# ─────────────────────────────────────────────────────────────────────────────
#  LAYER 3 — SNMP POLL
# ─────────────────────────────────────────────────────────────────────────────
def _snmp_check(ip, community='netguard', timeout=2):
    """
    Poll sysUptime via SNMP v2c.
    Returns (reachable: bool, uptime_str: str).
    OID 1.3.6.1.2.1.1.3.0 = sysUpTime
    OID 1.3.6.1.2.1.1.5.0 = sysName
    """
    try:
        from pysnmp.hlapi import (
            getCmd, SnmpEngine, CommunityData, UdpTransportTarget,
            ContextData, ObjectType, ObjectIdentity
        )
        iterator = getCmd(
            SnmpEngine(),
            CommunityData(community, mpModel=1),  # v2c
            UdpTransportTarget((ip, 161), timeout=timeout, retries=1),
            ContextData(),
            ObjectType(ObjectIdentity('1.3.6.1.2.1.1.3.0')),  # sysUpTime
            ObjectType(ObjectIdentity('1.3.6.1.2.1.1.5.0')),  # sysName
        )
        error_indication, error_status, _, var_binds = next(iterator)

        if error_indication or error_status:
            return False, ''

        uptime_ticks = int(var_binds[0][1])
        seconds      = uptime_ticks // 100
        days         = seconds // 86400
        hours        = (seconds % 86400) // 3600
        mins         = (seconds % 3600) // 60
        uptime_str   = f"{days}d {hours}h {mins}m"
        return True, uptime_str

    except ImportError:
        return False, 'snmp_not_installed'
    except Exception:
        return False, ''


# ─────────────────────────────────────────────────────────────────────────────
#  LAYER 4 — SSH QUICK CHECK
# ─────────────────────────────────────────────────────────────────────────────
def _ssh_check(ip, dev_type='cisco', timeout=8):
    """
    Quick SSH connection check.
    Does NOT run full harvest — just connects and disconnects.
    Returns (reachable: bool, banner: str).
    """
    CISCO_CREDS = [
        {'username': 'admin', 'password': 'cisco',  'secret': 'ciscoo'},
        {'username': 'admin', 'password': 'admin',  'secret': 'admin'},
    ]
    VYOS_CREDS = [
        {'username': 'admin', 'password': 'Admin@123'},
    ]

    creds_list = VYOS_CREDS if dev_type == 'firewall' else CISCO_CREDS

    try:
        import paramiko
        for creds in creds_list:
            try:
                client = paramiko.SSHClient()
                client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                client.connect(
                    ip,
                    username=creds['username'],
                    password=creds['password'],
                    timeout=timeout,
                    allow_agent=False,
                    look_for_keys=False,
                    banner_timeout=timeout,
                )
                transport = client.get_transport()
                banner = str(transport.remote_version) if transport else 'SSH-OK'
                client.close()
                return True, banner
            except paramiko.AuthenticationException:
                # Auth failed but device IS reachable
                return True, 'AUTH_FAILED_BUT_REACHABLE'
            except Exception:
                continue
        return False, ''
    except ImportError:
        return False, 'paramiko_not_installed'


# ─────────────────────────────────────────────────────────────────────────────
#  MAIN CHECK FUNCTION — 4 layers combined
# ─────────────────────────────────────────────────────────────────────────────
def check_device(hostname, ip, dev_type='router'):
    """
    Run all 4 check layers and return final status.
    Returns dict: {status, ping_ms, method_used, error_msg, snmp_uptime}
    """
    result = {
        'status':      'UNKNOWN',
        'ping_ms':     -1,
        'method_used': '',
        'error_msg':   '',
        'snmp_uptime': '',
    }

    if not ip or ip in ('—', '', 'None'):
        result['status']    = 'UNKNOWN'
        result['error_msg'] = 'No IP configured'
        return result

    # ── Layer 1: ICMP Ping ──────────────────────────────────────────────────
    ping_ok, ping_ms = _ping(ip, timeout=MONITOR_CONFIG['ping_timeout'])
    result['ping_ms'] = ping_ms

    if ping_ok:
        result['method_used'] = 'PING'
        if ping_ms > MONITOR_CONFIG['ping_warn_ms']:
            result['status'] = 'DEGRADED'
            result['error_msg'] = f'High latency: {ping_ms}ms'
        else:
            result['status'] = 'ONLINE'

        # ── Layer 3: SNMP (enrichment — runs even if ping OK) ──────────────
        snmp_ok, uptime = _snmp_check(ip, MONITOR_CONFIG['snmp_community'])
        if snmp_ok and uptime and 'not_installed' not in uptime:
            result['snmp_uptime']  = uptime
            result['method_used'] += '+SNMP'

        return result

    # Ping failed — try Layer 2: TCP port check
    tcp_ok, open_port = _tcp_check(ip, timeout=MONITOR_CONFIG['tcp_timeout'])

    if tcp_ok:
        result['status']      = 'DEGRADED'
        result['method_used'] = f'TCP:{open_port}'
        result['error_msg']   = f'Ping failed but port {open_port} open'

        # ── Layer 4: SSH quick check ───────────────────────────────────────
        if open_port == 22:
            ssh_ok, banner = _ssh_check(ip, dev_type, MONITOR_CONFIG['ssh_timeout'])
            if ssh_ok:
                result['method_used'] += '+SSH'
                if 'AUTH_FAILED' not in banner:
                    result['status'] = 'ONLINE'
                    result['error_msg'] = f'SSH OK ({banner[:30]})'

        return result

    # All layers failed — OFFLINE
    result['status']    = 'OFFLINE'
    result['error_msg'] = 'Ping + TCP + SSH all failed'
    result['method_used'] = 'ALL_FAILED'
    return result


# ─────────────────────────────────────────────────────────────────────────────
#  EVENT EMITTER — pushes to SSE queue
# ─────────────────────────────────────────────────────────────────────────────
def _emit(event_type, data):
    """Push event to SSE queue for browser."""
    event = {
        'type': event_type,
        'time': datetime.datetime.now().strftime('%H:%M:%S'),
        **data
    }
    try:
        monitor_event_queue.put_nowait(json.dumps(event))
    except _queue.Full:
        # Drop oldest event if queue full
        try:
            monitor_event_queue.get_nowait()
            monitor_event_queue.put_nowait(json.dumps(event))
        except Exception:
            pass




# ─────────────────────────────────────────────────────────────────────────────
#  AUTO-HARVEST FUNCTIONS
# ─────────────────────────────────────────────────────────────────────────────
import time as _time_module

_last_harvest_time = {}
_harvest_lock      = threading.Lock()


def _should_harvest(hostname):
    """Check if 7 minutes passed since last harvest for this device."""
    with _harvest_lock:
        last    = _last_harvest_time.get(hostname, 0)
        elapsed = _time_module.time() - last
        return elapsed >= MONITOR_CONFIG.get('harvest_interval', 420)


def _trigger_harvest(hostname, ip, dev_type):
    """Trigger config harvest for one online device in background thread."""
    def _do_harvest():
        try:
            print(f"📡 Auto-harvest: {hostname} ({ip})...")
            config_changed = False

            if dev_type == 'firewall':
                from harvest import harvest_firewall_vyos
                fw_config, _ = harvest_firewall_vyos(ip, hostname)
                if fw_config:
                    import os as _os
                    with open(f"network_configs/{hostname}_config.txt", 'w', encoding='utf-8') as f:
                        f.write(fw_config)
                    from database import upsert_device, save_config
                    upsert_device(hostname, ip, 'firewall')
                    status = save_config(hostname, fw_config)
                    config_changed = (status == 'changed')
                    print(f"📡 Auto-harvest FW: {hostname} → {status}")
            else:
                from harvest import harvest_single_device
                result = harvest_single_device(ip, force=True)
                if result:
                    from database import get_latest_config
                    latest = get_latest_config(hostname)
                    if latest:
                        config_changed = bool(latest.get('changed', 0))
                    print(f"📡 Auto-harvest: {hostname} complete")

            with _harvest_lock:
                _last_harvest_time[hostname] = _time_module.time()

            # Always emit topology_update so frontend refreshes counts + topology
            _emit('topology_update', {
                'hostname': hostname,
                'ip':       ip,
                'message':  f"{hostname} harvested — topology may have updated",
            })

            if config_changed:
                _emit('config_changed', {
                    'hostname': hostname, 'ip': ip,
                    'message':  f"{hostname} configuration changed — auto-detected",
                    'severity': 'WARNING',
                })
                from database import add_alert as _add_alert
                _add_alert(hostname, ip, 'CONFIG_CHANGED',
                           f"{hostname} config changed — auto-harvest detected change",
                           'WARNING')
                _send_config_change_email(hostname, ip)
                print(f"🔄 Config CHANGED: {hostname} — alert sent")

        except Exception as ex:
            print(f"📡 Auto-harvest error for {hostname}: {ex}")

    t = threading.Thread(target=_do_harvest, daemon=True, name=f"Harvest-{hostname}")
    t.start()


def _send_config_change_email(hostname, ip):
    """Send email when config change detected — includes diff of what changed."""
    try:
        from email_alerts import load_settings, send_email, get_recipients
        import datetime as _dt
        s = load_settings()
        if not s.get('enabled') or not s.get('alert_critical'):
            return
        recipients = get_recipients(s)
        if not recipients:
            return
        now = _dt.datetime.now().strftime('%b %d %Y  %H:%M:%S')

        # Get the last two config versions to show what changed
        diff_html = ''
        added_lines = []
        removed_lines = []
        try:
            from database import get_conn
            with get_conn() as conn:
                rows = conn.execute("""
                    SELECT id, config_text, harvested_at
                    FROM config_history
                    WHERE hostname=?
                    ORDER BY harvested_at DESC
                    LIMIT 2
                """, (hostname,)).fetchall()

            if len(rows) >= 2:
                new_cfg = set(rows[0]['config_text'].splitlines())
                old_cfg = set(rows[1]['config_text'].splitlines())
                added_lines   = [l for l in new_cfg - old_cfg if l.strip() and not l.strip().startswith('!')]
                removed_lines = [l for l in old_cfg - new_cfg if l.strip() and not l.strip().startswith('!')]

                def _esc(t):
                    return t.replace('&','&amp;').replace('<','&lt;').replace('>','&gt;')

                diff_rows = ''
                for line in removed_lines[:20]:
                    diff_rows += f'<div style="background:rgba(255,61,87,.08);color:#ff3d57;font-family:monospace;font-size:.75rem;padding:3px 8px;border-left:3px solid #ff3d57;margin-bottom:2px">− {_esc(line)}</div>'
                for line in added_lines[:20]:
                    diff_rows += f'<div style="background:rgba(0,224,122,.08);color:#00e07a;font-family:monospace;font-size:.75rem;padding:3px 8px;border-left:3px solid #00e07a;margin-bottom:2px">+ {_esc(line)}</div>'

                if diff_rows:
                    diff_html = f"""
                    <div style="margin-top:16px">
                      <div style="font-family:monospace;font-size:.7rem;font-weight:700;
                                  color:#fff;margin-bottom:8px;letter-spacing:.08em">
                        CONFIGURATION DIFF
                        <span style="color:#ff3d57;margin-left:8px">−{len(removed_lines)} removed</span>
                        <span style="color:#00e07a;margin-left:8px">+{len(added_lines)} added</span>
                      </div>
                      <div style="background:#030608;border:1px solid #1a2d45;
                                  border-radius:8px;padding:12px;max-height:400px;overflow:auto">
                        {diff_rows}
                        {'<div style="color:#5a7a9a;font-size:.7rem;padding:4px 8px">... and more changes</div>' if len(added_lines)+len(removed_lines) > 20 else ''}
                      </div>
                    </div>"""
        except Exception as de:
            print(f"📧 Diff error: {de}")

        subject = f"🔄 [NetGuard] Config Changed — {hostname} ({ip}) — {now}"
        if added_lines or removed_lines:
            subject = f"🔄 [NetGuard] Config Changed — {hostname} — +{len(added_lines)}/−{len(removed_lines)} lines — {now}"

        body = f"""
        <div style="background:#080d14;color:#cdd9e8;font-family:Arial,sans-serif;
                    padding:24px;max-width:700px;margin:0 auto">
          <div style="background:#111c2b;border:1px solid #1a2d45;
                      border-top:3px solid #ff7b35;border-radius:10px;padding:20px">
            <div style="font-size:.7rem;font-weight:700;letter-spacing:.2em;
                        color:#ff7b35;margin-bottom:6px">🔄 CONFIGURATION CHANGE DETECTED</div>
            <div style="font-size:1.3rem;font-weight:800;color:#fff">{hostname}</div>
            <div style="color:#5a7a9a;font-size:.8rem;margin-top:8px;font-family:monospace">
              IP: {ip}<br>
              Detected: {now}<br>
              Changes: <span style="color:#ff3d57">−{len(removed_lines)} lines removed</span>
                       &nbsp;/&nbsp;
                       <span style="color:#00e07a">+{len(added_lines)} lines added</span>
            </div>
            <div style="margin-top:12px;padding:10px;background:rgba(255,123,53,.08);
                        border:1px solid rgba(255,123,53,.2);border-radius:6px;
                        font-family:monospace;font-size:.78rem;color:#ff7b35">
              ⚠️ Review this change immediately — device was recently offline.
              This could indicate unauthorized configuration modification.
            </div>
            {diff_html}
          </div>
          <div style="margin-top:12px;font-size:.72rem;color:#5a7a9a;
                      font-family:monospace;text-align:center">
            NetGuard v6.0 · Security Monitor · BY: Suhail · Shamha · Hiqmi
          </div>
        </div>"""
        send_email(subject, body, recipients, s['sender'], s['password'])
        print(f"📧 Config change email sent for {hostname} (+{len(added_lines)}/−{len(removed_lines)} lines)")
    except Exception as ex:
        print(f"📧 Config change email error: {ex}")


def _send_device_alert_email(hostname, ip, alert_type, down_since=None):
    """Send email when device goes down or recovers."""
    try:
        from email_alerts import load_settings, send_email, get_recipients
        import datetime as _dt
        s = load_settings()
        if not s.get('enabled') or not s.get('alert_critical'):
            return
        recipients = get_recipients(s)
        if not recipients:
            return
        now = _dt.datetime.now().strftime('%b %d %Y  %H:%M:%S')
        if alert_type == 'DEVICE_DOWN':
            subject = f"🔴 [NetGuard] DEVICE OFFLINE — {hostname} ({ip}) — {now}"
            color   = '#ff3d57'
            title   = 'DEVICE OFFLINE'
            msg     = f"{hostname} ({ip}) is not responding to ping or TCP checks."
        else:
            subject = f"🟢 [NetGuard] DEVICE RECOVERED — {hostname} ({ip}) — {now}"
            color   = '#00e07a'
            title   = 'DEVICE RECOVERED'
            msg     = f"{hostname} ({ip}) is back online."
            if down_since:
                msg += f" Was offline since: {down_since}"
        body = f"""
        <div style="background:#080d14;color:#cdd9e8;font-family:Arial,sans-serif;
                    padding:24px;max-width:600px;margin:0 auto">
          <div style="background:#111c2b;border:1px solid #1a2d45;
                      border-top:3px solid {color};border-radius:10px;padding:20px">
            <div style="font-size:.7rem;font-weight:700;letter-spacing:.2em;
                        color:{color};margin-bottom:6px">{title}</div>
            <div style="font-size:1.2rem;font-weight:800;color:#fff">{hostname}</div>
            <div style="color:#5a7a9a;font-size:.8rem;margin-top:8px;font-family:monospace">
              IP: {ip}<br>Time: {now}
            </div>
            <div style="margin-top:10px;padding:10px;background:rgba(0,0,0,.2);
                        border:1px solid {color}44;border-radius:6px;
                        font-family:monospace;font-size:.78rem;color:{color}">
              {msg}
            </div>
          </div>
        </div>"""
        send_email(subject, body, recipients, s['sender'], s['password'])
        print(f"📧 {title} email sent for {hostname}")
    except Exception as ex:
        print(f"📧 Device alert email error: {ex}")


# ─────────────────────────────────────────────────────────────────────────────
#  MONITOR LOOP
# ─────────────────────────────────────────────────────────────────────────────


def _get_pc_devices():
    pc_devices = []
    try:
        import json as _j, re as _re2
        topo = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'topology.json')
        if not os.path.exists(topo):
            return []
        with open(topo) as f:
            links = _j.load(f)
        nodes = set()
        for lk in links:
            nodes.add(lk['data']['source'])
            nodes.add(lk['data']['target'])
        for node in nodes:
            if node.upper().startswith('PC-'):
                ip = node[3:]
                if _re2.match(r'\d+\.\d+\.\d+\.\d+', ip):
                    pc_devices.append({'hostname': node, 'ip': ip, 'type': 'pc'})
    except Exception:
        pass
    return pc_devices

def _monitor_loop():
    """Main monitoring loop. Runs in background thread."""
    global _monitor_running

    print("📡 NetGuard Live Monitor started")
    _emit('monitor_started', {'message': 'Live monitoring active'})

    while _monitor_running:
        if not MONITOR_CONFIG['enabled']:
            time.sleep(10)
            continue

        loop_start = time.time()

        # Get all known devices from database
        try:
            devices = get_all_devices()
        except Exception as ex:
            print(f"Monitor: DB error: {ex}")
            time.sleep(30)
            continue

        # Add static IPs for devices not yet in DB
        db_hostnames = {d['hostname'] for d in devices}
        for hostname, ip in STATIC_IPS.items():
            if hostname not in db_hostnames:
                devices.append({
                    'hostname': hostname,
                    'ip': ip,
                    'type': 'firewall' if 'FW' in hostname.upper() else 'router'
                })

        if not devices:
            time.sleep(MONITOR_CONFIG['interval'])
            continue

        print(f"📡 Monitor: checking {len(devices)} devices...")

        # Check each device
        for device in devices:
            if not _monitor_running:
                break

            hostname = device['hostname']
            ip       = device.get('ip', '')
            dev_type = device.get('type', 'router')

            # Get previous status from cache
            with _cache_lock:
                prev = _status_cache.get(hostname, {})
            prev_status = prev.get('status', 'UNKNOWN')

            # Run the 4-layer check
            try:
                chk = check_device(hostname, ip, dev_type)
            except Exception as ex:
                chk = {
                    'status': 'UNKNOWN', 'ping_ms': -1,
                    'method_used': 'ERROR', 'error_msg': str(ex),
                    'snmp_uptime': ''
                }

            new_status = chk['status']

            # Update database
            old_db_status = upsert_device_status(
                hostname, ip, new_status,
                ping_ms     = chk['ping_ms'],
                error_msg   = chk['error_msg'],
                method_used = chk['method_used'],
                snmp_uptime = chk['snmp_uptime'],
            )

            # Update memory cache
            with _cache_lock:
                _status_cache[hostname] = {
                    'status':      new_status,
                    'ping_ms':     chk['ping_ms'],
                    'ip':          ip,
                    'type':        dev_type,
                    'snmp_uptime': chk['snmp_uptime'],
                    'method_used': chk['method_used'],
                    'error_msg':   chk['error_msg'],
                    'last_checked': datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                }

            # ── Detect status change and fire events ───────────────────────
            # Capture down_since before status change for recovery email
            existing_down_since = prev.get('down_since', '') if isinstance(prev, dict) else ''

            if prev_status != 'UNKNOWN' and new_status != prev_status:

                if new_status == 'OFFLINE':
                    msg = f"{hostname} ({ip}) is not responding — {chk['error_msg']}"
                    add_alert(hostname, ip, 'DEVICE_DOWN', msg, 'CRITICAL')
                    _emit('device_down', {
                        'hostname': hostname,
                        'ip':       ip,
                        'type':     dev_type,
                        'message':  msg,
                        'severity': 'CRITICAL',
                    })
                    print(f"🔴 OFFLINE: {hostname} ({ip})")
                    # Send email immediately
                    threading.Thread(
                        target=_send_device_alert_email,
                        args=(hostname, ip, 'DEVICE_DOWN'),
                        daemon=True
                    ).start()

                elif new_status == 'DEGRADED':
                    msg = f"{hostname} ({ip}) degraded — {chk['error_msg']}"
                    add_alert(hostname, ip, 'DEVICE_DEGRADED', msg, 'WARNING')
                    _emit('device_degraded', {
                        'hostname': hostname,
                        'ip':       ip,
                        'type':     dev_type,
                        'message':  msg,
                        'ping_ms':  chk['ping_ms'],
                        'severity': 'WARNING',
                    })
                    print(f"🟡 DEGRADED: {hostname} ({ip}) - {chk['ping_ms']}ms")

                elif new_status == 'ONLINE' and prev_status in ('OFFLINE', 'DEGRADED'):
                    resolve_alert(hostname, 'DEVICE_DOWN')
                    resolve_alert(hostname, 'DEVICE_DEGRADED')
                    msg = f"{hostname} ({ip}) is back online"
                    add_alert(hostname, ip, 'DEVICE_UP', msg, 'INFO')
                    _emit('device_up', {
                        'hostname': hostname,
                        'ip':       ip,
                        'type':     dev_type,
                        'message':  msg,
                        'ping_ms':  chk['ping_ms'],
                        'severity': 'INFO',
                    })
                    print(f"🟢 RECOVERED: {hostname} ({ip}) - {chk['ping_ms']}ms")
                    threading.Thread(
                        target=_send_device_alert_email,
                        args=(hostname, ip, 'DEVICE_UP'),
                        daemon=True
                    ).start()
                    if dev_type != 'pc':
                        with _harvest_lock:
                            _last_harvest_time[hostname] = 0
                        threading.Thread(
                            target=_trigger_harvest,
                            args=(hostname, ip, dev_type),
                            daemon=True
                        ).start()
                    # Send recovery email immediately
                    threading.Thread(
                        target=_send_device_alert_email,
                        args=(hostname, ip, 'DEVICE_UP', existing_down_since),
                        daemon=True
                    ).start()
                    # Security: harvest immediately on recovery
                    # Device was offline — could have been compromised
                    print(f"🔐 Security harvest: {hostname} just recovered — checking config")
                    with _harvest_lock:
                        _last_harvest_time[hostname] = 0  # force immediate harvest next cycle
                    threading.Thread(
                        target=_trigger_harvest,
                        args=(hostname, ip, dev_type),
                        daemon=True
                    ).start()

            elif prev_status == 'UNKNOWN':
                # First check — just emit status update (no alert)
                _emit('device_status', {
                    'hostname': hostname,
                    'ip':       ip,
                    'status':   new_status,
                    'ping_ms':  chk['ping_ms'],
                })

        # Emit fleet-wide health snapshot after all checks
        try:
            stats = get_monitor_stats()
            _emit('fleet_status', stats)
        except Exception:
            pass

        # Sleep for remaining interval time
        elapsed  = time.time() - loop_start
        sleep_t  = max(5, MONITOR_CONFIG['interval'] - elapsed)
        print(f"📡 Monitor cycle done in {elapsed:.1f}s. Next check in {sleep_t:.0f}s")
        time.sleep(sleep_t)

    print("📡 NetGuard Live Monitor stopped")
    _emit('monitor_stopped', {'message': 'Live monitoring stopped'})


# ─────────────────────────────────────────────────────────────────────────────
#  PUBLIC API
# ─────────────────────────────────────────────────────────────────────────────
def start_monitor():
    """Start the background monitor thread."""
    global _monitor_thread, _monitor_running
    with _monitor_lock:
        if _monitor_running:
            return False
        _monitor_running = True
        _monitor_thread  = threading.Thread(
            target=_monitor_loop, daemon=True, name='NetGuardMonitor'
        )
        _monitor_thread.start()
        return True


def stop_monitor():
    """Stop the background monitor thread."""
    global _monitor_running
    _monitor_running = False


def get_status_cache():
    """Return current in-memory status cache."""
    with _cache_lock:
        return dict(_status_cache)


def update_config(new_cfg):
    """Update monitor configuration."""
    MONITOR_CONFIG.update(new_cfg)


if __name__ == '__main__':
    # Quick test
    print("Testing 4-layer check on FW1...")
    result = check_device('FW1', '192.168.214.3', 'firewall')
    print(f"Result: {result}")

    print("\nTesting R1...")
    result = check_device('R1', '10.10.0.2', 'router')
    print(f"Result: {result}")
