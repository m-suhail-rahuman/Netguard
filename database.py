"""
NetGuard Database Layer — database.py
======================================
SQLite-based storage for:
  • devices          — device inventory (hostname, ip, type, last_seen)
  • topology_links   — network connections (source, target, type, timestamp)
  • config_history   — every config snapshot with MD5 hash for change detection

How change detection works (same as SolarWinds NCM / Oxidized):
  1. Harvest collects running-config from device
  2. We compute MD5 hash of the config text
  3. If hash matches latest stored hash → config unchanged → skip insert
  4. If hash differs (or no previous record) → config changed → insert new row
  5. Dashboard can now show every version and diff between any two

100% free — SQLite is built into Python, zero dependencies.
"""

import sqlite3
import hashlib
import os
import datetime
import threading

DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'netguard.db')

# Thread-safe connection lock
_db_lock = threading.Lock()


# ─────────────────────────────────────────────────────────────────────────────
#  Connection helper
# ─────────────────────────────────────────────────────────────────────────────
def get_conn():
    """Return a new SQLite connection with WAL mode for concurrency."""
    conn = sqlite3.connect(DB_PATH, timeout=30)
    conn.row_factory = sqlite3.Row          # rows behave like dicts
    conn.execute("PRAGMA journal_mode=WAL") # multiple readers, one writer
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


# ─────────────────────────────────────────────────────────────────────────────
#  Schema creation
# ─────────────────────────────────────────────────────────────────────────────
def init_db():
    """
    Create all tables if they do not exist.
    Safe to call multiple times — uses IF NOT EXISTS.
    """
    with get_conn() as conn:
        conn.executescript("""

        -- ── Device Inventory ──────────────────────────────────────────────
        CREATE TABLE IF NOT EXISTS devices (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            hostname    TEXT    NOT NULL UNIQUE,
            ip          TEXT    NOT NULL DEFAULT '—',
            type        TEXT    NOT NULL DEFAULT 'router',
            last_seen   TEXT    NOT NULL,
            scan_count  INTEGER NOT NULL DEFAULT 0,
            created_at  TEXT    NOT NULL
        );

        -- ── Topology Links ────────────────────────────────────────────────
        CREATE TABLE IF NOT EXISTS topology_links (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            source      TEXT    NOT NULL,
            target      TEXT    NOT NULL,
            link_type   TEXT    NOT NULL DEFAULT 'infra',
            recorded_at TEXT    NOT NULL,
            UNIQUE(source, target, link_type)
        );

        -- ── Configuration History ─────────────────────────────────────────
        -- Every scan saves a new row IF config changed (hash differs)
        -- This lets us compare before/after any configuration change
        CREATE TABLE IF NOT EXISTS config_history (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            hostname      TEXT    NOT NULL,
            config_text   TEXT    NOT NULL,
            config_hash   TEXT    NOT NULL,
            total_lines   INTEGER NOT NULL DEFAULT 0,
            active_lines  INTEGER NOT NULL DEFAULT 0,
            harvested_at  TEXT    NOT NULL,
            changed       INTEGER NOT NULL DEFAULT 1
        );


        -- ── Device Live Status ───────────────────────────────────────────
        -- Updated every 60s by background monitor thread
        -- Tracks online/offline/degraded state per device
        CREATE TABLE IF NOT EXISTS device_status (
            hostname      TEXT    PRIMARY KEY,
            ip            TEXT    NOT NULL DEFAULT '',
            status        TEXT    NOT NULL DEFAULT 'UNKNOWN',
            ping_ms       INTEGER DEFAULT -1,
            last_seen     TEXT    DEFAULT '',
            last_checked  TEXT    DEFAULT '',
            down_since    TEXT    DEFAULT '',
            fail_count    INTEGER DEFAULT 0,
            check_count   INTEGER DEFAULT 0,
            snmp_uptime   TEXT    DEFAULT '',
            error_msg     TEXT    DEFAULT '',
            method_used   TEXT    DEFAULT ''
        );

        -- ── Alert History ─────────────────────────────────────────────────
        CREATE TABLE IF NOT EXISTS alert_history (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            hostname    TEXT    NOT NULL,
            ip          TEXT    DEFAULT '',
            alert_type  TEXT    NOT NULL,
            message     TEXT    NOT NULL,
            severity    TEXT    NOT NULL DEFAULT 'WARNING',
            created_at  TEXT    NOT NULL,
            resolved_at TEXT    DEFAULT '',
            ack         INTEGER DEFAULT 0
        );

        CREATE INDEX IF NOT EXISTS idx_alert_hostname
            ON alert_history(hostname);
        CREATE INDEX IF NOT EXISTS idx_alert_created
            ON alert_history(created_at DESC);
        CREATE INDEX IF NOT EXISTS idx_status_hostname
            ON device_status(hostname);

        -- Indexes for fast lookups
        CREATE INDEX IF NOT EXISTS idx_cfg_hostname
            ON config_history(hostname);
        CREATE INDEX IF NOT EXISTS idx_cfg_harvested
            ON config_history(harvested_at DESC);
        CREATE INDEX IF NOT EXISTS idx_devices_hostname
            ON devices(hostname);

        """)
    print(f"✅ NetGuard DB initialised → {DB_PATH}")


# ─────────────────────────────────────────────────────────────────────────────
#  Device functions
# ─────────────────────────────────────────────────────────────────────────────
def upsert_device(hostname, ip, dev_type):
    """
    Insert device if new, or update ip/type/last_seen/scan_count if existing.
    Returns True if this is a brand new device, False if it already existed.
    """
    now = _now()
    with _db_lock, get_conn() as conn:
        existing = conn.execute(
            "SELECT id FROM devices WHERE hostname=?", (hostname,)
        ).fetchone()

        if existing:
            conn.execute("""
                UPDATE devices
                SET ip=?, type=?, last_seen=?, scan_count=scan_count+1
                WHERE hostname=?
            """, (ip, dev_type, now, hostname))
            return False
        else:
            conn.execute("""
                INSERT INTO devices (hostname, ip, type, last_seen, scan_count, created_at)
                VALUES (?,?,?,?,1,?)
            """, (hostname, ip, dev_type, now, now))
            return True


def get_all_devices():
    """Return all devices ordered by type then hostname."""
    with get_conn() as conn:
        rows = conn.execute("""
            SELECT d.*,
                   (SELECT COUNT(*) FROM config_history c
                    WHERE c.hostname=d.hostname) AS version_count,
                   (SELECT COUNT(*) FROM config_history c
                    WHERE c.hostname=d.hostname AND c.changed=1) AS change_count
            FROM devices d
            ORDER BY
                CASE d.type WHEN 'router' THEN 0 WHEN 'switch' THEN 1 ELSE 2 END,
                d.hostname
        """).fetchall()
        return [dict(r) for r in rows]


# ─────────────────────────────────────────────────────────────────────────────
#  Config history functions
# ─────────────────────────────────────────────────────────────────────────────
def md5(text):
    """Compute MD5 hash of config text — same method as SolarWinds/Oxidized."""
    return hashlib.md5(text.encode('utf-8', errors='ignore')).hexdigest()


def save_config(hostname, config_text):
    """
    Save config snapshot if it changed since last save.
    Returns: 'new_device' | 'changed' | 'unchanged'
    """
    now     = _now()
    h       = md5(config_text)
    lines   = config_text.splitlines()
    total   = len(lines)
    active  = sum(1 for l in lines if l.strip() and not l.strip().startswith('!'))

    with _db_lock, get_conn() as conn:
        # Get the latest stored hash for this device
        latest = conn.execute("""
            SELECT config_hash FROM config_history
            WHERE hostname=?
            ORDER BY harvested_at DESC
            LIMIT 1
        """, (hostname,)).fetchone()

        if latest is None:
            # First time we see this device
            conn.execute("""
                INSERT INTO config_history
                    (hostname, config_text, config_hash, total_lines,
                     active_lines, harvested_at, changed)
                VALUES (?,?,?,?,?,?,1)
            """, (hostname, config_text, h, total, active, now))
            return 'new_device'

        elif latest['config_hash'] != h:
            # Config changed since last scan — save new version
            conn.execute("""
                INSERT INTO config_history
                    (hostname, config_text, config_hash, total_lines,
                     active_lines, harvested_at, changed)
                VALUES (?,?,?,?,?,?,1)
            """, (hostname, config_text, h, total, active, now))
            # Auto-cleanup: keep only latest 12 versions
            _cleanup_old_configs_conn(conn, hostname, keep=12)
            return 'changed'

        else:
            # Config UNCHANGED — only update last_seen in devices table
            # DO NOT insert a new row — this keeps database small
            conn.execute("""
                UPDATE devices SET last_seen=? WHERE hostname=?
            """, (now, hostname))
            return 'unchanged'


def get_config_versions(hostname, limit=20):
    """
    Return all config versions for a device, newest first.
    Only returns rows where changed=1 (actual changes) plus the latest scan.
    """
    with get_conn() as conn:
        rows = conn.execute("""
            SELECT id, hostname, config_hash, total_lines,
                   active_lines, harvested_at, changed
            FROM config_history
            WHERE hostname=?
            ORDER BY harvested_at DESC
            LIMIT ?
        """, (hostname, limit)).fetchall()
        return [dict(r) for r in rows]


def get_config_by_id(config_id):
    """Return full config text for a specific history entry."""
    with get_conn() as conn:
        row = conn.execute(
            "SELECT * FROM config_history WHERE id=?", (config_id,)
        ).fetchone()
        return dict(row) if row else None


def get_latest_config(hostname):
    """Return the most recent config for a device."""
    with get_conn() as conn:
        row = conn.execute("""
            SELECT * FROM config_history
            WHERE hostname=?
            ORDER BY harvested_at DESC
            LIMIT 1
        """, (hostname,)).fetchone()
        return dict(row) if row else None


def diff_configs(id_old, id_new):
    """
    Compare two config versions line by line.
    Returns list of diff lines with status:
      'added'   → line exists in new but not old
      'removed' → line exists in old but not new
      'same'    → line unchanged
    """
    old_row = get_config_by_id(id_old)
    new_row = get_config_by_id(id_new)

    if not old_row or not new_row:
        return []

    old_lines = set(old_row['config_text'].splitlines())
    new_lines = set(new_row['config_text'].splitlines())

    # Preserve order using new config as base
    all_lines = []
    new_list  = new_row['config_text'].splitlines()
    old_list  = old_row['config_text'].splitlines()

    # Lines removed (in old, not in new)
    removed = old_lines - new_lines
    # Lines added (in new, not in old)
    added   = new_lines - old_lines

    result = []
    # Show removed lines first (what was there before)
    for line in old_list:
        if line in removed:
            result.append({'status': 'removed', 'line': line})

    # Then show added lines (what is there now)
    for line in new_list:
        if line in added:
            result.append({'status': 'added', 'line': line})

    # Summary stats
    return {
        'removed_count': len(removed),
        'added_count':   len(added),
        'old_time':      old_row['harvested_at'],
        'new_time':      new_row['harvested_at'],
        'old_hostname':  old_row['hostname'],
        'lines':         result,
    }


# ─────────────────────────────────────────────────────────────────────────────
#  Topology functions
# ─────────────────────────────────────────────────────────────────────────────
def save_topology(links):
    """
    Save topology links from harvest.
    Uses INSERT OR REPLACE to update existing links.
    """
    now = _now()
    with _db_lock, get_conn() as conn:
        for link in links:
            try:
                data = link.get('data', link)
                src  = data.get('source', '')
                tgt  = data.get('target', '')
                ltype = data.get('type', 'infra')
                if src and tgt:
                    conn.execute("""
                        INSERT OR REPLACE INTO topology_links
                            (source, target, link_type, recorded_at)
                        VALUES (?,?,?,?)
                    """, (src, tgt, ltype, now))
            except Exception:
                continue


def get_topology():
    """Return all topology links formatted for Cytoscape."""
    with get_conn() as conn:
        rows = conn.execute(
            "SELECT source, target, link_type FROM topology_links"
        ).fetchall()
        return [
            {"data": {"source": r["source"],
                      "target": r["target"],
                      "type":   r["link_type"]}}
            for r in rows
        ]


# ─────────────────────────────────────────────────────────────────────────────
#  Stats / summary
# ─────────────────────────────────────────────────────────────────────────────
def get_db_stats():
    """Return summary stats about the database."""
    with get_conn() as conn:
        devices   = conn.execute("SELECT COUNT(*) FROM devices").fetchone()[0]
        configs   = conn.execute("SELECT COUNT(*) FROM config_history").fetchone()[0]
        changes   = conn.execute(
            "SELECT COUNT(*) FROM config_history WHERE changed=1"
        ).fetchone()[0]
        links     = conn.execute("SELECT COUNT(*) FROM topology_links").fetchone()[0]
        oldest    = conn.execute(
            "SELECT MIN(harvested_at) FROM config_history"
        ).fetchone()[0]
        return {
            'total_devices':  devices,
            'total_configs':  configs,
            'total_changes':  changes,
            'topology_links': links,
            'oldest_record':  oldest or '—',
            'db_path':        DB_PATH,
            'db_size_kb':     round(os.path.getsize(DB_PATH) / 1024, 1)
                              if os.path.exists(DB_PATH) else 0,
        }


# ─────────────────────────────────────────────────────────────────────────────
#  Internal helpers
# ─────────────────────────────────────────────────────────────────────────────
def _now():
    return datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')


# Auto-init when imported
init_db()




# ─────────────────────────────────────────────────────────────────────────────
#  RETENTION & CLEANUP FUNCTIONS
# ─────────────────────────────────────────────────────────────────────────────

def _cleanup_old_configs_conn(conn, hostname, keep=12):
    """
    Internal: Delete old config versions for a device using an existing connection.
    Keeps the most recent `keep` versions. Called inside save_config transaction.
    """
    try:
        rows = conn.execute("""
            SELECT id FROM config_history
            WHERE hostname=?
            ORDER BY harvested_at DESC
        """, (hostname,)).fetchall()

        if len(rows) > keep:
            ids_to_delete = [r['id'] for r in rows[keep:]]
            placeholders  = ','.join('?' * len(ids_to_delete))
            conn.execute(
                f"DELETE FROM config_history WHERE id IN ({placeholders})",
                ids_to_delete
            )
    except Exception as ex:
        print(f"  Cleanup warning for {hostname}: {ex}")


def cleanup_all_devices(keep=12):
    """
    Public: Clean up all devices — keep only latest `keep` versions each.
    Called from dashboard Delete button.
    Returns dict with deleted count and per-device summary.
    """
    with _db_lock, get_conn() as conn:
        # Get all hostnames
        hostnames = [r['hostname'] for r in conn.execute(
            "SELECT DISTINCT hostname FROM config_history"
        ).fetchall()]

        total_before = conn.execute(
            "SELECT COUNT(*) FROM config_history"
        ).fetchone()[0]

        for hostname in hostnames:
            _cleanup_old_configs_conn(conn, hostname, keep=keep)

        total_after = conn.execute(
            "SELECT COUNT(*) FROM config_history"
        ).fetchone()[0]

        deleted = total_before - total_after
        return {
            'deleted':  deleted,
            'devices':  len(hostnames),
            'kept_per': keep,
            'message':  f"Deleted {deleted} old record(s) — kept latest {keep} per device across {len(hostnames)} device(s)",
        }


def keep_only_last_harvest():
    """
    Aggressive clean: Keep ONLY the most recent harvest record per device.
    Used when user clicks 'Delete All Except Latest'.
    Returns deleted count.
    """
    with _db_lock, get_conn() as conn:
        # Find the latest ID per device
        latest_ids = [r['id'] for r in conn.execute("""
            SELECT MAX(id) as id FROM config_history
            GROUP BY hostname
        """).fetchall()]

        if not latest_ids:
            return {'deleted': 0, 'message': 'No records found'}

        total_before = conn.execute(
            "SELECT COUNT(*) FROM config_history"
        ).fetchone()[0]

        placeholders = ','.join('?' * len(latest_ids))
        conn.execute(
            f"DELETE FROM config_history WHERE id NOT IN ({placeholders})",
            latest_ids
        )

        total_after = conn.execute(
            "SELECT COUNT(*) FROM config_history"
        ).fetchone()[0]

        deleted = total_before - total_after
        return {
            'deleted': deleted,
            'message': f"Deleted {deleted} record(s) — kept only latest harvest per device",
        }


def get_storage_stats():
    """Return storage summary for dashboard."""
    with get_conn() as conn:
        total = conn.execute(
            "SELECT COUNT(*) FROM config_history"
        ).fetchone()[0]
        changed = conn.execute(
            "SELECT COUNT(*) FROM config_history WHERE changed=1"
        ).fetchone()[0]
        unchanged = total - changed
        per_device = conn.execute("""
            SELECT hostname, COUNT(*) as cnt
            FROM config_history
            GROUP BY hostname
            ORDER BY cnt DESC
        """).fetchall()
        db_size = os.path.getsize(DB_PATH) if os.path.exists(DB_PATH) else 0
        return {
            'total_records':   total,
            'changed_records': changed,
            'unchanged_records': unchanged,
            'db_size_kb':      round(db_size / 1024, 1),
            'db_size_mb':      round(db_size / 1024 / 1024, 2),
            'per_device':      [dict(r) for r in per_device],
        }

# ─────────────────────────────────────────────────────────────────────────────
#  LIVE MONITOR FUNCTIONS
# ─────────────────────────────────────────────────────────────────────────────

def upsert_device_status(hostname, ip, status, ping_ms=-1,
                          error_msg='', method_used='', snmp_uptime=''):
    """Update live status for a device. Called by monitor thread."""
    now = _now()
    with _db_lock, get_conn() as conn:
        existing = conn.execute(
            "SELECT status, fail_count, down_since FROM device_status WHERE hostname=?",
            (hostname,)
        ).fetchone()

        if existing:
            old_status = existing['status']
            fail_count = existing['fail_count']
            down_since = existing['down_since']

            if status == 'OFFLINE':
                fail_count += 1
                if not down_since:
                    down_since = now
            else:
                fail_count = 0
                down_since = ''

            conn.execute("""
                UPDATE device_status
                SET ip=?, status=?, ping_ms=?, last_checked=?,
                    last_seen=CASE WHEN ? != 'OFFLINE' THEN ? ELSE last_seen END,
                    down_since=?, fail_count=?, check_count=check_count+1,
                    error_msg=?, method_used=?, snmp_uptime=?
                WHERE hostname=?
            """, (ip, status, ping_ms, now,
                  status, now,
                  down_since, fail_count,
                  error_msg, method_used, snmp_uptime,
                  hostname))
            return old_status  # return previous status so caller can detect change
        else:
            conn.execute("""
                INSERT INTO device_status
                    (hostname, ip, status, ping_ms, last_seen, last_checked,
                     down_since, fail_count, check_count, error_msg, method_used, snmp_uptime)
                VALUES (?,?,?,?,?,?,?,?,1,?,?,?)
            """, (hostname, ip, status, ping_ms,
                  now if status != 'OFFLINE' else '',
                  now, '' if status != 'OFFLINE' else now,
                  0 if status != 'OFFLINE' else 1,
                  error_msg, method_used, snmp_uptime))
            return 'UNKNOWN'


def get_all_device_status():
    """Return live status of all devices."""
    with get_conn() as conn:
        rows = conn.execute("""
            SELECT ds.*, d.type
            FROM device_status ds
            LEFT JOIN devices d ON d.hostname = ds.hostname
            ORDER BY
                CASE ds.status
                    WHEN 'OFFLINE' THEN 0
                    WHEN 'DEGRADED' THEN 1
                    WHEN 'ONLINE' THEN 2
                    ELSE 3
                END,
                ds.hostname
        """).fetchall()
        return [dict(r) for r in rows]


def add_alert(hostname, ip, alert_type, message, severity='WARNING'):
    """Add an alert to history."""
    now = _now()
    with _db_lock, get_conn() as conn:
        conn.execute("""
            INSERT INTO alert_history
                (hostname, ip, alert_type, message, severity, created_at)
            VALUES (?,?,?,?,?,?)
        """, (hostname, ip, alert_type, message, severity, now))


def get_alerts(limit=100, unack_only=False):
    """Get alert history."""
    with get_conn() as conn:
        if unack_only:
            rows = conn.execute("""
                SELECT * FROM alert_history
                WHERE ack=0
                ORDER BY created_at DESC LIMIT ?
            """, (limit,)).fetchall()
        else:
            rows = conn.execute("""
                SELECT * FROM alert_history
                ORDER BY created_at DESC LIMIT ?
            """, (limit,)).fetchall()
        return [dict(r) for r in rows]


def ack_alert(alert_id):
    """Acknowledge an alert."""
    with _db_lock, get_conn() as conn:
        conn.execute("UPDATE alert_history SET ack=1 WHERE id=?", (alert_id,))


def resolve_alert(hostname, alert_type):
    """Mark all open alerts of a type as resolved."""
    now = _now()
    with _db_lock, get_conn() as conn:
        conn.execute("""
            UPDATE alert_history
            SET resolved_at=?, ack=1
            WHERE hostname=? AND alert_type=? AND resolved_at=''
        """, (now, hostname, alert_type))


def get_monitor_stats():
    """Return fleet-wide health summary."""
    with get_conn() as conn:
        total  = conn.execute("SELECT COUNT(*) FROM device_status").fetchone()[0]
        online = conn.execute("SELECT COUNT(*) FROM device_status WHERE status='ONLINE'").fetchone()[0]
        offline= conn.execute("SELECT COUNT(*) FROM device_status WHERE status='OFFLINE'").fetchone()[0]
        degrad = conn.execute("SELECT COUNT(*) FROM device_status WHERE status='DEGRADED'").fetchone()[0]
        alerts = conn.execute("SELECT COUNT(*) FROM alert_history WHERE ack=0").fetchone()[0]
        return {
            'total': total, 'online': online,
            'offline': offline, 'degraded': degrad,
            'unacked_alerts': alerts,
            'health_pct': round(online / total * 100) if total else 0,
        }

