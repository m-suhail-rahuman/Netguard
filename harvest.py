"""
NetGuard Harvest
=======================================================
 harvest

  • Ping-first gate — skip offline devices immediately (saves 15-30s per device)
  • All timeouts doubled for legacy c7200 / 3725 devices
  • Try SSH first, then Telnet, then reverse — supports all your lab devices
  • Config saved ONLY when hash changes (database.py handles this)
  • Monitor-triggered harvest uses same function (harvest_single_device)
"""

import os
import re
import json
import socket
import subprocess
import threading
import datetime
import signal
import sys
import time
import paramiko
from concurrent.futures import ThreadPoolExecutor, as_completed
from netmiko import ConnectHandler
from database import upsert_device, save_config, save_topology, init_db

# ─────────────────────────────────────────────────────────────────────────────
#  SEED / CREDENTIALS
# ─────────────────────────────────────────────────────────────────────────────

SEED_IP = '192.168.214.3'   # FW1 (VyOS) — entry point

FW_CREDENTIALS = {
    'username': 'admin',
    'password': 'Admin@123',
}

# All possible Cisco credentials — tried in order for every device
CREDENTIALS_LIST = [
    {'username': 'admin',  'password': 'cisco',  'secret': 'ciscoo'},
    {'username': 'admin',  'password': 'Admin@123', 'secret': 'Admin@123'},
    {'username': 'cisco',  'password': 'cisco',  'secret': 'cisco'},
    {'username': 'admin',  'password': 'admin',  'secret': 'admin'},
    {'username': 'admin',  'password': '1234',   'secret': '1234'},
    {'username': 'admin',  'password': '',        'secret': ''},
]

os.makedirs('network_configs', exist_ok=True)

# ─────────────────────────────────────────────────────────────────────────────
#  SHARED STATE
# ─────────────────────────────────────────────────────────────────────────────
processed_ips       = set()
processed_hostnames = set()
found_pc_ips        = set()
unknown_devices     = {}
probe_cache         = {}
processed_lock      = threading.Lock()
shutdown_flag       = threading.Event()
ip_to_host_map      = {}
all_device_ips      = {}

# ─────────────────────────────────────────────────────────────────────────────
#  MAC OUI — Cisco / Network device prefixes
# ─────────────────────────────────────────────────────────────────────────────
NETWORK_OUIS = {
    '00:00:0c','00:1a:a1','00:1b:8f','00:1c:57','00:1d:45',
    '00:1e:13','00:1e:be','00:1f:26','00:1f:9d','00:21:55',
    '00:22:55','00:23:04','00:23:33','00:24:13','00:24:97',
    '00:25:45','00:25:83','00:26:0b','00:26:99','00:27:0d',
    '00:30:71','00:30:80','00:60:2f','00:60:70','00:90:ab',
    'c8:9c:1d','e8:ba:70','f4:cf:e2',
    '00:10:db','00:12:1e','2c:6b:f5','3c:61:04',
    '00:0b:86','00:1a:1e','24:de:c6','b4:5d:50',
    '00:18:82','00:25:9e','04:f9:38','2c:ab:00',
    '00:50:56','00:0c:29','00:05:69',
    'c4:01','c8:01','ca:01','cc:01',
    'c4:02','c8:02','ca:02','cc:02',
    'c4:03','c8:03','ca:03','cc:03',
    'c4:04','c8:04','ca:04','cc:04',
    '0c:9b',
}


def signal_handler(sig, frame):
    print("\n\nSTOP SIGNAL — cleaning up...")
    shutdown_flag.set()
    sys.exit(0)

signal.signal(signal.SIGINT, signal_handler)


# ─────────────────────────────────────────────────────────────────────────────
#  DEVICE TYPE HELPERS
# ─────────────────────────────────────────────────────────────────────────────
def _is_switch(hostname):
    h = hostname.upper()
    return ('SW' in h or 'SWITCH' in h or 'DIST' in h or
            'ACCESS' in h or ('CORE' in h and 'SW' in h))

def _is_firewall(hostname):
    h = hostname.upper()
    return ('FW' in h or 'FIREWALL' in h or 'ASA' in h or
            'PFSENSE' in h or 'VYOS' in h or 'PA-' in h or
            'FGT' in h or 'FORTINET' in h)


# ─────────────────────────────────────────────────────────────────────────────
#  LAYER 1 — PING GATE 
#  Fast check before any SSH/Telnet attempt
#  Uses /bin/ping subprocess — works without root
# ─────────────────────────────────────────────────────────────────────────────
def ping_check(ip, timeout=3, count=2):
    """
    Ping an IP before attempting SSH/Telnet.
    Returns (reachable: bool, rtt_ms: float).
    Fast: 0.5s if online, timeout+0.5s if offline.
    """
    try:
        r = subprocess.run(
            ['/bin/ping', '-c', str(count), '-W', str(timeout), ip],
            capture_output=True,
            timeout=timeout * count + 4,
        )
        if r.returncode == 0:
            out = r.stdout.decode('utf-8', errors='ignore')
            m = re.search(r'rtt min/avg/max.*?=\s*[\d.]+/([\d.]+)/', out)
            rtt = float(m.group(1)) if m else 1.0
            return True, round(rtt, 1)
        return False, -1
    except Exception:
        return False, -1


# ─────────────────────────────────────────────────────────────────────────────
#  LAYER 2 — TCP PORT CHECK
# ─────────────────────────────────────────────────────────────────────────────
def port_open(ip, port, timeout=6):
    """Check if a TCP port is open."""
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            return True
    except Exception:
        return False


# ─────────────────────────────────────────────────────────────────────────────
#  LAYER 3 — MAC OUI Check
# ─────────────────────────────────────────────────────────────────────────────
def mac_is_network_device(mac):
    if not mac or mac in ('Incomplete', 'incomplete', ''):
        return False
    mac_clean = mac.lower().replace('.','').replace('-','').replace(':','')
    mac_colon = ':'.join(mac_clean[i:i+2] for i in range(0, len(mac_clean), 2))
    for oui in NETWORK_OUIS:
        if mac_colon.startswith(oui):
            return True
    return False


# ─────────────────────────────────────────────────────────────────────────────
#  LAYER 4 — ARP Age Validation
# ─────────────────────────────────────────────────────────────────────────────
def arp_age_valid(age_str):
    if age_str == '-':
        return True
    if age_str.isdigit():
        age = int(age_str)
        return 1 <= age <= 500
    return False


# ─────────────────────────────────────────────────────────────────────────────
#  QUICK PROBE — ping first then SSH/Telnet
# ─────────────────────────────────────────────────────────────────────────────
def quick_probe(ip):
    """
    Ping-first probe. Returns True if device responds to SSH/Telnet.
    Used for ARP entry classification.
    """
    with processed_lock:
        if ip in probe_cache:
            return probe_cache[ip]
        if ip in all_device_ips:
            return True

    # ── Layer 1: Ping gate ────────────────────────────────────────────────
    ping_ok, _ = ping_check(ip, timeout=3, count=2)
    if not ping_ok:
        with processed_lock:
            probe_cache[ip] = False
        return False

    # ── Layer 2: Port check then connect ─────────────────────────────────
    ssh_open    = port_open(ip, 22, timeout=6)
    telnet_open = port_open(ip, 23, timeout=6)

    if not ssh_open and not telnet_open:
        with processed_lock:
            probe_cache[ip] = False
        return False

    protocols = []
    if ssh_open:    protocols.append('cisco_ios')
    if telnet_open: protocols.append('cisco_ios_telnet')

    for proto in protocols:
        for creds in CREDENTIALS_LIST:
            try:
                params = {
                    'device_type': proto,
                    'host': ip,
                    'username': creds['username'],
                    'password': creds['password'],
                    'secret':   creds['secret'],
                    'conn_timeout': 20,
                    'read_timeout_override': 60,
                    'global_delay_factor': 4,
                }
                if proto == 'cisco_ios':
                    params['ssh_config_file'] = "~/.ssh/config"
                conn = ConnectHandler(**params)
                conn.enable()
                conn.disconnect()
                with processed_lock:
                    probe_cache[ip] = True
                return True
            except Exception:
                continue

    with processed_lock:
        probe_cache[ip] = False
    return False


# ─────────────────────────────────────────────────────────────────────────────
#  TRIPLE VERIFICATION — classify ARP entry
# ─────────────────────────────────────────────────────────────────────────────
def classify_arp_entry(p_ip, p_age, p_mac):
    with processed_lock:
        if p_ip in all_device_ips: return 'skip'
        if p_ip in processed_ips:  return 'skip'
    if quick_probe(p_ip):          return 'device'
    if mac_is_network_device(p_mac):
        print(f"    CISCO MAC DETECTED (offline/no-login): {p_ip} [{p_mac}]")
        return 'unknown'
    if arp_age_valid(p_age):       return 'pc'
    return 'skip'


# ─────────────────────────────────────────────────────────────────────────────
#  PHASE 1 — VyOS Firewall Harvest (Paramiko)
# ─────────────────────────────────────────────────────────────────────────────
def harvest_firewall_vyos(ip, hostname):
    """
    Harvest VyOS via Paramiko SSH.
    Ping-first gate added — skip if unreachable.
    """
    # ── Ping gate ─────────────────────────────────────────────────────────
    print(f"  Pinging {hostname} ({ip})...")
    ping_ok, rtt = ping_check(ip, timeout=4, count=2)
    if not ping_ok:
        print(f"  OFFLINE: {hostname} ({ip}) — ping failed, skipping harvest")
        return None, []
    print(f"  ONLINE: {hostname} ({ip}) — {rtt}ms — connecting...")

    WRAPPER = "/opt/vyatta/bin/vyatta-op-cmd-wrapper"
    try:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(
            ip,
            username=FW_CREDENTIALS['username'],
            password=FW_CREDENTIALS['password'],
            timeout=20,
            allow_agent=False,
            look_for_keys=False,
            banner_timeout=20,
        )

        def _cmd(vyos_cmd):
            _, stdout, _ = client.exec_command(f"{WRAPPER} {vyos_cmd}")
            stdout.channel.recv_exit_status()
            return stdout.read().decode('utf-8', errors='ignore')

        config    = _cmd("show configuration")
        ifaces    = _cmd("show interfaces")
        version   = _cmd("show version")
        arp_out   = _cmd("show arp")
        route_out = _cmd("show ip route")
        client.close()

        print(f"  FW1 ARP output snippet: {repr(arp_out[:200])}")

        full_config = (
            "! VyOS Firewall Configuration\n"
            f"! Hostname : {hostname}\n"
            f"! IP       : {ip}\n"
            "! Vendor   : VyOS (Open-source router/firewall)\n!\n"
            + config
            + "\n! --- Interfaces ---\n" + ifaces
            + "\n! --- Version ---\n"    + version
        )

        # Parse ARP for downstream neighbors
        neighbor_ips = set()
        for line in arp_out.splitlines():
            parts = line.split()
            if not parts:
                continue
            if not re.match(r'\d+\.\d+\.\d+\.\d+', parts[0]):
                continue
            if 'FAILED' in line:
                continue
            n_ip = parts[0]
            if '192.168.214' not in n_ip and n_ip != ip:
                neighbor_ips.add(n_ip)
                print(f"  FW1 ARP neighbor: {n_ip}")

        # Fallback: parse routing table
        if not neighbor_ips:
            for line in route_out.splitlines():
                if ('C>' in line or 'C ' in line) and '10.' in line:
                    m = re.search(r'(\d+\.\d+\.\d+\.)(\d+)/\d+', line)
                    if m:
                        base = m.group(1)
                        last = int(m.group(2))
                        host_ip = f"{base}{last + 1}"
                        if '192.168.214' not in host_ip:
                            neighbor_ips.add(host_ip)
                            print(f"  FW1 route neighbor: {host_ip}")

        print(f"  FW1 discovered {len(neighbor_ips)} neighbor(s): {neighbor_ips}")
        return full_config, list(neighbor_ips)

    except Exception as ex:
        print(f"  ERROR: VyOS SSH failed for {ip}: {ex}")
        return None, []


# ─────────────────────────────────────────────────────────────────────────────
#  SMART CONNECT — SSH then Telnet then swap, with long timeouts
#  Supports legacy c7200 / 3725 — all protocols tried
# ─────────────────────────────────────────────────────────────────────────────
def smart_connect(ip):
    """
    Try SSH first, then Telnet, with generous timeouts for legacy devices.
    Returns connected Netmiko object or None.
    """
    ssh_open    = port_open(ip, 22, timeout=8)
    telnet_open = port_open(ip, 23, timeout=8)

    # Build protocol list — try open ports first
    protocols = []
    if ssh_open:    protocols.append('cisco_ios')
    if telnet_open: protocols.append('cisco_ios_telnet')
    # Always add both as fallback even if port check timed out
    if 'cisco_ios' not in protocols:        protocols.append('cisco_ios')
    if 'cisco_ios_telnet' not in protocols: protocols.append('cisco_ios_telnet')

    for proto in protocols:
        if shutdown_flag.is_set():
            return None
        for creds in CREDENTIALS_LIST:
            try:
                params = {
                    'device_type':          proto,
                    'host':                 ip,
                    'username':             creds['username'],
                    'password':             creds['password'],
                    'secret':               creds['secret'],
                    'conn_timeout':         30,      # 30s connection timeout
                    'read_timeout_override':180,     # 3min read timeout for slow IOS
                    'global_delay_factor':  5,       # extra delay for legacy devices
                    'fast_cli':             False,   # disable fast mode for c7200/3725
                    'session_timeout':      180,
                    'banner_timeout':       30,
                }
                if proto == 'cisco_ios':
                    params['ssh_config_file'] = "~/.ssh/config"
                print(f"    Trying {ip} ({proto}) as {creds['username']}...")
                conn = ConnectHandler(**params)
                conn.enable()
                conn.send_command("terminal length 0", read_timeout=30)
                print(f"    Connected: {ip} via {proto} as {creds['username']}")
                return conn
            except Exception as ex:
                last_err = str(ex)[:60]
                print(f"    Failed {proto}/{creds['username']}: {last_err}")
                continue
    print(f"  ERROR: All protocols failed for {ip}")
    return None


# ─────────────────────────────────────────────────────────────────────────────
#  HARVEST SINGLE CISCO DEVICE
#  Public function — called by both run_harvest() and monitor auto-harvest
# ─────────────────────────────────────────────────────────────────────────────
def harvest_single_device(ip, force=False):
    """
    Ping-first then harvest one Cisco device.
    Returns dict with neighbors and links, or None if unreachable/failed.

    Args:
        ip:    Device IP address
        force: If True, re-harvest even if already in processed_ips
    """
    if shutdown_flag.is_set():
        return None

    # ── Skip if already processed (unless forced) ──────────────────────────
    if not force:
        with processed_lock:
            if ip in processed_ips:
                return None
        processed_ips.add(ip)

    # ── PING GATE — check device is alive before SSH ───────────────────────
    print(f"  Pinging {ip}...")
    ping_ok, rtt = ping_check(ip, timeout=4, count=2)

    if not ping_ok:
        print(f"  OFFLINE: {ip} — ping failed, skipping SSH entirely")
        return None

    print(f"  ONLINE: {ip} ({rtt}ms) — starting harvest...")

    # ── Lock and mark as being processed ──────────────────────────────────
    with processed_lock:
        processed_ips.add(ip)

    # ── Connect ────────────────────────────────────────────────────────────
    conn = smart_connect(ip)
    if not conn:
        print(f"  ERROR: {ip} ping OK but SSH/Telnet failed")
        return None

    try:
        raw_hostname = conn.find_prompt().replace('#','').replace('>','').strip()
        hostname     = re.sub(r'[^a-zA-Z0-9_-]', '', raw_hostname)

        with processed_lock:
            if hostname in processed_hostnames and not force:
                conn.disconnect()
                return None
            processed_hostnames.add(hostname)
            ip_to_host_map[ip] = hostname
            all_device_ips[ip] = hostname
            probe_cache[ip]    = True

        print(f"  OK Harvesting: {hostname} ({ip}) — {rtt}ms")

        # ── Get running config ─────────────────────────────────────────────
        try:
            config = conn.send_command(
                "show running-config",
                read_timeout=180,    # 3 min for large configs on slow c7200
                delay_factor=5,
            )
            if not config or "Invalid input" in config:
                config = conn.send_command(
                    "show run",
                    read_timeout=180,
                    delay_factor=5,
                )
            # Save config file
            with open(f"network_configs/{hostname}_config.txt", "w", encoding="utf-8") as f:
                f.write(config)

            # Save to database — only stores if changed (hash check in database.py)
            try:
                db_ip = '--'
                for m in re.finditer(r'ip address (\d+\.\d+\.\d+\.\d+)', config):
                    cand = m.group(1)
                    if not cand.startswith(('127.','0.')):
                        db_ip = cand
                        break
                db_type = 'switch' if _is_switch(hostname) else 'router'
                upsert_device(hostname, db_ip, db_type)
                status = save_config(hostname, config)
                icons  = {'new_device':'🆕', 'changed':'🔄', 'unchanged':'✅'}
                print(f"    DB: {hostname} {icons.get(status, status)}")
            except Exception as dbe:
                print(f"    DB warning: {dbe}")

        except Exception as ex:
            print(f"    Config warning for {hostname}: {ex}")
            config = ''

        # ── Index all interface IPs ────────────────────────────────────────
        try:
            brief = conn.send_command(
                "show ip interface brief",
                read_timeout=60,
                delay_factor=3,
            )
            for line in brief.splitlines():
                if not re.search(r'up\s+up', line, re.I):
                    continue
                m = re.search(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', line)
                if m:
                    dev_ip = m.group(1)
                    if not dev_ip.startswith(('0.','127.')):
                        with processed_lock:
                            all_device_ips[dev_ip] = hostname
                            probe_cache[dev_ip]    = True
        except Exception:
            pass

        # ── Discover neighbors via OSPF + CDP ─────────────────────────────
        infra_ips = set()
        try:
            disc = conn.send_command(
                "show ip ospf neighbor",
                read_timeout=60, delay_factor=3,
            )
            disc += "\n" + conn.send_command(
                "show cdp neighbors detail",
                read_timeout=60, delay_factor=3,
            )
            infra_ips = set(re.findall(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', disc))
            infra_ips.discard(ip)
        except Exception:
            pass

        local_links = []
        for n_ip in infra_ips:
            local_links.append({"source": hostname, "target": n_ip, "type": "infra"})

        # ── ARP table — triple verification ───────────────────────────────
        try:
            arp_data    = conn.send_command(
                "show ip arp",
                read_timeout=60, delay_factor=3,
            )
            arp_entries = re.findall(
                r'Internet\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s+(\d+|[-])\s+(\S+)\s+ARPA',
                arp_data
            )
            candidates = []
            for p_ip, p_age, p_mac in arp_entries:
                if p_ip == ip:             continue
                if '192.168.214' in p_ip:  continue
                if '10.10.0' in p_ip:      continue
                if p_ip in infra_ips:      continue
                candidates.append((p_ip, p_age, p_mac))

            if candidates:
                print(f"    Classifying {len(candidates)} ARP entries...")
                with ThreadPoolExecutor(max_workers=3) as pool:
                    future_map = {
                        pool.submit(classify_arp_entry, p_ip, p_age, p_mac): (p_ip, p_age, p_mac)
                        for p_ip, p_age, p_mac in candidates
                    }
                    for future in as_completed(future_map):
                        p_ip, p_age, p_mac = future_map[future]
                        try:
                            result = future.result()
                        except Exception:
                            result = 'skip'

                        if result == 'device':
                            local_links.append({"source": hostname, "target": p_ip, "type": "infra"})
                        elif result == 'unknown':
                            with processed_lock:
                                unknown_devices[p_ip] = p_mac
                            node_id = f"Device-{p_ip}"
                            local_links.append({"source": hostname, "target": node_id, "type": "infra"})
                            with open(f"network_configs/{node_id}.txt", "w") as f:
                                f.write(f"IP: {p_ip}\nMAC: {p_mac}\nSTATUS: Cisco hardware, login failed\n")
                        elif result == 'pc':
                            pc_label = f"PC-{p_ip}"
                            if p_ip not in found_pc_ips:
                                with processed_lock:
                                    found_pc_ips.add(p_ip)
                                with open(f"network_configs/{pc_label}.txt", "w") as f:
                                    f.write(f"IP: {p_ip}\nMAC: {p_mac}\nARP_AGE: {p_age}\n")
                            local_links.append({"source": hostname, "target": pc_label, "type": "pc"})
        except Exception as ex:
            print(f"    ARP scan warning for {hostname}: {ex}")

        conn.disconnect()
        time.sleep(3)   # extra pause for legacy devices

        # Build neighbor list for queue
        all_neighbors = list(infra_ips)
        for lk in local_links:
            if (lk['type'] == 'infra'
                    and not lk['target'].startswith('PC-')
                    and not lk['target'].startswith('Device-')):
                if lk['target'] not in all_neighbors:
                    all_neighbors.append(lk['target'])

        return {"hostname": hostname, "neighbors": all_neighbors, "links": local_links}

    except Exception as ex:
        print(f"    FATAL error processing {ip}: {ex}")
        try:
            conn.disconnect()
        except Exception:
            pass
        return None


# Keep backward-compatible name
def harvest_cisco_device(ip):
    return harvest_single_device(ip)


# ─────────────────────────────────────────────────────────────────────────────
#  BUILD TOPOLOGY JSON
# ─────────────────────────────────────────────────────────────────────────────
def build_and_save_topology(temp_links):
    """Build Cytoscape-format topology and save to file + database."""
    final_mapped_links = []
    pc_assignments     = {}

    # Infrastructure links
    for link in temp_links:
        if link['type'] != 'infra':
            continue
        target_raw  = link['target']
        source_node = link['source']
        target_node = (ip_to_host_map.get(target_raw) or
                       all_device_ips.get(target_raw) or target_raw)
        is_known = (target_node in processed_hostnames or
                    target_node.startswith('Device-') or
                    target_node in ('Internet', 'FW1'))
        if not is_known:
            continue
        if source_node == target_node:
            continue
        exists = any(
            (e['data']['source'] == target_node and e['data']['target'] == source_node) or
            (e['data']['source'] == source_node and e['data']['target'] == target_node)
            for e in final_mapped_links
        )
        if not exists:
            final_mapped_links.append({
                "data": {"source": source_node, "target": target_node, "type": "infra"}
            })

    # PC assignments
    for link in temp_links:
        if link['type'] != 'pc':
            continue
        pc_id         = link['target']
        current_owner = link['source']
        if pc_id not in pc_assignments:
            pc_assignments[pc_id] = current_owner
        else:
            prev = pc_assignments[pc_id]
            if _is_switch(current_owner) and not _is_switch(prev):
                pc_assignments[pc_id] = current_owner

    for pc_id, owner in pc_assignments.items():
        final_owner = owner
        if not _is_switch(owner) and not _is_firewall(owner):
            for lk in final_mapped_links:
                src_node = lk['data']['source']
                tgt_node = lk['data']['target']
                if src_node == owner and _is_switch(tgt_node):
                    final_owner = tgt_node
                    break
                elif tgt_node == owner and _is_switch(src_node):
                    final_owner = src_node
                    break
        final_mapped_links.append({
            "data": {"source": final_owner, "target": pc_id, "type": "pc"}
        })

    with open('topology.json', 'w') as f:
        json.dump(final_mapped_links, f, indent=4)

    try:
        save_topology(final_mapped_links)
        print('Topology saved to DB')
    except Exception as te:
        print(f'Topology DB save: {te}')

    return final_mapped_links


# ─────────────────────────────────────────────────────────────────────────────
#  MAIN HARVEST ORCHESTRATOR
# ─────────────────────────────────────────────────────────────────────────────
def run_harvest():
    """
    Full network harvest — called at startup and from Re-Scan button.
    Phase 1: VyOS firewall (ping → SSH)
    Phase 2: Cisco devices (ping → SSH/Telnet, sequential for stability)
    """
    start_dt = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"\nSTARTING NETGUARD HARVEST [{start_dt}]")
    print(f"  Perimeter: {SEED_IP} (FW1 — VyOS)")
    print(f"  Method   : Ping-First Perimeter Discovery\n")

    # Reset shared state for fresh run
    processed_ips.clear()
    processed_hostnames.clear()
    found_pc_ips.clear()
    unknown_devices.clear()
    probe_cache.clear()
    ip_to_host_map.clear()
    all_device_ips.clear()

    temp_links = []

    # ══════════════════════════════════════════════════════
    # PHASE 1 — Harvest VyOS Firewall
    # ══════════════════════════════════════════════════════
    print("PHASE 1: Harvesting perimeter firewall (FW1)...")
    fw_config, fw_neighbors = harvest_firewall_vyos(SEED_IP, 'FW1')

    if fw_config:
        with open('network_configs/FW1_config.txt', 'w', encoding='utf-8') as f:
            f.write(fw_config)
        try:
            upsert_device('FW1', SEED_IP, 'firewall')
            status = save_config('FW1', fw_config)
            icons  = {'new_device':'NEW', 'changed':'CHANGED', 'unchanged':'OK'}
            print(f"  DB: FW1 {icons.get(status, status)}")
        except Exception as e:
            print(f"  DB warning: {e}")

        with processed_lock:
            processed_hostnames.add('FW1')
            ip_to_host_map[SEED_IP] = 'FW1'
            all_device_ips[SEED_IP] = 'FW1'

        temp_links.append({"source": "Internet", "target": "FW1", "type": "infra"})
        print(f"  FW1 harvested successfully")
    else:
        print("  ERROR: Could not harvest FW1 — check SSH and GNS3")
        return

    # ══════════════════════════════════════════════════════
    # PHASE 2 — Harvest Cisco devices (sequential, ping-first)
    # ══════════════════════════════════════════════════════
    print(f"\nPHASE 2: Harvesting Cisco devices (ping-first, sequential)...")

    queue = [ip for ip in fw_neighbors if ip not in processed_ips]
    if not queue:
        print("  FW1 ARP empty — trying R1 direct (10.10.0.2)")
        queue = ['10.10.0.2']

    # Sequential processing — stable for legacy GNS3 devices
    while queue and not shutdown_flag.is_set():
        queue = [ip for ip in queue if ip not in processed_ips]
        if not queue:
            break

        next_ips = []
        for ip in queue:
            res = harvest_single_device(ip)
            if res:
                next_ips.extend(res['neighbors'])
                temp_links.extend(res['links'])

        queue = [
            ip for ip in set(next_ips)
            if ip not in processed_ips
            and not str(ip).startswith('PC-')
            and not str(ip).startswith('Device-')
            and '192.168.214' not in str(ip)
            and '10.10.0.' not in str(ip)
        ]

    # Add FW1→R1 topology link
    r1_host = ip_to_host_map.get('10.10.0.2', 'R1')
    temp_links.append({"source": "FW1", "target": r1_host, "type": "infra"})

    # ══════════════════════════════════════════════════════
    # BUILD TOPOLOGY
    # ══════════════════════════════════════════════════════
    build_and_save_topology(temp_links)

    # ══════════════════════════════════════════════════════
    # SUMMARY
    # ══════════════════════════════════════════════════════
    firewalls = sorted([h for h in processed_hostnames if _is_firewall(h)])
    routers   = sorted([h for h in processed_hostnames if not _is_switch(h) and not _is_firewall(h)])
    switches  = sorted([h for h in processed_hostnames if _is_switch(h)])

    print("\n" + "="*55)
    print(" HARVEST SUMMARY — NetGuard v6.0")
    print("="*55)
    print(f" FIREWALLS : {len(firewalls):<2} | {', '.join(firewalls)}")
    print(f" ROUTERS   : {len(routers):<2} | {', '.join(routers)}")
    print(f" SWITCHES  : {len(switches):<2} | {', '.join(switches)}")
    print(f" PCs       : {len(found_pc_ips):<2}")
    print("="*55)
    if unknown_devices:
        print("\nUnknown (Cisco MAC, login failed):")
        for ip, mac in unknown_devices.items():
            print(f"  {ip}  [{mac}]")


if __name__ == "__main__":
    run_harvest()
