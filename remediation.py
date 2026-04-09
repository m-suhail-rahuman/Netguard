"""
Automated Remediation Generator
Maps detected security issues to Cisco IOS CLI fix commands via Jinja2 templates.
"""
import os, re
from jinja2 import Template
from datetime import datetime

REMEDIATION_DIR = 'network_configs'


# ─────────────────────────────────────────────────────────────────────────────
#  JINJA2 REMEDIATION TEMPLATES
# ─────────────────────────────────────────────────────────────────────────────
TEMPLATES = {

    'no_service_password_encryption': {
        'title': 'Enable Service Password Encryption',
        'match': r'no service password-encryption',
        'template': Template("""\
! ── FIX: Enable Service Password Encryption ─────────────────
! Device : {{ device }}
service password-encryption
"""),
    },

    'enable_password_cleartext': {
        'title': 'Replace enable password with enable secret',
        'match': r'^enable password\s+\S+',
        'template': Template("""\
! ── FIX: Replace enable password (MD5-less) with enable secret ─
! Device : {{ device }}
no enable password
enable secret 0 N3tGuard@{{ device }}!
"""),
    },

    'telnet_enabled': {
        'title': 'Disable Telnet – Enforce SSH Only',
        'match': r'transport input.*(telnet|all)',
        'template': Template("""\
! ── FIX: Disable Telnet – Enforce SSH-Only Management ──────────
! Device : {{ device }}
line vty 0 4
 transport input ssh
 login local
!
! Verify SSH is configured:
ip ssh version 2
ip domain name lab.local
crypto key generate rsa modulus 2048
"""),
    },

    'http_server_enabled': {
        'title': 'Disable Unencrypted HTTP Management Server',
        'match': r'^ip http server',
        'template': Template("""\
! ── FIX: Disable HTTP Management Server ────────────────────────
! Device : {{ device }}
no ip http server
no ip http secure-server
"""),
    },

    'snmp_default_community': {
        'title': 'Remove Default / Insecure SNMP Communities',
        'match': r'snmp-server community (public|private|cisco|admin|test|monitor|read|write)',
        'template': Template("""\
! ── FIX: Remove Default SNMP Communities ───────────────────────
! Device : {{ device }}
no snmp-server community public
no snmp-server community private
no snmp-server community cisco
no snmp-server community admin
no snmp-server community test
no snmp-server community monitor
no snmp-server community read
no snmp-server community write
! (Optional) Secure read-only SNMP with ACL:
! ip access-list standard SNMP_ALLOWED
!  permit 192.168.214.0 0.0.0.255
! snmp-server community NetGuardRO RO SNMP_ALLOWED
"""),
    },

    'snmp_rw_community': {
        'title': 'Remove SNMP Read-Write Community',
        'match': r'snmp-server community\s+\S+\s+RW',
        'template': Template("""\
! ── FIX: Remove SNMP Read-Write Community ──────────────────────
! Device : {{ device }}
no snmp-server community {{ community_name }} RW
! NEVER use RW SNMP in production – prefer SNMP v3 with auth/priv:
! snmp-server group NGGROUP v3 priv
! snmp-server user ngadmin NGGROUP v3 auth sha AuthPass priv aes 128 PrivPass
"""),
    },

    'username_cleartext_password': {
        'title': 'Replace Cleartext Username Password with Secret Hash',
        'match': r'username\s+\S+\s+password\s+[07]?\s*\S+',
        'template': Template("""\
! ── FIX: Replace Cleartext Username Passwords ───────────────────
! Device : {{ device }}
! Remove the offending username(s) and re-create with 'secret':
no username {{ username }}
username {{ username }} privilege 15 secret 0 N3tGuard@{{ device }}!
"""),
    },

    'no_login_vty': {
        'title': 'Require Authentication on VTY Lines',
        'match': r'^no login$',
        'template': Template("""\
! ── FIX: Enforce Login Authentication on VTY Lines ─────────────
! Device : {{ device }}
line vty 0 4
 login local
 transport input ssh
 exec-timeout 10 0
"""),
    },

    'cleartext_line_password': {
        'title': 'Remove Cleartext Line Passwords',
        'match': r'^password\s+\S+',
        'template': Template("""\
! ── FIX: Remove Cleartext Console/VTY Passwords ─────────────────
! Device : {{ device }}
! Replace 'password' with local user authentication:
line con 0
 login local
line vty 0 4
 login local
! Ensure a local user exists:
username admin privilege 15 secret 0 N3tGuard@{{ device }}!
"""),
    },

    'exec_timeout_infinite': {
        'title': 'Set Session Exec Timeout',
        'match': r'exec-timeout 0 0|exec-timeout 0$',
        'template': Template("""\
! ── FIX: Set Idle Session Timeout (10 minutes) ───────────────────
! Device : {{ device }}
line con 0
 exec-timeout 10 0
line vty 0 4
 exec-timeout 10 0
"""),
    },

    'ssh_version_1': {
        'title': 'Enforce SSH Version 2',
        'match': r'ip ssh version 1',
        'template': Template("""\
! ── FIX: Enforce SSH Version 2 ──────────────────────────────────
! Device : {{ device }}
ip ssh version 2
ip ssh time-out 60
ip ssh authentication-retries 3
"""),
    },

    'no_logging': {
        'title': 'Enable Syslog / Buffered Logging',
        'match': r'^no logging|no logging buffered',
        'template': Template("""\
! ── FIX: Enable Logging ─────────────────────────────────────────
! Device : {{ device }}
service timestamps log datetime msec localtime
service timestamps debug datetime msec
logging buffered 32768 informational
logging console critical
! logging host <YOUR_SYSLOG_SERVER>
"""),
    },

    'no_banner': {
        'title': 'Add Legal Warning Banner',
        'match': r'^no banner',
        'template': Template("""\
! ── FIX: Add Warning Banner ─────────────────────────────────────
! Device : {{ device }}
banner motd ^
*************************************************************
* AUTHORIZED ACCESS ONLY                                    *
* Unauthorized access is prohibited and will be prosecuted *
* All sessions are logged and monitored                     *
*************************************************************
^
banner login ^
** Authorized Access Only - {{ device }} **
^
"""),
    },

    'small_servers': {
        'title': 'Disable TCP/UDP Small Servers',
        'match': r'service (tcp|udp)-small-servers',
        'template': Template("""\
! ── FIX: Disable Small Servers ──────────────────────────────────
! Device : {{ device }}
no service tcp-small-servers
no service udp-small-servers
no service finger
no ip bootp server
no ip identd
"""),
    },

    'ip_source_route': {
        'title': 'Disable IP Source Routing',
        'match': r'^ip source-route',
        'template': Template("""\
! ── FIX: Disable IP Source Routing ─────────────────────────────
! Device : {{ device }}
no ip source-route
"""),
    },

    'debug_enabled': {
        'title': 'Disable Active Debug Commands',
        'match': r'^debug (ip packet|all)',
        'template': Template("""\
! ── FIX: Disable Debug Commands ────────────────────────────────
! Device : {{ device }}
undebug all
no debug ip packet
"""),
    },

    'proxy_arp': {
        'title': 'Disable Proxy ARP on Interfaces',
        'match': r'^ip proxy-arp',
        'template': Template("""\
! ── FIX: Disable Proxy ARP ──────────────────────────────────────
! Device : {{ device }}
! Apply to each interface where proxy-arp is enabled:
interface <INTERFACE>
 no ip proxy-arp
"""),
    },

    'no_aaa_new_model': {
        'title': 'Enable AAA New-Model for Centralized Auth',
        'match': r'no aaa new-model|^aaa new-model',
        'template': Template("""! ── FIX: Enable AAA New-Model ───────────────────────────────────
! Device : {{ device }}
aaa new-model
aaa authentication login default local
aaa authentication enable default enable
aaa authorization exec default local
aaa authorization commands 15 default local
aaa accounting exec default start-stop local
"""),
    },

    'cdp_enabled_global': {
        'title': 'Disable CDP Globally (Information Disclosure)',
        'match': r'^cdp run|cdp enable',
        'template': Template("""! ── FIX: Disable CDP Globally ───────────────────────────────────
! Device : {{ device }}
! CDP leaks platform/IOS version to adjacent devices
no cdp run
! To disable per-interface as well:
! interface <INTERFACE>
!  no cdp enable
"""),
    },

    'ip_directed_broadcast': {
        'title': 'Disable IP Directed Broadcasts (Smurf Attack Vector)',
        'match': r'ip directed-broadcast',
        'template': Template("""! ── FIX: Disable IP Directed Broadcasts ─────────────────────────
! Device : {{ device }}
! Apply to ALL interfaces:
interface range FastEthernet0/0 - FastEthernet0/1
 no ip directed-broadcast
! Note: disabled by default on IOS 12.0+ but verify:
! show run | include directed-broadcast
"""),
    },

    'ospf_no_auth': {
        'title': 'Enable OSPF MD5 Authentication',
        'match': r'router ospf|ip ospf',
        'template': Template("""! ── FIX: Enable OSPF Authentication ─────────────────────────────
! Device : {{ device }}
! Under OSPF process:
router ospf 1
 area 0 authentication message-digest
!
! On each OSPF interface:
! interface <OSPF_INTERFACE>
!  ip ospf message-digest-key 1 md5 N3tGuard@OSPF!
"""),
    },

    'rip_no_auth': {
        'title': 'Enable RIP v2 with MD5 Authentication',
        'match': r'^router rip',
        'template': Template("""! ── FIX: Secure RIP Routing ──────────────────────────────────────
! Device : {{ device }}
router rip
 version 2
 no auto-summary
!
! Add MD5 key chain on interfaces:
key chain RIP_KEYS
 key 1
  key-string N3tGuard@RIP!
!
! interface <RIP_INTERFACE>
!  ip rip authentication mode md5
!  ip rip authentication key-chain RIP_KEYS
"""),
    },

    'no_ntp': {
        'title': 'Configure NTP for Log Integrity',
        'match': r'no ntp|^ntp server',
        'template': Template("""! ── FIX: Configure NTP ───────────────────────────────────────────
! Device : {{ device }}
! Accurate timestamps are critical for log forensics
ntp server 192.168.214.100 prefer
ntp server 8.8.8.8
service timestamps log datetime msec localtime show-timezone
service timestamps debug datetime msec localtime show-timezone
ntp update-calendar
"""),
    },

    'weak_rsa_key': {
        'title': 'Regenerate RSA Key (Minimum 2048-bit)',
        'match': r'crypto key generate rsa|ip ssh rsa',
        'template': Template("""! ── FIX: Generate Strong RSA Key ────────────────────────────────
! Device : {{ device }}
! WARNING: This will drop all active SSH sessions
crypto key zeroize rsa
ip domain name lab.netguard.local
crypto key generate rsa modulus 2048
ip ssh version 2
ip ssh time-out 60
ip ssh authentication-retries 3
ip ssh dh min size 2048
"""),
    },

    'no_service_tcp_keepalives': {
        'title': 'Enable TCP Keepalives to Detect Dead Sessions',
        'match': r'no service tcp-keepalives|tcp-keepalives',
        'template': Template("""! ── FIX: Enable TCP Keepalives ───────────────────────────────────
! Device : {{ device }}
service tcp-keepalives-in
service tcp-keepalives-out
"""),
    },

    'ip_domain_lookup': {
        'title': 'Disable IP Domain Lookup (Prevents Typo Delays)',
        'match': r'^ip domain.lookup|^no ip domain.lookup',
        'template': Template("""! ── FIX: Disable IP Domain Lookup ───────────────────────────────
! Device : {{ device }}
! Without this, mistyped commands cause 30s DNS lookup delay
no ip domain-lookup
"""),
    },

    'vty_no_acl': {
        'title': 'Apply ACL to Restrict VTY (Management) Access',
        'match': r'line vty',
        'template': Template("""! ── FIX: Restrict VTY Access with ACL ───────────────────────────
! Device : {{ device }}
ip access-list standard MGMT_ACCESS
 permit 192.168.214.0 0.0.0.255
 permit 192.168.10.0 0.0.0.255
 deny   any log
!
line vty 0 4
 access-class MGMT_ACCESS in
 transport input ssh
 login local
 exec-timeout 10 0
"""),
    },

}


# ─────────────────────────────────────────────────────────────────────────────
#  ISSUE → TEMPLATE MATCHER
# ─────────────────────────────────────────────────────────────────────────────
def _match_template(config_line: str) -> list:
    """Return list of (template_key, context_extras) for a config line."""
    matched = []
    line_lower = config_line.strip().lower()

    for key, tpl in TEMPLATES.items():
        if re.search(tpl['match'], line_lower, re.IGNORECASE):
            extras = {}
            # Extract username if relevant
            m = re.search(r'username\s+(\S+)', line_lower)
            if m:
                extras['username'] = m.group(1)
            # Extract community name if relevant
            m2 = re.search(r'snmp-server community\s+(\S+)', line_lower)
            if m2:
                extras['community_name'] = m2.group(1)
            matched.append((key, extras))

    return matched


def _deduplicate_keys(keys: list) -> list:
    seen = set()
    out  = []
    for k in keys:
        if k not in seen:
            seen.add(k)
            out.append(k)
    return out


# ─────────────────────────────────────────────────────────────────────────────
#  DEVICE REMEDIATION GENERATOR
# ─────────────────────────────────────────────────────────────────────────────
def generate_device_remediation(device_name: str, flagged_lines: list) -> dict:
    """
    Given a device name and its list of flagged analysis dicts,
    produce remediation commands.

    Returns:
        {
          'device': str,
          'remediations': [ {'title': str, 'commands': str}, … ],
          'full_script': str,
        }
    """
    matched_keys = []
    extra_context = {}

    for item in flagged_lines:
        line    = item.get('line', '')
        matches = _match_template(line)
        for key, extras in matches:
            matched_keys.append(key)
            extra_context.update(extras)

    matched_keys = _deduplicate_keys(matched_keys)

    remediations = []
    script_parts = [
        f"! ╔══════════════════════════════════════════════════════╗",
        f"! ║  NetGuard Remediation Script                         ║",
        f"! ║  Device  : {device_name:<42}║",
        f"! ║  Generated: {datetime.now().strftime('%Y-%m-%d %H:%M'):<41}║",
        f"! ╚══════════════════════════════════════════════════════╝",
        "!",
        f"conf t",
        "!",
    ]

    for key in matched_keys:
        tpl_data = TEMPLATES[key]
        ctx = {'device': device_name, **extra_context}
        try:
            rendered = tpl_data['template'].render(**ctx)
        except Exception:
            rendered = f"! Could not render template for {key}\n"

        remediations.append({
            'title':    tpl_data['title'],
            'commands': rendered.strip(),
            'key':      key,
        })
        script_parts.append(rendered)

    if not matched_keys:
        script_parts.append("! No automated remediation available for detected issues.")
        script_parts.append("! Review flagged lines manually.")

    script_parts.append("!")
    script_parts.append("end")
    script_parts.append("write memory")

    full_script = "\n".join(script_parts)

    return {
        'device':       device_name,
        'remediations': remediations,
        'full_script':  full_script,
        'issue_count':  len(matched_keys),
    }


# ─────────────────────────────────────────────────────────────────────────────
#  FILE SAVE
# ─────────────────────────────────────────────────────────────────────────────
def save_remediation_file(device_name: str, full_script: str) -> str:
    """Save remediation script to network_configs/<device>_remediation.txt"""
    os.makedirs(REMEDIATION_DIR, exist_ok=True)
    path = os.path.join(REMEDIATION_DIR, f"{device_name}_remediation.txt")
    with open(path, 'w', encoding='utf-8') as f:
        f.write(full_script)
    return path


def generate_and_save_all(analysis_results: list) -> dict:
    """
    Generate + save remediation for all devices from analyze_all_devices().
    Returns dict of device_name → remediation_data.
    """
    out = {}
    for device_data in analysis_results:
        device = device_data['device']
        flagged = device_data.get('flagged', [])
        rem = generate_device_remediation(device, flagged)
        save_remediation_file(device, rem['full_script'])
        out[device] = rem
    return out
