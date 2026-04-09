"""
NetGuard Security Audit Engine 
=====================================
30+ security checks across 7 categories based on:
  - CIS Cisco IOS Benchmark v4.1
  - NIST SP 800-115 (Network Security Testing)
  - NSA Cisco Router Security Configuration Guide
  - OWASP Network Security Testing Guide
  - CVE trending vulnerabilities for Cisco IOS

Categories:
  1. Authentication & Passwords
  2. Remote Access & Encryption
  3. Logging & Monitoring
  4. Network Protocols
  5. SNMP Security
  6. Routing Protocol Security
  7. Switch / Layer-2 Security
"""

import re
import os

# ─────────────────────────────────────────────────────────────────────────────
#  SEVERITY LEVELS
# ─────────────────────────────────────────────────────────────────────────────
SEV_CRITICAL = "CRITICAL"   # Immediate exploitation risk – must fix now
SEV_HIGH     = "HIGH"       # Significant risk – fix within 24 hours
SEV_MEDIUM   = "MEDIUM"     # Moderate risk – fix within 1 week
SEV_LOW      = "LOW"        # Minor risk – fix in next maintenance window
SEV_INFO     = "INFO"       # Best practice advisory


# ─────────────────────────────────────────────────────────────────────────────
#  AUDIT CHECK DEFINITIONS
#  Each check is a dict:
#    id         : unique check ID (e.g. "AUTH-001")
#    category   : display category name
#    title      : short vulnerability name
#    description: what is wrong and why it matters
#    severity   : SEV_* constant
#    cve        : related CVE or advisory (optional)
#    cis        : CIS Benchmark reference
#    detect     : callable(config_text) -> bool  (True = vulnerability EXISTS)
#    fix        : short fix guidance shown in UI
# ─────────────────────────────────────────────────────────────────────────────

AUDIT_CHECKS = [

    # ══════════════════════════════════════════════════════════════════════════
    #  CATEGORY 1 – AUTHENTICATION & PASSWORDS
    # ══════════════════════════════════════════════════════════════════════════
    {
        "id": "AUTH-001",
        "category": "Authentication & Passwords",
        "title": "Password Encryption Disabled",
        "description": "The 'no service password-encryption' command leaves all Type-0 and Type-7 passwords stored in plain text in the running config. Any user with read access to the config can harvest credentials instantly.",
        "severity": SEV_CRITICAL,
        "cve": "CWE-312",
        "cis": "CIS Cisco IOS 1.2",
        "detect": lambda cfg: "no service password-encryption" in cfg,
        "fix": "Run: service password-encryption",
    },
    {
        "id": "AUTH-002",
        "category": "Authentication & Passwords",
        "title": "Weak Enable Password (No Secret Hash)",
        "description": "The 'enable password' command stores the password using weak reversible Type-7 encoding or plain text. The 'enable secret' command must be used instead, which applies MD5/SHA-256 hashing.",
        "severity": SEV_CRITICAL,
        "cve": "CWE-916",
        "cis": "CIS Cisco IOS 1.1",
        "detect": lambda cfg: bool(re.search(r"^enable password\s+\S+", cfg, re.M)),
        "fix": "Replace: no enable password / enable secret 9 <strong-password>",
    },
    {
        "id": "AUTH-003",
        "category": "Authentication & Passwords",
        "title": "Cleartext Username Passwords",
        "description": "Username passwords using 'password 0' or 'password 7' are stored with no or weak encryption. Use 'secret 9' or 'secret 5' instead.",
        "severity": SEV_CRITICAL,
        "cve": "CWE-312",
        "cis": "CIS Cisco IOS 1.3",
        "detect": lambda cfg: bool(re.search(r"username\s+\S+\s+(privilege\s+\d+\s+)?password\s+[07]?\s*\S+", cfg, re.M)),
        "fix": "Replace username lines: username <user> privilege 15 secret 9 <hash>",
    },
    {
        "id": "AUTH-004",
        "category": "Authentication & Passwords",
        "title": "Default / Weak Credentials Detected",
        "description": "Default credentials (cisco/admin/router/password) are present. These are the first passwords attackers try and are listed in publicly available default credential databases.",
        "severity": SEV_CRITICAL,
        "cve": "CVE-2023-20198",
        "cis": "CIS Cisco IOS 1.1",
        "detect": lambda cfg: bool(re.search(
            r"(enable (password|secret)\s+(cisco|admin|router|password|12345|letmein|default|network|test|lab))|"
            r"(username\s+\S+\s+.*(password|secret)\s+[059]?\s*(cisco|admin|router|password|12345|letmein|test|lab))",
            cfg, re.M | re.I
        )),
        "fix": "Change all credentials to complex unique passwords immediately",
    },
    {
        "id": "AUTH-005",
        "category": "Authentication & Passwords",
        "title": "No AAA Authentication Configured",
        "description": "AAA (Authentication, Authorization, Accounting) is not enabled. Without AAA, there is no centralized access control, no per-user authorization, and no audit trail for privileged commands.",
        "severity": SEV_HIGH,
        "cve": "CWE-306",
        "cis": "CIS Cisco IOS 2.1",
        "detect": lambda cfg: "no aaa new-model" in cfg or "aaa new-model" not in cfg,
        "fix": "Enable: aaa new-model / aaa authentication login default local",
    },
    {
        "id": "AUTH-006",
        "category": "Authentication & Passwords",
        "title": "VTY Lines Have No Authentication",
        "description": "Console or VTY lines are configured with 'no login' or no login method, allowing unauthenticated remote access to the device CLI.",
        "severity": SEV_CRITICAL,
        "cve": "CWE-306",
        "cis": "CIS Cisco IOS 2.2",
        "detect": lambda cfg: bool(re.search(r"^no login$", cfg, re.M)),
        "fix": "Under all line vty: login local / transport input ssh",
    },
    {
        "id": "AUTH-007",
        "category": "Authentication & Passwords",
        "title": "Infinite Session Timeout (exec-timeout 0)",
        "description": "Setting exec-timeout to 0 means idle sessions never expire. An unattended privileged session can be hijacked by physical or network access.",
        "severity": SEV_HIGH,
        "cve": "CWE-613",
        "cis": "CIS Cisco IOS 2.5",
        "detect": lambda cfg: bool(re.search(r"exec-timeout\s+0\s+0|exec-timeout\s+0$", cfg, re.M)),
        "fix": "Set: exec-timeout 10 0 (10 min idle timeout) on all lines",
    },
    {
        "id": "AUTH-008",
        "category": "Authentication & Passwords",
        "title": "No Login Failure Rate Limiting",
        "description": "No brute-force protection is configured on VTY lines. An attacker can make unlimited login attempts without lockout.",
        "severity": SEV_MEDIUM,
        "cve": "CWE-307",
        "cis": "CIS Cisco IOS 2.6",
        "detect": lambda cfg: "login block-for" not in cfg,
        "fix": "Add: login block-for 120 attempts 5 within 60",
    },

    # ══════════════════════════════════════════════════════════════════════════
    #  CATEGORY 2 – REMOTE ACCESS & ENCRYPTION
    # ══════════════════════════════════════════════════════════════════════════
    {
        "id": "REMOTE-001",
        "category": "Remote Access & Encryption",
        "title": "Telnet Enabled on VTY Lines",
        "description": "Telnet transmits all data including passwords in plain text. A network attacker performing a man-in-the-middle or passive capture can steal administrator credentials. Telnet has no encryption.",
        "severity": SEV_CRITICAL,
        "cve": "CVE-1999-0504",
        "cis": "CIS Cisco IOS 3.1",
        "detect": lambda cfg: bool(re.search(r"transport input\s+(telnet|all|telnet\s+ssh)", cfg, re.M)),
        "fix": "Replace with: transport input ssh (and configure SSH v2)",
    },
    {
        "id": "REMOTE-002",
        "category": "Remote Access & Encryption",
        "title": "HTTP Management Server Enabled",
        "description": "The HTTP management server (ip http server) serves the web UI over unencrypted HTTP port 80. All management traffic including credentials is transmitted in cleartext and is vulnerable to interception.",
        "severity": SEV_CRITICAL,
        "cve": "CVE-2023-20198",
        "cis": "CIS Cisco IOS 3.3",
        "detect": lambda cfg: bool(re.search(r"^ip http server$", cfg, re.M)),
        "fix": "Run: no ip http server (use HTTPS or SSH instead)",
    },
    {
        "id": "REMOTE-003",
        "category": "Remote Access & Encryption",
        "title": "SSH Version 1 Enabled",
        "description": "SSHv1 has known cryptographic vulnerabilities including CRC-32 compensation attack and session hijacking. SSHv1 was deprecated in 2006 and should never be used in production environments.",
        "severity": SEV_HIGH,
        "cve": "CVE-2001-0572",
        "cis": "CIS Cisco IOS 3.2",
        "detect": lambda cfg: bool(re.search(r"ip ssh version 1", cfg, re.M)),
        "fix": "Replace with: ip ssh version 2",
    },
    {
        "id": "REMOTE-004",
        "category": "Remote Access & Encryption",
        "title": "SSH Not Configured",
        "description": "SSH is not configured on this device. Without SSH, only Telnet or console access is available, leaving management traffic unencrypted.",
        "severity": SEV_HIGH,
        "cve": "CWE-311",
        "cis": "CIS Cisco IOS 3.2",
        "detect": lambda cfg: "ip ssh version" not in cfg and "crypto key generate rsa" not in cfg,
        "fix": "Configure: ip domain-name lab.local / crypto key generate rsa modulus 2048 / ip ssh version 2",
    },
    {
        "id": "REMOTE-005",
        "category": "Remote Access & Encryption",
        "title": "No ACL Restricting VTY Access",
        "description": "VTY lines have no access-class ACL applied, meaning any IP address can attempt to connect to the management interface. Management access should be restricted to known admin networks only.",
        "severity": SEV_MEDIUM,
        "cve": "CWE-284",
        "cis": "CIS Cisco IOS 2.4",
        "detect": lambda cfg: "access-class" not in cfg,
        "fix": "Create ACL for mgmt IPs and apply: access-class MGMT_ACL in on VTY lines",
    },
    {
        "id": "REMOTE-006",
        "category": "Remote Access & Encryption",
        "title": "Weak RSA Key Size (< 2048 bits)",
        "description": "RSA keys smaller than 2048 bits are considered cryptographically weak. NIST has deprecated 1024-bit RSA since 2014. An attacker with sufficient compute resources can factor the private key.",
        "severity": SEV_MEDIUM,
        "cve": "CWE-326",
        "cis": "CIS Cisco IOS 3.5",
        "detect": lambda cfg: bool(re.search(r"crypto key generate rsa modulus (512|768|1024)\b", cfg, re.M)),
        "fix": "Regenerate: crypto key generate rsa modulus 2048",
    },

    # ══════════════════════════════════════════════════════════════════════════
    #  CATEGORY 3 – LOGGING & MONITORING
    # ══════════════════════════════════════════════════════════════════════════
    {
        "id": "LOG-001",
        "category": "Logging & Monitoring",
        "title": "Logging Not Configured",
        "description": "No logging is configured on this device. Without logging, there is no audit trail of configuration changes, login attempts, or security events. Attackers can operate undetected.",
        "severity": SEV_HIGH,
        "cve": "CWE-778",
        "cis": "CIS Cisco IOS 4.1",
        "detect": lambda cfg: "logging" not in cfg or "no logging" in cfg,
        "fix": "Add: logging buffered 32768 / logging host <syslog-server>",
    },
    {
        "id": "LOG-002",
        "category": "Logging & Monitoring",
        "title": "No Timestamps on Log Messages",
        "description": "Log messages lack timestamps, making it impossible to correlate security events, perform forensic analysis, or meet compliance requirements that mandate timestamped audit logs.",
        "severity": SEV_MEDIUM,
        "cve": "CWE-778",
        "cis": "CIS Cisco IOS 4.2",
        "detect": lambda cfg: "service timestamps log" not in cfg,
        "fix": "Add: service timestamps log datetime msec localtime",
    },
    {
        "id": "LOG-003",
        "category": "Logging & Monitoring",
        "title": "No Warning Banner Configured",
        "description": "No MOTD/login banner is present. Legal requirements in most jurisdictions require a warning banner to establish that unauthorized access is prohibited, otherwise prosecution for unauthorized access may fail.",
        "severity": SEV_MEDIUM,
        "cve": "CWE-693",
        "cis": "CIS Cisco IOS 5.1",
        "detect": lambda cfg: "banner motd" not in cfg and "banner login" not in cfg,
        "fix": "Add: banner motd ^ AUTHORIZED ACCESS ONLY - All sessions logged ^",
    },
    {
        "id": "LOG-004",
        "category": "Logging & Monitoring",
        "title": "No NTP Server Configured",
        "description": "Without NTP synchronization, device clocks drift and log timestamps become unreliable. This breaks forensic timelines and log correlation across multiple devices.",
        "severity": SEV_MEDIUM,
        "cve": "CWE-778",
        "cis": "CIS Cisco IOS 4.3",
        "detect": lambda cfg: "ntp server" not in cfg,
        "fix": "Add: ntp server <ntp-ip> / clock timezone <TZ> 0",
    },
    {
        "id": "LOG-005",
        "category": "Logging & Monitoring",
        "title": "Active Debug Commands Running",
        "description": "Debug commands (debug all, debug ip packet, etc.) are currently active. Debug mode generates excessive CPU load, can crash the router under traffic load, and may expose sensitive data in log output.",
        "severity": SEV_HIGH,
        "cve": "CWE-400",
        "cis": "CIS Cisco IOS 4.4",
        "detect": lambda cfg: bool(re.search(r"^debug\s+(all|ip|ospf|eigrp|bgp|aaa)", cfg, re.M)),
        "fix": "Run: undebug all (immediately on live devices)",
    },

    # ══════════════════════════════════════════════════════════════════════════
    #  CATEGORY 4 – NETWORK PROTOCOLS & HARDENING
    # ══════════════════════════════════════════════════════════════════════════
    {
        "id": "NET-001",
        "category": "Network Protocols & Hardening",
        "title": "IP Source Routing Enabled",
        "description": "IP source routing allows a sender to specify the route a packet takes through the network, bypassing firewalls and access controls. This is a classic technique used in IP spoofing and session hijacking attacks.",
        "severity": SEV_HIGH,
        "cve": "CVE-1999-0909",
        "cis": "CIS Cisco IOS 6.1",
        "detect": lambda cfg: "no ip source-route" not in cfg and "ip source-route" in cfg,
        "fix": "Add: no ip source-route",
    },
    {
        "id": "NET-002",
        "category": "Network Protocols & Hardening",
        "title": "CDP Enabled (Topology Exposure)",
        "description": "Cisco Discovery Protocol broadcasts device model, IOS version, IP addresses, and network topology to all connected neighbors. This information directly assists attackers in reconnaissance and targeting specific exploits.",
        "severity": SEV_MEDIUM,
        "cve": "CVE-2020-3120",
        "cis": "CIS Cisco IOS 6.2",
        "detect": lambda cfg: ("no cdp run" not in cfg and "cdp run" in cfg) or \
                              ("no cdp enable" not in cfg and re.search(r"^cdp enable", cfg, re.M) is not None),
        "fix": "Disable globally: no cdp run / On external interfaces: no cdp enable",
    },
    {
        "id": "NET-003",
        "category": "Network Protocols & Hardening",
        "title": "LLDP Enabled (Topology Exposure)",
        "description": "Link Layer Discovery Protocol (LLDP) broadcasts device information to all neighbors. Like CDP, this helps attackers map the network, identify device types, and target specific firmware exploits.",
        "severity": SEV_MEDIUM,
        "cve": "CVE-2021-1353",
        "cis": "CIS Cisco IOS 6.3",
        "detect": lambda cfg: "lldp run" in cfg or "lldp transmit" in cfg,
        "fix": "Disable: no lldp run (globally) or no lldp transmit/receive per interface",
    },
    {
        "id": "NET-004",
        "category": "Network Protocols & Hardening",
        "title": "IP Proxy ARP Enabled",
        "description": "Proxy ARP allows the router to respond to ARP requests on behalf of hosts in other subnets. This can enable ARP-based man-in-the-middle attacks and allows network scanning without routing through the gateway.",
        "severity": SEV_MEDIUM,
        "cve": "CVE-2002-0701",
        "cis": "CIS Cisco IOS 6.5",
        "detect": lambda cfg: "no ip proxy-arp" not in cfg and re.search(r"interface\s+\S+", cfg, re.M) is not None,
        "fix": "Add on each interface: no ip proxy-arp",
    },
    {
        "id": "NET-005",
        "category": "Network Protocols & Hardening",
        "title": "IP Redirects Enabled",
        "description": "ICMP Redirect messages allow a router to inform hosts of a better route. Attackers can exploit this to perform ICMP redirect attacks, redirecting traffic through a malicious host for interception.",
        "severity": SEV_LOW,
        "cve": "CVE-1999-0265",
        "cis": "CIS Cisco IOS 6.6",
        "detect": lambda cfg: "no ip redirects" not in cfg and re.search(r"interface\s+\S+", cfg, re.M) is not None,
        "fix": "Add on each interface: no ip redirects",
    },
    {
        "id": "NET-006",
        "category": "Network Protocols & Hardening",
        "title": "IP Directed Broadcasts Enabled",
        "description": "IP directed broadcasts can be used to amplify DoS attacks (Smurf attack). A single spoofed packet can trigger responses from every host in a subnet, overwhelming the target.",
        "severity": SEV_HIGH,
        "cve": "CVE-1999-0513",
        "cis": "CIS Cisco IOS 6.7",
        "detect": lambda cfg: "ip directed-broadcast" in cfg and "no ip directed-broadcast" not in cfg,
        "fix": "Add on each interface: no ip directed-broadcast",
    },
    {
        "id": "NET-007",
        "category": "Network Protocols & Hardening",
        "title": "TCP/UDP Small Servers Enabled",
        "description": "TCP/UDP small server services (echo, chargen, daytime, discard) are enabled. These legacy diagnostic services have been exploited for DoS amplification attacks and should be disabled on all production devices.",
        "severity": SEV_HIGH,
        "cve": "CVE-1999-0103",
        "cis": "CIS Cisco IOS 6.8",
        "detect": lambda cfg: "service tcp-small-servers" in cfg or "service udp-small-servers" in cfg,
        "fix": "Add: no service tcp-small-servers / no service udp-small-servers",
    },
    {
        "id": "NET-008",
        "category": "Network Protocols & Hardening",
        "title": "Finger Service Enabled",
        "description": "The Finger service reveals active users and their idle times to anyone who queries port 79. This is an information disclosure vulnerability used in early-stage reconnaissance.",
        "severity": SEV_MEDIUM,
        "cve": "CVE-1999-0612",
        "cis": "CIS Cisco IOS 6.9",
        "detect": lambda cfg: "service finger" in cfg and "no service finger" not in cfg,
        "fix": "Add: no service finger",
    },

    # ══════════════════════════════════════════════════════════════════════════
    #  CATEGORY 5 – SNMP SECURITY
    # ══════════════════════════════════════════════════════════════════════════
    {
        "id": "SNMP-001",
        "category": "SNMP Security",
        "title": "SNMP Default Community Strings",
        "description": "Default SNMP community strings (public/private) are configured. These are universally known and allow any attacker to read the entire device MIB (public) or write configuration changes (private).",
        "severity": SEV_CRITICAL,
        "cve": "CVE-2002-0012",
        "cis": "CIS Cisco IOS 7.1",
        "detect": lambda cfg: bool(re.search(
            r"snmp-server community\s+(public|private|cisco|admin|test|monitor|read|write)\s+",
            cfg, re.M | re.I
        )),
        "fix": "Remove defaults: no snmp-server community public / private. Use SNMPv3 with auth/priv.",
    },
    {
        "id": "SNMP-002",
        "category": "SNMP Security",
        "title": "SNMP Read-Write Community Configured",
        "description": "An SNMP Read-Write (RW) community string is configured. This allows anyone with the string to modify device configuration through SNMP writes, including changing routing tables, ACLs, and passwords.",
        "severity": SEV_CRITICAL,
        "cve": "CVE-2002-0013",
        "cis": "CIS Cisco IOS 7.2",
        "detect": lambda cfg: bool(re.search(r"snmp-server community\s+\S+\s+RW", cfg, re.M | re.I)),
        "fix": "Remove all RW communities. Migrate to SNMPv3: snmp-server group <grp> v3 priv",
    },
    {
        "id": "SNMP-003",
        "category": "SNMP Security",
        "title": "SNMPv1/v2c In Use (No Encryption)",
        "description": "SNMPv1 and v2c transmit community strings and all SNMP data in plain text. A passive network attacker can capture community strings and gain full read (or write) access to the device.",
        "severity": SEV_HIGH,
        "cve": "CVE-2002-0012",
        "cis": "CIS Cisco IOS 7.3",
        "detect": lambda cfg: bool(re.search(r"snmp-server community\s+\S+\s+(RO|RW)", cfg, re.M | re.I)) \
                              and "snmp-server group" not in cfg,
        "fix": "Migrate to SNMPv3: snmp-server user <user> <grp> v3 auth sha <pass> priv aes 128 <pass>",
    },
    {
        "id": "SNMP-004",
        "category": "SNMP Security",
        "title": "SNMP Has No ACL Restriction",
        "description": "SNMP community strings are not restricted by an access control list. Any IP address can poll the device via SNMP, enabling attackers to enumerate the entire network topology from any location.",
        "severity": SEV_HIGH,
        "cve": "CWE-284",
        "cis": "CIS Cisco IOS 7.4",
        "detect": lambda cfg: bool(re.search(r"snmp-server community\s+\S+\s+(RO|RW)\s*$", cfg, re.M | re.I)),
        "fix": "Create ACL and restrict: snmp-server community <str> RO <acl-number>",
    },

    # ══════════════════════════════════════════════════════════════════════════
    #  CATEGORY 6 – ROUTING PROTOCOL SECURITY
    # ══════════════════════════════════════════════════════════════════════════
    {
        "id": "ROUTE-001",
        "category": "Routing Protocol Security",
        "title": "OSPF Running Without Authentication",
        "description": "OSPF is configured without neighbor authentication. An attacker who can inject crafted OSPF packets can advertise fake routes, causing traffic to be redirected through attacker-controlled hosts (BGP/OSPF hijacking).",
        "severity": SEV_HIGH,
        "cve": "CVE-2013-0149",
        "cis": "CIS Cisco IOS 8.1",
        "detect": lambda cfg: "router ospf" in cfg and "ip ospf authentication" not in cfg \
                              and "area 0 authentication" not in cfg,
        "fix": "Add under OSPF: area 0 authentication message-digest / On interfaces: ip ospf message-digest-key 1 md5 <key>",
    },
    {
        "id": "ROUTE-002",
        "category": "Routing Protocol Security",
        "title": "EIGRP Running Without Authentication",
        "description": "EIGRP neighbors are not authenticated. An attacker can inject fake EIGRP updates to poison routing tables, divert traffic to malicious destinations, or cause network-wide routing loops.",
        "severity": SEV_HIGH,
        "cve": "CVE-2016-6386",
        "cis": "CIS Cisco IOS 8.2",
        "detect": lambda cfg: "router eigrp" in cfg and "authentication mode md5" not in cfg,
        "fix": "Configure EIGRP MD5 auth on interfaces: ip authentication mode eigrp <AS> md5",
    },
    {
        "id": "ROUTE-003",
        "category": "Routing Protocol Security",
        "title": "RIP Running Without Authentication",
        "description": "RIP version 1 or 2 is running without authentication. RIP is trivially spoofable — an attacker can inject false routes to redirect any traffic in the network to a destination of their choice.",
        "severity": SEV_CRITICAL,
        "cve": "CVE-1999-0254",
        "cis": "CIS Cisco IOS 8.3",
        "detect": lambda cfg: "router rip" in cfg and "ip rip authentication" not in cfg,
        "fix": "Add under interfaces: ip rip authentication mode md5 / ip rip authentication key-chain <chain>",
    },

    # ══════════════════════════════════════════════════════════════════════════
    #  CATEGORY 7 – SWITCH / LAYER-2 SECURITY
    # ══════════════════════════════════════════════════════════════════════════
    {
        "id": "SW-001",
        "category": "Switch / Layer-2 Security",
        "title": "No DHCP Snooping Configured",
        "description": "DHCP snooping is not enabled. Without it, any host can act as a rogue DHCP server, assigning themselves as the default gateway to perform a man-in-the-middle attack on all hosts in the VLAN.",
        "severity": SEV_HIGH,
        "cve": "CWE-923",
        "cis": "CIS Cisco IOS 9.1",
        "detect": lambda cfg: "ip dhcp snooping" not in cfg and \
                              ("switchport" in cfg or "vlan" in cfg.lower()),
        "fix": "Enable: ip dhcp snooping / ip dhcp snooping vlan <vlan-list>",
    },
    {
        "id": "SW-002",
        "category": "Switch / Layer-2 Security",
        "title": "No Dynamic ARP Inspection",
        "description": "Dynamic ARP Inspection (DAI) is not enabled. Without DAI, ARP spoofing attacks allow any host to intercept all traffic destined for any other host on the same VLAN.",
        "severity": SEV_HIGH,
        "cve": "CWE-923",
        "cis": "CIS Cisco IOS 9.2",
        "detect": lambda cfg: "ip arp inspection" not in cfg and \
                              ("switchport" in cfg or "vlan" in cfg.lower()),
        "fix": "Enable: ip arp inspection vlan <vlan-list>",
    },
    {
        "id": "SW-003",
        "category": "Switch / Layer-2 Security",
        "title": "Native VLAN 1 on Trunk Ports",
        "description": "VLAN 1 is used as the native VLAN on trunk ports. VLAN 1 carries management traffic and control protocols. Using VLAN 1 as native exposes management traffic to VLAN hopping attacks.",
        "severity": SEV_MEDIUM,
        "cve": "CVE-2005-4814",
        "cis": "CIS Cisco IOS 9.3",
        "detect": lambda cfg: bool(re.search(r"switchport trunk native vlan 1", cfg, re.M | re.I)) or \
                              (re.search(r"encapsulation dot1Q 1 native", cfg, re.M | re.I) is not None),
        "fix": "Change native VLAN: switchport trunk native vlan 999 (unused VLAN)",
    },
    {
        "id": "SW-004",
        "category": "Switch / Layer-2 Security",
        "title": "Spanning Tree BPDU Guard Not Enabled",
        "description": "BPDU Guard is not configured on access ports. Without it, an attacker can connect a rogue switch and become the STP root bridge, redirecting all VLAN traffic through their device.",
        "severity": SEV_HIGH,
        "cve": "CWE-693",
        "cis": "CIS Cisco IOS 9.4",
        "detect": lambda cfg: "spanning-tree portfast bpduguard" not in cfg and \
                              "bpduguard enable" not in cfg and \
                              ("switchport" in cfg or "vlan" in cfg.lower()),
        "fix": "Enable globally: spanning-tree portfast bpduguard default",
    },
    {
        "id": "SW-005",
        "category": "Switch / Layer-2 Security",
        "title": "No Port Security on Access Ports",
        "description": "Port security is not configured on switch access ports. Any device can plug in and gain network access. MAC flooding attacks can also fill the switch's CAM table, causing it to broadcast all frames (fail-open to hub mode).",
        "severity": SEV_MEDIUM,
        "cve": "CWE-284",
        "cis": "CIS Cisco IOS 9.5",
        "detect": lambda cfg: "port-security" not in cfg and \
                              ("switchport mode access" in cfg or "switchport access vlan" in cfg),
        "fix": "On access interfaces: switchport port-security maximum 1 / switchport port-security violation restrict",
    },
    {
        "id": "SW-006",
        "category": "Switch / Layer-2 Security",
        "title": "DTP Auto-Negotiation Enabled (VLAN Hopping Risk)",
        "description": "Switch ports are in dynamic/auto mode, allowing DTP (Dynamic Trunking Protocol) negotiation. An attacker can send DTP packets to negotiate a trunk link and gain access to all VLANs on the switch.",
        "severity": SEV_MEDIUM,
        "cve": "CVE-2005-4814",
        "cis": "CIS Cisco IOS 9.6",
        "detect": lambda cfg: bool(re.search(r"switchport mode (dynamic|auto|desirable)", cfg, re.M | re.I)),
        "fix": "Set all access ports to: switchport mode access / switchport nonegotiate",
    },
]


# ─────────────────────────────────────────────────────────────────────────────
#  AUDIT ENGINE
# ─────────────────────────────────────────────────────────────────────────────

SEVERITY_ORDER = {SEV_CRITICAL: 4, SEV_HIGH: 3, SEV_MEDIUM: 2, SEV_LOW: 1, SEV_INFO: 0}
SEVERITY_SCORE = {SEV_CRITICAL: 30, SEV_HIGH: 15, SEV_MEDIUM: 6, SEV_LOW: 2, SEV_INFO: 0}


def audit_device(device_name: str, config_text: str) -> dict:
    """
    Run all audit checks against a device config.
    Returns structured audit result dict.
    """
    config_lower = config_text.lower()
    findings = []

    for check in AUDIT_CHECKS:
        try:
            # Try both original and lowercased config for checks
            triggered = check["detect"](config_text) or check["detect"](config_lower)
        except Exception:
            try:
                triggered = check["detect"](config_text)
            except Exception:
                triggered = False

        if triggered:
            findings.append({
                "id":          check["id"],
                "category":    check["category"],
                "title":       check["title"],
                "description": check["description"],
                "severity":    check["severity"],
                "cve":         check.get("cve", "—"),
                "cis":         check.get("cis", "—"),
                "fix":         check["fix"],
            })

    # Sort by severity (most severe first)
    findings.sort(key=lambda f: SEVERITY_ORDER.get(f["severity"], 0), reverse=True)

    # Risk score
    raw_score = sum(SEVERITY_SCORE.get(f["severity"], 0) for f in findings)
    risk_score = min(100, raw_score)

    # Severity counts
    counts = {SEV_CRITICAL: 0, SEV_HIGH: 0, SEV_MEDIUM: 0, SEV_LOW: 0, SEV_INFO: 0}
    for f in findings:
        counts[f["severity"]] += 1

    # Risk level label
    if risk_score >= 70:   risk_level = "CRITICAL"
    elif risk_score >= 45: risk_level = "HIGH"
    elif risk_score >= 20: risk_level = "MEDIUM"
    elif risk_score >= 5:  risk_level = "LOW"
    else:                  risk_level = "SAFE"

    return {
        "device":     device_name,
        "findings":   findings,
        "score":      risk_score,
        "level":      risk_level,
        "counts":     counts,
        "total_checks": len(AUDIT_CHECKS),
        "passed":     len(AUDIT_CHECKS) - len(findings),
        "failed":     len(findings),
    }



def audit_vyos_device(hostname, config_text):
    """Security audit for VyOS firewall — 6 checks."""
    findings = []
    cfg = config_text.lower()

    # Check for plaintext-password — only flag if it's the vyos default user
    # admin user should only have encrypted-password (hashed) which is SAFE
    cfg_lines = config_text.splitlines()
    has_plaintext = False
    for i, line in enumerate(cfg_lines):
        if 'plaintext-password' in line.lower():
            # Check context — if it's the vyos user that's acceptable during install
            # but flag if it's admin user or if password looks like default 'vyos'
            context = ' '.join(cfg_lines[max(0,i-3):i+1]).lower()
            if 'user vyos' in context or 'user admin' in context:
                has_plaintext = True
                break

    if has_plaintext:
        findings.append({
            'id': 'FW-001', 'category': 'Authentication & Passwords',
            'severity': 'CRITICAL',
            'title': 'VyOS Default User Has Plaintext Password',
            'description': 'The vyos/admin user has a plaintext password stored in config. Change to a strong encrypted password.',
            'fix': 'configure; set system login user vyos authentication plaintext-password <NewPass>; commit; save',
            'cve': 'CWE-521', 'cis': 'CIS VyOS 1.1',
        })

    if 'set firewall' not in cfg:
        findings.append({
            'id': 'FW-002', 'category': 'Network Protocols & Hardening',
            'severity': 'CRITICAL',
            'title': 'No Firewall Rules Configured on VyOS',
            'description': 'No firewall rules exist — all traffic is permitted through the firewall.',
            'fix': 'set firewall ipv4 name WAN_IN default-action drop',
            'cve': 'CWE-284', 'cis': 'CIS VyOS 1.2',
        })

    if 'listen-address' not in cfg and 'set service ssh' in cfg:
        findings.append({
            'id': 'FW-003', 'category': 'Remote Access & Encryption',
            'severity': 'HIGH',
            'title': 'SSH Listening on All VyOS Interfaces',
            'description': 'SSH not restricted to management interface — exposed to all networks.',
            'fix': 'set service ssh listen-address <mgmt-ip>',
            'cve': 'CWE-668', 'cis': 'CIS VyOS 2.1',
        })

    if 'set service ntp' not in cfg:
        findings.append({
            'id': 'FW-004', 'category': 'Logging & Monitoring',
            'severity': 'MEDIUM',
            'title': 'NTP Not Configured on VyOS',
            'description': 'No NTP server — log timestamps unreliable for forensic analysis.',
            'fix': 'set service ntp server 192.168.214.100',
            'cve': '—', 'cis': 'CIS VyOS 3.1',
        })

    if 'set system syslog' not in cfg:
        findings.append({
            'id': 'FW-005', 'category': 'Logging & Monitoring',
            'severity': 'MEDIUM',
            'title': 'Syslog Not Configured on VyOS',
            'description': 'No syslog — security events not logged or forwarded.',
            'fix': 'set system syslog local facility all level info',
            'cve': '—', 'cis': 'CIS VyOS 3.2',
        })

    if 'rolling' in cfg or 'nightly' in cfg:
        findings.append({
            'id': 'FW-006', 'category': 'Network Protocols & Hardening',
            'severity': 'LOW',
            'title': 'VyOS Unstable Rolling Build in Use',
            'description': 'Running a nightly/rolling build — not recommended for production.',
            'fix': 'Use VyOS LTS stable release for production.',
            'cve': '—', 'cis': 'CIS VyOS 4.1',
        })

    # Score
    score_map = {'CRITICAL': 30, 'HIGH': 15, 'MEDIUM': 6, 'LOW': 2}
    raw = sum(score_map.get(f['severity'], 0) for f in findings)
    score = min(100, raw)
    counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0, 'INFO': 0}
    for f in findings:
        counts[f['severity']] = counts.get(f['severity'], 0) + 1

    if score >= 70:   level = 'CRITICAL'
    elif score >= 45: level = 'HIGH'
    elif score >= 20: level = 'MEDIUM'
    elif score >= 5:  level = 'LOW'
    else:             level = 'SAFE'

    return {
        'device': hostname, 'findings': findings,
        'score': score, 'level': level, 'counts': counts,
        'total_checks': 6, 'passed': 6 - len(findings), 'failed': len(findings),
    }

def audit_all_devices(config_dir: str = "network_configs") -> list:
    """
    Audit every *_config.txt file in config_dir.
    Returns list of audit result dicts, sorted by risk score (highest first).
    """
    results = []

    if not os.path.exists(config_dir):
        return results

    for filename in sorted(os.listdir(config_dir)):
        if not filename.endswith("_config.txt"):
            continue

        device_name = filename.replace("_config.txt", "")
        filepath    = os.path.join(config_dir, filename)

        try:
            with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                config_text = f.read()
        except Exception:
            continue

        # VyOS firewall uses different audit
        if device_name.upper().startswith('FW') or 'FIREWALL' in device_name.upper():
            result = audit_vyos_device(device_name, config_text)
        else:
            result = audit_device(device_name, config_text)
        results.append(result)

    results.sort(key=lambda r: r["score"], reverse=True)
    return results


def get_audit_summary(results: list) -> dict:
    """
    Compute fleet-wide summary statistics.
    """
    total_critical = sum(r["counts"][SEV_CRITICAL] for r in results)
    total_high     = sum(r["counts"][SEV_HIGH]     for r in results)
    total_medium   = sum(r["counts"][SEV_MEDIUM]   for r in results)
    total_low      = sum(r["counts"][SEV_LOW]      for r in results)
    total_findings = total_critical + total_high + total_medium + total_low
    avg_score      = int(sum(r["score"] for r in results) / len(results)) if results else 0

    categories = {}
    for result in results:
        for finding in result["findings"]:
            cat = finding["category"]
            categories[cat] = categories.get(cat, 0) + 1

    return {
        "devices":         len(results),
        "total_findings":  total_findings,
        "total_critical":  total_critical,
        "total_high":      total_high,
        "total_medium":    total_medium,
        "total_low":       total_low,
        "avg_score":       avg_score,
        "categories":      categories,
        "checks_available": len(AUDIT_CHECKS),
    }


# ─────────────────────────────────────────────────────────────────────────────
#  CLI TEST
# ─────────────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    results = audit_all_devices()
    summary = get_audit_summary(results)

    print(f"\n{'='*60}")
    print(f"  NETGUARD AUDIT ENGINE v4.0")
    print(f"  {summary['checks_available']} checks | {summary['devices']} devices | {summary['total_findings']} findings")
    print(f"{'='*60}")

    for r in results:
        bar   = "█" * (r["score"] // 5) + "░" * (20 - r["score"] // 5)
        crit  = r["counts"][SEV_CRITICAL]
        high  = r["counts"][SEV_HIGH]
        print(f"  {r['device']:<10} [{bar}] {r['score']:>3}/100 "
              f"({r['level']})  C:{crit} H:{high}")

    print(f"\n  Fleet Average Score : {summary['avg_score']}/100")
    print(f"  Total CRITICAL      : {summary['total_critical']}")
    print(f"  Total HIGH          : {summary['total_high']}")
