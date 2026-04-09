"""
Phase 2: TF-IDF + Random Forest ML Security Engine
Classifies Cisco IOS configuration lines into:
    SAFE | LOW | MEDIUM | HIGH | CRITICAL
"""
import os, re, pickle
import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline, FeatureUnion
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.metrics import accuracy_score, classification_report

MODEL_DIR  = 'ml_model'
MODEL_PATH = os.path.join(MODEL_DIR, 'cisco_security_classifier.pkl')
os.makedirs(MODEL_DIR, exist_ok=True)

RISK_LEVELS  = ['SAFE', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL']
RISK_WEIGHTS = {'SAFE': 0, 'LOW': 1, 'MEDIUM': 4, 'HIGH': 12, 'CRITICAL': 25}
RISK_BADGE   = {'SAFE': 'success', 'LOW': 'info', 'MEDIUM': 'warning',
                'HIGH': 'orange',  'CRITICAL': 'danger'}


# ─────────────────────────────────────────────────────────────────────────────
#  LABELED DATASET  (350 total data  samples across 5 risk classes)
# ─────────────────────────────────────────────────────────────────────────────
CISCO_DATASET = [
    # ── CRITICAL ──────────────────────────────────────────────────────────────
    ("no service password-encryption",                        "CRITICAL"),
    ("enable password cisco",                                 "CRITICAL"),
    ("enable password admin",                                 "CRITICAL"),
    ("enable password letmein",                               "CRITICAL"),
    ("enable password router",                                "CRITICAL"),
    ("enable password password",                              "CRITICAL"),
    ("enable password 12345",                                 "CRITICAL"),
    ("enable password network",                               "CRITICAL"),
    ("enable password default",                               "CRITICAL"),
    ("enable password secret123",                             "CRITICAL"),
    ("transport input telnet",                                "CRITICAL"),
    ("transport input all",                                   "CRITICAL"),
    ("transport input telnet ssh",                            "CRITICAL"),
    ("transport input telnet rlogin",                         "CRITICAL"),
    ("ip http server",                                        "CRITICAL"),
    ("ip http server port 80",                                "CRITICAL"),
    ("snmp-server community public RO",                       "CRITICAL"),
    ("snmp-server community private RW",                      "CRITICAL"),
    ("snmp-server community admin RW",                        "CRITICAL"),
    ("snmp-server community cisco RW",                        "CRITICAL"),
    ("snmp-server community test RW",                         "CRITICAL"),
    ("snmp-server community monitor RW",                      "CRITICAL"),
    ("snmp-server community read RO",                         "CRITICAL"),
    ("snmp-server community write RW",                        "CRITICAL"),
    ("snmp-server community network RW",                      "CRITICAL"),
    ("username admin password 0 cisco",                       "CRITICAL"),
    ("username cisco password 0 cisco",                       "CRITICAL"),
    ("username admin password cisco",                         "CRITICAL"),
    ("username guest password 0 guest",                       "CRITICAL"),
    ("username operator password 0 operator",                 "CRITICAL"),
    ("username root password 0 root",                         "CRITICAL"),
    ("username admin password 0 P@ssw0rd",                    "CRITICAL"),
    ("username admin privilege 15 password 0 cisco",          "CRITICAL"),
    ("username admin privilege 15 password 0 admin",          "CRITICAL"),
    ("no login",                                              "CRITICAL"),
    ("password cisco",                                        "CRITICAL"),
    ("password admin",                                        "CRITICAL"),
    ("password router",                                       "CRITICAL"),
    ("password password123",                                  "CRITICAL"),
    ("service tcp-small-servers",                             "CRITICAL"),
    ("service udp-small-servers",                             "CRITICAL"),
    ("service finger",                                        "CRITICAL"),
    ("ip bootp server",                                       "CRITICAL"),
    ("ip identd",                                             "CRITICAL"),
    ("ip source-route",                                       "CRITICAL"),
    ("ip rcmd rcp-enable",                                    "CRITICAL"),
    ("ip rcmd rsh-enable",                                    "CRITICAL"),
    ("tftp-server flash",                                     "CRITICAL"),
    ("service config",                                        "CRITICAL"),
    ("ip ftp username anonymous",                             "CRITICAL"),
    ("ip ftp password anonymous",                             "CRITICAL"),

    # ── HIGH ──────────────────────────────────────────────────────────────────
    ("exec-timeout 0 0",                                      "HIGH"),
    ("exec-timeout 0",                                        "HIGH"),
    ("ip ssh version 1",                                      "HIGH"),
    ("no logging buffered",                                   "HIGH"),
    ("no logging",                                            "HIGH"),
    ("no service timestamps log",                             "HIGH"),
    ("no service timestamps debug",                           "HIGH"),
    ("no service timestamps",                                 "HIGH"),
    ("no banner motd",                                        "HIGH"),
    ("no banner login",                                       "HIGH"),
    ("no banner exec",                                        "HIGH"),
    ("debug ip packet",                                       "HIGH"),
    ("debug all",                                             "HIGH"),
    ("no ip ssh",                                             "HIGH"),
    ("logging console debugging",                             "HIGH"),
    ("no aaa new-model",                                      "HIGH"),
    ("no aaa authentication login default",                   "HIGH"),
    ("permit any any",                                        "HIGH"),
    ("ip access-list permit any",                             "HIGH"),
    ("no logging trap",                                       "HIGH"),
    ("ip proxy-arp",                                          "HIGH"),
    ("no ip verify unicast source reachable-via",             "HIGH"),
    ("no ip dhcp snooping",                                   "HIGH"),
    ("no ip arp inspection",                                   "HIGH"),
    ("no storm-control",                                      "HIGH"),
    ("snmp-server traps enable",                              "HIGH"),
    ("exec-timeout 120 0",                                    "HIGH"),
    ("no aaa authorization",                                  "HIGH"),
    ("no aaa accounting",                                     "HIGH"),
    ("access-list 100 permit ip any any",                     "HIGH"),
    ("access-list 1 permit any",                              "HIGH"),
    ("ip http secure-server",                                 "HIGH"),
    ("no ip access-group",                                    "HIGH"),
    ("no ntp server",                                         "HIGH"),
    ("no service timestamps log datetime",                    "HIGH"),
    ("no service timestamps debug datetime",                  "HIGH"),
    ("debug ip routing",                                      "HIGH"),
    ("debug eigrp packets",                                   "HIGH"),
    ("exec-timeout 480 0",                                    "HIGH"),
    ("no logging console",                                    "HIGH"),
    ("logging facility local0",                               "HIGH"),
    ("no ip domain-name",                                     "HIGH"),
    ("no aaa authentication enable default",                  "HIGH"),
    ("ip unnumbered",                                         "HIGH"),
    ("no banner",                                             "HIGH"),

    # ── MEDIUM ────────────────────────────────────────────────────────────────
    ("ip redirects",                                          "MEDIUM"),
    ("ip unreachables",                                       "MEDIUM"),
    ("ip mask-reply",                                         "MEDIUM"),
    ("cdp enable",                                            "MEDIUM"),
    ("cdp run",                                               "MEDIUM"),
    ("ip directed-broadcast",                                 "MEDIUM"),
    ("no ip cef",                                             "MEDIUM"),
    ("duplex half",                                           "MEDIUM"),
    ("ip helper-address 255.255.255.255",                     "MEDIUM"),
    ("exec-timeout 30 0",                                     "MEDIUM"),
    ("no spanning-tree portfast bpduguard",                   "MEDIUM"),
    ("spanning-tree portfast",                                "MEDIUM"),
    ("no port-security",                                      "MEDIUM"),
    ("switchport mode dynamic",                               "MEDIUM"),
    ("vlan 1",                                                "MEDIUM"),
    ("interface vlan 1",                                      "MEDIUM"),
    ("no switchport nonegotiate",                             "MEDIUM"),
    ("no ip tcp intercept",                                   "MEDIUM"),
    ("lldp run",                                              "MEDIUM"),
    ("logging buffered 4096",                                 "MEDIUM"),
    ("no ntp",                                                "MEDIUM"),
    ("no clock timezone",                                     "MEDIUM"),
    ("no ip source guard",                                    "MEDIUM"),
    ("ip nat inside source static 0.0.0.0 0.0.0.0",          "MEDIUM"),
    ("no ip domain-lookup",                                   "MEDIUM"),
    ("ip nat overload",                                       "MEDIUM"),
    ("ip helper-address 10.10.0.1",                           "MEDIUM"),
    ("cdp advertise-v2",                                      "MEDIUM"),
    ("lldp transmit",                                         "MEDIUM"),
    ("lldp receive",                                          "MEDIUM"),
    ("no spanning-tree bpduguard",                            "MEDIUM"),
    ("switchport mode trunk",                                 "MEDIUM"),
    ("switchport trunk native vlan 1",                        "MEDIUM"),
    ("no ip arp proxy",                                       "MEDIUM"),
    ("exec-timeout 60 0",                                     "MEDIUM"),
    ("no dhcp snooping",                                      "MEDIUM"),
    ("no dynamic arp inspection",                             "MEDIUM"),

    # ── LOW ───────────────────────────────────────────────────────────────────
    ("no ip domain lookup",                                   "LOW"),
    ("no mop enabled",                                        "LOW"),
    ("no mop sysid",                                          "LOW"),
    ("no ip split-horizon",                                   "LOW"),
    ("no auto-summary",                                       "LOW"),
    ("no keepalive",                                          "LOW"),
    ("media-type rj45",                                       "LOW"),
    ("no fair-queue",                                         "LOW"),
    ("no queue-limit",                                        "LOW"),
    ("passive-interface default",                             "LOW"),
    ("encapsulation dot1Q 1 native",                          "LOW"),
    ("bandwidth 100000",                                      "LOW"),
    ("delay 100",                                             "LOW"),
    ("no cdp log mismatch duplex",                            "LOW"),
    ("no ip route-cache",                                     "LOW"),
    ("no ip mroute-cache",                                    "LOW"),
    ("no ip address",                                         "LOW"),
    ("speed auto",                                            "LOW"),
    ("duplex auto",                                           "LOW"),
    ("shutdown",                                              "LOW"),
    ("no shutdown",                                           "LOW"),
    ("redistribute connected subnets",                        "LOW"),
    ("redistribute static",                                   "LOW"),
    ("default-information originate",                         "LOW"),
    ("no ip forward-protocol nd",                             "LOW"),
    ("no ip ospf dead-interval",                              "LOW"),

    # ── SAFE ──────────────────────────────────────────────────────────────────
    ("hostname R1",                                           "SAFE"),
    ("hostname R2",                                           "SAFE"),
    ("hostname SW1",                                          "SAFE"),
    ("hostname Firewall",                                     "SAFE"),
    ("interface FastEthernet0/0",                             "SAFE"),
    ("interface GigabitEthernet0/0",                          "SAFE"),
    ("interface FastEthernet1/1",                             "SAFE"),
    ("interface Loopback0",                                   "SAFE"),
    ("ip address 192.168.1.1 255.255.255.0",                  "SAFE"),
    ("ip address 10.10.1.1 255.255.255.252",                  "SAFE"),
    ("ip address 172.16.0.1 255.255.0.0",                     "SAFE"),
    ("router ospf 1",                                         "SAFE"),
    ("router bgp 65001",                                      "SAFE"),
    ("router eigrp 100",                                      "SAFE"),
    ("network 192.168.1.0 0.0.0.255 area 0",                  "SAFE"),
    ("network 10.0.0.0 0.255.255.255 area 0",                 "SAFE"),
    ("enable secret 5 $1$abc$hashvalue",                      "SAFE"),
    ("enable secret 9 $9$abc$hashvalue",                      "SAFE"),
    ("service password-encryption",                           "SAFE"),
    ("transport input ssh",                                   "SAFE"),
    ("transport input none",                                  "SAFE"),
    ("no ip http server",                                     "SAFE"),
    ("no ip http secure-server",                              "SAFE"),
    ("ip ssh version 2",                                      "SAFE"),
    ("ip ssh time-out 60",                                    "SAFE"),
    ("ip ssh authentication-retries 3",                       "SAFE"),
    ("logging buffered 16384",                                "SAFE"),
    ("logging host 192.168.1.100",                            "SAFE"),
    ("service timestamps log datetime msec",                  "SAFE"),
    ("service timestamps debug datetime msec",                "SAFE"),
    ("no ip source-route",                                    "SAFE"),
    ("no ip bootp server",                                    "SAFE"),
    ("no service tcp-small-servers",                          "SAFE"),
    ("no service udp-small-servers",                          "SAFE"),
    ("no service finger",                                     "SAFE"),
    ("no ip identd",                                          "SAFE"),
    ("no ip rcmd rcp-enable",                                 "SAFE"),
    ("no ip rcmd rsh-enable",                                 "SAFE"),
    ("no snmp-server",                                        "SAFE"),
    ("login local",                                           "SAFE"),
    ("login block-for 120 attempts 5 within 60",              "SAFE"),
    ("banner motd ^ Authorized access only ^",                "SAFE"),
    ("banner login ^ Unauthorized access prohibited ^",       "SAFE"),
    ("no ip proxy-arp",                                       "SAFE"),
    ("no ip redirects",                                       "SAFE"),
    ("no ip unreachables",                                    "SAFE"),
    ("no ip mask-reply",                                      "SAFE"),
    ("no cdp enable",                                         "SAFE"),
    ("no cdp run",                                            "SAFE"),
    ("no lldp transmit",                                      "SAFE"),
    ("no lldp receive",                                       "SAFE"),
    ("spanning-tree portfast bpduguard default",              "SAFE"),
    ("ip dhcp snooping",                                      "SAFE"),
    ("ip dhcp snooping vlan 10,20",                           "SAFE"),
    ("ip arp inspection vlan 10,20",                          "SAFE"),
    ("version 15.3",                                          "SAFE"),
    ("aaa new-model",                                         "SAFE"),
    ("aaa authentication login default local",                "SAFE"),
    ("aaa authorization exec default local",                  "SAFE"),
    ("redundancy",                                            "SAFE"),
    ("ip cef",                                                "SAFE"),
    ("no ipv6 cef",                                           "SAFE"),
    ("ntp server 192.168.1.1",                                "SAFE"),
    ("ntp server pool.ntp.org",                               "SAFE"),
    ("clock timezone EST -5",                                 "SAFE"),
    ("username admin privilege 15 secret 5 $1$abc$xyz",       "SAFE"),
    ("username operator privilege 5 secret 5 $1$def$xyz",     "SAFE"),
    ("crypto key generate rsa modulus 2048",                  "SAFE"),
    ("access-class MGMT_ACCESS in",                           "SAFE"),
    ("ip access-group OUTSIDE_IN in",                         "SAFE"),
    ("encapsulation dot1Q 10",                                "SAFE"),
    ("encapsulation dot1Q 20",                                "SAFE"),
    ("ip nat inside",                                         "SAFE"),
    ("ip nat outside",                                        "SAFE"),
    ("end",                                                   "SAFE"),
    ("!",                                                     "SAFE"),
    ("building configuration",                                "SAFE"),
    ("current configuration",                                 "SAFE"),
    ("boot-start-marker",                                     "SAFE"),
    ("boot-end-marker",                                       "SAFE"),
    ("upgrade fpd auto",                                      "SAFE"),
    ("ip domain name lab.local",                              "SAFE"),
    ("multilink bundle-name authenticated",                   "SAFE"),
    ("no ip icmp rate-limit unreachable",                     "SAFE"),
    ("exec-timeout 5 0",                                      "SAFE"),
    ("exec-timeout 10 0",                                     "SAFE"),
    ("privilege level 15",                                    "SAFE"),
    ("logging synchronous",                                   "SAFE"),
    ("stopbits 1",                                            "SAFE"),
    ("length 0",                                              "SAFE"),
    ("description MANAGEMENT_TO_UBUNTU",                      "SAFE"),
    ("description WAN_LINK",                                  "SAFE"),
    ("ip route 0.0.0.0 0.0.0.0 192.168.1.1",                 "SAFE"),
    ("ip forward-protocol nd",                                "SAFE"),
    ("aqm-register-fnf",                                      "SAFE"),
    ("gatekeeper shutdown",                                   "SAFE"),
    ("mgcp profile default",                                  "SAFE"),

    # ── EXPANDED DATASET (patch11) ────────────────────────────────────────────

    # More CRITICAL — BGP/OSPF no auth
    ("router ospf 1",                                          "MEDIUM"),
    ("router bgp 65001",                                       "SAFE"),
    ("neighbor 10.10.1.1 remote-as 65002",                     "SAFE"),
    ("no area 0 authentication",                               "CRITICAL"),
    ("no ip ospf authentication",                              "CRITICAL"),
    ("ip ospf authentication-key cisco",                       "CRITICAL"),
    ("area 0 authentication",                                  "SAFE"),
    ("ip ospf message-digest-key 1 md5 cisco123",              "HIGH"),
    ("neighbor 10.1.1.1 password cisco",                       "HIGH"),
    ("no bgp default ipv4-unicast",                            "SAFE"),

    # More CRITICAL — weak/cleartext
    ("username netadmin password 0 netadmin",                  "CRITICAL"),
    ("username sysadmin password 7 0822455D0A16",              "CRITICAL"),
    ("enable password 0 cisco123",                             "CRITICAL"),
    ("line vty 0 4",                                           "SAFE"),
    ("line con 0",                                             "SAFE"),
    ("password 7 0822455D0A16",                                "CRITICAL"),
    ("snmp-server community netguard RW",                      "CRITICAL"),
    ("snmp-server community management RO",                    "HIGH"),
    ("snmp-server community secret123 RW",                     "CRITICAL"),
    ("ip ftp username cisco",                                  "CRITICAL"),
    ("ip ftp password cisco",                                  "CRITICAL"),

    # More HIGH — access control
    ("access-list 10 permit any",                              "HIGH"),
    ("access-list 99 permit any",                              "HIGH"),
    ("ip access-list standard ANY_PERMIT",                     "HIGH"),
    ("permit ip 0.0.0.0 255.255.255.255 any",                  "HIGH"),
    ("no ip access-class",                                     "HIGH"),
    ("exec-timeout 1440 0",                                    "HIGH"),
    ("exec-timeout 999 0",                                     "HIGH"),
    ("no login local",                                         "HIGH"),
    ("no ip domain lookup",                                    "MEDIUM"),
    ("no ip domain-lookup",                                    "MEDIUM"),

    # More HIGH — logging/monitoring
    ("no logging on",                                          "HIGH"),
    ("no logging host",                                        "HIGH"),
    ("logging 0.0.0.0",                                        "HIGH"),
    ("no snmp-server trap",                                    "HIGH"),
    ("no ip sla",                                              "MEDIUM"),
    ("no archive",                                             "MEDIUM"),

    # More MEDIUM — L2 security
    ("switchport trunk native vlan 1",                         "MEDIUM"),
    ("switchport mode dynamic desirable",                      "MEDIUM"),
    ("switchport mode dynamic auto",                           "MEDIUM"),
    ("no switchport port-security",                            "MEDIUM"),
    ("no spanning-tree guard root",                            "MEDIUM"),
    ("spanning-tree portfast trunk",                           "MEDIUM"),
    ("no vlan filter",                                         "MEDIUM"),
    ("vtp mode transparent",                                   "MEDIUM"),
    ("vtp mode server",                                        "MEDIUM"),
    ("vtp password",                                           "SAFE"),
    ("vtp version 3",                                          "SAFE"),

    # More SAFE — hardened config
    ("username admin privilege 15 secret 9 $9$xyz",            "SAFE"),
    ("username operator privilege 5 secret 5 $1$abc$xyz",      "SAFE"),
    ("ip ssh source-interface Loopback0",                      "SAFE"),
    ("ip ssh logging events",                                  "SAFE"),
    ("ip ssh stricthostkeycheck",                              "SAFE"),
    ("no ip http secure-server",                               "SAFE"),
    ("ip access-class MGMT in",                                "SAFE"),
    ("access-class 10 in",                                     "SAFE"),
    ("logging source-interface Loopback0",                     "SAFE"),
    ("logging trap notifications",                             "SAFE"),
    ("logging buffered 65536",                                 "SAFE"),
    ("archive log config",                                     "SAFE"),
    ("logging userinfo",                                       "SAFE"),
    ("security passwords min-length 8",                        "SAFE"),
    ("security authentication failure rate 5 log",             "SAFE"),
    ("login delay 3",                                          "SAFE"),
    ("login on-failure log",                                   "SAFE"),
    ("login on-success log",                                   "SAFE"),
    ("no vstack",                                              "SAFE"),
    ("no ip bootp server",                                     "SAFE"),
    ("spanning-tree bpduguard enable",                         "SAFE"),
    ("spanning-tree guard root",                               "SAFE"),
    ("storm-control broadcast level 10",                       "SAFE"),
    ("storm-control action shutdown",                          "SAFE"),
    ("ip dhcp snooping trust",                                 "SAFE"),
    ("ip arp inspection trust",                                 "SAFE"),
    ("ip verify source",                                       "SAFE"),
    ("dot1x system-auth-control",                              "SAFE"),
    ("authentication port-control auto",                       "SAFE"),

    # More VyOS firewall
    ("set firewall ipv4 forward filter default-action drop",   "SAFE"),
    ("set firewall ipv4 input filter default-action drop",     "SAFE"),
    ("set firewall group network-group RFC1918",                "SAFE"),
    ("set firewall ipv4 name WAN_IN rule 10 protocol tcp",     "SAFE"),
    ("set system login user admin authentication plaintext-password admin", "CRITICAL"),
    ("set service telnet listen-address 0.0.0.0",              "CRITICAL"),
    ("set nat source rule 100 translation address masquerade", "MEDIUM"),
    ("set system ntp server pool.ntp.org",                     "SAFE"),
    ("set system syslog host 192.168.1.100 facility all",      "SAFE"),
    ("set service ssh disable-password-authentication",        "SAFE"),
    ("set firewall state-policy established action accept",    "SAFE"),
    ("set firewall state-policy related action accept",        "SAFE"),
    ("set firewall state-policy invalid action drop",          "SAFE"),
    ("set system login banner pre-login",                      "SAFE"),
    ("set firewall ipv4 name WAN_IN rule 999 action drop",     "SAFE"),
    ("set system option ctrl-alt-delete disabled",             "SAFE"),
    ("set service ssh access-control allow user admin",        "SAFE"),
    ("set system login user admin authentication plaintext-password vyos123", "CRITICAL"),
    ("set service dns forwarding allow-from 0.0.0.0/0",        "HIGH"),
    ("set service dns forwarding listen-address 0.0.0.0",      "HIGH"),

    # VyOS Firewall lines
    ("set system login user admin authentication plaintext-password vyos", "CRITICAL"),
    ("set service telnet", "CRITICAL"),
    ("set firewall ipv4 name WAN_IN default-action accept", "CRITICAL"),
    ("set service http port 80", "HIGH"),
    ("set service ssh listen-address 0.0.0.0", "HIGH"),
    ("set firewall name WAN_IN default-action accept", "HIGH"),
    ("rolling nightly build unstable", "MEDIUM"),
    ("set system syslog global facility all level err", "MEDIUM"),
    ("set firewall ipv4 name WAN_IN default-action drop", "SAFE"),
    ("set firewall ipv4 name WAN_IN rule 10 action accept", "SAFE"),
    ("set firewall ipv4 name WAN_IN rule 10 state established", "SAFE"),
    ("set service ssh port 22", "SAFE"),
    ("set service ssh listen-address 192.168.214.3", "SAFE"),
    ("set system login user admin authentication encrypted-password", "SAFE"),
    ("set system syslog local facility all level info", "SAFE"),
    ("set system host-name FW1", "SAFE"),
    ("mgcp behavior rsip-range tgcp-only",                    "SAFE"),
    ("ip tcp synwait-time 5",                                 "SAFE"),
    ("no ip http server",                                     "SAFE"),
    ("no cdp log mismatch duplex",                            "SAFE"),
]


# ─────────────────────────────────────────────────────────────────────────────
#  MODEL TRAINING
# ─────────────────────────────────────────────────────────────────────────────
def train_model(verbose=True):
    """Train TF-IDF + Random Forest pipeline and persist to disk."""
    lines, labels = zip(*CISCO_DATASET)

    X_train, X_test, y_train, y_test = train_test_split(
        lines, labels, test_size=0.2, random_state=42, stratify=labels
    )

    feature_union = FeatureUnion([
        ('word', TfidfVectorizer(
            analyzer='word',
            ngram_range=(1, 3),
            max_features=8000,
            sublinear_tf=True,
            token_pattern=r'(?u)\b\w[\w.-]*\b',
        )),
        ('char', TfidfVectorizer(
            analyzer='char_wb',
            ngram_range=(3, 6),
            max_features=8000,
            sublinear_tf=True,
        )),
    ])

    pipeline = Pipeline([
        ('features', feature_union),
        ('clf', RandomForestClassifier(
            n_estimators=600,
            max_depth=None,
            class_weight='balanced',
            min_samples_leaf=1,
            max_features='sqrt',
            random_state=42,
            n_jobs=-1,
        )),
    ])

    pipeline.fit(X_train, y_train)
    y_pred = pipeline.predict(X_test)

    acc = accuracy_score(y_test, y_pred)

    if verbose:
        print("\n" + "="*55)
        print("  📊 ML MODEL TRAINING COMPLETE")
        print("="*55)
        print(f"  Dataset : {len(lines)} labeled config lines")
        print(f"  Train   : {len(X_train)} | Test : {len(X_test)}")
        print(f"  Accuracy: {acc*100:.1f}%")
        print("="*55)
        print(classification_report(y_test, y_pred,
                                    target_names=RISK_LEVELS, zero_division=0))

    with open(MODEL_PATH, 'wb') as f:
        pickle.dump(pipeline, f)

    return pipeline, acc


def load_model():
    """Load the trained model from disk."""
    if not os.path.exists(MODEL_PATH):
        return None
    with open(MODEL_PATH, 'rb') as f:
        return pickle.load(f)


def ensure_model_trained(verbose=True):
    """Train the model if it doesn't exist yet; return the pipeline."""
    model = load_model()
    if model is None:
        if verbose:
            print("🤖 No existing model found. Training now...")
        model, _ = train_model(verbose=verbose)
    return model


# ─────────────────────────────────────────────────────────────────────────────
#  RULE-BASED OVERRIDE ENGINE
#  Applied after ML classification to catch definitive patterns the RF may miss
# ─────────────────────────────────────────────────────────────────────────────
import re as _re

_RULES = [
    # (compiled_pattern, forced_risk, confidence)
    # ── CRITICAL overrides ──
    (_re.compile(r'^no service password-encryption'),          'CRITICAL', 0.99),
    (_re.compile(r'^enable password\s+\S'),                    'CRITICAL', 0.99),
    (_re.compile(r'^transport input.*(telnet|all)\b'),         'CRITICAL', 0.99),
    (_re.compile(r'^ip http server($|\s)'),                    'CRITICAL', 0.99),
    (_re.compile(r'^snmp-server community\s+\S+\s+RW'),        'CRITICAL', 0.98),
    (_re.compile(r'^snmp-server community\s+(public|private)'), 'CRITICAL', 0.98),
    (_re.compile(r'^username\s+\S+\s+password\s+[07]?\s*\S'),  'CRITICAL', 0.97),
    (_re.compile(r'^password\s+\S'),                           'CRITICAL', 0.95),
    (_re.compile(r'^no login$'),                               'CRITICAL', 0.99),
    (_re.compile(r'^service (tcp|udp)-small-servers'),         'CRITICAL', 0.99),
    (_re.compile(r'^service finger'),                          'CRITICAL', 0.99),
    (_re.compile(r'^ip bootp server'),                         'CRITICAL', 0.99),
    (_re.compile(r'^ip source-route'),                         'CRITICAL', 0.99),
    (_re.compile(r'^ip rcmd (rcp|rsh)-enable'),                'CRITICAL', 0.99),
    (_re.compile(r'^tftp-server'),                             'CRITICAL', 0.99),
    (_re.compile(r'^ip identd'),                               'CRITICAL', 0.98),
    # ── HIGH overrides ──
    (_re.compile(r'^exec-timeout 0'),                          'HIGH', 0.97),
    (_re.compile(r'^exec-timeout [1-9]\d\d'),                  'HIGH', 0.90),
    (_re.compile(r'^ip ssh version 1'),                        'HIGH', 0.99),
    (_re.compile(r'^no (logging buffered|logging$)'),          'HIGH', 0.95),
    (_re.compile(r'^no service timestamps'),                   'HIGH', 0.95),
    (_re.compile(r'^no banner'),                               'HIGH', 0.95),
    (_re.compile(r'^debug (all|ip|ospf|eigrp|bgp)'),           'HIGH', 0.95),
    (_re.compile(r'^no ip ssh'),                               'HIGH', 0.95),
    (_re.compile(r'^no aaa (new-model|authentication|authorization|accounting)'), 'HIGH', 0.92),
    # ── MEDIUM overrides ──
    (_re.compile(r'^cdp (run|enable|advertise)'),              'MEDIUM', 0.88),
    (_re.compile(r'^lldp (run|transmit|receive)'),             'MEDIUM', 0.88),
    (_re.compile(r'^ip (redirects|unreachables|mask-reply|directed-broadcast)'), 'MEDIUM', 0.90),
    (_re.compile(r'^ip proxy-arp'),                            'HIGH', 0.90),
    (_re.compile(r'^access-list\s+\d+\s+permit\s+(any|ip any)'), 'HIGH', 0.92),
    (_re.compile(r'^permit any any'),                          'HIGH', 0.95),
    # -- VyOS FIREWALL overrides --
    (_re.compile(r'set firewall.*default-action accept'),   'CRITICAL', 0.98),
    (_re.compile(r'set service telnet'),                     'CRITICAL', 0.99),
    (_re.compile(r'plaintext-password (vyos|admin|cisco)'), 'CRITICAL', 0.99),
    (_re.compile(r'set firewall.*default-action drop'),      'SAFE',     0.99),
    (_re.compile(r'set firewall.*state established'),        'SAFE',     0.99),
    # -- VyOS specific SAFE overrides --
    (_re.compile(r'encrypted-password'),                       'SAFE',     0.99),
    (_re.compile(r'^service \{'),                             'SAFE',     0.99),
    (_re.compile(r'^\}'),                                     'SAFE',     0.99),
    (_re.compile(r'set firewall ipv4.*default-action drop'),   'SAFE',     0.99),
    (_re.compile(r'set service ssh listen-address \d'),       'SAFE',     0.99),
    (_re.compile(r'set system host-name'),                     'SAFE',     0.99),
    (_re.compile(r'set interfaces ethernet'),                  'SAFE',     0.95),
    # -- SAFE overrides (force-SAFE for explicit hardening lines) ──
    (_re.compile(r'^no ip http server'),                       'SAFE', 0.99),
    (_re.compile(r'^transport input ssh$'),                    'SAFE', 0.99),
    (_re.compile(r'^transport input none$'),                   'SAFE', 0.99),
    (_re.compile(r'^ip ssh version 2'),                        'SAFE', 0.99),
    (_re.compile(r'^service password-encryption'),             'SAFE', 0.99),
    (_re.compile(r'^enable secret [059]'),                     'SAFE', 0.99),
    (_re.compile(r'^no ip source-route'),                      'SAFE', 0.99),
    (_re.compile(r'^no ip bootp server'),                      'SAFE', 0.99),
    (_re.compile(r'^no service (tcp|udp)-small-servers'),      'SAFE', 0.99),
    (_re.compile(r'^no ip proxy-arp'),                         'SAFE', 0.99),
    (_re.compile(r'^no ip redirects'),                         'SAFE', 0.99),
    (_re.compile(r'^no ip unreachables'),                      'SAFE', 0.99),
    (_re.compile(r'^login local'),                             'SAFE', 0.99),
    (_re.compile(r'^no snmp-server$'),                         'SAFE', 0.99),
]

def _rule_override(line: str):
    """Return (risk, confidence) if a rule matches, else None."""
    s = line.strip().lower()
    for pat, risk, conf in _RULES:
        if pat.search(s):
            return risk, conf
    return None


# ─────────────────────────────────────────────────────────────────────────────
#  INFERENCE
# ─────────────────────────────────────────────────────────────────────────────
def preprocess_line(line: str) -> str:
    """Normalise a config line for classification."""
    return line.strip().lower()


def classify_line(model, line: str) -> dict:
    """
    Classify a single config line.
    Rule-based engine takes priority; ML fills in the rest.
    Returns {line, risk, confidence, method}.
    """
    cleaned = preprocess_line(line)
    if not cleaned or cleaned.startswith('!'):
        return {'line': line, 'risk': 'SAFE', 'confidence': 1.0, 'method': 'rule'}

    # Rule-based first
    override = _rule_override(cleaned)
    if override:
        risk, conf = override
        return {'line': line, 'risk': risk, 'confidence': conf, 'method': 'rule'}

    # ML fallback
    proba   = model.predict_proba([cleaned])[0]
    classes = model.classes_
    idx     = np.argmax(proba)
    risk    = classes[idx]
    conf    = float(proba[idx])
    return {'line': line, 'risk': risk, 'confidence': round(conf, 3), 'method': 'ml'}


def analyze_config(config_text: str, model=None) -> list:
    """
    Analyse every line of a device config.
    Returns list of {line, risk, confidence} dicts.
    Only returns lines with risk != SAFE (plus lines classified SAFE but
    explicitly interesting).
    """
    if model is None:
        model = ensure_model_trained(verbose=False)

    results = []
    for raw_line in config_text.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        result = classify_line(model, line)
        results.append(result)
    return results


def compute_risk_score(analysis: list) -> dict:
    """
    Compute an overall 0–100 risk score from analysis results.
    Returns {score, level, counts}.
    """
    counts = {r: 0 for r in RISK_LEVELS}
    for item in analysis:
        counts[item['risk']] += 1

    raw = (counts['CRITICAL'] * RISK_WEIGHTS['CRITICAL'] +
           counts['HIGH']     * RISK_WEIGHTS['HIGH']     +
           counts['MEDIUM']   * RISK_WEIGHTS['MEDIUM']   +
           counts['LOW']      * RISK_WEIGHTS['LOW'])

    score = min(100, raw)

    if score >= 70:
        level = 'CRITICAL'
    elif score >= 45:
        level = 'HIGH'
    elif score >= 25:
        level = 'MEDIUM'
    elif score >= 10:
        level = 'LOW'
    else:
        level = 'SAFE'

    return {'score': score, 'level': level, 'counts': counts}


# ─────────────────────────────────────────────────────────────────────────────
#  BATCH ANALYSIS (all devices in network_configs/)
# ─────────────────────────────────────────────────────────────────────────────
def analyze_all_devices(config_dir='network_configs') -> list:
    """
    Run ML analysis on every *_config.txt file.
    Returns list of device result dicts.
    """
    model = ensure_model_trained(verbose=False)
    results = []

    if not os.path.exists(config_dir):
        return results

    for filename in sorted(os.listdir(config_dir)):
        if not filename.endswith('_config.txt'):
            continue
        device_name = filename.replace('_config.txt', '')
        filepath    = os.path.join(config_dir, filename)

        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                config_text = f.read()
        except Exception:
            continue

        analysis  = analyze_config(config_text, model)
        risk_data = compute_risk_score(analysis)

        # Separate flagged lines (HIGH / CRITICAL) for display
        flagged = [a for a in analysis if a['risk'] in ('HIGH', 'CRITICAL')]
        notable = [a for a in analysis if a['risk'] == 'MEDIUM']

        results.append({
            'device':   device_name,
            'score':    risk_data['score'],
            'level':    risk_data['level'],
            'counts':   risk_data['counts'],
            'flagged':  flagged,
            'notable':  notable,
            'total_lines': len(analysis),
        })

    # Sort by score descending
    results.sort(key=lambda x: x['score'], reverse=True)
    return results


# ─────────────────────────────────────────────────────────────────────────────
#  CLI ENTRY-POINT  (for standalone testing)
# ─────────────────────────────────────────────────────────────────────────────
if __name__ == '__main__':
    print("🚀 Training ML model...")
    train_model(verbose=True)
    print(f"\n✅ Model saved → {MODEL_PATH}")

    print("\n🔍 Running analysis on network_configs/ ...")
    results = analyze_all_devices()
    for r in results:
        bar = '█' * (r['score'] // 5) + '░' * (20 - r['score'] // 5)
        print(f"  {r['device']:<10} [{bar}] {r['score']:>3}/100  ({r['level']})")
