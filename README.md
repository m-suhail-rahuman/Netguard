# NetGuard 
### AI-Driven Automated Network Configuration, Topology Mapping & Security Assessment System

> Final Year Project — 2026


---

## What is NetGuard?

NetGuard is a full-stack network security monitoring system that automatically discovers, audits, and monitors Cisco network devices in real time. It combines machine learning, automated remediation, and live alerting into a single dashboard.

---

## Features

| Feature | Description |
|---|---|
| 🔴 Live Monitor | Real-time ICMP+TCP+SNMP 4-layer device health check every 60s |
| 🛡️ Security Audit | 40 checks aligned with CIS Benchmark v4.1 and NIST SP 800-115 |
| 🤖 ML Risk Engine | TF-IDF + Random Forest hybrid classifier for threat detection |
| 🗺️ Live Topology | Auto-discovered network map via OSPF + ARP + CDP |
| ⚡ Auto-Remediation | Applies Cisco IOS fix commands automatically via SSH/Telnet |
| 📧 Email Alerts | Automatic alerts for device down, config changes, and scan reports |
| 💾 Config History | MD5 hash-based change detection with version diff viewer |
| 📊 PDF Export | Full security report generation with ReportLab |

---

## Tech Stack

- **Backend:** Python, Flask, Netmiko, Paramiko, PySnmp
- **Frontend:** HTML, CSS, JavaScript, Cytoscape.js
- **Database:** SQLite
- **ML:** scikit-learn (TF-IDF + Random Forest)
- **Network Lab:** GNS3 with Cisco c7200, 3725, VyOS
- **Protocols:** SSH, Telnet, SNMP, OSPF, ICMP

---

## Lab Topology **Devices tested:**
- 4x Cisco Routers (c7200 / 3725)
- 2x Cisco Switches
- 1x VyOS Firewall

## 🏗️ Lab Setup & Prerequisites

To run this demonstration, you need a virtualized network environment.

### 💿 Download Requirements
* **GNS3 Network Emulator:** [Download GNS3 (v3.0+)](https://www.gns3.com/software/download)
* **Ubuntu (Control Node):** [Download Ubuntu Server 24.04 LTS](https://ubuntu.com/download/server) (Used to host the Flask app and ML engine)
* **Cisco IOS Images:** You will need your own `c7200` or `3725` binary images (due to licensing) to import into GNS3.

### 🛠️ GNS3 Lab Creation
1.  **Import Devices:** Add your Cisco IOS images and a VyOS appliance to the GNS3 marketplace.
2.  **Topology:** Connect 4x Cisco Routers and 1x VyOS Firewall as defined in your project topology.
3.  **Connectivity:** Connect your Ubuntu Control Node to the same management cloud/switch in GNS3 so it can reach the router IPs (e.g., `10.10.4.2`).

### 🔑 Basic Device Configuration (Cisco)
To allow NetGuard to audit and remediate your lab routers, they **must** have SSH and SNMP enabled:
```bash
conf t
hostname R4
ip domain-name lab.local
crypto key generate rsa modulus 2048
username admin privilege 15 password cisco
line vty 0 4
  transport input ssh
  login local
exit
# Enable SNMP for monitoring
snmp-server community public RO
```

---

### 3. Quick Download Summary Table
| Component | Official Link | Purpose |
| :--- | :--- | :--- |
| **GNS3** | [gns3.com/software](https://www.gns3.com/software/download) | Network Emulation |
| **Ubuntu** | [ubuntu.com/download](https://ubuntu.com/download) | Hosting Backend/ML |
| **VyOS** | [vyos.io/rolling-release](https://vyos.io/rolling-release) | Open-source Firewall |

**Network Automation Framework**.


## Installation

### 1. Clone the repository
```bash
git clone https://github.com/YOUR_USERNAME/netguard.git
cd netguard
```

### 2. Create virtual environment
```bash
python3 -m venv venv
source venv/bin/activate
```

### 3. Install dependencies
```bash
pip install -r requirements.txt
```

### 4. Configure your devices
Edit `harvest.py` and update:
- `SEED_IP` — your firewall IP
- `FW_CREDENTIALS` — your firewall credentials
- `CREDENTIALS_LIST` — your device credentials

### 5. Configure email alerts (optional)
Go to Settings page in the dashboard after starting.

### 6. Run
```bash
python3 main.py
```
Open browser: `http://127.0.0.1:5000`

**Login:** suhail / suhail (change in app.py)

---

## Screenshots

> See LinkedIn post for full demo screenshots and video.
>https://www.linkedin.com/in/mohamadsuhail/
---

## Security Notice

This project was built for a controlled GNS3 lab environment.
Do not deploy on production networks without proper security hardening.
Never commit real device credentials to GitHub.

---

## Acknowledgements

Built as part of our Final Year Project.
Thanks to our supervisor and university for the support.

**NetGuard 2026**
