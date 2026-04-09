"""
NetGuard Email Alerts
======================
Sends two types of emails:
  1. CRITICAL alert — fires immediately when CRITICAL findings found
  2. Full scan report — fires after every Re-Scan completes (HTML attachment)

Settings stored in: ~/netguard_email.json
"""

import smtplib
import json
import os
import datetime
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.base import MIMEBase
from email import encoders

SETTINGS_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'netguard_email.json')

DEFAULT_SETTINGS = {
    "enabled":    False,
    "sender":     "",
    "password":   "",
    "recipient1": "",
    "recipient2": "",
    "alert_critical": True,
    "alert_report":   True,
}


# ── Settings helpers ──────────────────────────────────────────────────────────
def load_settings():
    if os.path.exists(SETTINGS_FILE):
        try:
            with open(SETTINGS_FILE) as f:
                s = json.load(f)
            # Fill missing keys with defaults
            for k, v in DEFAULT_SETTINGS.items():
                s.setdefault(k, v)
            return s
        except Exception:
            pass
    return DEFAULT_SETTINGS.copy()


def save_settings(data):
    with open(SETTINGS_FILE, 'w') as f:
        json.dump(data, f, indent=2)


def get_recipients(settings):
    """Return list of valid recipient addresses."""
    r = []
    r1 = (settings.get('recipient1') or '').strip()
    r2 = (settings.get('recipient2') or '').strip()
    if r1 and '@' in r1:
        r.append(r1)
    if r2 and '@' in r2:
        r.append(r2)
    return r


# ── Core send function ────────────────────────────────────────────────────────
def send_email(subject, body_html, recipients, sender, password,
               attachment_html=None, attachment_name=None):
    """
    Send an HTML email via Gmail SMTP.
    Optionally attach an HTML file (the full report).
    Returns (True, '') on success or (False, error_message) on failure.
    """
    if not recipients:
        return False, "No recipients configured"

    msg = MIMEMultipart('mixed')
    msg['From']    = f"NetGuard Alerts <{sender}>"
    msg['To']      = ', '.join(recipients)
    msg['Subject'] = subject

    # Body
    msg.attach(MIMEText(body_html, 'html'))

    # Attachment
    if attachment_html and attachment_name:
        part = MIMEBase('application', 'octet-stream')
        part.set_payload(attachment_html.encode('utf-8'))
        encoders.encode_base64(part)
        part.add_header('Content-Disposition',
                        f'attachment; filename="{attachment_name}"')
        part.add_header('Content-Type', 'text/html; charset=utf-8')
        msg.attach(part)

    try:
        with smtplib.SMTP_SSL('smtp.gmail.com', 465, timeout=15) as server:
            server.login(sender, password)
            server.sendmail(sender, recipients, msg.as_string())
        return True, ''
    except smtplib.SMTPAuthenticationError:
        return False, 'Gmail authentication failed — check App Password'
    except smtplib.SMTPException as ex:
        return False, f'SMTP error: {ex}'
    except Exception as ex:
        return False, f'Send failed: {ex}'


# ── HTML Report Builder ───────────────────────────────────────────────────────
def build_html_report(audit_data, db_history=None):
    """
    Builds a full standalone HTML security report.
    Styled to match NetGuard design — opens in any browser.
    """
    now   = datetime.datetime.now().strftime('%B %d, %Y  %H:%M:%S')
    s     = audit_data.get('summary', {})
    devs  = audit_data.get('devices', [])

    total_c = s.get('total_critical', 0)
    total_h = s.get('total_high', 0)
    total_m = s.get('total_medium', 0)
    total_l = s.get('total_low', 0)
    total_f = s.get('total_findings', 0)

    def sev_color(sev):
        return {'CRITICAL':'#ff3d57','HIGH':'#ff7b35',
                'MEDIUM':'#ffc642','LOW':'#00d2c8','INFO':'#3d9dff'}.get(sev,'#5a7a9a')

    def level_color(lvl):
        return {'CRITICAL':'#ff3d57','HIGH':'#ff7b35',
                'MEDIUM':'#ffc642','LOW':'#00d2c8','SAFE':'#00e07a'}.get(lvl,'#5a7a9a')

    # Device cards
    dev_cards_html = ''
    for d in devs:
        col   = level_color(d.get('level',''))
        score = d.get('score', 0)
        dev_cards_html += f"""
        <div style="background:#111c2b;border:1px solid #1a2d45;border-radius:10px;
                    padding:16px;border-left:4px solid {col}">
          <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:8px">
            <span style="font-family:monospace;font-weight:700;color:#fff;font-size:1rem">{d.get('device','')}</span>
            <span style="background:{col}22;color:{col};border:1px solid {col}55;
                         border-radius:5px;padding:3px 10px;font-size:.75rem;font-weight:700">{d.get('level','')}</span>
          </div>
          <div style="display:flex;align-items:center;gap:12px">
            <span style="font-family:monospace;font-size:1.8rem;font-weight:800;color:{col}">{score}</span>
            <div style="flex:1">
              <div style="background:rgba(255,255,255,.06);border-radius:999px;height:6px;margin-bottom:5px">
                <div style="width:{score}%;height:100%;background:{col};border-radius:999px"></div>
              </div>
              <span style="color:#5a7a9a;font-size:.72rem;font-family:monospace">{d.get('failed',0)}/{d.get('total_checks',0)} checks failed</span>
            </div>
          </div>
        </div>"""

    # Findings table rows
    findings_rows = ''
    for d in devs:
        for f in d.get('findings', []):
            col = sev_color(f.get('severity',''))
            findings_rows += f"""
            <tr>
              <td style="color:#5a7a9a;font-family:monospace;font-size:.75rem">{f.get('id','')}</td>
              <td><span style="background:{col}22;color:{col};border:1px solid {col}55;
                               border-radius:4px;padding:2px 7px;font-size:.7rem;font-weight:700;font-family:monospace">{f.get('severity','')}</span></td>
              <td style="font-weight:600;color:#cdd9e8">{f.get('title','')}</td>
              <td><span style="background:rgba(61,157,255,.1);color:#3d9dff;border:1px solid rgba(61,157,255,.2);
                               border-radius:4px;padding:2px 6px;font-size:.7rem;font-family:monospace">{d.get('device','')}</span></td>
              <td style="color:#00e07a;font-family:monospace;font-size:.72rem">{f.get('fix','')[:80]}{'…' if len(f.get('fix',''))>80 else ''}</td>
            </tr>"""

    # Config change summary
    change_rows = ''
    if db_history:
        seen = {}
        for row in db_history:
            hn = row.get('hostname','')
            if hn not in seen:
                seen[hn] = {'changed': 0, 'total': 0, 'last': row.get('harvested_at','')}
            seen[hn]['total'] += 1
            if row.get('changed'): seen[hn]['changed'] += 1
        for hn, info in seen.items():
            icon  = '🔄' if info['changed'] else '✓'
            color = '#ff7b35' if info['changed'] else '#5a7a9a'
            change_rows += f"""
            <tr>
              <td style="font-family:monospace;font-weight:700;color:#3d9dff">{hn}</td>
              <td style="color:{color};font-weight:700">{icon} {'CHANGED' if info['changed'] else 'unchanged'}</td>
              <td style="color:#5a7a9a;font-family:monospace;font-size:.75rem">{info['total']} versions saved</td>
              <td style="color:#5a7a9a;font-family:monospace;font-size:.75rem">{info['last']}</td>
            </tr>"""

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>NetGuard Security Report — {now}</title>
<style>
  *{{box-sizing:border-box;margin:0;padding:0}}
  body{{background:#080d14;color:#cdd9e8;font-family:'Segoe UI',Arial,sans-serif;font-size:14px;padding:0}}
  .wrap{{max-width:960px;margin:0 auto;padding:32px 24px}}
  h1{{font-size:1.6rem;font-weight:800;color:#fff;letter-spacing:1px}}
  h2{{font-size:1rem;font-weight:700;color:#fff;margin:28px 0 12px;display:flex;align-items:center;gap:8px}}
  table{{width:100%;border-collapse:collapse;background:#111c2b;border:1px solid #1a2d45;border-radius:10px;overflow:hidden}}
  thead th{{background:#0d1520;padding:9px 14px;font-size:.68rem;font-weight:700;letter-spacing:.1em;color:#5a7a9a;text-transform:uppercase;text-align:left;border-bottom:1px solid #1a2d45}}
  tbody td{{padding:9px 14px;border-bottom:1px solid rgba(26,45,69,.4);vertical-align:middle}}
  tbody tr:last-child td{{border-bottom:none}}
  tbody tr:hover td{{background:rgba(61,157,255,.04)}}
  .badge{{display:inline-block;padding:5px 16px;border-radius:8px;font-weight:800;font-size:1.5rem;font-family:monospace}}
  .footer{{margin-top:32px;padding-top:16px;border-top:1px solid #1a2d45;font-size:.72rem;color:#5a7a9a;font-family:monospace;text-align:center}}
</style>
</head>
<body>
<div class="wrap">

  <!-- Header -->
  <div style="background:linear-gradient(135deg,#0d1520,#111c2b);border:1px solid #1a2d45;
              border-radius:14px;padding:28px 32px;margin-bottom:24px;
              border-top:3px solid #3d9dff">
    <div style="display:flex;justify-content:space-between;align-items:flex-start">
      <div>
        <div style="font-size:.75rem;font-weight:700;letter-spacing:.2em;color:#3d9dff;margin-bottom:6px">NETGUARD</div>
        <h1>Security Assessment Report</h1>
        <div style="color:#5a7a9a;font-size:.8rem;margin-top:6px;font-family:monospace">
          Generated: {now} &nbsp;·&nbsp; 40 checks &nbsp;·&nbsp; CIS Benchmark v4.1 &nbsp;·&nbsp; NIST SP 800-115
        </div>
      </div>
      <div style="text-align:right">
        <div style="font-size:.7rem;color:#5a7a9a;margin-bottom:4px">OVERALL RISK</div>
        <div style="font-size:2rem;font-weight:800;color:{'#ff3d57' if total_c>0 else '#ff7b35' if total_h>0 else '#ffc642'}">{total_f} FINDINGS</div>
      </div>
    </div>
  </div>

  <!-- Summary Cards -->
  <div style="display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin-bottom:24px">
    <div style="background:#111c2b;border:1px solid #1a2d45;border-radius:10px;padding:16px;border-top:3px solid #ff3d57">
      <div style="font-size:.65rem;font-weight:700;letter-spacing:.1em;color:#5a7a9a;text-transform:uppercase;margin-bottom:6px">CRITICAL</div>
      <div class="badge" style="color:#ff3d57">{total_c}</div>
    </div>
    <div style="background:#111c2b;border:1px solid #1a2d45;border-radius:10px;padding:16px;border-top:3px solid #ff7b35">
      <div style="font-size:.65rem;font-weight:700;letter-spacing:.1em;color:#5a7a9a;text-transform:uppercase;margin-bottom:6px">HIGH</div>
      <div class="badge" style="color:#ff7b35">{total_h}</div>
    </div>
    <div style="background:#111c2b;border:1px solid #1a2d45;border-radius:10px;padding:16px;border-top:3px solid #ffc642">
      <div style="font-size:.65rem;font-weight:700;letter-spacing:.1em;color:#5a7a9a;text-transform:uppercase;margin-bottom:6px">MEDIUM</div>
      <div class="badge" style="color:#ffc642">{total_m}</div>
    </div>
    <div style="background:#111c2b;border:1px solid #1a2d45;border-radius:10px;padding:16px;border-top:3px solid #00d2c8">
      <div style="font-size:.65rem;font-weight:700;letter-spacing:.1em;color:#5a7a9a;text-transform:uppercase;margin-bottom:6px">LOW</div>
      <div class="badge" style="color:#00d2c8">{total_l}</div>
    </div>
  </div>

  <!-- Device Summary -->
  <h2><span style="color:#3d9dff">▍</span> Device Security Summary</h2>
  <div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(280px,1fr));gap:12px;margin-bottom:24px">
    {dev_cards_html}
  </div>

  <!-- All Findings -->
  <h2><span style="color:#ff3d57">▍</span> All Security Findings</h2>
  <table style="margin-bottom:24px">
    <thead><tr><th>ID</th><th>Severity</th><th>Vulnerability</th><th>Device</th><th>Fix Guidance</th></tr></thead>
    <tbody>{findings_rows}</tbody>
  </table>

  {'<!-- Config Changes --><h2><span style="color:#ff7b35">▍</span> Configuration Change Detection (MD5)</h2><table style="margin-bottom:24px"><thead><tr><th>Device</th><th>Status</th><th>Versions</th><th>Last Saved</th></tr></thead><tbody>' + change_rows + '</tbody></table>' if change_rows else ''}

  <div class="footer">
    NetGuard &nbsp;·&nbsp; AI-Driven Network Security Assessment &nbsp;·&nbsp;
    BY: Suhail · Shamha · Hiqmi &nbsp;·&nbsp; {now}
  </div>
</div>
</body>
</html>"""
    return html


# ── Alert email body ──────────────────────────────────────────────────────────
def build_alert_body(device, findings):
    """Simple HTML body for instant CRITICAL alert email."""
    rows = ''.join(f"""
        <tr>
          <td style="font-family:monospace;color:#5a7a9a">{f.get('id','')}</td>
          <td style="color:#ff3d57;font-weight:700">{f.get('severity','')}</td>
          <td style="color:#cdd9e8;font-weight:600">{f.get('title','')}</td>
          <td style="color:#00e07a;font-family:monospace;font-size:.85em">{f.get('fix','')[:60]}</td>
        </tr>""" for f in findings)

    return f"""
    <div style="background:#080d14;color:#cdd9e8;font-family:Arial,sans-serif;padding:24px;max-width:680px;margin:0 auto">
      <div style="background:#111c2b;border:1px solid #1a2d45;border-top:3px solid #ff3d57;
                  border-radius:10px;padding:20px;margin-bottom:16px">
        <div style="font-size:.7rem;font-weight:700;letter-spacing:.2em;color:#ff3d57;margin-bottom:6px">⚠️ NETGUARD CRITICAL ALERT</div>
        <div style="font-size:1.3rem;font-weight:800;color:#fff">Device: {device}</div>
        <div style="color:#5a7a9a;font-size:.8rem;margin-top:4px;font-family:monospace">
          {len(findings)} CRITICAL finding{'s' if len(findings)!=1 else ''} detected &nbsp;·&nbsp;
          {datetime.datetime.now().strftime('%b %d %Y  %H:%M:%S')}
        </div>
      </div>
      <table style="width:100%;border-collapse:collapse;background:#111c2b;border:1px solid #1a2d45;border-radius:8px;overflow:hidden">
        <thead><tr>
          <th style="background:#0d1520;padding:8px 12px;font-size:.65rem;color:#5a7a9a;text-align:left;border-bottom:1px solid #1a2d45;text-transform:uppercase">ID</th>
          <th style="background:#0d1520;padding:8px 12px;font-size:.65rem;color:#5a7a9a;text-align:left;border-bottom:1px solid #1a2d45;text-transform:uppercase">Severity</th>
          <th style="background:#0d1520;padding:8px 12px;font-size:.65rem;color:#5a7a9a;text-align:left;border-bottom:1px solid #1a2d45;text-transform:uppercase">Issue</th>
          <th style="background:#0d1520;padding:8px 12px;font-size:.65rem;color:#5a7a9a;text-align:left;border-bottom:1px solid #1a2d45;text-transform:uppercase">Fix</th>
        </tr></thead>
        <tbody>{rows}</tbody>
      </table>
      <div style="margin-top:16px;font-size:.72rem;color:#5a7a9a;font-family:monospace;text-align:center">
        NetGuard &nbsp;·&nbsp; BY: Suhail · Shamha · Hiqmi
      </div>
    </div>"""


# ── Public trigger functions (called from app.py) ─────────────────────────────
def send_critical_alerts(audit_data):
    """
    Called after every audit.
    Sends one email per device that has CRITICAL findings.
    """
    settings = load_settings()
    if not settings.get('enabled') or not settings.get('alert_critical'):
        return
    recipients = get_recipients(settings)
    if not recipients:
        return

    for d in audit_data.get('devices', []):
        crits = [f for f in d.get('findings', []) if f.get('severity') == 'CRITICAL']
        if not crits:
            continue
        subject = f"🚨 [NetGuard] CRITICAL Alert — {d['device']} — {len(crits)} vulnerabilities"
        body    = build_alert_body(d['device'], crits)
        ok, err = send_email(subject, body, recipients,
                             settings['sender'], settings['password'])
        if ok:
            print(f"📧 Alert sent for {d['device']} to {recipients}")
        else:
            print(f"⚠️  Email failed for {d['device']}: {err}")


def send_scan_report(audit_data, db_history=None):
    """
    Called after Re-Scan completes.
    Sends full HTML report as email attachment.
    """
    settings = load_settings()
    if not settings.get('enabled') or not settings.get('alert_report'):
        return
    recipients = get_recipients(settings)
    if not recipients:
        return

    s       = audit_data.get('summary', {})
    c       = s.get('total_critical', 0)
    h       = s.get('total_high', 0)
    devs    = len(audit_data.get('devices', []))
    now_str = datetime.datetime.now().strftime('%b %d %Y %H:%M')
    fname   = datetime.datetime.now().strftime('NetGuard_Report_%Y%m%d_%H%M.html')

    subject = (f"📊 [NetGuard] Scan Report — {devs} device{'s' if devs!=1 else ''} "
               f"| {c} CRITICAL | {h} HIGH — {now_str}")

    body = f"""
    <div style="background:#080d14;color:#cdd9e8;font-family:Arial,sans-serif;
                padding:24px;max-width:680px;margin:0 auto">
      <div style="background:#111c2b;border:1px solid #1a2d45;border-top:3px solid #3d9dff;
                  border-radius:10px;padding:20px;margin-bottom:16px">
        <div style="font-size:.7rem;font-weight:700;letter-spacing:.2em;color:#3d9dff;margin-bottom:6px">📊 NETGUARD SCAN COMPLETE</div>
        <div style="font-size:1.3rem;font-weight:800;color:#fff">{devs} Device{'s' if devs!=1 else ''} Scanned</div>
        <div style="color:#5a7a9a;font-size:.8rem;margin-top:4px;font-family:monospace">{now_str}</div>
      </div>
      <div style="display:flex;gap:10px;margin-bottom:16px">
        <div style="flex:1;background:#ff3d5722;border:1px solid #ff3d5544;border-radius:8px;padding:14px;text-align:center">
          <div style="color:#5a7a9a;font-size:.65rem;text-transform:uppercase;letter-spacing:.1em">Critical</div>
          <div style="color:#ff3d57;font-size:1.8rem;font-weight:800;font-family:monospace">{c}</div>
        </div>
        <div style="flex:1;background:#ff7b3522;border:1px solid #ff7b3544;border-radius:8px;padding:14px;text-align:center">
          <div style="color:#5a7a9a;font-size:.65rem;text-transform:uppercase;letter-spacing:.1em">High</div>
          <div style="color:#ff7b35;font-size:1.8rem;font-weight:800;font-family:monospace">{h}</div>
        </div>
        <div style="flex:1;background:#ffc64222;border:1px solid #ffc64244;border-radius:8px;padding:14px;text-align:center">
          <div style="color:#5a7a9a;font-size:.65rem;text-transform:uppercase;letter-spacing:.1em">Medium</div>
          <div style="color:#ffc642;font-size:1.8rem;font-weight:800;font-family:monospace">{s.get('total_medium',0)}</div>
        </div>
        <div style="flex:1;background:#00d2c822;border:1px solid #00d2c844;border-radius:8px;padding:14px;text-align:center">
          <div style="color:#5a7a9a;font-size:.65rem;text-transform:uppercase;letter-spacing:.1em">Low</div>
          <div style="color:#00d2c8;font-size:1.8rem;font-weight:800;font-family:monospace">{s.get('total_low',0)}</div>
        </div>
      </div>
      <div style="background:#111c2b;border:1px solid #1a2d45;border-radius:8px;padding:14px;
                  font-family:monospace;font-size:.78rem;color:#5a7a9a;text-align:center">
        📎 Full report attached as <strong style="color:#cdd9e8">{fname}</strong> — open in any browser
      </div>
      <div style="margin-top:16px;font-size:.72rem;color:#5a7a9a;font-family:monospace;text-align:center">
        NetGuard &nbsp;·&nbsp; BY: Suhail · Shamha · Hiqmi
      </div>
    </div>"""

    report_html = build_html_report(audit_data, db_history)
    ok, err = send_email(subject, body, recipients,
                         settings['sender'], settings['password'],
                         attachment_html=report_html,
                         attachment_name=fname)
    if ok:
        print(f"📧 Scan report sent to {recipients}")
    else:
        print(f"⚠️  Report email failed: {err}")


if __name__ == '__main__':
    # Quick test
    s = load_settings()
    print("Current settings:", json.dumps(s, indent=2))
