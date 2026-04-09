"""
NetGuard PDF Report Generator  –  reportlab
"""
import os, sqlite3
from datetime import datetime
from io import BytesIO

from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.lib.units import mm
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.enums import TA_CENTER
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak
)
from reportlab.pdfgen import canvas as rl_canvas

W, H = A4

# ── Palette ───────────────────────────────────────────────────────────────────
C_BG     = colors.HexColor('#080d14')
C_BORDER = colors.HexColor('#1a2d45')
C_BLUE   = colors.HexColor('#2d8cf0')
C_GREEN  = colors.HexColor('#00e07a')
C_YELLOW = colors.HexColor('#f5a623')
C_ORANGE = colors.HexColor('#e8712a')
C_RED    = colors.HexColor('#e84040')
C_DIM    = colors.HexColor('#5a7a9a')
C_TEXT   = colors.HexColor('#cdd9e8')
C_WHITE  = colors.white
C_LGREY  = colors.HexColor('#f4f7fb')
C_ROW2   = colors.HexColor('#eaf0f8')
C_DARK   = colors.HexColor('#1a2540')

SEV_COL = {'CRITICAL':C_RED,'HIGH':C_ORANGE,'MEDIUM':C_YELLOW,
           'LOW':C_BLUE,'SAFE':C_GREEN,'UNKNOWN':C_DIM}
SEV_BG  = {'CRITICAL':colors.HexColor('#fff0f0'),'HIGH':colors.HexColor('#fff7f0'),
           'MEDIUM':colors.HexColor('#fffbf0'),'LOW':colors.HexColor('#f0f7ff'),
           'SAFE':colors.HexColor('#f0fff7'),'UNKNOWN':colors.HexColor('#f7f7f7')}

def _hx(col):
    """Return hex string like 'e84040' from a Color object."""
    return col.hexval()[2:]


# ── Canvas: header + footer every page ───────────────────────────────────────
class ReportCanvas(rl_canvas.Canvas):
    def showPage(self):
        self._draw_chrome()
        super().showPage()
    def save(self):
        self._draw_chrome()
        super().save()
    def _draw_chrome(self):
        self.saveState()
        # dark header band
        self.setFillColor(C_BG)
        self.rect(0, H-22*mm, W, 22*mm, fill=1, stroke=0)
        self.setFillColor(C_GREEN)
        self.rect(0, H-22*mm, W, 1.5, fill=1, stroke=0)
        # title text
        self.setFont('Helvetica-Bold', 10)
        self.setFillColor(C_GREEN);  self.drawString(18*mm, H-13*mm, 'NETGUARD')
        self.setFillColor(C_BLUE);   self.drawString(18*mm+63, H-13*mm, 'SECURITY')
        self.setFillColor(C_TEXT);   self.drawString(18*mm+126, H-13*mm, 'REPORT')
        self.setFont('Helvetica', 7)
        self.setFillColor(C_DIM)
        self.drawRightString(W-18*mm, H-13*mm, 'CONFIDENTIAL — Internal Use Only')
        # footer line
        self.setStrokeColor(C_BORDER); self.setLineWidth(0.5)
        self.line(18*mm, 14*mm, W-18*mm, 14*mm)
        self.setFont('Helvetica', 7); self.setFillColor(C_DIM)
        self.drawString(18*mm, 9*mm,
            'NetGuard  |  TF-IDF + Random Forest  |  40 Security Checks  |  CIS Benchmark v4.1')
        self.drawRightString(W-18*mm, 9*mm, f'Page {self._pageNumber}')
        self.restoreState()


# ── Styles ────────────────────────────────────────────────────────────────────
def _S():
    return {
        'title':   ParagraphStyle('title',  fontName='Helvetica-Bold', fontSize=20,
                                  textColor=C_WHITE, leading=26),
        'h2':      ParagraphStyle('h2',     fontName='Helvetica-Bold', fontSize=12,
                                  textColor=C_BLUE, spaceBefore=10, spaceAfter=5),
        'h3':      ParagraphStyle('h3',     fontName='Helvetica-Bold', fontSize=9.5,
                                  textColor=C_DARK, spaceBefore=6, spaceAfter=3),
        'body':    ParagraphStyle('body',   fontName='Helvetica', fontSize=8.5,
                                  textColor=C_DARK, leading=13),
        'mono':    ParagraphStyle('mono',   fontName='Courier', fontSize=7,
                                  textColor=C_DARK, leading=10),
        'th':      ParagraphStyle('th',     fontName='Helvetica-Bold', fontSize=8,
                                  textColor=C_WHITE),
        'td':      ParagraphStyle('td',     fontName='Helvetica', fontSize=8,
                                  textColor=C_DARK, leading=10),
        'td_m':    ParagraphStyle('td_m',   fontName='Courier', fontSize=7,
                                  textColor=C_DARK, leading=9),
        'sev':     ParagraphStyle('sev',    fontName='Helvetica-Bold', fontSize=8,
                                  alignment=TA_CENTER),
        'cov_sub': ParagraphStyle('cov_sub',fontName='Helvetica', fontSize=10,
                                  textColor=C_DIM, alignment=TA_CENTER),
    }


def _sec_bar(title, S):
    t = Table([[Paragraph(title, S['h2'])]], colWidths=[W-36*mm])
    t.setStyle(TableStyle([
        ('BACKGROUND',    (0,0),(-1,-1), C_LGREY),
        ('LINEBELOW',     (0,0),(-1,-1), 2, C_BLUE),
        ('TOPPADDING',    (0,0),(-1,-1), 7),
        ('BOTTOMPADDING', (0,0),(-1,-1), 7),
        ('LEFTPADDING',   (0,0),(-1,-1), 10),
    ]))
    return t


def _stat_box(label, value, col):
    bw = (W-36*mm)/4
    inner = Table([
        [Paragraph(str(value),
                   ParagraphStyle('sv', fontName='Helvetica-Bold', fontSize=22,
                                  alignment=TA_CENTER, textColor=col))],
        [Paragraph(label,
                   ParagraphStyle('sl', fontName='Helvetica-Bold', fontSize=7.5,
                                  alignment=TA_CENTER, textColor=C_DIM))],
    ], colWidths=[bw-6])
    inner.setStyle(TableStyle([
        ('BACKGROUND',    (0,0),(-1,-1), SEV_BG.get(label, C_LGREY)),
        ('LINEBELOW',     (0,0),(-1,0),  3, col),
        ('TOPPADDING',    (0,0),(-1,-1), 9),
        ('BOTTOMPADDING', (0,0),(-1,-1), 9),
        ('ALIGN',         (0,0),(-1,-1), 'CENTER'),
    ]))
    return inner


# ── Cover ─────────────────────────────────────────────────────────────────────
def _cover(story, summary, S):
    now = datetime.now().strftime('%B %d, %Y  at  %H:%M')
    tb = Table([
        [Paragraph('<font color="#00e07a"><b>NETGUARD</b></font>'
                   '<font color="#2d8cf0">  SECURITY</font>'
                   '<font color="#cdd9e8">  ASSESSMENT REPORT</font>', S['title'])],
        [Paragraph(f'Generated: {now}', S['cov_sub'])],
    ], colWidths=[W-36*mm])
    tb.setStyle(TableStyle([
        ('BACKGROUND',    (0,0),(-1,-1), C_BG),
        ('LINEBELOW',     (0,0),(0,0),   2, C_GREEN),
        ('TOPPADDING',    (0,0),(0,0),   18),('BOTTOMPADDING',(0,0),(0,0),10),
        ('TOPPADDING',    (0,1),(0,1),   8), ('BOTTOMPADDING',(0,1),(0,1),16),
        ('LEFTPADDING',   (0,0),(-1,-1), 16),
    ]))
    story.append(tb); story.append(Spacer(1, 6*mm))

    counts = summary.get('severity_counts', {})
    meta = [
        ['Devices Scanned',  str(summary.get('total_devices', 0))],
        ['Total Findings',   str(summary.get('total_findings', 0))],
        ['Classification',   'CONFIDENTIAL — Internal Use Only'],
        ['Audit Framework',  'CIS Benchmark v4.1 · NIST SP 800-115 · CVE Database'],
        ['ML Engine',        'TF-IDF + Random Forest (Hybrid Rule+ML Classifier)'],
        ['Discovery Engine', 'CDP/SSH/Telnet Recursive Harvest · Triple Verification v4.3'],
    ]
    mt = Table(meta, colWidths=[48*mm, W-36*mm-48*mm])
    mt.setStyle(TableStyle([
        ('FONTNAME',     (0,0),(0,-1), 'Helvetica-Bold'),
        ('FONTNAME',     (1,0),(1,-1), 'Helvetica'),
        ('FONTSIZE',     (0,0),(-1,-1), 8.5),
        ('TEXTCOLOR',    (0,0),(0,-1),  C_DIM),
        ('TEXTCOLOR',    (1,0),(1,-1),  C_DARK),
        ('TOPPADDING',   (0,0),(-1,-1), 5),('BOTTOMPADDING',(0,0),(-1,-1),5),
        ('LINEBELOW',    (0,0),(-1,-2), 0.3, C_BORDER),
        ('LINEBELOW',    (0,-1),(-1,-1),1,   C_BORDER),
    ]))
    story.append(mt); story.append(Spacer(1, 7*mm))

    bw    = (W-36*mm)/4
    boxes = [_stat_box('CRITICAL',counts.get('CRITICAL',0),C_RED),
             _stat_box('HIGH',    counts.get('HIGH',    0),C_ORANGE),
             _stat_box('MEDIUM',  counts.get('MEDIUM',  0),C_YELLOW),
             _stat_box('LOW',     counts.get('LOW',     0),C_BLUE)]
    st = Table([boxes], colWidths=[bw]*4)
    st.setStyle(TableStyle([
        ('LEFTPADDING', (0,0),(-1,-1),3),('RIGHTPADDING',(0,0),(-1,-1),3),
        ('TOPPADDING',  (0,0),(-1,-1),0),('BOTTOMPADDING',(0,0),(-1,-1),0),
        ('VALIGN',      (0,0),(-1,-1),'TOP'),
    ]))
    story.append(st); story.append(Spacer(1, 6*mm))

    ab = Table([[Paragraph(
        'This report was generated automatically by <b>NetGuard </b>, an AI-powered '
        'network security assessment platform. It performs recursive device discovery using '
        'CDP/SSH/Telnet, audits all discovered Cisco IOS configurations against 40 security '
        'checks aligned with CIS Benchmark v4.1 and NIST SP 800-115, and classifies risk '
        'using a hybrid TF-IDF + Random Forest machine learning engine. Remediation commands '
        'are generated automatically using Jinja2 templates.', S['body']
    )]], colWidths=[W-36*mm])
    ab.setStyle(TableStyle([
        ('BACKGROUND',    (0,0),(-1,-1), C_LGREY),
        ('LINEBELOW',     (0,0),(-1,-1), 1.5, C_BLUE),
        ('TOPPADDING',    (0,0),(-1,-1), 10),('BOTTOMPADDING',(0,0),(-1,-1),10),
        ('LEFTPADDING',   (0,0),(-1,-1), 12),('RIGHTPADDING', (0,0),(-1,-1),12),
    ]))
    story.append(ab)


# ── Device summary table ──────────────────────────────────────────────────────
def _device_summary(story, devices, S):
    story.append(Spacer(1, 5*mm))
    story.append(_sec_bar('Device Security Summary', S))
    story.append(Spacer(1, 3*mm))

    hdr  = ['#','Hostname','IP','Type','Score','Level','Crit','High','Med','Low']
    rows = [[Paragraph(h, S['th']) for h in hdr]]
    for i, d in enumerate(devices, 1):
        lv  = d.get('level','UNKNOWN').upper()
        col = SEV_COL.get(lv, C_DIM)
        cnt = d.get('severity_counts', {})
        rows.append([
            Paragraph(str(i),                                          S['td']),
            Paragraph(str(d.get('device','—')),                        S['td']),
            Paragraph(str(d.get('ip','—')),                            S['td']),
            Paragraph(str(d.get('type','router')),                     S['td']),
            Paragraph(str(d.get('score','—')),                         S['td']),
            Paragraph(f'<font color="#{_hx(col)}"><b>{lv}</b></font>', S['sev']),
            Paragraph(str(cnt.get('CRITICAL',0)),                      S['td']),
            Paragraph(str(cnt.get('HIGH',    0)),                      S['td']),
            Paragraph(str(cnt.get('MEDIUM',  0)),                      S['td']),
            Paragraph(str(cnt.get('LOW',     0)),                      S['td']),
        ])
    cw = [x*mm for x in [8,34,28,18,18,22,14,14,14,14]]
    t  = Table(rows, colWidths=cw, repeatRows=1)
    ts = TableStyle([
        ('BACKGROUND',    (0,0),(-1,0), C_BG),
        ('LINEBELOW',     (0,0),(-1,0), 2, C_BLUE),
        ('TOPPADDING',    (0,0),(-1,0), 7),('BOTTOMPADDING',(0,0),(-1,0),7),
        ('FONTSIZE',      (0,1),(-1,-1),8),
        ('TOPPADDING',    (0,1),(-1,-1),5),('BOTTOMPADDING',(0,1),(-1,-1),5),
        ('ROWBACKGROUNDS',(0,1),(-1,-1),[C_WHITE, C_ROW2]),
        ('GRID',          (0,0),(-1,-1),0.3, colors.HexColor('#dde3ea')),
        ('ALIGN',         (0,0),(-1,-1),'CENTER'),
        ('VALIGN',        (0,0),(-1,-1),'MIDDLE'),
        ('ALIGN',         (1,1),(2,-1), 'LEFT'),
    ])
    for i, d in enumerate(devices, 1):
        lv = d.get('level','UNKNOWN').upper()
        ts.add('BACKGROUND',(5,i),(5,i), SEV_BG.get(lv, C_WHITE))
    t.setStyle(ts)
    story.append(t)


# ── All findings ──────────────────────────────────────────────────────────────
def _findings_table(story, devices, S):
    story.append(PageBreak())
    story.append(_sec_bar('Security Findings — All Devices', S))
    story.append(Spacer(1, 3*mm))

    hdr  = ['ID','Severity','Device','Finding Title','CVE / CIS','Recommended Fix']
    rows = [[Paragraph(h, S['th']) for h in hdr]]
    for d in devices:
        dev = d.get('device','—')
        for f in d.get('findings', []):
            lv  = f.get('severity','UNKNOWN').upper()
            col = SEV_COL.get(lv, C_DIM)
            fix = str(f.get('fix','—'))
            if len(fix) > 60: fix = fix[:57]+'...'
            rows.append([
                Paragraph(str(f.get('id','—')),  S['td_m']),
                Paragraph(f'<font color="#{_hx(col)}"><b>{lv}</b></font>', S['sev']),
                Paragraph(dev,                    S['td']),
                Paragraph(str(f.get('title','—')),S['td']),
                Paragraph(str(f.get('cve','—')),  S['td_m']),
                Paragraph(fix,                    S['td_m']),
            ])
    cw = [x*mm for x in [18,20,22,58,30,44]]
    t  = Table(rows, colWidths=cw, repeatRows=1)
    t.setStyle(TableStyle([
        ('BACKGROUND',    (0,0),(-1,0), C_BG),
        ('LINEBELOW',     (0,0),(-1,0), 2, C_RED),
        ('TOPPADDING',    (0,0),(-1,0), 7),('BOTTOMPADDING',(0,0),(-1,0),7),
        ('FONTSIZE',      (0,1),(-1,-1),7.5),
        ('TOPPADDING',    (0,1),(-1,-1),4),('BOTTOMPADDING',(0,1),(-1,-1),4),
        ('ROWBACKGROUNDS',(0,1),(-1,-1),[C_WHITE, C_ROW2]),
        ('GRID',          (0,0),(-1,-1),0.3, colors.HexColor('#dde3ea')),
        ('VALIGN',        (0,0),(-1,-1),'MIDDLE'),
        ('ALIGN',         (1,0),(1,-1), 'CENTER'),
    ]))
    story.append(t)


# ── Per-device detail ─────────────────────────────────────────────────────────
def _device_detail(story, devices, S):
    config_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'network_configs')

    for d in devices:
        name  = d.get('device','Unknown')
        lv    = d.get('level','UNKNOWN').upper()
        score = d.get('score','—')
        col   = SEV_COL.get(lv, C_DIM)

        story.append(PageBreak())

        dh = Table([[Paragraph(
            f'<b>{name}</b>  '
            f'<font color="#{_hx(C_DIM)}">— Score: {score}  |  Risk: </font>'
            f'<font color="#{_hx(col)}"><b>{lv}</b></font>',
            ParagraphStyle('dh', fontName='Helvetica-Bold', fontSize=11, textColor=C_DARK)
        )]], colWidths=[W-36*mm])
        dh.setStyle(TableStyle([
            ('BACKGROUND',    (0,0),(-1,-1), SEV_BG.get(lv, C_LGREY)),
            ('LINEBELOW',     (0,0),(-1,-1), 2, col),
            ('TOPPADDING',    (0,0),(-1,-1), 10),('BOTTOMPADDING',(0,0),(-1,-1),10),
            ('LEFTPADDING',   (0,0),(-1,-1), 14),
        ]))
        story.append(dh); story.append(Spacer(1, 3*mm))

        findings = d.get('findings', [])
        if findings:
            story.append(Paragraph(f'Findings ({len(findings)})', S['h3']))
            fhdr  = ['ID','Severity','Title','Fix Command']
            frows = [[Paragraph(h, S['th']) for h in fhdr]]
            for f in findings:
                flv  = f.get('severity','UNKNOWN').upper()
                fcol = SEV_COL.get(flv, C_DIM)
                fix  = str(f.get('fix','—'))
                if len(fix) > 70: fix = fix[:67]+'...'
                frows.append([
                    Paragraph(str(f.get('id','—')),   S['td_m']),
                    Paragraph(f'<font color="#{_hx(fcol)}"><b>{flv}</b></font>', S['sev']),
                    Paragraph(str(f.get('title','—')), S['td']),
                    Paragraph(fix,                     S['td_m']),
                ])
            ft = Table(frows, colWidths=[20*mm,20*mm,72*mm,80*mm], repeatRows=1)
            ft.setStyle(TableStyle([
                ('BACKGROUND',    (0,0),(-1,0), C_BG),
                ('LINEBELOW',     (0,0),(-1,0), 1.5, col),
                ('TOPPADDING',    (0,0),(-1,0), 6),('BOTTOMPADDING',(0,0),(-1,0),6),
                ('FONTSIZE',      (0,1),(-1,-1),7.5),
                ('TOPPADDING',    (0,1),(-1,-1),4),('BOTTOMPADDING',(0,1),(-1,-1),4),
                ('ROWBACKGROUNDS',(0,1),(-1,-1),[C_WHITE, C_ROW2]),
                ('GRID',          (0,0),(-1,-1),0.3, colors.HexColor('#dde3ea')),
                ('VALIGN',        (0,0),(-1,-1),'MIDDLE'),
                ('ALIGN',         (1,0),(1,-1), 'CENTER'),
            ]))
            story.append(ft); story.append(Spacer(1, 3*mm))

        # Config snippet
        cfg_path = os.path.join(config_dir, f'{name}_config.txt')
        if not os.path.exists(cfg_path):
            # try without _config suffix
            cfg_path = os.path.join(config_dir, f'{name}.txt')
        if os.path.exists(cfg_path):
            with open(cfg_path, 'r', errors='ignore') as fh:
                lines = fh.read().splitlines()
            story.append(Paragraph('Running Configuration (excerpt)', S['h3']))
            shown = lines[:40]
            txt   = '\n'.join(shown)
            if len(lines) > 40:
                txt += f'\n... ({len(lines)-40} more lines in full config file)'
            ct = Table([[Paragraph(
                txt.replace('&','&amp;').replace('<','&lt;').replace('>','&gt;')
                   .replace('\n','<br/>'), S['mono']
            )]], colWidths=[W-36*mm])
            ct.setStyle(TableStyle([
                ('BACKGROUND',    (0,0),(-1,-1), colors.HexColor('#f8fafc')),
                ('LINEBEFORE',    (0,0),(0,-1),  2.5, C_BLUE),
                ('TOPPADDING',    (0,0),(-1,-1), 8),('BOTTOMPADDING',(0,0),(-1,-1),8),
                ('LEFTPADDING',   (0,0),(-1,-1), 10),
            ]))
            story.append(ct)


# ── Config history ────────────────────────────────────────────────────────────
def _config_history(story, S):
    db_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'netguard.db')
    if not os.path.exists(db_path): return
    try:
        conn = sqlite3.connect(db_path); conn.row_factory = sqlite3.Row
        rows = conn.execute(
            "SELECT hostname,harvested_at,total_lines,active_lines,changed "
            "FROM config_history ORDER BY harvested_at DESC LIMIT 60"
        ).fetchall(); conn.close()
    except Exception: return
    if not rows: return

    story.append(PageBreak())
    story.append(_sec_bar('Configuration Change History (SQLite)', S))
    story.append(Spacer(1, 3*mm))

    hdr   = ['Hostname','Scanned At','Total Lines','Active Lines','Changed?']
    trows = [[Paragraph(h, S['th']) for h in hdr]]
    for r in rows:
        ch    = r['changed']
        chcol = C_RED if ch else C_GREEN
        trows.append([
            Paragraph(str(r['hostname']),     S['td']),
            Paragraph(str(r['harvested_at']), S['td']),
            Paragraph(str(r['total_lines']),  S['td']),
            Paragraph(str(r['active_lines']), S['td']),
            Paragraph(f'<font color="#{_hx(chcol)}"><b>{"CHANGED" if ch else "unchanged"}</b></font>', S['sev']),
        ])
    t = Table(trows, colWidths=[35*mm,55*mm,28*mm,28*mm,26*mm], repeatRows=1)
    t.setStyle(TableStyle([
        ('BACKGROUND',    (0,0),(-1,0), C_BG),
        ('LINEBELOW',     (0,0),(-1,0), 2, C_GREEN),
        ('TOPPADDING',    (0,0),(-1,0), 7),('BOTTOMPADDING',(0,0),(-1,0),7),
        ('FONTSIZE',      (0,1),(-1,-1),8),
        ('TOPPADDING',    (0,1),(-1,-1),5),('BOTTOMPADDING',(0,1),(-1,-1),5),
        ('ROWBACKGROUNDS',(0,1),(-1,-1),[C_WHITE, C_ROW2]),
        ('GRID',          (0,0),(-1,-1),0.3, colors.HexColor('#dde3ea')),
        ('VALIGN',        (0,0),(-1,-1),'MIDDLE'),
        ('ALIGN',         (2,0),(4,-1), 'CENTER'),
    ]))
    story.append(t)


# ── ENTRY POINT ───────────────────────────────────────────────────────────────
def generate_pdf_report(audit_data: dict) -> bytes:
    """Build full PDF and return as bytes. Call from Flask route."""
    buf     = BytesIO()
    S       = _S()
    summary = audit_data.get('summary', {})
    devices = audit_data.get('devices', [])

    doc = SimpleDocTemplate(
        buf, pagesize=A4,
        leftMargin=18*mm, rightMargin=18*mm,
        topMargin=28*mm,  bottomMargin=22*mm,
        title='NetGuard Security Assessment Report',
        author='NetGuard',
        subject='Network Security Audit',
    )
    story = []
    _cover(story, summary, S)
    _device_summary(story, devices, S)
    _findings_table(story, devices, S)
    _device_detail(story, devices, S)
    _config_history(story, S)
    doc.build(story, canvasmaker=ReportCanvas)
    return buf.getvalue()
