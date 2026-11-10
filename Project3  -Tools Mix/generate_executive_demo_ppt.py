from pathlib import Path

from pptx import Presentation
from pptx.dml.color import RGBColor
from pptx.enum.shapes import MSO_SHAPE
from pptx.enum.text import MSO_ANCHOR, PP_ALIGN
from pptx.util import Inches, Pt


OUTPUT = Path(__file__).with_name("OT_Platform_Executive_Management_Review.pptx")
WIDTH, HEIGHT = 13.333, 7.5

COLORS = {
    "navy": "101C2C",
    "navy2": "172A3D",
    "teal": "22A99A",
    "mint": "D9F3EC",
    "orange": "EA9653",
    "paper": "F4F7F9",
    "white": "FFFFFF",
    "ink": "182536",
    "muted": "5F6F7F",
    "line": "D9E1E7",
    "blue": "4E7DA6",
    "red": "C76157",
}


def color(value):
    return RGBColor.from_string(COLORS.get(value, value))


def rect(slide, x, y, w, h, fill, line=None, shape=MSO_SHAPE.RECTANGLE):
    item = slide.shapes.add_shape(shape, Inches(x), Inches(y), Inches(w), Inches(h))
    item.fill.solid()
    item.fill.fore_color.rgb = color(fill)
    if line:
        item.line.color.rgb = color(line)
        item.line.width = Pt(0.8)
    else:
        item.line.fill.background()
    return item


def text(slide, value, x, y, w, h, size=16, fill="ink", bold=False,
         font="Aptos", align=PP_ALIGN.LEFT, valign=MSO_ANCHOR.TOP,
         margin=0.02):
    box = slide.shapes.add_textbox(Inches(x), Inches(y), Inches(w), Inches(h))
    frame = box.text_frame
    frame.clear()
    frame.word_wrap = True
    frame.margin_left = Inches(margin)
    frame.margin_right = Inches(margin)
    frame.margin_top = Inches(margin)
    frame.margin_bottom = Inches(margin)
    frame.vertical_anchor = valign
    paragraph = frame.paragraphs[0]
    paragraph.alignment = align
    paragraph.space_after = Pt(0)
    run = paragraph.add_run()
    run.text = value
    run.font.name = font
    run.font.size = Pt(size)
    run.font.bold = bold
    run.font.color.rgb = color(fill)
    return box


def bullet_list(slide, items, x, y, w, h, size=14, fill="ink", gap=8):
    box = slide.shapes.add_textbox(Inches(x), Inches(y), Inches(w), Inches(h))
    frame = box.text_frame
    frame.clear()
    frame.word_wrap = True
    frame.margin_left = Inches(0.02)
    frame.margin_right = Inches(0.02)
    frame.margin_top = Inches(0.02)
    frame.margin_bottom = Inches(0.02)
    for index, item in enumerate(items):
        paragraph = frame.paragraphs[0] if index == 0 else frame.add_paragraph()
        paragraph.text = item
        paragraph.level = 0
        paragraph.font.name = "Aptos"
        paragraph.font.size = Pt(size)
        paragraph.font.color.rgb = color(fill)
        paragraph.space_after = Pt(gap)
        paragraph.bullet = True
    return box


def background(slide, fill="paper"):
    rect(slide, 0, 0, WIDTH, HEIGHT, fill)


def header(slide, eyebrow, title, subtitle=None, dark=False):
    fg = "white" if dark else "ink"
    secondary = "mint" if dark else "muted"
    text(slide, eyebrow.upper(), 0.62, 0.42, 10.8, 0.26, 10, "teal", True)
    text(slide, title, 0.62, 0.78, 12.0, 0.58, 28, fg, True, font="Aptos Display")
    if subtitle:
        text(slide, subtitle, 0.64, 1.42, 11.9, 0.45, 13, secondary)


def footer(slide, page, dark=False):
    fg = "mint" if dark else "muted"
    text(slide, "OT PLATFORM  /  MANAGEMENT DEMO", 0.64, 7.12, 8.0, 0.2, 8, fg, True)
    text(slide, f"{page:02d}", 12.15, 7.08, 0.5, 0.24, 9, fg, True, align=PP_ALIGN.RIGHT)


def card(slide, x, y, w, h, title, body, accent="teal", fill="white"):
    rect(slide, x, y, w, h, fill, line="line")
    rect(slide, x, y, 0.07, h, accent)
    text(slide, title, x + 0.22, y + 0.18, w - 0.4, 0.32, 15, "ink", True)
    text(slide, body, x + 0.22, y + 0.62, w - 0.42, h - 0.75, 12, "muted")


def dashboard_slide(deck, blank, page, title, subtitle, image_name, value_title, value_body,
                    caveat, redact_records=False):
    slide = deck.slides.add_slide(blank)
    background(slide)
    header(slide, f"{page - 2:02d}  /  Dashboard walkthrough", title, subtitle)
    image_path = Path(__file__).with_name(image_name)
    slide.shapes.add_picture(str(image_path), Inches(0.65), Inches(2.0), width=Inches(8.45), height=Inches(4.75))
    if redact_records:
        rect(slide, 0.65, 5.58, 8.45, 1.17, "navy2")
        text(slide, "Device-level identifiers omitted from this presentation.",
             0.9, 5.96, 7.9, 0.32, 12, "white", True)
    card(slide, 9.35, 2.0, 3.32, 2.0, value_title, value_body, "teal")
    card(slide, 9.35, 4.22, 3.32, 2.53, "Interpretation", caveat, "orange")
    text(slide, "Illustrative UI capture · not verified client data", 0.68, 6.82, 8.2, 0.18, 9, "muted")
    footer(slide, page)
    return slide


def make_deck():
    deck = Presentation()
    deck.slide_width = Inches(WIDTH)
    deck.slide_height = Inches(HEIGHT)
    blank = deck.slide_layouts[6]

    slide = deck.slides.add_slide(blank)
    background(slide, "navy")
    rect(slide, 0, 0, 0.15, HEIGHT, "teal")
    text(slide, "OT PLATFORM  /  EXECUTIVE DEMO", 0.8, 0.7, 7.2, 0.3, 11, "teal", True)
    text(slide, "Operational clarity\nfor OT security", 0.8, 1.45, 6.8, 1.55, 34, "white", True, font="Aptos Display")
    text(slide, "Bring asset visibility, threat context, audit evidence, and operational risk into one working view.",
         0.84, 3.35, 6.1, 0.85, 18, "mint")
    text(slide, "A management walkthrough of what is visible, what is verified, and where a human decision remains essential.",
         0.84, 5.55, 6.0, 0.8, 12, "white")
    stages = [("01", "ESTATE"), ("02", "EXPOSURE"), ("03", "EVIDENCE"), ("04", "PRIORITY")]
    for index, (number, label) in enumerate(stages):
        y = 1.35 + index * 1.17
        rect(slide, 8.1, y, 4.25, 0.82, "navy2", line="blue")
        text(slide, number, 8.34, y + 0.17, 0.55, 0.3, 12, "orange", True)
        text(slide, label, 9.05, y + 0.15, 2.8, 0.34, 15, "white", True)
        if index < len(stages) - 1:
            rect(slide, 8.52, y + 0.82, 0.025, 0.35, "teal")
    footer(slide, 1, dark=True)

    slide = deck.slides.add_slide(blank)
    background(slide)
    header(slide, "01  /  Management value", "Move from scattered signals to shared context",
           "The platform connects security evidence to the operational questions leaders ask.")
    cards = [
        (0.65, "See the estate", "Live OT device inventory, connectivity, site filters, and device-level context.", "teal"),
        (3.78, "Prioritize exposure", "Vulnerability severity and CVE context alongside asset risk and business impact.", "orange"),
        (6.91, "Explain the evidence", "Source-aware events, local indicator matches, and searchable investigation records.", "blue"),
        (10.04, "Track the work", "Audit assignments, workbook revisions, response dry-runs, and readiness gaps.", "teal"),
    ]
    for x, title, body, accent in cards:
        card(slide, x, 2.15, 2.63, 2.5, title, body, accent)
    rect(slide, 0.65, 5.12, 12.02, 0.92, "mint")
    text(slide, "Leadership outcome", 0.9, 5.34, 2.25, 0.25, 12, "teal", True)
    text(slide, "A clearer view of coverage, exposure, evidence quality, and the next accountable step.",
         3.05, 5.29, 9.25, 0.35, 17, "ink", True)
    footer(slide, 2)

    dashboard_slide(
        deck, blank, 3, "Executive overview", "Estate, risk and feed status in a single landing view.",
        "dashboard-overview.png", "Management value",
        "Quick read of asset counts, connectivity, risk distribution, and feed completeness.",
        "This capture shows demo content and indicates Claroty credentials are required. Validate the tenant connection before using any count as an operational measure.",
        redact_records=True,
    )
    dashboard_slide(
        deck, blank, 4, "OT asset coverage", "Inventory view for finding and inspecting connected OT assets.",
        "dashboard-devices.png", "Operational use",
        "Review asset types, online state and risk; search or filter the inventory and drill into a device.",
        "Loaded counts can be partial while more pages remain. Use site and owner context to prioritize follow-up; do not treat missing data as absence of risk.",
    )
    dashboard_slide(
        deck, blank, 5, "Vulnerability exposure", "Connect device context to related findings and remediation status.",
        "dashboard-vulnerabilities.png", "Management value",
        "Focus reviews on critical/high findings and open exposure, then inspect the linked OT devices.",
        "Live totals require a configured xDome connection. Adjacent MITRE, aging and user analytics are sample data and are labeled in the application.",
    )
    dashboard_slide(
        deck, blank, 6, "SIEM evidence workbench", "Search and summarize evidence stored locally by this platform.",
        "dashboard-siem.png", "Analyst workflow",
        "Sync configured read-only feeds, search normalized local events, and inspect source attribution and evidence health.",
        "Search is limited to locally stored records; it does not query a remote SIEM. A configured credential is not proof of a tested connection.",
    )

    slide = deck.slides.add_slide(blank)
    background(slide)
    header(slide, "05  /  Security audit and governance", "Make review work visible and traceable",
           "Capture assessment ownership, response evidence, review decisions, and revision history.")
    card(slide, 0.65, 2.05, 3.8, 1.65, "Assign", "Create audits from local templates, set an owner and due date, and track status and progress.", "teal")
    card(slide, 4.77, 2.05, 3.8, 1.65, "Evidence", "Record control ratings, supporting evidence, comments, reviewer notes, and response completeness.", "orange")
    card(slide, 8.89, 2.05, 3.8, 1.65, "Review", "Submit versioned workbooks, preserve revision history, and expose progress and response-derived scores.", "blue")
    rect(slide, 0.65, 4.05, 12.02, 2.25, "navy")
    text(slide, "GOVERNANCE USE", 0.95, 4.35, 2.0, 0.28, 11, "teal", True)
    bullet_list(slide, [
        "Use a named control owner and reviewer; document exceptions and acceptance decisions.",
        "Use source labels and immutable workbook revisions to support review and follow-up.",
        "Treat displayed compliance scores as local response calculations, not certification or independent assurance.",
        "The platform records assessment workflow; it does not prove that a control operates effectively.",
    ], 0.95, 4.78, 11.1, 1.35, size=13, fill="white", gap=5)
    footer(slide, 7)

    slide = deck.slides.add_slide(blank)
    background(slide, "navy")
    header(slide, "06  /  Claroty xDome", "OT visibility: what the live connection covers",
           "Claroty xDome is the platform's primary live OT source when credentials are configured.", dark=True)
    claroty_topics = [
        (0.65, 2.05, "Device inventory", "Paged asset records, site context, identifiers, type, manufacturer, connectivity, and risk."),
        (4.77, 2.05, "Vulnerabilities", "Live findings and severity context, with device associations and CVE exposure views."),
        (8.89, 2.05, "Alerts and events", "Live xDome alerts, network/OT activity, and events linked to affected devices where available."),
        (0.65, 4.05, "Investigation context", "Alert details, observed endpoints, site/device details, and reported MITRE technique references."),
        (4.77, 4.05, "Feed health", "Diagnostics, pagination/partial-load indicators, and source labels help distinguish missing from zero."),
        (8.89, 4.05, "Boundaries", "xDome does not supply SOC analysts, local playbook assignments, case workflow, or SLA records."),
    ]
    for x, y, title, body in claroty_topics:
        card(slide, x, y, 3.8, 1.65, title, body, "teal" if y < 3 else "orange")
    text(slide, "Configured credentials are encrypted locally; feed data may be partial until all pages load.",
         0.72, 6.32, 11.8, 0.3, 12, "mint")
    footer(slide, 8, dark=True)

    slide = deck.slides.add_slide(blank)
    background(slide)
    header(slide, "07  /  Risk management", "Prioritize exposure with source-aware context",
           "Use device risk, vulnerability evidence, and governance follow-up to guide review decisions.")
    rect(slide, 0.65, 2.05, 5.75, 3.95, "white", line="line")
    text(slide, "RISK REVIEW INPUTS", 0.95, 2.32, 4.8, 0.3, 11, "teal", True)
    bullet_list(slide, [
        "Live xDome device risk and criticality context",
        "CVE severity, exploitability, aging, and exposure indicators",
        "Risk & Exposures matrix derived from loaded device and vulnerability records",
        "IT risk register, assessment, acceptance, and planning templates",
        "Audit response gaps and assigned follow-up work",
    ], 0.95, 2.8, 4.95, 2.45, size=13, gap=8)
    rect(slide, 6.83, 2.05, 5.84, 3.95, "navy")
    text(slide, "INTERPRETATION", 7.12, 2.32, 4.9, 0.3, 11, "orange", True)
    text(slide, "Production Risk Score", 7.12, 2.86, 4.9, 0.36, 18, "white", True)
    text(slide, "CVSS 25%  ·  Criticality 25%  ·  Impact 20%\nExploitability 10%  ·  Aging 10%  ·  Exposure 10%",
         7.12, 3.4, 4.95, 0.8, 14, "mint")
    text(slide, "The score is a prioritization aid, not a prediction or a substitute for risk acceptance by the accountable owner. The CVE matrix is explicitly derived; sample CAB analytics remain separate.",
         7.12, 4.5, 4.95, 1.15, 12, "white")
    footer(slide, 9)

    slide = deck.slides.add_slide(blank)
    background(slide, "navy")
    header(slide, "08  /  SECUMAT", "Audit workflow and local template library",
           "26 files are available in Audit Templates & Question Bank; spreadsheet templates can be loaded into the audit workflow.", dark=True)
    rect(slide, 0.65, 1.95, 12.02, 0.75, "navy2", line="blue")
    text(slide, "SELECT TEMPLATE  →  ASSIGN OWNER  →  RECORD RATINGS + EVIDENCE  →  REVIEW / SUBMIT VERSION",
         0.9, 2.18, 11.5, 0.25, 12, "white", True, align=PP_ALIGN.CENTER)
    template_columns = [
        [
            "Audit Questions for companies.xlsx",
            "CDR_3rd Party SaaS_CRQ123456_ProjectName__v1.3.0.xlsx",
            "CDR_Enterprise IT_CRQ123456_ProjectName__v1.2.0.xlsx",
            "CDR_Product_CRQ123456_ProjectName__v1.0.0.xlsx",
            "Security-Questionnaire.xlsx",
            "Third Party-Security-Questionnaire-v2.0.xlsx",
            "ZF Security Maturity Secumat_CIS_Controls_Version_8_NIST_ISO27k1_updated Questionnaire.xlsx",
            "ISO 42001 questions for auditing.xlsx",
            "IC-ISO-27001-Auditor-Checklist-10838.xlsx",
            "IC-ISO-27001-Checklist-10838.xlsx",
            "IC-ISO-27001-Compliance-Checklist-10838.xlsx",
            "IC-ISO-27001-Internal-Audit-Schedule-10838.xlsx",
            "IC-ISO-27002-Information-Security-Guidelines-Checklist-10838.xlsx",
        ],
        [
            "IC-ISO-27001-Business-Continuity-Checklist-10838.xlsx",
            "IC-ISO-27001-Risk-Assessment-10838.xlsx",
            "IC-ISO-27001-Sample-Form-10838.xlsx",
            "IC-IT-Risk-Acceptance-Form-11644.xlsx",
            "IC-IT-Risk-Assessment-Checklist-Example-11644.xlsx",
            "IC-IT-Risk-Assessment-Policy-11644_WORD.docx",
            "IC-IT-Risk-Register-11644.xlsx",
            "IT RISK ANALYSIS TEMPLATE.xlsx",
            "IT RISK ASSESSMENT DASHBOARD REPORT TEMPLATE.xlsx",
            "IT RISK ASSESSMENT MATRIX TEMPLATE.xlsx",
            "IT RISK MANAGEMENT planning template.xlsx",
            "IT-Risk-Management-Plan-11644_WORD.docx",
            "SIMPLE IT RISK ASSESSMENT TEMPLATE .xlsx",
        ],
    ]
    for index, (x, items) in enumerate(zip((0.65, 6.83), template_columns)):
        rect(slide, x, 2.92, 5.84, 3.72, "navy2", line="blue")
        text(slide, "QUESTIONNAIRES & STANDARDS" if index == 0 else "RISK, CONTINUITY & GOVERNANCE",
             x + 0.2, 3.08, 5.45, 0.22, 9, "teal" if index == 0 else "orange", True)
        text(slide, "\n".join(f"• {item}" for item in items), x + 0.2, 3.38, 5.45, 3.05,
             8.5, "white", font="Aptos")
    text(slide, "SECUMAT is a local assessment workflow. Scores reflect recorded responses; they are not an external certification.",
         0.72, 6.76, 11.7, 0.2, 9, "mint")
    footer(slide, 10, dark=True)

    slide = deck.slides.add_slide(blank)
    background(slide, "navy")
    header(slide, "02  /  Demo narrative", "A focused five-minute walkthrough",
           "Show one operational story end to end; keep sample and live evidence visibly distinct.", dark=True)
    steps = [
        ("01", "Overview", "Estate, risk, and source labels"),
        ("02", "Devices + CVEs", "Filter an asset and inspect exposure"),
        ("03", "Observable pivot", "Check local indicators and sightings"),
        ("04", "SIEM Workbench", "Sync feeds; search normalized evidence"),
        ("05", "Risk + audit", "Prioritize and show review history"),
    ]
    for index, (number, title, body) in enumerate(steps):
        x = 0.65 + index * 2.48
        rect(slide, x, 2.35, 2.2, 2.15, "navy2", line="blue")
        text(slide, number, x + 0.2, 2.58, 0.5, 0.32, 13, "orange", True)
        text(slide, title, x + 0.2, 3.08, 1.8, 0.56, 16, "white", True)
        text(slide, body, x + 0.2, 3.78, 1.82, 0.62, 11, "mint")
        if index < len(steps) - 1:
            rect(slide, x + 2.2, 3.39, 0.25, 0.035, "teal")
    text(slide, "Demo guardrail", 0.7, 5.34, 2.0, 0.3, 11, "orange", True)
    text(slide, "Use configured sources only. A no-hit local pivot is not proof of safety; unavailable feeds are not zero-risk.",
         2.45, 5.3, 9.8, 0.55, 14, "white")
    footer(slide, 11, dark=True)

    slide = deck.slides.add_slide(blank)
    background(slide)
    header(slide, "03  /  Data and integrations", "Connected where verified; explicit where not",
           "The same workspace supports live OT feeds, manual API sync, and inbound event collection.")
    rect(slide, 0.65, 2.05, 5.82, 3.78, "white", line="line")
    rect(slide, 0.65, 2.05, 5.82, 0.12, "teal")
    text(slide, "LIVE + MANUAL READ-ONLY", 0.92, 2.33, 5.0, 0.3, 11, "teal", True)
    text(slide, "Claroty xDome", 0.92, 2.85, 2.2, 0.32, 17, "ink", True)
    text(slide, "Primary OT feeds when configured", 3.25, 2.88, 2.7, 0.28, 12, "muted")
    text(slide, "Rubrik Security Cloud", 0.92, 3.35, 2.55, 0.32, 16, "ink", True)
    text(slide, "Read-only API activity + audit", 3.25, 3.38, 2.7, 0.28, 12, "muted")
    text(slide, "11 on-demand API feeds", 0.92, 3.94, 4.0, 0.34, 16, "ink", True)
    text(slide, "GitHub · GitLab · MISP · Keycloak · OpenSearch · Wazuh Indexer\nSentinelOne · Defender for Cloud Apps · Prisma Cloud · ONTAP · Cato auditFeed",
         0.92, 4.42, 5.02, 0.85, 12, "muted")
    text(slide, "Encrypted credentials; feed status is reported separately from configuration.",
         0.92, 5.43, 5.0, 0.28, 10, "muted")

    rect(slide, 6.83, 2.05, 5.84, 3.78, "white", line="line")
    rect(slide, 6.83, 2.05, 5.84, 0.12, "orange")
    text(slide, "INGEST + EXTEND", 7.1, 2.33, 5.1, 0.3, 11, "orange", True)
    text(slide, "Inbound event paths", 7.1, 2.85, 4.7, 0.33, 17, "ink", True)
    bullet_list(slide, [
        "Webhook and REST JSON receivers",
        "HTTP bridge for RFC 5424/3164 syslog",
        "Rubrik PD-CEF webhook normalization",
        "29 configurable vendor cards; many remain settings-only",
    ], 7.12, 3.32, 4.95, 1.65, size=12, gap=8)
    text(slide, "Saved credentials do not equal a tested connection.", 7.1, 5.39, 4.9, 0.3, 11, "red", True)
    footer(slide, 12)

    slide = deck.slides.add_slide(blank)
    background(slide)
    header(slide, "04  /  Automation and control", "Make repeatable work easier, not autonomous",
           "Reduce collection and evidence assembly while preserving human review and operational control.")
    rect(slide, 0.65, 2.02, 5.85, 3.46, "white", line="line")
    rect(slide, 0.65, 2.02, 0.08, 3.46, "teal")
    text(slide, "WHAT IT CAN AUTOMATE", 0.95, 2.3, 4.9, 0.3, 11, "teal", True)
    bullet_list(slide, [
        "Refresh configured API feeds and normalize records",
        "Route identifiable alerts and vulnerabilities to local evidence",
        "Match inbound indicators against the local threat index",
        "Maintain audit workbook versions and export reports",
        "Record playbook dry-runs and estimate automation ROI",
    ], 0.95, 2.78, 5.0, 2.35, size=13, gap=7)
    rect(slide, 6.82, 2.02, 5.85, 3.46, "white", line="line")
    rect(slide, 6.82, 2.02, 0.08, 3.46, "orange")
    text(slide, "WHAT IT DOES NOT CLAIM", 7.12, 2.3, 4.9, 0.3, 11, "orange", True)
    bullet_list(slide, [
        "Playbooks are dry-runs; no vendor response action or autonomous remediation executes",
        "Zero Trust policy decisions are simulated; no access or firewall enforcement occurs",
        "Snort rules are indexed and searchable; engine availability may be checked, but rules are not run or deployed",
        "Some analytics are sample data; configured credentials do not confirm a working feed or coverage",
    ], 7.12, 2.78, 4.9, 2.15, size=13, gap=9)
    rect(slide, 0.65, 5.82, 12.02, 0.78, "navy")
    text(slide, "MANAGEMENT ASK", 0.92, 6.05, 1.7, 0.24, 10, "teal", True)
    text(slide, "Nominate data owners, approve least-privilege read accounts, and select the first pilot integration.",
         2.6, 6.0, 9.45, 0.3, 13, "white", True)
    footer(slide, 13)

    deck.core_properties.title = "OT Platform | Executive Demo"
    deck.core_properties.subject = "Management overview of OT security visibility, integrations, and automation"
    deck.core_properties.author = "OT Platform"
    deck.save(OUTPUT)
    check = Presentation(OUTPUT)
    assert len(check.slides) == 13
    return OUTPUT


if __name__ == "__main__":
    print(make_deck())