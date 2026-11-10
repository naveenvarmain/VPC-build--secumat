from pathlib import Path
from PIL import Image, ImageDraw, ImageFont


OUTPUT = Path(__file__).with_name("OT_Platform_Executive_OnePager.png")
WIDTH, HEIGHT = 1600, 900
COLORS = {
    "bg": "#101C2C",
    "panel": "#172A3D",
    "panel2": "#1B3448",
    "teal": "#22A99A",
    "mint": "#BDE9DE",
    "orange": "#EA9653",
    "white": "#FFFFFF",
    "ink": "#182536",
    "muted": "#667789",
    "paper": "#F4F7F9",
    "line": "#D9E1E7",
    "red": "#C76157",
}
FONT_ROOT = Path("C:/Windows/Fonts")
REGULAR = ImageFont.truetype(str(FONT_ROOT / "segoeui.ttf"), 22)
SMALL = ImageFont.truetype(str(FONT_ROOT / "segoeui.ttf"), 18)
TINY = ImageFont.truetype(str(FONT_ROOT / "segoeui.ttf"), 15)
MEDIUM = ImageFont.truetype(str(FONT_ROOT / "seguisb.ttf"), 22)
BOLD = ImageFont.truetype(str(FONT_ROOT / "segoeuib.ttf"), 25)
TITLE = ImageFont.truetype(str(FONT_ROOT / "seguisb.ttf"), 55)


def wrap(draw, value, font, max_width):
    lines = []
    current = ""
    for word in value.split():
        candidate = word if not current else f"{current} {word}"
        if draw.textbbox((0, 0), candidate, font=font)[2] <= max_width:
            current = candidate
        else:
            if current:
                lines.append(current)
            current = word
    if current:
        lines.append(current)
    return lines


def paragraph(draw, value, xy, font, fill, max_width, leading=7, max_lines=None):
    x, y = xy
    lines = wrap(draw, value, font, max_width)
    if max_lines:
        lines = lines[:max_lines]
    for line in lines:
        draw.text((x, y), line, font=font, fill=fill)
        y += font.size + leading
    return y


def pill(draw, x, y, w, label, value, accent):
    draw.rounded_rectangle((x, y, x + w, y + 78), radius=13, fill=COLORS["panel2"], outline="#355064", width=1)
    draw.text((x + 17, y + 11), value, font=BOLD, fill=accent)
    draw.text((x + 17, y + 48), label.upper(), font=TINY, fill=COLORS["mint"])


def main():
    image = Image.new("RGB", (WIDTH, HEIGHT), COLORS["bg"])
    draw = ImageDraw.Draw(image)
    draw.rectangle((0, 0, 13, HEIGHT), fill=COLORS["teal"])

    draw.text((64, 42), "OT PLATFORM  /  MANAGEMENT ONE-PAGER", font=SMALL, fill=COLORS["teal"])
    draw.text((64, 79), "Operational clarity for OT security", font=TITLE, fill=COLORS["white"])
    paragraph(draw, "Bring asset, threat, audit, and risk context into one operations view.",
              (67, 151), REGULAR, COLORS["mint"], 900, leading=3, max_lines=1)
    pill(draw, 1128, 52, 190, "Primary live source", "Claroty xDome", COLORS["teal"])
    pill(draw, 1334, 52, 205, "Manual API feeds", "11 sources", COLORS["orange"])

    # Four management outcomes
    cards = [
        (64, "01", "SEE THE ESTATE", "OT devices, site context, connectivity, and asset detail."),
        (438, "02", "PRIORITIZE EXPOSURE", "CVE severity and device risk help focus review."),
        (812, "03", "INVESTIGATE FASTER", "Search local events, pivot observables, and trace evidence."),
        (1186, "04", "TRACK THE WORK", "Audit assignments, workbook history, and reports."),
    ]
    for x, number, heading, body in cards:
        draw.rounded_rectangle((x, 218, x + 350, 346), radius=12, fill=COLORS["paper"])
        draw.text((x + 18, 234), number, font=MEDIUM, fill=COLORS["teal"])
        draw.text((x + 66, 236), heading, font=MEDIUM, fill=COLORS["ink"])
        paragraph(draw, body, (x + 20, 280), SMALL, COLORS["muted"], 310, leading=3, max_lines=2)

    # Five-minute demo storyline
    draw.text((64, 378), "A FIVE-MINUTE DEMO", font=MEDIUM, fill=COLORS["white"])
    draw.text((332, 381), "One story from OT asset to accountable next step", font=SMALL, fill=COLORS["mint"])
    steps = [
        ("01", "Overview", "Estate + risk"),
        ("02", "Devices / CVEs", "Inspect exposure"),
        ("03", "IOC pivot", "Check local evidence"),
        ("04", "SIEM", "Sync + search"),
        ("05", "Audit", "Review history"),
    ]
    start_x, gap, step_w = 64, 16, 280
    for index, (num, title, caption) in enumerate(steps):
        x = start_x + index * (step_w + gap)
        draw.rounded_rectangle((x, 420, x + step_w, 501), radius=10, fill=COLORS["panel"], outline="#355064", width=1)
        draw.text((x + 14, 432), num, font=MEDIUM, fill=COLORS["orange"])
        draw.text((x + 57, 430), title, font=MEDIUM, fill=COLORS["white"])
        draw.text((x + 57, 465), caption, font=TINY, fill=COLORS["mint"])
        if index < len(steps) - 1:
            draw.line((x + step_w, 460, x + step_w + gap - 3, 460), fill=COLORS["teal"], width=3)

    # Integration coverage
    draw.rounded_rectangle((64, 531, 1472, 665), radius=11, fill=COLORS["panel"], outline="#355064", width=1)
    draw.text((86, 550), "INTEGRATIONS", font=MEDIUM, fill=COLORS["teal"])
    paragraph(draw, "Claroty xDome live feeds when configured; Rubrik read-only API and webhook. Eleven manual read-only API feeds: GitHub, GitLab, MISP, Keycloak, OpenSearch, Wazuh Indexer, SentinelOne, Defender for Cloud Apps, Prisma Cloud, NetApp ONTAP, and Cato auditFeed.",
              (270, 546), SMALL, COLORS["white"], 1155, leading=4, max_lines=3)
    draw.text((270, 624), "Additional event intake: webhook  /  REST JSON  /  syslog HTTP bridge", font=TINY, fill=COLORS["mint"])

    # Automation and guardrails
    draw.rounded_rectangle((64, 690, 756, 822), radius=11, fill=COLORS["paper"])
    draw.text((86, 708), "AUTOMATES REPEATABLE WORK", font=MEDIUM, fill=COLORS["teal"])
    paragraph(draw, "Feed refresh, event normalization and routing, local IOC matching, workbook versioning, report export, playbook dry-runs, and ROI estimates.",
              (86, 747), SMALL, COLORS["ink"], 638, leading=4, max_lines=3)

    draw.rounded_rectangle((780, 690, 1536, 822), radius=11, fill=COLORS["panel2"])
    draw.text((804, 708), "GUARDRAILS", font=MEDIUM, fill=COLORS["orange"])
    paragraph(draw, "No autonomous response or policy enforcement. Some analytics are sample data; credentials alone do not verify coverage. A local no-hit is not proof of safety.",
              (804, 747), SMALL, COLORS["white"], 700, leading=4, max_lines=3)

    draw.text((64, 849), "MANAGEMENT NEXT STEP", font=TINY, fill=COLORS["teal"])
    draw.text((270, 846), "Choose a pilot site, data owner, and least-privilege read accounts.", font=SMALL, fill=COLORS["white"])
    draw.text((1494, 850), "OT PLATFORM", font=TINY, fill=COLORS["mint"], anchor="ra")

    image.save(OUTPUT, format="PNG", optimize=True)
    return OUTPUT


if __name__ == "__main__":
    print(main())
