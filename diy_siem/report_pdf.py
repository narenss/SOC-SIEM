"""Generate a PDF export of dashboard stats + recent alerts (ReportLab)."""

from __future__ import annotations

from datetime import datetime, timezone
from io import BytesIO
from zoneinfo import ZoneInfo

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

from diy_siem import db

_IST = ZoneInfo("Asia/Kolkata")


def _ist_label(dt: datetime | None) -> str:
    if dt is None:
        return "—"
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(_IST).strftime("%Y-%m-%d %H:%M:%S IST")


def _alert_time_ist(created: object) -> str:
    if created is None:
        return "—"
    if isinstance(created, datetime):
        return _ist_label(created)
    if isinstance(created, str):
        s = created.strip().replace("Z", "+00:00")
        try:
            return _ist_label(datetime.fromisoformat(s))
        except ValueError:
            return _esc(created, 80)
    return _esc(str(created), 80)


def _esc(s: str | None, max_len: int = 2000) -> str:
    if not s:
        return "—"
    t = str(s).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    if len(t) > max_len:
        t = t[: max_len - 1] + "…"
    return t


def build_alerts_pdf_bytes() -> bytes:
    stats = db.alert_stats()
    alerts = db.list_alerts_with_explanations(limit=200)

    buf = BytesIO()
    doc = SimpleDocTemplate(
        buf,
        pagesize=A4,
        leftMargin=14 * mm,
        rightMargin=14 * mm,
        topMargin=12 * mm,
        bottomMargin=14 * mm,
        title="Amrita SIEM — Alert report",
    )
    styles = getSampleStyleSheet()
    title_style = ParagraphStyle(
        name="Title",
        parent=styles["Heading1"],
        fontSize=16,
        spaceAfter=6,
        textColor=colors.HexColor("#6d102c"),
    )
    body = ParagraphStyle(
        name="Body",
        parent=styles["Normal"],
        fontSize=9,
        leading=11,
    )
    small = ParagraphStyle(
        name="Small",
        parent=styles["Normal"],
        fontSize=8,
        leading=10,
        textColor=colors.HexColor("#444444"),
    )

    story: list = []
    story.append(Paragraph("Amrita SIEM — Alert report", title_style))
    story.append(
        Paragraph(
            f"Generated: {_ist_label(datetime.now(timezone.utc))}",
            small,
        )
    )
    story.append(Spacer(1, 4 * mm))

    total = stats.get("total_alerts", 0)
    with_ai = stats.get("alerts_with_explanation", 0)
    by_rule = stats.get("by_rule") or []
    by_sev = stats.get("by_severity") or []

    summary_lines = [
        f"<b>Total alerts:</b> {total}",
        f"<b>With AI explanation:</b> {with_ai} of {total}",
        "<b>By rule:</b> "
        + ("; ".join(f"{_esc(r.get('rule_name'))}: {r.get('count', 0)}" for r in by_rule) or "—"),
        "<b>By severity:</b> "
        + ("; ".join(f"{_esc(s.get('severity'))}: {s.get('count', 0)}" for s in by_sev) or "—"),
    ]
    for line in summary_lines:
        story.append(Paragraph(line, body))
    story.append(Spacer(1, 6 * mm))
    story.append(Paragraph("<b>Recent alerts</b>", styles["Heading2"]))
    story.append(Spacer(1, 2 * mm))

    # Table: Time | Rule | Severity | Summary | AI (wrapped)
    hdr = ["Time (IST)", "Rule", "Sev", "Summary", "AI explanation"]
    data = [[Paragraph(f"<b>{h}</b>", body) for h in hdr]]
    for a in alerts:
        tlab = _alert_time_ist(a.get("created_at"))
        data.append(
            [
                Paragraph(_esc(tlab, 80), body),
                Paragraph(_esc(a.get("rule_name"), 120), body),
                Paragraph(_esc(a.get("severity"), 40), body),
                Paragraph(_esc(a.get("summary"), 800), body),
                Paragraph(_esc(a.get("ai_explanation"), 4000), body),
            ]
        )

    if len(data) == 1:
        data.append(
            [
                Paragraph("—", body),
                Paragraph("—", body),
                Paragraph("—", body),
                Paragraph("<i>No alerts in database.</i>", body),
                Paragraph("—", body),
            ]
        )

    col_widths = [32 * mm, 28 * mm, 16 * mm, 42 * mm, 62 * mm]
    tbl = Table(data, colWidths=col_widths, repeatRows=1)
    tbl.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#f5e8ec")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.HexColor("#6d102c")),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("FONTSIZE", (0, 0), (-1, -1), 8),
                ("GRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#cccccc")),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("LEFTPADDING", (0, 0), (-1, -1), 4),
                ("RIGHTPADDING", (0, 0), (-1, -1), 4),
                ("TOPPADDING", (0, 0), (-1, -1), 3),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
            ]
        )
    )
    story.append(tbl)

    doc.build(story)
    return buf.getvalue()
