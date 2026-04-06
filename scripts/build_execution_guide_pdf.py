#!/usr/bin/env python3
"""Build EXECUTION_GUIDE.pdf — step-by-step lab execution using repo examples."""

from __future__ import annotations

from pathlib import Path

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import PageBreak, Paragraph, SimpleDocTemplate, Spacer

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "EXECUTION_GUIDE.pdf"


def main() -> None:
    styles = getSampleStyleSheet()
    title = ParagraphStyle(
        name="DocTitle",
        parent=styles["Heading1"],
        fontSize=18,
        spaceAfter=8,
        textColor=colors.HexColor("#1a1a1a"),
    )
    h2 = ParagraphStyle(
        name="H2",
        parent=styles["Heading2"],
        fontSize=12,
        spaceBefore=10,
        spaceAfter=6,
        textColor=colors.HexColor("#4a148c"),
    )
    body = ParagraphStyle(
        name="Body",
        parent=styles["Normal"],
        fontSize=10,
        leading=14,
    )
    mono = ParagraphStyle(
        name="Mono",
        parent=styles["Code"],
        fontName="Courier",
        fontSize=8.5,
        leading=11,
        leftIndent=8,
        backColor=colors.HexColor("#f5f5f5"),
    )
    small = ParagraphStyle(
        name="Small",
        parent=styles["Normal"],
        fontSize=9,
        leading=12,
        textColor=colors.HexColor("#555555"),
    )

    story: list = []
    story.append(Paragraph("DIY SIEM — Step-by-step execution guide", title))
    story.append(
        Paragraph(
            "Use this document with the examples and scripts already in this repository.",
            small,
        )
    )
    story.append(Spacer(1, 4 * mm))

    sections: list[tuple[str, list[str]]] = [
        (
            "1. Prerequisites",
            [
                "Docker Desktop (or Docker Engine + Compose v2). On Apple Silicon, images are multi-arch.",
                "Optional: allocate ~10–12 GB RAM to Docker on 16 GB Macs (Settings → Resources).",
                "Python 3 for the correlator, dashboard, and Graylog bootstrap (see below).",
            ],
        ),
        (
            "2. Configure environment",
            [
                "From the project root directory, copy the sample environment file if you do not already have .env:",
            ],
        ),
    ]

    for heading, bullets in sections:
        story.append(Paragraph(heading, h2))
        for b in bullets:
            story.append(Paragraph(f"• {b}", body))
        story.append(Spacer(1, 2 * mm))

    story.append(Paragraph("cd to your project folder, then:", small))
    story.append(Spacer(1, 1 * mm))
    story.append(Paragraph("cp -n .env.example .env", mono))
    story.append(Spacer(1, 2 * mm))
    story.append(
        Paragraph(
            "Edit <b>.env</b> if needed: Graylog API URL/credentials, Postgres, Ollama, Flask port. "
            "Default Graylog UI login is <b>admin</b> / <b>admin</b> unless you changed the hash in .env.",
            body,
        )
    )

    story.append(Paragraph("3. Start the stack (Graylog + Postgres)", h2))
    story.append(Paragraph("docker compose up -d", mono))
    story.append(Spacer(1, 2 * mm))
    story.append(
        Paragraph(
            "First start may take 2–5 minutes. Check: <b>docker compose ps</b> and "
            "<b>docker compose logs -f graylog</b> (Ctrl+C to stop following logs).",
            body,
        )
    )
    story.append(
        Paragraph(
            "Open the Graylog web UI: <b>http://127.0.0.1:9000</b>",
            body,
        )
    )

    story.append(Paragraph("4. Linux host only (optional)", h2))
    story.append(
        Paragraph(
            "On bare-metal Linux, OpenSearch may need vm.max_map_count=262144 (see README). "
            "Docker Desktop on macOS usually does not require this.",
            small,
        )
    )

    story.append(Paragraph("5. Create Graylog inputs (examples path)", h2))
    story.append(
        Paragraph(
            "Run the bundled script so Syslog UDP 5140, GELF TCP 12201, and Beats TCP 5044 exist:",
            body,
        )
    )
    story.append(Paragraph("./scripts/bootstrap_inputs.sh", mono))
    story.append(
        Paragraph(
            "Alternatively create inputs manually in Graylog: System → Inputs → Syslog UDP on port 5140, etc.",
            small,
        )
    )

    story.append(Paragraph("6. Python virtual environment", h2))
    story.append(Paragraph("python3 -m venv .venv", mono))
    story.append(Paragraph("source .venv/bin/activate   # Windows: .venv\\Scripts\\activate", mono))
    story.append(Paragraph("pip install -r requirements.txt", mono))

    story.append(Paragraph("7. Streams + extractors (automated)", h2))
    story.append(
        Paragraph(
            "After inputs exist and the Graylog API responds, register extractors and DIY-SIEM streams:",
            body,
        )
    )
    story.append(Paragraph("python -m diy_siem graylog-bootstrap", mono))
    story.append(
        Paragraph(
            "This is idempotent. It adds regex extractors on the Syslog input and streams such as "
            "<b>DIY-SIEM Lab</b>, <b>DIY-SIEM Authentication</b>, and <b>DIY-SIEM Web</b> for messages containing "
            "the <b>diy-siem</b> marker.",
            body,
        )
    )

    story.append(Paragraph("8. Send demo logs (existing scripts)", h2))
    story.append(
        Paragraph(
            "Run from the <b>project root</b>. Scripts send syslog/GELF to localhost inputs matching the compose port map.",
            body,
        )
    )
    demo_cmds = [
        "./scripts/send_test_syslog.sh",
        "./scripts/send_auth_sample_syslog.sh",
        "./scripts/send_realistic_linux_sshd.sh",
        "./scripts/send_realistic_apache_nginx.sh",
        "./scripts/send_realistic_windows_events.sh",
        "./scripts/send_test_gelf.sh",
        "./scripts/send_winlogbeat_style_gelf.sh",
        "./scripts/send_all_demo_logs.sh    # runs hello + realistic batches + GELF samples",
    ]
    for c in demo_cmds:
        story.append(Paragraph(c, mono))
    story.append(Spacer(1, 2 * mm))
    story.append(
        Paragraph(
            "In Graylog: Search → time range <b>Last 5 minutes</b> → query e.g. <b>diy-siem</b>. "
            "Open a message to verify fields. Under Streams, open DIY-SIEM Lab / Authentication / Web to confirm routing.",
            body,
        )
    )

    story.append(PageBreak())
    story.append(Paragraph("9. Correlation, database, and dashboard", h2))
    story.append(
        Paragraph(
            "Examples of CLI commands (Postgres must be reachable; tables created on first DB init):",
            body,
        )
    )
    cli_cmds = [
        "python -m diy_siem test-db          # optional test row",
        "python -m diy_siem poll             # search Graylog, insert alerts (+ Ollama if enabled)",
        "python -m diy_siem list-alerts",
        "python -m diy_siem serve           # dashboard http://127.0.0.1:5000/",
    ]
    for c in cli_cmds:
        story.append(Paragraph(c, mono))
    story.append(
        Paragraph(
            "Send at least one message that matches your correlation rules (e.g. containing <b>diy-siem</b> per README) "
            "before <b>poll</b> so there is data to match.",
            small,
        )
    )

    story.append(Paragraph("10. Ollama (optional)", h2))
    story.append(
        Paragraph(
            "Install Ollama locally, pull the model named in <b>OLLAMA_MODEL</b> in .env (e.g. llama3.2). "
            "If Ollama is offline, set <b>OLLAMA_ENABLED=false</b> so poll still creates alerts without LLM calls.",
            body,
        )
    )

    story.append(Paragraph("11. Dashboard in Docker (optional)", h2))
    story.append(
        Paragraph(
            "Instead of <b>python -m diy_siem serve</b> on the host, you can run the dashboard container:",
            body,
        )
    )
    story.append(Paragraph("docker compose --profile dashboard up -d --build", mono))
    story.append(Paragraph("Then open http://127.0.0.1:5000/", body))

    story.append(Paragraph("12. Example configs for real agents (repo files)", h2))
    story.append(
        Paragraph(
            "These files illustrate how to point real forwarders at this lab; they are not auto-run by the scripts above:",
            body,
        )
    )
    ex_files = [
        "examples/rsyslog-forward-graylog.conf — rsyslog template (commented)",
        "examples/filebeat-graylog.yml — Filebeat → Logstash/Beats input",
        "examples/winlogbeat-graylog.yml — Winlogbeat → Beats TCP 5044",
    ]
    for line in ex_files:
        story.append(Paragraph(f"• {line}", body))
    story.append(
        Paragraph(
            "Ensure <b>bootstrap_inputs.sh</b> created Beats TCP 5044 before using Filebeat/Winlogbeat.",
            small,
        )
    )

    story.append(Paragraph("13. Ports (localhost)", h2))
    story.append(
        Paragraph(
            "9000 Graylog UI · 5140 syslog · 12201 GELF · 5044 Beats · 5432 Postgres · 5000 Flask (default).",
            body,
        )
    )

    story.append(Spacer(1, 6 * mm))
    story.append(
        Paragraph(
            "For troubleshooting (macOS Docker credential helper, native Graylog alerts, correlation ideas), see README.md.",
            small,
        )
    )

    doc = SimpleDocTemplate(
        str(OUT),
        pagesize=A4,
        leftMargin=18 * mm,
        rightMargin=18 * mm,
        topMargin=14 * mm,
        bottomMargin=16 * mm,
        title="DIY SIEM — Execution guide",
    )
    doc.build(story)
    print(f"Wrote {OUT}")


if __name__ == "__main__":
    main()
