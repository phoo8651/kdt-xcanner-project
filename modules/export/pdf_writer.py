#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
pdf_writer.py
Unified PDF report generator for Xcanner.

Features
- Netscan Enhanced TXT -> PDF (build_pdf_from_txt)
- Masscan CSV -> PDF (build_pdf_from_csv)
- Auto-discovery helpers (_find_latest_txt, _find_latest_csv)
- Consistent visual style and shared utilities
- CLI with subcommands:
    * netscan  : Build from *_enhanced.txt (auto-detect if omitted)
    * masscan  : Build from masscan CSV (auto-detect if omitted)

Dependencies
    pip install reportlab
"""

from __future__ import annotations

import argparse
import csv
import os
import re
import sys
from datetime import datetime
from collections import Counter, defaultdict
from glob import glob
from itertools import islice
from typing import Any, Dict, List, Tuple, Optional

# ReportLab imports
try:
    from reportlab.lib.pagesizes import A4, landscape, portrait
    from reportlab.lib import colors
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import mm
    from reportlab.platypus import (
        SimpleDocTemplate,
        Paragraph,
        Spacer,
        LongTable,
        Table,
        TableStyle,
        Image,
        ListFlowable,
        ListItem,
        Flowable,
    )
    from reportlab.pdfgen.canvas import Canvas
except Exception as e:
    print("[!] reportlab is required. Install: pip install reportlab", file=sys.stderr)
    raise

# ---------------------------------------------------------------------------
# Shared palette and primitives
# ---------------------------------------------------------------------------
PALETTE = {
    "ink": colors.HexColor("#0b1220"),
    "muted": colors.HexColor("#6b7280"),
    "chip_bg": colors.HexColor("#eef2ff"),
    "chip_border": colors.HexColor("#c7d2fe"),
    "banner": colors.HexColor("#1f2937"),
    "banner_accent": colors.HexColor("#6366f1"),
    "row_alt": colors.HexColor("#f9fafb"),
    "table_header": colors.HexColor("#111827"),
    "card_border": colors.HexColor("#e5e7eb"),
}


class SectionBanner(Flowable):
    """A bold section banner with a colored accent bar."""

    def __init__(self, text: str, width: float = 0, height: float = 16):
        super().__init__()
        self.text = text
        self.w = width
        self.h = height

    def wrap(self, availWidth, availHeight):
        self.w = availWidth
        return self.w, self.h

    def draw(self):
        c = self.canv
        c.saveState()
        c.setFillColor(PALETTE["banner"])
        c.rect(0, 0, self.w, self.h, stroke=0, fill=1)
        c.setFillColor(PALETTE["banner_accent"])
        c.rect(0, 0, 4, self.h, stroke=0, fill=1)
        c.setFillColor(colors.white)
        c.setFont("Helvetica-Bold", 10)
        c.drawString(8, 3, self.text)
        c.restoreState()


def _footer(canvas: Canvas, doc):
    canvas.saveState()
    footer_text = (
        f"Xcanner • {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} • Page {doc.page}"
    )
    canvas.setFont("Helvetica", 8)
    canvas.setFillColor(PALETTE["muted"])
    canvas.drawRightString(200 * mm, 10 * mm, footer_text)
    canvas.restoreState()


def _kv_table(pairs: List[Tuple[str, str]], col_widths=None):
    data = [["Key", "Value"]] + pairs
    t = Table(data, colWidths=col_widths, hAlign="LEFT", repeatRows=1)
    t.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), PALETTE["table_header"]),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("FONTSIZE", (0, 0), (-1, 0), 10),
                ("FONTSIZE", (0, 1), (-1, -1), 9),
                ("LEADING", (0, 1), (-1, -1), 11),
                ("INNERGRID", (0, 0), (-1, -1), 0.25, colors.lightgrey),
                ("BOX", (0, 0), (-1, -1), 0.6, PALETTE["card_border"]),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("LEFTPADDING", (0, 0), (-1, -1), 6),
                ("RIGHTPADDING", (0, 0), (-1, -1), 6),
                ("TOPPADDING", (0, 0), (-1, -1), 4),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ]
        )
    )
    return t


def _simple_table(
    head: List[str], rows: List[List[Any]], col_widths=None, zebra=True, long=False
):
    data = [head] + rows
    T = LongTable if long else Table
    t = T(data, colWidths=col_widths, repeatRows=1, hAlign="LEFT")
    style = [
        ("BACKGROUND", (0, 0), (-1, 0), PALETTE["table_header"]),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, 0), 9),
        ("FONTSIZE", (0, 1), (-1, -1), 8),
        ("LEADING", (0, 1), (-1, -1), 10),
        ("INNERGRID", (0, 0), (-1, -1), 0.25, colors.lightgrey),
        ("BOX", (0, 0), (-1, -1), 0.6, PALETTE["card_border"]),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 4),
        ("RIGHTPADDING", (0, 0), (-1, -1), 4),
        ("TOPPADDING", (0, 0), (-1, -1), 2),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 2),
    ]
    if zebra and len(rows) > 0:
        style.append(
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [PALETTE["row_alt"], colors.white])
        )
    t.setStyle(TableStyle(style))
    return t


def _shorten(txt: Any, max_chars=300) -> str:
    if txt is None:
        return ""
    s = str(txt)
    return (s[: max_chars - 1] + "…") if len(s) > max_chars else s


# ---------------------------------------------------------------------------
# Netscan Enhanced TXT implementation
# ---------------------------------------------------------------------------
def _parse_enhanced_txt(path: str) -> Dict[str, Any]:
    with open(path, "r", encoding="utf-8") as f:
        txt = f.read()

    lines = [ln.rstrip() for ln in txt.splitlines()]
    blob = "\n".join(lines)

    ctx: Dict[str, Any] = {}
    m = re.search(r"Target\s*:\s*(.+)", blob)
    ctx["Target"] = m.group(1).strip() if m else ""
    m = re.search(r"Ports Spec\s*:\s*\[(.+?)\]", blob)
    ctx["Ports Spec"] = m.group(1).strip() if m else ""
    m = re.search(r"Protocols\s*:\s*(.+)", blob)
    ctx["Protocols"] = m.group(1).strip() if m else ""
    m = re.search(r"TCP mode\s*:\s*(.+)", blob)
    ctx["TCP mode"] = m.group(1).strip() if m else ""
    m = re.search(r"Interface\s*:\s*(.+)", blob)
    ctx["Interface"] = m.group(1).strip() if m else ""
    m = re.search(r"Capture \(pcap\)\s*:\s*(.+)", blob)
    ctx["Capture"] = m.group(1).strip() if m else ""
    m = re.search(r"Generated at\s*:\s*([0-9\-:]+)", blob)
    ctx["Generated at"] = m.group(1).strip() if m else ""

    # TCP
    tcp = {"states": {}, "open": [], "closed": []}
    m = re.search(r"-- TCP --\s*States\s*:\s*\{([^}]+)\}", blob, re.S)
    if m:
        d = m.group(1)
        for kv in d.split(","):
            if ":" in kv:
                k, v = kv.split(":", 1)
                try:
                    tcp["states"][k.strip(" '\"")] = int(re.sub(r"\D", "", v) or "0")
                except Exception:
                    tcp["states"][k.strip(" '\"")] = 0
    m = re.search(r"Open ports\s*:\s*\[([^\]]*)\]", blob)
    if m:
        tcp["open"] = [p.strip() for p in m.group(1).split(",") if p.strip()]
    m = re.search(r"Closed ports\s*:\s*\[([^\]]*)\]", blob)
    if m:
        tcp["closed"] = [p.strip() for p in m.group(1).split(",") if p.strip()]

    # UDP
    udp = {"states": {}, "open": [], "closed": []}
    m = re.search(r"-- UDP --\s*States\s*:\s*\{([^}]+)\}", blob, re.S)
    if m:
        d = m.group(1)
        for kv in d.split(","):
            if ":" in kv:
                k, v = kv.split(":", 1)
                try:
                    udp["states"][k.strip(" '\"")] = int(re.sub(r"\D", "", v) or "0")
                except Exception:
                    udp["states"][k.strip(" '\"")] = 0
    m = re.search(r"-- UDP --.*?Open ports\s*:\s*(.+)", blob, re.S)
    if m:
        s = m.group(1).splitlines()[0].strip()
        if s != "-" and s.startswith("["):
            udp["open"] = [p.strip() for p in s.strip("[]").split(",") if p.strip()]
    m = re.search(r"-- UDP --.*?Closed ports\s*:\s*\[([^\]]*)\]", blob, re.S)
    if m:
        udp["closed"] = [p.strip() for p in m.group(1).split(",") if p.strip()]

    # ICMP
    m = re.search(r"-- ICMP --\s*Host status\s*:\s*(.+)", blob)
    icmp = {"host_status": m.group(1).strip() if m else ""}

    # DNS lines
    dns = []
    for line in lines:
        if line.strip().startswith("- resolver="):
            rr = {}
            for part in line.split():
                for key in ("resolver", "qname", "qtype", "ok"):
                    if part.startswith(key + "="):
                        rr[key] = part.split("=", 1)[1]
            if rr:
                dns.append(rr)

    # OS best guess
    m = re.search(
        r"-- OS best guess --\s*source=(.+?)\s+label=(.+?)\s+score=([0-9.]+)",
        blob,
        re.S,
    )
    os_guess = {"source": "", "label": "", "score": ""}
    if m:
        os_guess = {
            "source": m.group(1).strip(),
            "label": m.group(2).strip(),
            "score": m.group(3).strip(),
        }

    # OS feature hints
    hints = []
    in_hints = False
    for line in lines:
        if line.strip().startswith("-- OS feature hints"):
            in_hints = True
            continue
        if in_hints:
            if not line.strip().startswith("- port "):
                continue
            m = re.match(r"- port\s+(\d+):\s*(.*)", line.strip())
            if m:
                port = m.group(1)
                rest = m.group(2)
                row = {"port": port}
                for kv in rest.split():
                    if "=" in kv:
                        k, v = kv.split("=", 1)
                        row[k] = v
                hints.append(row)

    # Assets total
    assets_total = None
    m = re.search(r"-- Asset Inventory --\s*Total assets identified:\s*(\d+)", blob)
    if m:
        try:
            assets_total = int(m.group(1))
        except Exception:
            assets_total = None

    # Recommendations
    recos = []
    rec_block = re.search(
        r"-- Security Recommendations --(.+?)(?:Enhanced report generated at|$)",
        blob,
        re.S,
    )
    if rec_block:
        for line in rec_block.group(1).splitlines():
            line = line.strip()
            if not line:
                continue
            line = re.sub(r"^\d+\.\s*", "", line)
            recos.append(line)

    return {
        "context": ctx,
        "tcp": tcp,
        "udp": udp,
        "icmp": icmp,
        "dns": dns,
        "os_guess": os_guess,
        "hints": hints,
        "assets_total": assets_total,
        "recommendations": recos,
        "raw_text": txt,
    }


def _find_latest_txt(search_dir: str = "./result") -> Optional[str]:
    sd = os.path.abspath(search_dir)
    if not os.path.isdir(sd):
        return None
    latest = None
    latest_e = None
    for p in glob(os.path.join(sd, "*.txt")):
        try:
            mt = os.path.getmtime(p)
        except OSError:
            continue
        if latest is None or mt > latest[0]:
            latest = (mt, p)
        if "enhanced" in os.path.basename(p).lower():
            if latest_e is None or mt > latest_e[0]:
                latest_e = (mt, p)
    return latest_e[1] if latest_e else (latest[1] if latest else None)


def _compute_top_ports(parsed: Dict[str, Any], limit=10):
    ports: Dict[str, int] = {}
    for p in parsed.get("tcp", {}).get("open") or []:
        ports[p] = ports.get(p, 0) + 1
    for p in parsed.get("udp", {}).get("open") or []:
        ports[p] = ports.get(p, 0) + 1
    items = sorted(
        ports.items(),
        key=lambda x: (-x[1], int(x[0]) if str(x[0]).isdigit() else 10**9),
    )
    return items[:limit]


def build_pdf_from_txt(
    input_txt: str,
    output_pdf: str,
    landscape_mode: bool = True,
    title: str = "Xcanner Report - Netscan",
    logo_path: Optional[str] = None,
) -> str:
    data = _parse_enhanced_txt(input_txt)

    pagesize = landscape(A4) if landscape_mode else portrait(A4)
    doc = SimpleDocTemplate(
        output_pdf,
        pagesize=pagesize,
        rightMargin=20,
        leftMargin=20,
        topMargin=24,
        bottomMargin=24,
        title=title,
        author="Xcanner",
        subject="NetScan Enhanced Text Report",
        creator="Xcanner",
    )
    styles = getSampleStyleSheet()
    styles.add(
        ParagraphStyle(name="Small", fontSize=8, leading=10, textColor=PALETTE["muted"])
    )
    styles.add(ParagraphStyle(name="H1", fontSize=20, leading=24))
    styles.add(ParagraphStyle(name="H2", fontSize=13, leading=16))

    story: List[Any] = []

    # Optional logo
    if logo_path and os.path.exists(logo_path):
        try:
            img = Image(logo_path)
            max_w = doc.width * 0.5
            if img.drawWidth > max_w:
                r = max_w / float(img.drawWidth)
                img.drawWidth = max_w
                img.drawHeight = img.drawHeight * r
            story.append(img)
            story.append(Spacer(1, 10))
        except Exception:
            pass

    story.append(Paragraph(f"<b>{title}</b>", styles["H1"]))
    story.append(Spacer(1, 4))
    story.append(
        Paragraph(
            "Generated: %s" % datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            styles["Small"],
        )
    )
    story.append(
        Paragraph("Source TXT: %s" % os.path.abspath(input_txt), styles["Small"])
    )
    story.append(Spacer(1, 10))

    # 1) Summary
    story.append(SectionBanner("Summary"))
    story.append(Spacer(1, 4))
    ctx = data["context"]
    summary_pairs = [
        ("Target", ctx.get("Target", "")),
        ("Ports Spec", ctx.get("Ports Spec", "")),
        ("Protocols", ctx.get("Protocols", "")),
        ("TCP mode", ctx.get("TCP mode", "")),
        ("Interface", ctx.get("Interface", "")),
        ("Capture (pcap)", ctx.get("Capture", "")),
        ("Generated at", ctx.get("Generated at", "")),
    ]
    story.append(_kv_table(summary_pairs, col_widths=[60 * mm, None]))
    story.append(Spacer(1, 8))

    # 2) Top Ports
    story.append(SectionBanner("Top Ports"))
    story.append(Spacer(1, 4))
    tp = _compute_top_ports(data) or []
    story.append(
        _simple_table(
            ["Port", "Count"],
            [[str(p), str(c)] for p, c in tp] or [["-", "-"]],
            col_widths=[30 * mm, None],
        )
    )
    story.append(Spacer(1, 8))

    # 3) TCP
    story.append(SectionBanner("TCP"))
    story.append(Spacer(1, 4))
    tcp_states = (
        ", ".join(
            "%s:%s" % (k, v)
            for k, v in (data.get("tcp", {}).get("states", {}) or {}).items()
        )
        or "-"
    )
    story.append(_kv_table([("States", tcp_states)], col_widths=[40 * mm, None]))
    story.append(Spacer(1, 4))
    story.append(
        _simple_table(
            ["Open Ports"],
            [[p] for p in (data.get("tcp", {}).get("open") or ["-"])],
            col_widths=[None],
        )
    )
    story.append(Spacer(1, 4))
    story.append(
        _simple_table(
            ["Closed Ports"],
            [[p] for p in (data.get("tcp", {}).get("closed") or ["-"])],
            col_widths=[None],
        )
    )
    story.append(Spacer(1, 8))

    # 4) UDP
    story.append(SectionBanner("UDP"))
    story.append(Spacer(1, 4))
    udp_states = (
        ", ".join(
            "%s:%s" % (k, v)
            for k, v in (data.get("udp", {}).get("states", {}) or {}).items()
        )
        or "-"
    )
    story.append(_kv_table([("States", udp_states)], col_widths=[40 * mm, None]))
    story.append(Spacer(1, 4))
    story.append(
        _simple_table(
            ["Open Ports"],
            [[p] for p in (data.get("udp", {}).get("open") or ["-"])],
            col_widths=[None],
        )
    )
    story.append(Spacer(1, 4))
    story.append(
        _simple_table(
            ["Closed Ports"],
            [[p] for p in (data.get("udp", {}).get("closed") or ["-"])],
            col_widths=[None],
        )
    )
    story.append(Spacer(1, 8))

    # 5) ICMP
    story.append(SectionBanner("ICMP"))
    story.append(Spacer(1, 4))
    story.append(
        _kv_table(
            [("Host status", data.get("icmp", {}).get("host_status", "-"))],
            col_widths=[40 * mm, None],
        )
    )
    story.append(Spacer(1, 8))

    # 6) DNS
    story.append(SectionBanner("DNS Checks"))
    story.append(Spacer(1, 4))
    dns_rows = [
        [
            rr.get("resolver", ""),
            rr.get("qname", ""),
            rr.get("qtype", ""),
            rr.get("ok", ""),
        ]
        for rr in (data.get("dns") or [])
    ]
    story.append(
        _simple_table(
            ["Resolver", "Qname", "Qtype", "OK"],
            dns_rows or [["-", "-", "-", "-"]],
            col_widths=[35 * mm, None, 20 * mm, 15 * mm],
        )
    )
    story.append(Spacer(1, 8))

    # 7) OS best guess
    story.append(SectionBanner("OS Best Guess"))
    story.append(Spacer(1, 4))
    og = data.get("os_guess", {})
    story.append(
        _kv_table(
            [
                ("Source", og.get("source", "-")),
                ("Label", og.get("label", "-")),
                ("Score", og.get("score", "-")),
            ],
            col_widths=[40 * mm, None],
        )
    )
    story.append(Spacer(1, 8))

    # 8) OS feature hints
    story.append(SectionBanner("OS Feature Hints"))
    story.append(Spacer(1, 4))
    hint_head = ["port", "ttl", "win", "ops", "mss", "wscale", "sack"]
    hint_rows = [[h.get(k, "") for k in hint_head] for h in (data.get("hints") or [])]
    story.append(
        _simple_table(
            [c.upper() for c in hint_head],
            hint_rows or [["-"] * len(hint_head)],
            col_widths=[18 * mm, 18 * mm, 22 * mm, 22 * mm, 22 * mm, 22 * mm, 22 * mm],
        )
    )
    story.append(Spacer(1, 8))

    # 9) Enhanced analysis
    story.append(SectionBanner("Enhanced Analysis"))
    story.append(Spacer(1, 4))
    pairs = []
    if data.get("assets_total") is not None:
        pairs.append(("Total assets identified", str(data["assets_total"])))
    story.append(_kv_table(pairs or [("Note", "-")], col_widths=[60 * mm, None]))
    recs = data.get("recommendations") or []
    if recs:
        story.append(Spacer(1, 4))
        story.append(Paragraph("<b>Security Recommendations</b>", styles["H2"]))
        items = [ListItem(Paragraph(r, styles["Normal"])) for r in recs]
        story.append(ListFlowable(items, bulletType="1", start="1"))
    story.append(Spacer(1, 8))

    doc.build(story, onFirstPage=_footer, onLaterPages=_footer)
    return output_pdf


# ---------------------------------------------------------------------------
# Masscan CSV implementation
# ---------------------------------------------------------------------------
BASE_COLS = ["ip", "port", "protocol", "state", "source"]


def _split_columns(header: List[str]):
    base = [c for c in BASE_COLS if c in header]
    ctx = [c for c in header if c not in base]
    return base, ctx


def _read_csv(path: str, max_rows: Optional[int] = None):
    rows: List[Dict[str, str]] = []
    with open(path, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        header = reader.fieldnames or []
        base_cols, ctx_cols = _split_columns(header)
        for i, row in enumerate(reader):
            rows.append(row)
            if max_rows and i + 1 >= max_rows:
                break
    return header, base_cols, ctx_cols, rows


def _extract_context(ctx_cols: List[str], rows: List[Dict[str, str]]):
    ctx: Dict[str, str] = {}
    if not rows:
        return ctx
    for c in ctx_cols:
        val = rows[0].get(c, "")
        if not val:
            for r in rows[1:]:
                val = r.get(c, "")
                if val:
                    break
        if val != "":
            ctx[c] = val
    return ctx


def _compute_stats(base_cols: List[str], rows: List[Dict[str, str]]):
    host_set = set()
    ports_counter = Counter()
    proto_counter = Counter()
    state_counter = Counter()
    host_ports = defaultdict(set)

    for r in rows:
        ip = r.get("host") or r.get("ip") or r.get("target") or ""
        port = str(r.get("port", "")).strip()
        proto = (r.get("protocol") or "").lower()
        state = (r.get("state") or "").lower()

        if ip:
            host_set.add(ip)
        if port:
            ports_counter[port] += 1
        if proto:
            proto_counter[proto] += 1
        if state:
            state_counter[state] += 1
        if ip and port:
            host_ports[ip].add(port)

    top_ports = ports_counter.most_common(10)
    per_host_counts = [len(v) for v in host_ports.values()]
    avg_ports_per_host = (
        round(sum(per_host_counts) / len(per_host_counts), 2)
        if per_host_counts
        else 0.0
    )

    return {
        "total_findings": len(rows),
        "unique_hosts": len(host_set),
        "unique_ports": len(ports_counter),
        "protocol_breakdown": dict(proto_counter),
        "state_breakdown": dict(state_counter),
        "top_ports": top_ports,
        "avg_ports_per_host": avg_ports_per_host,
    }


def _estimate_col_widths(doc_width, header, rows, min_w=58, max_w=220, sample_rows=300):
    """Estimate column widths using character counts from a sample of rows."""
    char_counts = [max(len(str(h)), 3) for h in header]

    for r in islice(rows, 0, sample_rows):
        for idx, col in enumerate(header):
            val = str(r.get(col, ""))
            char_counts[idx] = max(char_counts[idx], len(val))

    raw_widths = [max(min_w, min(max_w, int(c * 5.5))) for c in char_counts]
    total = sum(raw_widths)

    if total <= doc_width:
        return raw_widths

    scale = doc_width / float(total)
    scaled = [max(min_w, min(max_w, int(w * scale))) for w in raw_widths]
    diff = doc_width - sum(scaled)
    if abs(diff) >= 1:
        scaled[-1] = max(min_w, min(max_w, scaled[-1] + int(diff)))
    return scaled


def build_pdf_from_csv(
    input_csv: str,
    output_pdf: str,
    landscape_mode: bool = False,
    title: str = "Xcanner Masscan Report",
    logo_path: Optional[str] = None,
    max_rows: Optional[int] = None,
    compact: bool = False,
) -> str:
    header, base_cols, ctx_cols, rows = _read_csv(input_csv, max_rows=max_rows)
    ctx = _extract_context(ctx_cols, rows)
    stats = _compute_stats(base_cols, rows)

    pagesize = landscape(A4) if landscape_mode else portrait(A4)
    doc = SimpleDocTemplate(
        output_pdf,
        pagesize=pagesize,
        rightMargin=20,
        leftMargin=20,
        topMargin=24,
        bottomMargin=24,
        title=title,
        author="Xcanner",
        subject="Network Scan Report (Masscan CSV)",
        creator="Xcanner",
    )
    styles = getSampleStyleSheet()
    styles.add(
        ParagraphStyle(name="Small", fontSize=8, leading=10, textColor=PALETTE["muted"])
    )
    styles.add(
        ParagraphStyle(
            name="Cell",
            fontSize=8 if compact else 9,
            leading=10 if compact else 11,
            allowWidows=1,
            allowOrphans=1,
            wordWrap="CJK",
        )
    )
    styles.add(ParagraphStyle(name="H1", fontSize=20, leading=24))
    styles.add(ParagraphStyle(name="H2", fontSize=13, leading=16))

    story: List[Any] = []

    # Optional logo
    if logo_path and os.path.exists(logo_path):
        try:
            img = Image(logo_path)
            max_w = doc.width * 0.5
            if img.drawWidth > max_w:
                ratio = max_w / float(img.drawWidth)
                img.drawWidth = max_w
                img.drawHeight = img.drawHeight * ratio
            story.append(img)
            story.append(Spacer(1, 10))
        except Exception:
            pass

    story.append(Paragraph(f"<b>{title}</b>", styles["H1"]))
    story.append(Spacer(1, 4))
    story.append(
        Paragraph(
            f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            styles["Small"],
        )
    )
    story.append(
        Paragraph(f"Source CSV: {os.path.abspath(input_csv)}", styles["Small"])
    )
    story.append(Spacer(1, 10))

    # Summary
    story.append(SectionBanner("Summary"))
    story.append(Spacer(1, 4))
    proto_str = (
        ", ".join(f"{k}:{v}" for k, v in stats["protocol_breakdown"].items()) or "-"
    )
    state_str = (
        ", ".join(f"{k}:{v}" for k, v in stats["state_breakdown"].items()) or "-"
    )
    summary_pairs = [
        ("Total Findings", str(stats["total_findings"])),
        ("Unique Hosts", str(stats["unique_hosts"])),
        ("Unique Ports", str(stats["unique_ports"])),
        ("Avg Ports / Host", str(stats["avg_ports_per_host"])),
        ("Protocol Breakdown", proto_str),
        ("State Breakdown", state_str),
    ]
    story.append(_kv_table(summary_pairs, col_widths=[60 * mm, None]))
    story.append(Spacer(1, 8))

    if ctx:
        story.append(SectionBanner("Run Context (from run.py options)"))
        story.append(Spacer(1, 4))
        ctx_pairs = [(k, _shorten(v, 200)) for k, v in ctx.items()]
        story.append(_kv_table(ctx_pairs, col_widths=[60 * mm, None]))
        story.append(Spacer(1, 8))

    # Top Ports
    story.append(SectionBanner("Top Ports"))
    story.append(Spacer(1, 4))
    top_rows = [[str(p), str(cnt)] for p, cnt in (stats["top_ports"] or [])]
    story.append(
        _simple_table(
            ["Port", "Count"], top_rows or [["-", "-"]], col_widths=[30 * mm, None]
        )
    )
    story.append(Spacer(1, 10))

    # Findings table
    story.append(SectionBanner("Findings"))
    story.append(Spacer(1, 4))

    desired = ["ip", "port", "protocol", "source"]
    table_head = [c for c in desired if c in header]

    cell_style = styles["Cell"]
    data_rows = []
    for r in rows:
        row = [Paragraph(_shorten(r.get(c, ""), 800), cell_style) for c in table_head]
        data_rows.append(row)

    col_widths = _estimate_col_widths(
        doc.width,
        table_head,
        rows,
        min_w=46 if compact else 58,
        max_w=180 if compact else 220,
        sample_rows=300,
    )

    findings_table = _simple_table(
        table_head, data_rows, col_widths=col_widths, zebra=True, long=True
    )
    story.append(findings_table)
    story.append(Spacer(1, 6))
    story.append(
        Paragraph(
            "Note: Findings include base fields and captured run options. Long cell values are truncated in view but preserved in CSV.",
            styles["Small"],
        )
    )

    # Build
    doc.build(story, onLaterPages=_footer, onFirstPage=_footer)
    return output_pdf


def _find_latest_csv(
    search_dir: str = "./result", prefer_masscan: bool = True
) -> Optional[str]:
    candidates = []
    sd = os.path.abspath(search_dir)
    if not os.path.isdir(sd):
        return None
    for path in glob(os.path.join(sd, "*.csv")):
        try:
            mtime = os.path.getmtime(path)
            candidates.append((mtime, path))
        except OSError:
            pass
    if not candidates:
        return None
    candidates.sort(key=lambda x: x[0], reverse=True)
    if prefer_masscan:
        masscan_only = [
            (m, p) for (m, p) in candidates if "masscan" in os.path.basename(p).lower()
        ]
        if masscan_only:
            return masscan_only[0][1]
    return candidates[0][1]


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def _cli():
    p = argparse.ArgumentParser(
        description="Xcanner PDF Writer (netscan enhanced TXT / masscan CSV)"
    )
    sub = p.add_subparsers(dest="cmd")

    # netscan subcommand
    pn = sub.add_parser("netscan", help="Build PDF from enhanced netscan TXT")
    pn.add_argument(
        "--input-txt",
        default=None,
        help="Path to *_enhanced.txt (auto-search ./result if omitted)",
    )
    pn.add_argument(
        "--output", default=None, help="Output PDF path (auto-name if omitted)"
    )
    pn.add_argument(
        "--search-dir",
        default="./result",
        help="Folder to search when --input-txt omitted",
    )
    pn.add_argument(
        "--portrait", action="store_true", help="Force portrait (default landscape)"
    )
    pn.add_argument("--title", default="Xcanner Report - Netscan", help="Report title")
    pn.add_argument("--logo", default=None, help="Logo image path")

    # masscan subcommand
    pm = sub.add_parser("masscan", help="Build PDF from masscan CSV")
    pm.add_argument(
        "--input-csv",
        default=None,
        help="Path to masscan CSV. If omitted, auto-search is used.",
    )
    pm.add_argument(
        "--output",
        default=None,
        help="Output PDF path. If omitted, derived from input name.",
    )
    pm.add_argument(
        "--search-dir",
        default="./result",
        help="Where to find CSVs if --input-csv omitted.",
    )
    g = pm.add_mutually_exclusive_group()
    g.add_argument(
        "--prefer-masscan",
        dest="prefer_masscan",
        action="store_true",
        default=True,
        help="Prefer filenames containing 'masscan' (default)",
    )
    g.add_argument(
        "--no-prefer-masscan",
        dest="prefer_masscan",
        action="store_false",
        help="Do not prefer 'masscan' filenames",
    )
    pm.add_argument("--landscape", action="store_true", help="Render in landscape")
    pm.add_argument("--title", default="Xcanner Masscan Report", help="Report title")
    pm.add_argument("--logo", default=None, help="Optional logo image path")
    pm.add_argument(
        "--max-rows", type=int, default=None, help="Limit rows read from CSV"
    )
    pm.add_argument(
        "--compact",
        action="store_true",
        help="Compact table (smaller fonts & narrower columns)",
    )

    # convenience: if user passes no subcommand but gives an --input path, infer by extension
    p.add_argument(
        "--input",
        default=None,
        help="Convenience: path to TXT/CSV; selects subcommand automatically",
    )
    p.add_argument(
        "--output", default=None, help="Output PDF path (optional when using --input)"
    )
    p.add_argument(
        "--logo", default=None, help="Logo image path (used by --input mode)"
    )
    p.add_argument("--title", default=None, help="Title (used by --input mode)")
    p.add_argument(
        "--landscape",
        action="store_true",
        help="Landscape (used by --input mode for CSV only)",
    )
    p.add_argument(
        "--portrait",
        action="store_true",
        help="Portrait (used by --input mode for TXT only)",
    )

    args = p.parse_args()

    if args.cmd == "netscan":
        input_txt = args.input_txt or _find_latest_txt(args.search_dir)
        if not input_txt:
            print(
                "[!] No TXT found in %s" % os.path.abspath(args.search_dir),
                file=sys.stderr,
            )
            sys.exit(2)
        out = args.output
        if not out:
            base = os.path.splitext(os.path.basename(input_txt))[0]
            ts = datetime.now().strftime("%Y%m%d-%H%M%S")
            out_dir = os.path.dirname(os.path.abspath(input_txt)) or "."
            out = os.path.join(out_dir, f"{base}_report_{ts}.pdf")
        os.makedirs(os.path.dirname(os.path.abspath(out)) or ".", exist_ok=True)
        pdf = build_pdf_from_txt(
            input_txt=input_txt,
            output_pdf=out,
            landscape_mode=(not args.portrait),
            title=args.title,
            logo_path=args.logo,
        )
        print(f"[*] PDF generated: {pdf}")
        return

    if args.cmd == "masscan":
        input_csv = args.input_csv or _find_latest_csv(
            args.search_dir, args.prefer_masscan
        )
        if not input_csv:
            print(
                f"[!] No CSV found in {os.path.abspath(args.search_dir)}. Pass --input-csv or set --search-dir.",
                file=sys.stderr,
            )
            sys.exit(2)
        out = args.output
        if not out:
            base = os.path.splitext(os.path.basename(input_csv))[0]
            ts = datetime.now().strftime("%Y%m%d-%H%M%S")
            out_dir = os.path.dirname(os.path.abspath(input_csv)) or "."
            out = os.path.join(out_dir, f"{base}_report_{ts}.pdf")
        os.makedirs(os.path.dirname(os.path.abspath(out)) or ".", exist_ok=True)
        pdf = build_pdf_from_csv(
            input_csv=input_csv,
            output_pdf=out,
            landscape_mode=args.landscape,
            title=args.title,
            logo_path=args.logo,
            max_rows=args.max_rows,
            compact=args.compact,
        )
        print(f"[*] PDF generated: {pdf}")
        return

    # --input convenience mode
    if args.input:
        ext = os.path.splitext(args.input.lower())[1]
        out = args.output
        if not out:
            base = os.path.splitext(os.path.basename(args.input))[0]
            ts = datetime.now().strftime("%Y%m%d-%H%M%S")
            out_dir = os.path.dirname(os.path.abspath(args.input)) or "."
            out = os.path.join(out_dir, f"{base}_report_{ts}.pdf")
        os.makedirs(os.path.dirname(os.path.abspath(out)) or ".", exist_ok=True)

        if ext == ".txt":
            title = args.title or "Xcanner Report - Netscan"
            pdf = build_pdf_from_txt(
                input_txt=args.input,
                output_pdf=out,
                landscape_mode=(not args.portrait),
                title=title,
                logo_path=args.logo,
            )
            print(f"[*] PDF generated: {pdf}")
            return
        elif ext == ".csv":
            title = args.title or "Xcanner Masscan Report"
            pdf = build_pdf_from_csv(
                input_csv=args.input,
                output_pdf=out,
                landscape_mode=args.landscape,
                title=title,
                logo_path=args.logo,
            )
            print(f"[*] PDF generated: {pdf}")
            return
        else:
            print(
                "[!] Unknown file extension for --input. Use .txt (netscan) or .csv (masscan).",
                file=sys.stderr,
            )
            sys.exit(2)

    # If nothing specified, show help and exit
    p.print_help()
    sys.exit(2)


if __name__ == "__main__":
    _cli()
