#!/usr/bin/env python3
"""Generate the analysis-rule figures from documented constants and validation JSON.

Stdlib only:

    python docs/figures/generate_analysis_rules.py
"""

from __future__ import annotations

import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[1]
VALIDATION = REPO / "docs" / "analysis-cache-validation.json"

BG = "#737a83"
PLOT = "#626a74"
INK = "#f7f4ed"
MUTED = "#ded9cf"
GRID = "#9299a2"
ACCENT = "#80b7a2"
ACCENT_2 = "#d8b16f"
ALERT = "#d88282"


def esc(value: object) -> str:
    return (
        str(value)
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
    )


def text(x: float, y: float, value: object, *, size: int = 12,
         anchor: str = "start", weight: int = 400, fill: str = INK) -> str:
    return (
        f'<text x="{x:.1f}" y="{y:.1f}" text-anchor="{anchor}" '
        'font-family="ui-sans-serif,Segoe UI,Helvetica,Arial,sans-serif" '
        f'font-size="{size}" font-weight="{weight}" fill="{fill}">{esc(value)}</text>'
    )


def write_score_ceilings() -> None:
    rows = [
        ("Process census", 33, 30, "5 families"),
        ("malfind region", 24, 24, "4 families"),
        ("Network socket", 34, 30, "6 families"),
        ("Scheduled task", 27, 27, "4 families"),
        ("UserAssist entry", 30, 30, "4 families"),
        ("SSDT module", 10, 10, "1 family"),
    ]
    width, height = 920, 410
    left, right, top, bottom = 190, 58, 76, 48
    plot_w = width - left - right
    plot_h = height - top - bottom
    row_h = plot_h / len(rows)
    axis_max = 35
    x = lambda value: left + value / axis_max * plot_w
    parts = [
        '<?xml version="1.0" encoding="UTF-8"?>',
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" '
        f'viewBox="0 0 {width} {height}" role="img" aria-labelledby="title desc">',
        '<title id="title">Maximum score by analysis surface</title>',
        '<desc id="desc">Horizontal bars show theoretical hypothesis-family totals, the '
        '30 point cap, and the 9 point surfacing threshold.</desc>',
        f'<rect width="{width}" height="{height}" fill="{BG}"/>',
        text(width / 2, 28, "Bounded evidence model by analysis surface", size=17,
             anchor="middle", weight=700),
        text(width / 2, 49, "Strongest rule per family; independent families sum; global cap = 30",
             size=12, anchor="middle", fill=MUTED),
    ]
    for tick in range(0, 36, 5):
        tx = x(tick)
        parts.append(f'<line x1="{tx:.1f}" y1="{top}" x2="{tx:.1f}" y2="{height-bottom}" '
                     f'stroke="{GRID}" stroke-width="1" opacity="0.55"/>')
        parts.append(text(tx, height - 21, tick, size=11, anchor="middle", fill=MUTED))
    threshold_x = x(9)
    parts.append(f'<line x1="{threshold_x:.1f}" y1="{top-10}" x2="{threshold_x:.1f}" '
                 f'y2="{height-bottom}" stroke="{ACCENT_2}" stroke-width="2"/>')
    parts.append(text(threshold_x + 5, top - 15, "surface ≥ 9", size=11, fill=ACCENT_2))

    for index, (label, raw, bounded, families) in enumerate(rows):
        cy = top + index * row_h + row_h / 2
        bar_y = cy - 11
        parts.append(text(left - 14, cy + 4, label, anchor="end", weight=600))
        parts.append(f'<rect x="{left}" y="{bar_y:.1f}" width="{plot_w:.1f}" height="22" '
                     f'rx="4" fill="{PLOT}"/>')
        parts.append(f'<rect x="{left}" y="{bar_y:.1f}" width="{x(bounded)-left:.1f}" '
                     f'height="22" rx="4" fill="{ACCENT}"/>')
        if raw > 30:
            parts.append(f'<rect x="{x(30):.1f}" y="{bar_y:.1f}" '
                         f'width="{x(raw)-x(30):.1f}" height="22" fill="{ALERT}" opacity="0.75"/>')
        value = f"{bounded}" if raw == bounded else f"{raw} → {bounded} cap"
        parts.append(text(x(min(raw, 34)) - 5, cy + 4, value, anchor="end", weight=700))
        parts.append(text(width - right + 8, cy + 4, families, size=11, fill=MUTED))
    parts.append(text(left + plot_w / 2, height - 5, "ordinal evidence points", size=11,
                      anchor="middle", fill=MUTED))
    parts.append("</svg>")
    (HERE / "analysis-score-ceilings.svg").write_text("\n".join(parts) + "\n", encoding="utf-8")


def write_cache_validation(payload: dict) -> None:
    captures = payload["captures"]
    surfaces = ["process", "malfind", "netscan", "scheduled_tasks", "userassist", "ssdt"]
    labels = {
        "process": "Process", "malfind": "malfind", "netscan": "netscan",
        "scheduled_tasks": "Tasks", "userassist": "UserAssist", "ssdt": "SSDT",
    }
    width, height = 980, 500
    left, top = 178, 116
    cell_w, cell_h = 124, 104
    parts = [
        '<?xml version="1.0" encoding="UTF-8"?>',
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" '
        f'viewBox="0 0 {width} {height}" role="img" aria-labelledby="title desc">',
        '<title id="title">Cache-only validation matrix</title>',
        '<desc id="desc">Each cell shows cached input objects and objects surfaced after '
        'the revised rules. Missing artifacts are marked unavailable rather than clean.</desc>',
        f'<rect width="{width}" height="{height}" fill="{BG}"/>',
        text(width / 2, 30, "Cache-only validation — no Volatility rerun", size=17,
             anchor="middle", weight=700),
        text(width / 2, 52, "cell = input objects → surfaced objects; zero means evaluated and quiet",
             size=12, anchor="middle", fill=MUTED),
    ]
    for col, surface in enumerate(surfaces):
        parts.append(text(left + col * cell_w + cell_w / 2, top - 18, labels[surface],
                          anchor="middle", weight=600))
    for row_index, capture in enumerate(captures):
        y = top + row_index * cell_h
        parts.append(text(left - 14, y + 39, capture["label"], anchor="end", weight=700))
        parts.append(text(left - 14, y + 59, "cached JSON", size=11,
                          anchor="end", fill=MUTED))
        by_name = {item["name"]: item for item in capture["surfaces"]}
        for col, surface in enumerate(surfaces):
            item = by_name[surface]
            x = left + col * cell_w
            available = item["input_objects"] is not None
            fill = PLOT if available else BG
            stroke = GRID
            dash = "" if available else ' stroke-dasharray="5 4"'
            parts.append(f'<rect x="{x+5}" y="{y+5}" width="{cell_w-10}" height="{cell_h-10}" '
                         f'rx="6" fill="{fill}" stroke="{stroke}" stroke-width="1.2"{dash}/>')
            if available:
                value = f'{item["input_objects"]} → {item["surfaced"]}'
                color = ACCENT_2 if item["surfaced"] else INK
                parts.append(text(x + cell_w / 2, y + 48, value, size=17,
                                  anchor="middle", weight=700, fill=color))
                parts.append(text(x + cell_w / 2, y + 69,
                                  "surfaced" if item["surfaced"] else "no row ≥ 9",
                                  size=11, anchor="middle", fill=MUTED))
            else:
                parts.append(text(x + cell_w / 2, y + 50, "unavailable", size=12,
                                  anchor="middle", weight=600, fill=MUTED))

    base_y = top + len(captures) * cell_h + 35
    noise = captures[0]["suppressed_noise"]
    parts.append(text(left, base_y, "Correlated noise removed", size=13, weight=700))
    summaries = [
        ("Unattributed public sockets", noise["public_established_without_pid_before"],
         noise["public_established_without_pid_after"]),
        ("UserAssist location-only rows", noise["userassist_location_only_before"],
         noise["userassist_location_only_after"]),
    ]
    for idx, (label, before, after) in enumerate(summaries):
        y = base_y + 32 + idx * 36
        parts.append(text(left, y + 4, label, size=12))
        bar_x = left + 255
        parts.append(f'<rect x="{bar_x}" y="{y-10}" width="{before*8}" height="14" '
                     f'rx="3" fill="{ALERT}"/>')
        parts.append(text(bar_x + before * 8 + 8, y + 2, f"{before} before", size=11,
                          fill=MUTED))
        parts.append(text(bar_x + 430, y + 2, f"{after} after", size=11,
                          fill=ACCENT, weight=700))
    parts.append(text(width - 25, height - 18,
                      "Missing cache ≠ clean result", size=11, anchor="end", fill=MUTED))
    parts.append("</svg>")
    (HERE / "analysis-cache-validation.svg").write_text("\n".join(parts) + "\n", encoding="utf-8")


def main() -> None:
    payload = json.loads(VALIDATION.read_text(encoding="utf-8"))
    write_score_ceilings()
    write_cache_validation(payload)
    print("wrote analysis-score-ceilings.svg and analysis-cache-validation.svg")


if __name__ == "__main__":
    main()
