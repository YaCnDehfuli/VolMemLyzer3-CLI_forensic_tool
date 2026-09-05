#!/usr/bin/env python3
"""Generate docs/figures/extract-wall-clock.svg from benchmarks/results.json.

Bar labels use the same second formatting as benchmarks/results.md
(four decimals below 10s, two decimals otherwise). Stdlib only.

    python docs/figures/generate_extract_wall_clock.py
"""

from __future__ import annotations

import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[1]
RESULTS = REPO / "benchmarks" / "results.json"
OUT = HERE / "extract-wall-clock.svg"

INK = "#2f3a42"
LINE = "#5a6570"
TEXT = "#f3efe6"
MUTED = "#e4ddd0"
BG = "#7d8289"
FILLS = {
    "serial": "#4f6574",
    "parallel": "#4f6d62",
    "cache_warm": "#6a5a4a",
}


def _fmt_seconds(value: float) -> str:
    if value < 10:
        return f"{value:.4f}"
    return f"{value:.2f}"


def _esc(text: str) -> str:
    return (
        text.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
    )


def main() -> None:
    payload = json.loads(RESULTS.read_text(encoding="utf-8"))
    summary = payload["summary"]
    rows = [
        (
            "serial",
            f"serial · workers={payload['serial_jobs']}",
            summary["serial"]["wall_s"],
        ),
        (
            "parallel",
            f"parallel · workers={payload['parallel_jobs']}",
            summary["parallel"]["wall_s"],
        ),
        (
            "cache_warm",
            f"cache-warm · workers={payload['parallel_jobs']}",
            summary["cache_warm"]["wall_s"],
        ),
    ]

    width, height = 880, 420
    pad_l, pad_r, pad_t, pad_b = 72, 28, 64, 88
    plot_w = width - pad_l - pad_r
    plot_h = height - pad_t - pad_b
    max_s = max(row[2]["median"] for row in rows)
    axis_max = max_s * 1.12
    n = len(rows)
    gap = 36
    bar_w = (plot_w - (n - 1) * gap) / n

    parts = [
        '<?xml version="1.0" encoding="UTF-8"?>',
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" '
        f'viewBox="0 0 {width} {height}" role="img" '
        'aria-label="volmemlyzer extract wall-clock for serial, parallel, and cache-warm">',
        f'<rect x="0" y="0" width="{width}" height="{height}" fill="{BG}"/>',
        f'<text x="{width/2:.1f}" y="28" text-anchor="middle" '
        f'font-family="ui-sans-serif, Helvetica, Arial, sans-serif" '
        f'font-size="16" font-weight="700" fill="{TEXT}">'
        "volmemlyzer extract wall-clock (median of 3 runs)</text>",
        f'<text x="{width/2:.1f}" y="48" text-anchor="middle" '
        f'font-family="ui-sans-serif, Helvetica, Arial, sans-serif" '
        f'font-size="12" fill="{MUTED}">'
        "cache-warm is artifact reuse, not a Volatility speedup</text>",
        f'<line x1="{pad_l}" y1="{pad_t}" x2="{pad_l}" y2="{pad_t + plot_h}" '
        f'stroke="{LINE}" stroke-width="1.4"/>',
        f'<line x1="{pad_l}" y1="{pad_t + plot_h}" x2="{pad_l + plot_w}" '
        f'y2="{pad_t + plot_h}" stroke="{LINE}" stroke-width="1.4"/>',
    ]

    for tick in (0.0, axis_max / 2, axis_max):
        y = pad_t + plot_h - (tick / axis_max) * plot_h
        label = _fmt_seconds(tick) if tick else "0"
        parts.append(
            f'<line x1="{pad_l - 6}" y1="{y:.1f}" x2="{pad_l}" y2="{y:.1f}" '
            f'stroke="{LINE}" stroke-width="1.2"/>'
        )
        parts.append(
            f'<text x="{pad_l - 10}" y="{y + 4:.1f}" text-anchor="end" '
            f'font-family="ui-sans-serif, Helvetica, Arial, sans-serif" '
            f'font-size="11" fill="{MUTED}">{_esc(label)}</text>'
        )

    parts.append(
        f'<text x="18" y="{pad_t + plot_h / 2:.1f}" text-anchor="middle" '
        f'transform="rotate(-90 18 {pad_t + plot_h / 2:.1f})" '
        f'font-family="ui-sans-serif, Helvetica, Arial, sans-serif" '
        f'font-size="11" fill="{MUTED}">seconds</text>'
    )

    for i, (key, label, wall) in enumerate(rows):
        median = wall["median"]
        bar_h = (median / axis_max) * plot_h
        x = pad_l + i * (bar_w + gap)
        y = pad_t + plot_h - bar_h
        fill = FILLS[key]
        parts.append(
            f'<rect x="{x:.1f}" y="{y:.1f}" width="{bar_w:.1f}" height="{bar_h:.1f}" '
            f'rx="6" ry="6" fill="{fill}" stroke="{INK}" stroke-width="1.2"/>'
        )
        median_label = f"{_fmt_seconds(median)}s"
        range_label = f"{_fmt_seconds(wall['min'])}–{_fmt_seconds(wall['max'])}"
        parts.append(
            f'<text x="{x + bar_w / 2:.1f}" y="{y - 8:.1f}" text-anchor="middle" '
            f'font-family="ui-sans-serif, Helvetica, Arial, sans-serif" '
            f'font-size="14" font-weight="700" fill="{TEXT}">{_esc(median_label)}</text>'
        )
        parts.append(
            f'<text x="{x + bar_w / 2:.1f}" y="{pad_t + plot_h + 22:.1f}" '
            f'text-anchor="middle" '
            f'font-family="ui-sans-serif, Helvetica, Arial, sans-serif" '
            f'font-size="12" fill="{TEXT}">{_esc(label)}</text>'
        )
        parts.append(
            f'<text x="{x + bar_w / 2:.1f}" y="{pad_t + plot_h + 40:.1f}" '
            f'text-anchor="middle" '
            f'font-family="ui-sans-serif, Helvetica, Arial, sans-serif" '
            f'font-size="11" fill="{MUTED}">{_esc(range_label)}</text>'
        )

    footer = (
        f"image {payload['image']['size_bytes']} bytes · "
        f"{payload['plugin_count']} plugins · Volatility 3 {payload['volatility3_version']}"
    )
    parts.append(
        f'<text x="{width/2:.1f}" y="{height - 18}" text-anchor="middle" '
        f'font-family="ui-sans-serif, Helvetica, Arial, sans-serif" '
        f'font-size="11" fill="{MUTED}">{_esc(footer)}</text>'
    )
    parts.append("</svg>")
    OUT.write_text("\n".join(parts) + "\n", encoding="utf-8")
    print(f"wrote {OUT}")


if __name__ == "__main__":
    main()
