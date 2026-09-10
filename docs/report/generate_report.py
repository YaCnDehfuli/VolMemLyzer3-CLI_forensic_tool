#!/usr/bin/env python3
"""Build the self-contained GitHub Pages report from repository source documents."""

from __future__ import annotations

import html
import json
import re
from collections import Counter
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
DOCS = ROOT / "docs"
REPOSITORY = "https://github.com/YaCnDehfuli/VolMemLyzer3-CLI_forensic_tool"


def split_markdown_row(line: str) -> list[str]:
    """Split a Markdown table row while preserving pipes inside code spans."""
    text = line.strip().removeprefix("|").removesuffix("|")
    cells: list[str] = []
    current: list[str] = []
    in_code = False
    for char in text:
        if char == "`":
            in_code = not in_code
            current.append(char)
        elif char == "|" and not in_code:
            cells.append("".join(current).strip())
            current = []
        else:
            current.append(char)
    cells.append("".join(current).strip())
    return cells


def plain_markdown(value: str) -> str:
    value = re.sub(r"\[([^]]+)]\([^)]+\)", r"\1", value)
    return value.replace("`", "").replace("**", "").strip()


def inline_markdown(value: str) -> str:
    """Render only the safe inline Markdown constructs used by the source tables."""
    tokens: list[tuple[str, str]] = []

    def save(kind: str, content: str) -> str:
        tokens.append((kind, content))
        return f"\x00{len(tokens) - 1}\x00"

    value = re.sub(r"`([^`]+)`", lambda m: save("code", m.group(1)), value)
    value = re.sub(
        r"\[([^]]+)]\((https?://[^)]+)\)",
        lambda m: save("link", json.dumps([m.group(1), m.group(2)])),
        value,
    )
    rendered = html.escape(value).replace("**", "")
    for index, (kind, content) in enumerate(tokens):
        marker = f"\x00{index}\x00"
        if kind == "code":
            replacement = f"<code>{html.escape(content)}</code>"
        else:
            label, url = json.loads(content)
            replacement = (
                f'<a href="{html.escape(url, quote=True)}" target="_blank" '
                f'rel="noreferrer">{html.escape(label)}</a>'
            )
        rendered = rendered.replace(marker, replacement)
    return rendered


def parse_features() -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    group = ""
    for line in (ROOT / "FEATURES.md").read_text(encoding="utf-8").splitlines():
        heading = re.match(r"^## (.+?) \((\d+)\)$", line)
        if heading:
            group = heading.group(1)
            continue
        if not line.startswith("| `"):
            continue
        cells = [plain_markdown(cell) for cell in split_markdown_row(line)]
        if len(cells) >= 5:
            interpretation = re.search(r"Interpretation:\s*(.*?)(?:\s+Notes:|$)", cells[4])
            rows.append(
                {
                    "group": group,
                    "feature": cells[0],
                    "type": cells[1],
                    "domain": cells[2],
                    "unit": cells[3],
                    "description": cells[4],
                    "interpretation": interpretation.group(1).strip() if interpretation else "Context-dependent.",
                }
            )
    return rows


def parse_rules() -> list[dict[str, str]]:
    lines = (DOCS / "ANALYSIS_RULES.md").read_text(encoding="utf-8").splitlines()
    rules: list[dict[str, str]] = []
    surface = ""
    family = "General"
    index = 0
    while index < len(lines):
        line = lines[index]
        if line.startswith("### "):
            surface = plain_markdown(line[4:])
            family = "General"
        elif line.startswith("#### "):
            family = plain_markdown(line[5:])

        is_separator = (
            index + 1 < len(lines)
            and lines[index + 1].startswith("|")
            and set(lines[index + 1].replace("|", "").replace(":", "").replace("-", "").strip()) == set()
        )
        if line.startswith("|") and is_separator:
            headers = split_markdown_row(line)
            cursor = index + 2
            table_rows: list[list[str]] = []
            while cursor < len(lines) and lines[cursor].startswith("|"):
                table_rows.append(split_markdown_row(lines[cursor]))
                cursor += 1

            if "Flag" in headers and "Weight" in headers and surface[:1].isdigit():
                for cells in table_rows:
                    row = dict(zip(headers, cells))
                    flag = plain_markdown(row.get("Flag", ""))
                    condition = next(
                        (
                            row[key]
                            for key in (
                                "Exact condition",
                                "Exact test",
                                "Exact regular expression",
                                "Exact token/test",
                                "Condition",
                            )
                            if row.get(key)
                        ),
                        "",
                    )
                    if flag == "BITS_TRANSFER":
                        condition = (
                            "Exact `bitsadmin` action stem with arguments matching "
                            "`(?:^|\\s)/transfer(?:\\s|$)`, or wrapper arguments matching "
                            "`\\bbitsadmin(?:\\.exe)?\\s+/transfer(?:\\s|$)`"
                        )
                    hypothesis = next(
                        (
                            row[key]
                            for key in ("Investigative hypothesis", "Interpretation", "Constraint")
                            if row.get(key)
                        ),
                        "",
                    )
                    rules.append(
                        {
                            "surface": re.sub(r"^\d+\.\s*", "", surface),
                            "family": plain_markdown(row.get("Family") or family),
                            "flag": flag,
                            "weight": plain_markdown(row.get("Weight", "")),
                            "condition": inline_markdown(condition),
                            "hypothesis": inline_markdown(hypothesis),
                            "attack": inline_markdown(row.get("ATT&CK", "Omit")),
                        }
                    )
            index = cursor - 1
        index += 1

    # KNOWN_TOOL is specified in prose because the exact stem list is too wide for
    # the Markdown rule table. Include it in the filterable report explicitly.
    rules.append(
        {
            "surface": "UserAssist execution history",
            "family": "Tool-identity family",
            "flag": "KNOWN_TOOL",
            "weight": "12",
            "condition": inline_markdown(
                "Exact normalized basename match after removing only a trailing `32` or `64`: "
                "`mimikatz`, `psexec`, `procdump`, `bloodhound`, `sharphound`, `rubeus`, "
                "`seatbelt`, `powersploit`, `empire`, `crackmapexec`, `cme`, `koadic`, "
                "`evil-winrm`, `lazagne`, `winpeas`, `nc`, `ncat`, `netcat`, `plink`, "
                "`pscp`, `beacon`, `cobaltstrike`, `metasploit`, `msfvenom`, `pafish`, "
                "`sharpdpapi`, `sharpup`, `sharproast`, `hashdump`, `pwdump`, `adfind`, "
                "`wce`, `mimidrv`, `lsassy`, or `kerberoast`"
            ),
            "hypothesis": "Execution history contains a name associated with dual-use or red-team tooling; file identity is not proven",
            "attack": "Omit by filename alone",
        }
    )
    return rules


def feature_bars(features: list[dict[str, str]]) -> str:
    counts = Counter(row["group"] for row in features)
    top = counts.most_common(12)
    maximum = max(value for _, value in top)
    rows = []
    for name, value in top:
        width = value / maximum * 100
        rows.append(
            f'<div class="bar-row"><span>{html.escape(name)}</span>'
            f'<div class="bar-track"><i style="width:{width:.2f}%"></i></div>'
            f'<strong>{value}</strong></div>'
        )
    return "".join(rows)


def validation_rows(validation: dict) -> str:
    names = ["process", "malfind", "netscan", "scheduled_tasks", "userassist", "ssdt"]
    captures = validation["captures"]
    output = []
    for capture in captures:
        surfaces = {row["name"]: row for row in capture["surfaces"]}
        cells = []
        for name in names:
            row = surfaces[name]
            value = "Unavailable" if row["input_objects"] is None else f'{row["surfaced"]}/{row["input_objects"]}'
            cells.append(f"<td>{html.escape(value)}</td>")
        output.append(f'<tr><th>{html.escape(capture["label"])}</th>{"".join(cells)}</tr>')
    return "".join(output)


def main() -> None:
    features = parse_features()
    rules = parse_rules()
    validation = json.loads((DOCS / "analysis-cache-validation.json").read_text(encoding="utf-8"))
    surface_count = len({row["surface"] for row in rules})
    group_count = len({row["group"] for row in features})
    rule_json = json.dumps(rules, ensure_ascii=False).replace("</", "<\\/")
    feature_json = json.dumps(features, ensure_ascii=False).replace("</", "<\\/")

    document = f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta name="description" content="Interactive VolMemLyzer rule, validation, and feature reference.">
  <meta property="og:title" content="VolMemLyzer analysis evidence report">
  <meta property="og:description" content="Exact memory-forensics rules, bounded scoring, cache validation, and 520 extracted features.">
  <title>VolMemLyzer · Analysis evidence report</title>
  <style>
    :root {{
      color-scheme: dark;
      --bg: #07101d;
      --panel: #0c1828;
      --panel-2: #101f31;
      --line: #22354a;
      --text: #edf5ff;
      --muted: #9fb0c3;
      --cyan: #51d6df;
      --blue: #70a7ff;
      --amber: #f4c66a;
      --red: #ff7c88;
      --green: #62d49b;
      --max: 1180px;
    }}
    * {{ box-sizing: border-box; }}
    html {{ scroll-behavior: smooth; }}
    body {{ margin: 0; background: radial-gradient(circle at 80% -20%, #153250 0, transparent 34rem), var(--bg); color: var(--text); font: 15px/1.6 Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; }}
    a {{ color: var(--cyan); text-decoration-thickness: 1px; text-underline-offset: 3px; }}
    code {{ color: #d4edff; background: #13263a; border: 1px solid #29415a; border-radius: 4px; padding: .08rem .32rem; font-size: .88em; overflow-wrap: anywhere; }}
    .shell {{ width: min(var(--max), calc(100% - 40px)); margin: auto; }}
    .topbar {{ position: sticky; z-index: 20; top: 0; border-bottom: 1px solid rgba(80,110,140,.35); background: rgba(7,16,29,.9); backdrop-filter: blur(14px); }}
    .topbar .shell {{ min-height: 64px; display: flex; align-items: center; justify-content: space-between; gap: 24px; }}
    .brand {{ color: var(--text); text-decoration: none; font-weight: 780; letter-spacing: -.02em; }}
    .brand span {{ color: var(--cyan); }}
    nav {{ display: flex; gap: 20px; overflow-x: auto; }}
    nav a {{ white-space: nowrap; color: var(--muted); text-decoration: none; font-size: 13px; }}
    nav a:hover {{ color: var(--text); }}
    .hero {{ padding: 92px 0 58px; }}
    .eyebrow {{ color: var(--cyan); font-size: 12px; font-weight: 800; letter-spacing: .16em; text-transform: uppercase; }}
    h1 {{ max-width: 850px; margin: 14px 0 18px; font-size: clamp(42px, 7vw, 78px); line-height: .98; letter-spacing: -.055em; }}
    .lede {{ max-width: 790px; color: #bfd0e1; font-size: clamp(17px, 2vw, 21px); }}
    .actions {{ display: flex; flex-wrap: wrap; gap: 12px; margin-top: 30px; }}
    .button {{ display: inline-flex; padding: 11px 16px; border: 1px solid var(--line); border-radius: 7px; color: var(--text); background: var(--panel); text-decoration: none; font-weight: 700; }}
    .button.primary {{ background: var(--cyan); color: #041319; border-color: var(--cyan); }}
    .metrics {{ display: grid; grid-template-columns: repeat(6, 1fr); gap: 1px; margin-top: 56px; border: 1px solid var(--line); background: var(--line); }}
    .metric {{ min-width: 0; padding: 20px; background: rgba(12,24,40,.96); }}
    .metric strong {{ display: block; color: var(--text); font-size: 29px; line-height: 1.15; }}
    .metric span {{ color: var(--muted); font-size: 12px; text-transform: uppercase; letter-spacing: .08em; }}
    section {{ padding: 62px 0; border-top: 1px solid rgba(50,75,100,.36); }}
    h2 {{ margin: 0; font-size: clamp(29px, 4vw, 46px); letter-spacing: -.035em; }}
    h3 {{ margin-top: 0; font-size: 18px; }}
    .section-head {{ display: grid; grid-template-columns: minmax(0, 2fr) minmax(260px, 1fr); gap: 42px; align-items: end; margin-bottom: 32px; }}
    .section-head p, .muted {{ color: var(--muted); }}
    .grid-2 {{ display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 18px; }}
    .panel {{ border: 1px solid var(--line); background: linear-gradient(145deg, rgba(16,31,49,.92), rgba(10,22,37,.92)); padding: 24px; }}
    .pipeline {{ display: grid; grid-template-columns: repeat(6, 1fr); gap: 8px; align-items: stretch; }}
    .pipeline div {{ position: relative; min-height: 96px; padding: 16px 13px; border: 1px solid var(--line); background: var(--panel); }}
    .pipeline div:not(:last-child)::after {{ content: "→"; position: absolute; right: -10px; top: 34px; z-index: 2; color: var(--cyan); background: var(--bg); }}
    .pipeline b {{ display: block; font-size: 13px; }}
    .pipeline span {{ color: var(--muted); font-size: 12px; }}
    .ladder {{ display: grid; grid-template-columns: 9fr 5fr 6fr 11fr; min-height: 94px; border: 1px solid var(--line); }}
    .ladder div {{ display: flex; flex-direction: column; justify-content: center; padding: 14px; border-right: 1px solid rgba(7,16,29,.55); color: #07101d; }}
    .ladder b {{ font-size: 16px; }}
    .ladder span {{ font-size: 12px; font-weight: 700; }}
    .low {{ background: #7ba7ba; }} .medium {{ background: var(--amber); }} .high {{ background: #ff9a6a; }} .critical {{ background: var(--red); }}
    .callout {{ border-left: 3px solid var(--cyan); padding: 4px 0 4px 18px; color: #cbd9e7; }}
    .controls {{ display: grid; grid-template-columns: minmax(220px, 2fr) repeat(2, minmax(150px, 1fr)); gap: 10px; margin: 22px 0 14px; }}
    input, select {{ width: 100%; min-height: 42px; padding: 9px 11px; color: var(--text); background: #091625; border: 1px solid var(--line); border-radius: 5px; font: inherit; }}
    .result-count {{ color: var(--muted); margin-bottom: 10px; font-size: 13px; }}
    .table-wrap {{ overflow: auto; max-height: 680px; border: 1px solid var(--line); background: rgba(8,19,32,.7); }}
    table {{ width: 100%; border-collapse: collapse; text-align: left; }}
    th, td {{ padding: 12px 14px; border-bottom: 1px solid #1d3044; vertical-align: top; }}
    thead th {{ position: sticky; top: 0; z-index: 3; background: #102036; color: #c9d9e8; font-size: 11px; letter-spacing: .08em; text-transform: uppercase; }}
    tbody th {{ white-space: nowrap; }}
    tbody tr:hover {{ background: rgba(81,214,223,.055); }}
    .weight {{ display: inline-flex; min-width: 30px; justify-content: center; color: #07101d; background: var(--amber); font-weight: 850; border-radius: 3px; }}
    .flag {{ color: #dffcff; font: 700 12px/1.35 ui-monospace, SFMono-Regular, Menlo, monospace; }}
    .rule-meta {{ color: var(--muted); font-size: 12px; }}
    .validation-table th, .validation-table td {{ text-align: center; }}
    .validation-table tbody th {{ text-align: left; }}
    .finding {{ display: grid; grid-template-columns: 1.2fr .8fr; gap: 18px; margin-top: 18px; }}
    .finding-path {{ font: 700 18px ui-monospace, SFMono-Regular, Menlo, monospace; color: var(--cyan); }}
    .score {{ font-size: 42px; font-weight: 850; letter-spacing: -.04em; }}
    .score small {{ color: var(--muted); font-size: 16px; }}
    .bar-row {{ display: grid; grid-template-columns: 105px minmax(90px, 1fr) 32px; align-items: center; gap: 10px; margin: 9px 0; font-size: 12px; }}
    .bar-row span {{ overflow: hidden; text-overflow: ellipsis; white-space: nowrap; color: #c1d0df; }}
    .bar-track {{ height: 9px; background: #172a3d; }}
    .bar-track i {{ display: block; height: 100%; background: linear-gradient(90deg, var(--blue), var(--cyan)); }}
    .feature-note {{ font-size: 13px; color: var(--muted); }}
    .boundaries {{ display: grid; grid-template-columns: repeat(3, 1fr); gap: 14px; }}
    .boundary {{ border-top: 2px solid var(--amber); padding: 17px; background: var(--panel); }}
    .boundary strong {{ display: block; margin-bottom: 7px; }}
    footer {{ padding: 42px 0 70px; color: var(--muted); border-top: 1px solid var(--line); font-size: 13px; }}
    @media (max-width: 900px) {{
      .metrics {{ grid-template-columns: repeat(3, 1fr); }}
      .pipeline {{ grid-template-columns: repeat(3, 1fr); }}
      .section-head, .grid-2, .finding {{ grid-template-columns: 1fr; }}
      .boundaries {{ grid-template-columns: 1fr; }}
    }}
    @media (max-width: 620px) {{
      .shell {{ width: min(100% - 24px, var(--max)); }}
      nav {{ display: none; }}
      .hero {{ padding-top: 62px; }}
      .metrics {{ grid-template-columns: repeat(2, 1fr); }}
      .pipeline {{ grid-template-columns: 1fr 1fr; }}
      .controls {{ grid-template-columns: 1fr; }}
      .ladder {{ grid-template-columns: 1fr; }}
      .ladder div {{ min-height: 58px; }}
    }}
    @media print {{ .topbar, .controls {{ display: none; }} body {{ background: white; color: #111; }} .panel, .metric, .table-wrap {{ background: white; border-color: #bbb; }} .muted, .rule-meta, .section-head p {{ color: #444; }} }}
  </style>
</head>
<body>
  <header class="topbar">
    <div class="shell">
      <a class="brand" href="#top">VolMemLyzer<span>3</span></a>
      <nav aria-label="Report sections">
        <a href="#method">Method</a><a href="#rules">Rules</a><a href="#validation">Validation</a><a href="#features">Features</a><a href="#boundaries">Boundaries</a>
      </nav>
    </div>
  </header>

  <main id="top">
    <div class="shell hero">
      <div class="eyebrow">Memory forensics · analysis evidence report</div>
      <h1>Rules you can inspect.<br>Scores you can defend.</h1>
      <p class="lede">A browser-readable reference for VolMemLyzer's analyst-facing hypotheses, bounded evidence scoring, cache-only validation, and extracted feature schema. Findings prioritize review; they are not malware verdicts.</p>
      <div class="actions">
        <a class="button primary" href="#rules">Explore exact rules</a>
        <a class="button" href="{REPOSITORY}/blob/main/docs/ANALYSIS_RULES.md">Read the full specification</a>
        <a class="button" href="{REPOSITORY}/blob/main/FEATURES.md">Open semantic feature source</a>
      </div>
      <div class="metrics" aria-label="Report summary">
        <div class="metric"><strong>{surface_count}</strong><span>Analysis surfaces</span></div>
        <div class="metric"><strong>{len(rules)}</strong><span>Rule conditions</span></div>
        <div class="metric"><strong>{len(features)}</strong><span>Extracted features</span></div>
        <div class="metric"><strong>{group_count}</strong><span>Feature groups</span></div>
        <div class="metric"><strong>30</strong><span>Score ceiling</span></div>
        <div class="metric"><strong>178</strong><span>Passing tests</span></div>
      </div>
    </div>

    <section id="method">
      <div class="shell">
        <div class="section-head"><div><div class="eyebrow">Method</div><h2>Evidence is correlated before it is scored.</h2></div><p>The engine keeps the strongest observation in each hypothesis family, sums independent families, and caps the result at 30. The default surfacing threshold is 9.</p></div>
        <div class="pipeline" aria-label="Analysis pipeline">
          <div><b>01 · Collect</b><span>Volatility JSON artifacts</span></div>
          <div><b>02 · Normalize</b><span>Fields, paths, identities</span></div>
          <div><b>03 · Evaluate</b><span>Explicit conditions</span></div>
          <div><b>04 · Correlate</b><span>Strongest per family</span></div>
          <div><b>05 · Bound</b><span>Sum, then cap at 30</span></div>
          <div><b>06 · Review</b><span>Surface at ≥9</span></div>
        </div>
        <div class="panel" style="margin-top:18px">
          <h3>Shared ordinal ladder</h3>
          <div class="ladder" aria-label="Risk score bands">
            <div class="low"><b>Low</b><span>0–8 · context</span></div>
            <div class="medium"><b>Medium</b><span>9–13 · review</span></div>
            <div class="high"><b>High</b><span>14–19 · corroborated</span></div>
            <div class="critical"><b>Critical</b><span>20–30 · several hypotheses</span></div>
          </div>
          <p class="callout">The number is an ordinal evidence value—not probability, confidence, or a detection verdict. ATT&amp;CK references identify compatible mechanisms, not confirmed adversary behavior.</p>
        </div>
      </div>
    </section>

    <section id="rules">
      <div class="shell">
        <div class="section-head"><div><div class="eyebrow">Rule explorer</div><h2>Every surfaced condition, searchable.</h2></div><p>Filter by analysis surface or hypothesis family. Conditions and weights are generated from the repository's full specification; follow ATT&amp;CK links for official technique definitions.</p></div>
        <div class="controls">
          <input id="rule-search" type="search" placeholder="Search flag, condition, hypothesis, ATT&amp;CK…" aria-label="Search rules">
          <select id="rule-surface" aria-label="Filter rules by surface"><option value="">All surfaces</option></select>
          <select id="rule-family" aria-label="Filter rules by family"><option value="">All families</option></select>
        </div>
        <div class="result-count" id="rule-count"></div>
        <div class="table-wrap">
          <table><thead><tr><th>Rule</th><th>Surface / family</th><th>Weight</th><th>Exact condition</th><th>Hypothesis / ATT&amp;CK</th></tr></thead><tbody id="rule-body"></tbody></table>
        </div>
      </div>
    </section>

    <section id="validation">
      <div class="shell">
        <div class="section-head"><div><div class="eyebrow">Cache-only validation</div><h2>Measured against two supplied cache sets.</h2></div><p>Pure scorer functions were invoked over cached JSON. No UI, memory-image rerun, or network reputation lookup influenced the results. Unavailable artifacts are never treated as clean.</p></div>
        <div class="grid-2">
          <div class="panel">
            <h3>Surfaced / evaluated objects</h3>
            <div class="table-wrap" style="max-height:none"><table class="validation-table"><thead><tr><th>Cache</th><th>Process</th><th>Malfind</th><th>Network</th><th>Tasks</th><th>UserAssist</th><th>SSDT</th></tr></thead><tbody>{validation_rows(validation)}</tbody></table></div>
          </div>
          <div class="panel">
            <h3>What the negative controls removed</h3>
            <img src="figures/analysis-cache-validation.svg" alt="Cache validation matrix" style="display:block;width:100%;height:auto">
          </div>
        </div>
        <div class="finding">
          <div class="panel">
            <div class="eyebrow">Observed cache example · 2580_5.vmem</div>
            <p class="finding-path">powershell.exe (5048) → Z:\\malware.exe (7936)</p>
            <p><code>OP</code> non-system location +7 · <code>SCRIPT_CHILD_EXTERNAL</code> external native child +6 · <code>WOW</code> 32-bit context +2.</p>
            <p class="muted">PID 7936 is present in pslist, psscan, and psxview. The cache contains no PID 2580; the filename is not converted into evidence.</p>
          </div>
          <div class="panel"><div class="eyebrow">Bounded result</div><div class="score">15<small>/30 · High</small></div><p>Normal agreement between discovery views adds no points. Only suspicious, independent hypotheses contribute.</p></div>
        </div>
      </div>
    </section>

    <section id="features">
      <div class="shell">
        <div class="section-head"><div><div class="eyebrow">Feature schema</div><h2>520 extracted features without a 900-line scroll.</h2></div><p>Features describe image-level measurements produced by registered extractors. They are separate from the analyst-facing surfacing rules above and generally require host-class baselines before interpretation.</p></div>
        <div class="grid-2">
          <div class="panel"><h3>Largest feature groups</h3>{feature_bars(features)}</div>
          <div class="panel"><h3>How to read the catalog</h3><p>Search by feature name, plugin group, or documented interpretation. Ratios and entropy values are measurements—not automatic indicators. Empty plugin output means unavailable coverage, not a zero-risk host.</p><p class="feature-note">The full semantic source remains versioned in <a href="{REPOSITORY}/blob/main/FEATURES.md">FEATURES.md</a>; this interface is generated from it.</p></div>
        </div>
        <div class="controls">
          <input id="feature-search" type="search" placeholder="Search 520 features…" aria-label="Search extracted features">
          <select id="feature-group" aria-label="Filter by plugin group"><option value="">All plugin groups</option></select>
          <select id="feature-type" aria-label="Filter by feature type"><option value="">All feature types</option></select>
        </div>
        <div class="result-count" id="feature-count"></div>
        <div class="table-wrap">
          <table><thead><tr><th>Feature</th><th>Plugin group</th><th>Documented interpretation</th><th>Description</th></tr></thead><tbody id="feature-body"></tbody></table>
        </div>
      </div>
    </section>

    <section id="boundaries">
      <div class="shell">
        <div class="section-head"><div><div class="eyebrow">Claim boundary</div><h2>What this report refuses to overstate.</h2></div><p>Credibility depends on preserving uncertainty and recording why tempting rules were rejected.</p></div>
        <div class="boundaries">
          <div class="boundary"><strong>No malware verdict</strong><span>Surfaced objects are review leads. A quiet result cannot establish that an image is clean.</span></div>
          <div class="boundary"><strong>No score inflation</strong><span>Correlated observations share a family; duplicates and repeated SSDT entries cannot manufacture severity.</span></div>
          <div class="boundary"><strong>No missing-data assumption</strong><span>Failed and zero-byte deep-plugin artifacts remain unavailable instead of becoming negative evidence.</span></div>
          <div class="boundary"><strong>No filename-to-technique jump</strong><span>Dual-use tool names and dump filenames are hints. They do not prove binary identity or adversary behavior.</span></div>
          <div class="boundary"><strong>No raw-RWX verdict</strong><span>All 31 cached malfind rows were private RWX and stayed below threshold without payload or loader corroboration.</span></div>
          <div class="boundary"><strong>No port-only C2 claim</strong><span>Ports are supporting context because this layer does not parse application protocols or reputation.</span></div>
        </div>
      </div>
    </section>
  </main>

  <footer><div class="shell">Generated from <a href="{REPOSITORY}/blob/main/docs/ANALYSIS_RULES.md">ANALYSIS_RULES.md</a>, <a href="{REPOSITORY}/blob/main/FEATURES.md">FEATURES.md</a>, and <a href="analysis-cache-validation.json">cache-validation metadata</a>. Validation source revision: <code>{html.escape(validation['analysis_commit'])}</code>.</div></footer>

  <script>
    const rules = {rule_json};
    const features = {feature_json};
    const byId = id => document.getElementById(id);
    const esc = value => String(value ?? '').replace(/[&<>"']/g, char => ({{'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}}[char]));
    const options = (element, values) => values.forEach(value => element.insertAdjacentHTML('beforeend', `<option value="${{esc(value)}}">${{esc(value)}}</option>`));
    options(byId('rule-surface'), [...new Set(rules.map(row => row.surface))].sort());
    options(byId('rule-family'), [...new Set(rules.map(row => row.family))].sort());
    options(byId('feature-group'), [...new Set(features.map(row => row.group))].sort());
    options(byId('feature-type'), [...new Set(features.map(row => row.type))].sort());

    function renderRules() {{
      const query = byId('rule-search').value.trim().toLowerCase();
      const surface = byId('rule-surface').value;
      const family = byId('rule-family').value;
      const filtered = rules.filter(row => (!surface || row.surface === surface) && (!family || row.family === family) && (!query || Object.values(row).join(' ').toLowerCase().includes(query)));
      byId('rule-count').textContent = `${{filtered.length}} of ${{rules.length}} rule conditions`;
      byId('rule-body').innerHTML = filtered.map(row => `<tr><td><span class="flag">${{esc(row.flag)}}</span></td><td>${{esc(row.surface)}}<div class="rule-meta">${{esc(row.family)}}</div></td><td><span class="weight">${{esc(row.weight)}}</span></td><td>${{row.condition}}</td><td>${{row.hypothesis ? row.hypothesis + '<br>' : ''}}<span class="rule-meta">${{row.attack}}</span></td></tr>`).join('');
    }}

    function renderFeatures() {{
      const query = byId('feature-search').value.trim().toLowerCase();
      const group = byId('feature-group').value;
      const type = byId('feature-type').value;
      const filtered = features.filter(row => (!group || row.group === group) && (!type || row.type === type) && (!query || Object.values(row).join(' ').toLowerCase().includes(query)));
      byId('feature-count').textContent = `${{filtered.length}} of ${{features.length}} extracted features`;
      byId('feature-body').innerHTML = filtered.map(row => `<tr><td><span class="flag">${{esc(row.feature)}}</span></td><td>${{esc(row.group)}}</td><td>${{esc(row.interpretation)}}</td><td>${{esc(row.description)}}</td></tr>`).join('');
    }}

    ['rule-search','rule-surface','rule-family'].forEach(id => byId(id).addEventListener('input', renderRules));
    ['feature-search','feature-group','feature-type'].forEach(id => byId(id).addEventListener('input', renderFeatures));
    renderRules();
    renderFeatures();
  </script>
</body>
</html>
"""
    (DOCS / "index.html").write_text(document, encoding="utf-8")
    print(f"wrote docs/index.html with {len(rules)} rules and {len(features)} features")


if __name__ == "__main__":
    main()
