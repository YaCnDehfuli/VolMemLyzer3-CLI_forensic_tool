"""High-level scoring entry point shared by triage and live re-scoring.

:func:`score_records` is deliberately free of any Volatility/VolMemLyzer import so
it runs in the API process (for ``/rescore``), the worker (for triage), and the
test suite alike — it takes already-parsed plugin records and a profile dict and
returns a fully explained, JSON-ready scored view.
"""
from __future__ import annotations

from .context import build_context
from .engine import ScoringEngine
from .profile import TuningProfile

# Canonical plugin keys the context/rules understand. The triage extractor caches
# raw JSON for each of these (those the image supports) so re-scoring never needs
# Volatility again.
CONTEXT_PLUGINS: tuple[str, ...] = (
    "pslist", "pstree", "psscan", "psxview", "cmdline", "malfind", "ldrmodules",
    "handles", "privileges", "threads", "netscan", "svcscan", "scheduled_tasks",
    "userassist", "hivelist", "hivescan", "ssdt",
)

# VolMemLyzer / Volatility plugin names → canonical context keys.
_ALIASES: dict[str, str] = {
    "registry.userassist": "userassist",
    "registry.hivelist": "hivelist",
    "registry.hivescan": "hivescan",
    "thrdscan": "threads",
    "envars": "envars",
}


def normalize_plugin_key(name: str) -> str:
    key = (name or "").strip().lower()
    if key.startswith("windows."):
        key = key[len("windows."):]
    return _ALIASES.get(key, key)


def score_records(records: dict[str, list[dict]], profile: dict | None = None,
                  plugins: list[str] | tuple[str, ...] | None = None) -> dict:
    """Score parsed plugin records under a profile → explained, JSON-ready view.

    Returns keys: ``scored_objects``, ``attack_techniques``, ``risk_summary``,
    ``profile`` (the effective profile echoed back), ``process_risk`` (a
    pid→verdict map that enriches a process inventory) and
    ``unevaluated_sources``.

    ``plugins`` is the selected extraction plan, when the caller has one. A rule
    keyed to a plugin nobody selected had no evidence to read and could not fire
    — which is a different claim from the rule running and finding nothing, and
    the caller has to be able to tell a reader which one happened.
    """
    prof = TuningProfile.from_dict(profile) if profile else TuningProfile.from_preset("balanced")
    ctx = build_context(records)
    engine = ScoringEngine()
    result = engine.score(ctx, prof)

    # One verdict per process the rules ran against, not only the shortlist.
    # A process can be named by several findings; the row carries the strongest
    # score, since the ladder is ordinal, and the union of what fired.
    findings_by_pid: dict[int, list[dict]] = {}
    for o in (obj.to_dict() for obj in result.all_objects):
        pid = o.get("pid")
        if pid is not None:
            findings_by_pid.setdefault(int(pid), []).append(o)

    process_risk: dict[int, dict] = {}
    for pid in ctx.procs:
        found = findings_by_pid.get(int(pid)) or []
        if not found:
            process_risk[int(pid)] = {
                "state": "no_indicator_fired", "risk": None, "score": 0,
                "confidence": None, "techniques": [], "flags": [],
            }
            continue
        strongest = max(found, key=lambda o: o["score"])
        flags: list[str] = []
        techniques: list[str] = []
        for o in found:
            # Every rule that fired, superseded or not. Family dedup decides what
            # *scores*; it does not decide what was observed, and dropping the
            # weaker observation here would hide a real finding from the analyst
            # rather than merely stop it being counted twice.
            for c in o["contributions"]:
                if c["rule_id"] not in flags:
                    flags.append(c["rule_id"])
            for t in o["techniques"]:
                if t not in techniques:
                    techniques.append(t)
        process_risk[int(pid)] = {
            "state": "scored",
            "risk": strongest["risk"],
            "score": strongest["score"],
            "confidence": max(o["confidence"] for o in found),
            "techniques": techniques,
            "flags": flags,
        }

    return {
        "scored_objects": result.surfaced(),
        "attack_techniques": result.attack_techniques,
        "risk_summary": result.risk_summary,
        "profile": result.profile,
        "process_risk": process_risk,
        "unevaluated_sources": unevaluated_sources(engine.rules, records, plugins),
    }


def unevaluated_sources(rules, records: dict[str, list[dict]],
                        plugins: list[str] | tuple[str, ...] | None = None) -> list[str]:
    """Plugins the rules read that this run has no evidence from.

    Reported once, as a property of the run: the gap is identical for every
    object, so repeating it per row would state a fact about the extraction as
    if it were a finding about the artifact.
    """
    available = {normalize_plugin_key(p) for p in (plugins if plugins is not None else records)}
    wanted: set[str] = set()
    for rule in rules:
        wanted.update(normalize_plugin_key(s) for s in rule.data_sources)
    return sorted(wanted - available)


def diff_scored(prev_objects: list[dict], cur_objects: list[dict]) -> dict:
    """Diff two ``scored_objects`` lists (appeared/disappeared/changed)."""
    return ScoringEngine.diff(prev_objects, cur_objects)
