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


def score_records(records: dict[str, list[dict]], profile: dict | None = None) -> dict:
    """Score parsed plugin records under a profile → explained, JSON-ready view.

    Returns keys: ``scored_objects``, ``attack_techniques``, ``risk_summary``,
    ``profile`` (the effective profile echoed back), and ``process_risk`` (a
    pid→verdict map used to enrich the process inventory).
    """
    prof = TuningProfile.from_dict(profile) if profile else TuningProfile.from_preset("balanced")
    ctx = build_context(records)
    result = ScoringEngine().score(ctx, prof)
    objects = result.surfaced()

    process_risk: dict[int, dict] = {}
    for o in objects:
        if o["object_type"] == "process" and o["pid"] is not None:
            process_risk[int(o["pid"])] = {
                "risk": o["risk"],
                "score": o["score"],
                "confidence": o["confidence"],
                "techniques": o["techniques"],
                "flags": [c["rule_id"] for c in o["contributions"]],
            }
    return {
        "scored_objects": objects,
        "attack_techniques": result.attack_techniques,
        "risk_summary": result.risk_summary,
        "profile": result.profile,
        "process_risk": process_risk,
    }


def diff_scored(prev_objects: list[dict], cur_objects: list[dict]) -> dict:
    """Diff two ``scored_objects`` lists (appeared/disappeared/changed)."""
    return ScoringEngine.diff(prev_objects, cur_objects)
