"""The VolMemLyzer scoring engine: explainable, MITRE-aligned, tunable.

One engine scores every artifact VolMemLyzer extracts. A rule is *data* — its
ATT&CK alignment, the plugins it reads, a severity and a source confidence, the
investigative hypothesis it tests, and a pure predicate — so a verdict is always
traceable to the rules and evidence that produced it.

Scoring keeps the strongest observation within each hypothesis family, sums the
independent families on a bounded 0–30 ladder, and derives confidence by
noisy-OR over the rules that fired. Re-scoring is pure and runs in milliseconds
from cached plugin records, so a profile change never re-runs Volatility.

Public surface:

* :func:`score_records` — parsed plugin records + a profile → explained verdicts;
* :func:`diff_scored` — what changed between two scorings (live-tuning feedback);
* :class:`TuningProfile` — presets plus per-rule overrides;
* :data:`CONTEXT_PLUGINS` — the plugin set worth caching for re-scoring.
"""
from .profile import TuningProfile
from .rules import MAX_RISK_SCORE, RISK_BANDS, Contribution, Hit, Rule, ScoredObject
from .service import (
    CONTEXT_PLUGINS,
    diff_scored,
    normalize_plugin_key,
    score_records,
)

__all__ = [
    "CONTEXT_PLUGINS",
    "MAX_RISK_SCORE",
    "RISK_BANDS",
    "Contribution",
    "Hit",
    "Rule",
    "ScoredObject",
    "TuningProfile",
    "diff_scored",
    "normalize_plugin_key",
    "score_records",
]
