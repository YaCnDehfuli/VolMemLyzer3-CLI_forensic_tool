"""Core data types for the explainable scoring engine.

A rule is *data*: identity, MITRE alignment, the plugins it reads, a severity and
a source-confidence, and a pure ``evaluate`` predicate that returns the objects it
fires on. Nothing here touches Volatility or the model — rules operate on already
parsed plugin records (see :mod:`.context`) so the whole engine is unit-testable
and re-runs in milliseconds from cached artifacts.

The weight a fired rule contributes is derived from ``severity × confidence`` by a
single documented formula (:data:`SEVERITY_POINTS`), never an arbitrary constant.
Every contribution to an object's score is recorded, so a verdict is always fully
traceable back to the rules and evidence that produced it.
"""
from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:  # pragma: no cover - typing only
    from .context import TriageContext

# Object kinds a rule can score. The engine groups hits per (type, key).
OBJ_PROCESS = "process"
OBJ_CONNECTION = "connection"
OBJ_PERSISTENCE = "persistence"
OBJ_KERNEL = "kernel"

# Severity (1..4) → base points. These map onto the risk bands
# (Medium≥9 / High≥14 / Critical≥20): one strong-but-uncertain signal lands in
# Medium, two corroborating signals reach High/Critical. Chosen to preserve the
# magnitudes of the original VolMemLyzer scorers (+2/+4/+8/+12) while making the
# relationship to severity explicit and uniform across every category.
SEVERITY_POINTS: dict[int, int] = {1: 3, 2: 5, 3: 8, 4: 12}

# The ladder every object is read on. Bounded on purpose: a score is ordinal
# evidence, not a probability, and an unbounded sum lets one noisy category
# outrun every other. Matches the bands above.
MAX_RISK_SCORE = 30
RISK_BANDS: tuple[tuple[str, int], ...] = (
    ("Critical", 20), ("High", 14), ("Medium", 9), ("Low", 0),
)

# A rule that fires but only corroborates. Context never reaches the surfacing
# floor on its own, however many context rules agree: they describe what most
# software does, so on their own they rank the busiest process first rather than
# the most anomalous one. They still lift a real signal's confidence.
CONTEXT_ONLY = "context"


@dataclass(frozen=True)
class Hit:
    """One object a rule fired on, with the concrete evidence that triggered it."""

    key: str            # stable identity within the object type (e.g. str(pid))
    label: str          # human label, e.g. "evil.exe (1337)"
    evidence: str       # analyst-facing reason, quoting the artifact
    pid: int | None = None


@dataclass(frozen=True)
class Rule:
    """A single, tunable, MITRE-aligned detection heuristic."""

    id: str
    title: str
    tactic: str                 # ATT&CK tactic name(s), human readable
    technique_id: str           # e.g. "T1055"
    technique_name: str
    data_sources: tuple[str, ...]
    object_type: str            # OBJ_PROCESS | OBJ_CONNECTION | OBJ_PERSISTENCE
    severity: int               # 1..4
    confidence: float           # 0..1 — reliability of the source signal
    evaluate: Callable[[TriageContext], list[Hit]]
    # The investigative hypothesis this rule tests: identity, location, lineage,
    # discovery, payload, loader_behavior, listener, volume, … Only the strongest
    # rule within a family counts toward an object's score, so one underlying
    # fact observed several ways is counted once. Defaults to the rule's own id,
    # i.e. a family of one, which is the plain sum.
    family: str = ""
    enabled: bool = True
    rationale: str = ""         # why this heuristic / weight (documented inline)
    # Context corroborates but never surfaces alone. See CONTEXT_ONLY.
    context_only: bool = False

    @property
    def hypothesis(self) -> str:
        return self.family or self.id

    @property
    def base_weight(self) -> float:
        """Default score contribution = severity points × source confidence."""
        return round(SEVERITY_POINTS.get(self.severity, 3) * self.confidence, 2)


@dataclass
class Contribution:
    """One rule's recorded contribution to a scored object (full explainability)."""

    rule_id: str
    title: str
    weight: float
    evidence: str
    technique_id: str
    technique_name: str
    tactic: str
    severity: int
    confidence: float
    family: str = ""
    context_only: bool = False
    superseded: bool = False    # a stronger rule in the same family outscored it

    def to_dict(self) -> dict:
        return {
            "rule_id": self.rule_id,
            "title": self.title,
            "weight": round(self.weight, 2),
            "evidence": self.evidence,
            "mitre": {
                "technique_id": self.technique_id,
                "technique_name": self.technique_name,
                "tactic": self.tactic,
            },
            "severity": self.severity,
            "confidence": round(self.confidence, 3),
            "family": self.family,
            "context_only": self.context_only,
            # Recorded, never silently dropped: the analyst can see that this
            # observation was made and why it did not add to the score.
            "superseded": self.superseded,
        }


@dataclass
class ScoredObject:
    """A process / connection / persistence item with its scored, explained verdict."""

    object_type: str
    key: str
    label: str
    pid: int | None
    score: float
    risk: str
    confidence: float
    tactics: list[str] = field(default_factory=list)
    techniques: list[str] = field(default_factory=list)
    contributions: list[Contribution] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "object_type": self.object_type,
            "key": self.key,
            "label": self.label,
            "pid": self.pid,
            "score": round(self.score, 2),
            "score_max": MAX_RISK_SCORE,
            "risk": self.risk,
            "confidence": round(self.confidence, 3),
            "tactics": self.tactics,
            "techniques": self.techniques,
            "contributions": [c.to_dict() for c in self.contributions],
        }
