"""The scoring engine: rules + correlations + profile → explained verdicts.

Given a parsed :class:`~.context.TriageContext` and a
:class:`~.profile.TuningProfile`, the engine:

1. runs every *enabled* rule and groups the resulting hits per object;
2. records one :class:`~.rules.Contribution` per fired rule (weight resolved from
   the profile), so nothing is opaque;
3. applies correlation rules — a bonus + a confidence lift when independent
   signals co-occur on the same object;
4. keeps only the strongest contribution within each *hypothesis family* before
   summing — so one fact observed from two angles is counted once — caps the
   result at :data:`~.rules.MAX_RISK_SCORE`, derives an aggregate confidence
   (noisy-OR of the contributing rules, then lifted by any correlation) and the
   risk band; and
5. surfaces only objects that clear the per-category score threshold **and** the
   confidence floor (and, if required, are corroborated) — suppressing lone weak
   indicators.

Re-running is pure and fast, which is what makes live tuning possible: the same
cached artifacts are re-scored on every profile change without touching Volatility.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from .catalog import default_rules
from .context import TriageContext
from .correlate import Correlation, default_correlations
from .profile import TuningProfile
from .rules import MAX_RISK_SCORE, Contribution, Rule, ScoredObject


def _mark_superseded(contribs: list[Contribution]) -> None:
    """Keep the strongest contribution per hypothesis family; flag the rest.

    Ported from VolMemLyzer's ``_record_evidence``/``_finish_evidence`` pair,
    which kept one observation per family before summing. Superseded
    contributions stay on the object so the analyst still sees what was
    observed — they simply stop adding to the score.
    """
    strongest: dict[str, Contribution] = {}
    for c in contribs:
        best = strongest.get(c.family)
        if best is None or c.weight > best.weight:
            strongest[c.family] = c
    for c in contribs:
        c.superseded = strongest.get(c.family) is not c


def _noisy_or(confidences: list[float]) -> float:
    prod = 1.0
    for c in confidences:
        prod *= (1.0 - max(0.0, min(1.0, c)))
    return 1.0 - prod


@dataclass
class ScoringResult:
    objects: list[ScoredObject] = field(default_factory=list)
    attack_techniques: list[dict] = field(default_factory=list)
    risk_summary: dict = field(default_factory=dict)
    profile: dict = field(default_factory=dict)

    def surfaced(self) -> list[dict]:
        return [o.to_dict() for o in self.objects]

    def to_dict(self) -> dict:
        return {
            "objects": self.surfaced(),
            "attack_techniques": self.attack_techniques,
            "risk_summary": self.risk_summary,
            "profile": self.profile,
        }


class ScoringEngine:
    def __init__(self, rules: list[Rule] | None = None,
                 correlations: list[Correlation] | None = None) -> None:
        self.rules = rules if rules is not None else default_rules()
        self.correlations = correlations if correlations is not None else default_correlations()

    # -- scoring ---------------------------------------------------------
    def score(self, ctx: TriageContext, profile: TuningProfile | None = None) -> ScoringResult:
        profile = profile or TuningProfile.from_preset("balanced")
        rule_by_id = {r.id: r for r in self.rules}

        # 1) collect contributions per (object_type, key)
        groups: dict[tuple[str, str], dict] = {}
        for rule in self.rules:
            if not profile.rule_enabled(rule):
                continue
            try:
                hits = rule.evaluate(ctx)
            except Exception:  # noqa: S112 — one failing rule must not stop scoring
                continue
            weight = profile.rule_weight(rule)
            for hit in hits:
                gk = (rule.object_type, hit.key)
                grp = groups.setdefault(gk, {
                    "object_type": rule.object_type, "key": hit.key,
                    "label": hit.label, "pid": hit.pid,
                    "contribs": [], "fired": set(),
                })
                if hit.pid is not None:
                    grp["pid"] = hit.pid
                grp["contribs"].append(Contribution(
                    rule_id=rule.id, title=rule.title, weight=weight,
                    evidence=hit.evidence, technique_id=rule.technique_id,
                    technique_name=rule.technique_name, tactic=rule.tactic,
                    severity=rule.severity, confidence=rule.confidence,
                    family=rule.hypothesis, context_only=rule.context_only,
                ))
                grp["fired"].add(rule.id)

        # 2) correlations, scoring, banding
        objects: list[ScoredObject] = []
        for grp in groups.values():
            contribs: list[Contribution] = grp["contribs"]
            fired: set[str] = grp["fired"]
            _mark_superseded(contribs)
            correlated = False
            for corr in self.correlations:
                if corr.fires(fired):
                    correlated = True
                    contribs.append(Contribution(
                        rule_id=corr.id, title=corr.title, weight=corr.bonus,
                        evidence=(f"{corr.title}: independent signals "
                                  f"{sorted(corr.members & fired)} corroborate"),
                        technique_id=corr.technique_id,
                        technique_name=corr.technique_name, tactic=corr.tactic,
                        severity=4, confidence=corr.confidence_boost,
                    ))

            # Only the strongest observation in each hypothesis family counts,
            # then independent families sum on a bounded ladder. Without this a
            # single fact seen from two angles — "runs from %TEMP%" and "not
            # under a system root" — is counted twice and outranks an object
            # with two genuinely independent signals.
            score = min(MAX_RISK_SCORE,
                        sum(c.weight for c in contribs if not c.superseded))
            # Aggregate confidence rises with each *independent* fired rule.
            confidence = _noisy_or([rule_by_id[r].confidence for r in fired])
            if correlated:
                boost = max(cor.confidence_boost for cor in self.correlations
                            if cor.fires(fired))
                confidence = max(confidence, boost)

            techniques, tactics = [], []
            for c in contribs:
                if c.technique_id not in techniques:
                    techniques.append(c.technique_id)
                if c.tactic not in tactics:
                    tactics.append(c.tactic)

            objects.append(ScoredObject(
                object_type=grp["object_type"], key=grp["key"], label=grp["label"],
                pid=grp["pid"], score=score, risk=profile.band(score),
                confidence=confidence, tactics=tactics, techniques=techniques,
                contributions=sorted(contribs, key=lambda c: c.weight, reverse=True),
            ))
            # stash correlation flag for surfacing decision
            objects[-1]._correlated = correlated  # type: ignore[attr-defined]

        # 3) surface + sort
        surfaced = [o for o in objects if self._surfaces(o, profile)]
        surfaced.sort(key=lambda o: (o.score, o.confidence), reverse=True)

        return ScoringResult(
            objects=surfaced,
            attack_techniques=self._attack(surfaced),
            risk_summary=self._summary(surfaced),
            profile=profile.to_dict(),
        )

    @staticmethod
    def _surfaces(o: ScoredObject, profile: TuningProfile) -> bool:
        # Context corroborates a real signal; it is never the reason an object is
        # shown. An object whose every scoring contribution is context describes
        # ordinary behaviour, so surfacing it ranks the busiest process first.
        if all(c.context_only for c in o.contributions if not c.superseded):
            return False
        if o.score < profile.surface_threshold(o.object_type):
            return False
        if o.confidence < profile.confidence_floor:
            return False
        return not (profile.require_correlation and not getattr(o, "_correlated", False))

    @staticmethod
    def _attack(objects: list[ScoredObject]) -> list[dict]:
        agg: dict[str, dict] = {}
        for o in objects:
            for c in o.contributions:
                e = agg.setdefault(c.technique_id, {
                    "technique_id": c.technique_id, "name": c.technique_name,
                    "tactic": c.tactic, "object_count": 0, "evidence": c.evidence,
                })
                e["object_count"] += 1
        return sorted(agg.values(), key=lambda t: t["object_count"], reverse=True)

    @staticmethod
    def _summary(objects: list[ScoredObject]) -> dict:
        bands = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
        types: dict[str, int] = {}
        for o in objects:
            bands[o.risk] = bands.get(o.risk, 0) + 1
            types[o.object_type] = types.get(o.object_type, 0) + 1
        return {"total": len(objects), "by_risk": bands, "by_type": types}

    # -- diffing (live-tuning feedback) ---------------------------------
    @staticmethod
    def diff(prev: list[dict], cur: list[dict]) -> dict:
        """What changed between two scored-object lists (for the tuning UI)."""
        def index(objs):
            return {(o["object_type"], o["key"]): o for o in objs}
        pi, ci = index(prev or []), index(cur or [])
        appeared, disappeared, changed = [], [], []
        for k, o in ci.items():
            if k not in pi:
                appeared.append({"object_type": k[0], "key": k[1], "label": o["label"],
                                 "risk": o["risk"], "score": o["score"]})
        for k, o in pi.items():
            if k not in ci:
                disappeared.append({"object_type": k[0], "key": k[1], "label": o["label"],
                                    "risk": o["risk"], "score": o["score"]})
        for k in pi.keys() & ci.keys():
            a, b = pi[k], ci[k]
            if (a["score"] != b["score"] or a["risk"] != b["risk"]
                    or a["confidence"] != b["confidence"]):
                changed.append({
                    "object_type": k[0], "key": k[1], "label": b["label"],
                    "score_from": a["score"], "score_to": b["score"],
                    "risk_from": a["risk"], "risk_to": b["risk"],
                    "confidence_from": a["confidence"], "confidence_to": b["confidence"],
                })
        return {"appeared": appeared, "disappeared": disappeared, "changed": changed}
