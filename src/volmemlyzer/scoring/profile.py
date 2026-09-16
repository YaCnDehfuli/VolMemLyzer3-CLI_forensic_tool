"""Tuning profile: the live-adjustable configuration the analyst drives.

A profile is pure JSON so it can be persisted per investigation and round-tripped
to the frontend. Two layers:

* a **sensitivity preset** (Conservative / Balanced / Aggressive) that scales the
  risk-band cut-offs, the confidence floor, and per-category surfacing thresholds
  in one move; and
* an **advanced** per-rule panel (``rule_overrides``) that enables/disables a rule
  or replaces its weight.

The engine re-scores from cached artifacts in milliseconds, so moving any of these
controls re-renders the IoC table without re-running Volatility. Defaults are the
research-backed Balanced preset.
"""
from __future__ import annotations

from dataclasses import dataclass, field

PRESETS = ("conservative", "balanced", "aggressive")

# Risk-band lower cut-offs per preset. Aggressive surfaces weaker signals;
# Conservative demands stronger corroboration before it calls something High.
_PRESET_BANDS: dict[str, dict[str, int]] = {
    "conservative": {"critical": 26, "high": 18, "medium": 12},
    "balanced": {"critical": 20, "high": 14, "medium": 9},
    "aggressive": {"critical": 16, "high": 11, "medium": 6},
}
_PRESET_FLOOR: dict[str, float] = {
    "conservative": 0.55, "balanced": 0.35, "aggressive": 0.2,
}
# Minimum score for an object of each type to be *surfaced* in the IoC table.
# Kept low on purpose: the *risk band* communicates severity, the threshold only
# filters the weakest lone signals (the confidence floor does the rest). One
# strong (severity-4) signal surfaces as Low; corroboration lifts the band.
_PRESET_THRESHOLDS: dict[str, dict[str, int]] = {
    "conservative": {"process": 9, "connection": 8, "persistence": 5, "kernel": 9},
    "balanced": {"process": 4, "connection": 5, "persistence": 2, "kernel": 9},
    "aggressive": {"process": 3, "connection": 4, "persistence": 1, "kernel": 9},
}


@dataclass
class RuleOverride:
    enabled: bool | None = None
    weight: float | None = None

    def to_dict(self) -> dict:
        out: dict = {}
        if self.enabled is not None:
            out["enabled"] = self.enabled
        if self.weight is not None:
            out["weight"] = self.weight
        return out


@dataclass
class TuningProfile:
    preset: str = "balanced"
    risk_bands: dict[str, int] = field(default_factory=lambda: dict(_PRESET_BANDS["balanced"]))
    confidence_floor: float = _PRESET_FLOOR["balanced"]
    category_thresholds: dict[str, int] = field(
        default_factory=lambda: dict(_PRESET_THRESHOLDS["balanced"])
    )
    require_correlation: bool = False
    rule_overrides: dict[str, RuleOverride] = field(default_factory=dict)

    # -- construction ----------------------------------------------------
    @classmethod
    def from_preset(cls, name: str) -> TuningProfile:
        key = (name or "balanced").strip().lower()
        if key not in PRESETS:
            key = "balanced"
        return cls(
            preset=key,
            risk_bands=dict(_PRESET_BANDS[key]),
            confidence_floor=_PRESET_FLOOR[key],
            category_thresholds=dict(_PRESET_THRESHOLDS[key]),
        )

    @classmethod
    def from_dict(cls, data: dict | None) -> TuningProfile:
        data = data or {}
        base = cls.from_preset(data.get("preset", "balanced"))
        if isinstance(data.get("risk_bands"), dict):
            base.risk_bands.update({k: int(v) for k, v in data["risk_bands"].items()})
        if data.get("confidence_floor") is not None:
            base.confidence_floor = max(0.0, min(1.0, float(data["confidence_floor"])))
        if isinstance(data.get("category_thresholds"), dict):
            base.category_thresholds.update(
                {k: int(v) for k, v in data["category_thresholds"].items()}
            )
        base.require_correlation = bool(data.get("require_correlation", False))
        for rid, ov in (data.get("rule_overrides") or {}).items():
            if not isinstance(ov, dict):
                continue
            base.rule_overrides[str(rid)] = RuleOverride(
                enabled=ov.get("enabled"),
                weight=(float(ov["weight"]) if ov.get("weight") is not None else None),
            )
        return base

    def to_dict(self) -> dict:
        return {
            "preset": self.preset,
            "risk_bands": dict(self.risk_bands),
            "confidence_floor": self.confidence_floor,
            "category_thresholds": dict(self.category_thresholds),
            "require_correlation": self.require_correlation,
            "rule_overrides": {k: v.to_dict() for k, v in self.rule_overrides.items()},
        }

    # -- per-rule resolution --------------------------------------------
    def rule_enabled(self, rule) -> bool:
        ov = self.rule_overrides.get(rule.id)
        if ov is not None and ov.enabled is not None:
            return ov.enabled
        return rule.enabled

    def rule_weight(self, rule) -> float:
        ov = self.rule_overrides.get(rule.id)
        if ov is not None and ov.weight is not None:
            return float(ov.weight)
        return rule.base_weight

    # -- banding + surfacing --------------------------------------------
    def band(self, score: float) -> str:
        b = self.risk_bands
        if score >= b.get("critical", 20):
            return "Critical"
        if score >= b.get("high", 14):
            return "High"
        if score >= b.get("medium", 9):
            return "Medium"
        return "Low"

    def surface_threshold(self, object_type: str) -> int:
        return int(self.category_thresholds.get(object_type, 0))
