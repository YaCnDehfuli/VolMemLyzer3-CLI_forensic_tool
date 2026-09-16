"""Correlation rules: reward independent signals that co-occur on one object.

A single weak indicator should stay low-confidence; several *independent* signals
landing on the same process are what turn a hunch into a finding. A correlation
fires only when at least ``min_count`` of its member rules fired on the same
object, and it prefers members drawn from *different* data sources (so two views
of the same artifact don't self-corroborate). When it fires it adds a bonus
contribution and lifts the object's confidence toward ``confidence_boost`` — which
is how a correlated object clears the confidence floor that suppresses lone weak
signals.
"""
from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class Correlation:
    id: str
    title: str
    tactic: str
    technique_id: str
    technique_name: str
    members: frozenset[str]        # rule ids that corroborate each other
    min_count: int                 # how many members must fire
    bonus: float                   # extra score when it fires
    confidence_boost: float        # object confidence is raised toward this
    require_distinct_sources: bool = True
    member_sources: dict[str, tuple[str, ...]] = field(default_factory=dict)

    def fires(self, fired_rule_ids: set[str]) -> bool:
        present = self.members & fired_rule_ids
        if len(present) < self.min_count:
            return False
        if self.require_distinct_sources and self.member_sources:
            sources: set[str] = set()
            for rid in present:
                sources.update(self.member_sources.get(rid, ()))
            if len(sources) < self.min_count:
                return False
        return True


def default_correlations() -> list[Correlation]:
    return [
        Correlation(
            "corr_strong_injection", "Corroborated code injection",
            "Defense Evasion", "T1055", "Process Injection",
            members=frozenset({"malfind_rwx_private", "malfind_pe_header",
                               "malfind_shellcode", "ldrmodules_unlinked",
                               "thread_unbacked_start"}),
            min_count=2, bonus=8.0, confidence_boost=0.92,
            member_sources={
                "malfind_rwx_private": ("malfind",),
                "malfind_pe_header": ("malfind",),
                "malfind_shellcode": ("malfind",),
                "ldrmodules_unlinked": ("ldrmodules",),
                "thread_unbacked_start": ("threads",),
            },
        ),
        Correlation(
            "corr_masquerade", "Corroborated masquerading",
            "Defense Evasion", "T1036", "Masquerading",
            members=frozenset({"core_proc_wrong_path", "core_proc_wrong_parent",
                               "core_proc_illegal_instances", "core_proc_masquerade_name"}),
            min_count=2, bonus=8.0, confidence_boost=0.9,
            member_sources={
                "core_proc_wrong_path": ("cmdline",),
                "core_proc_wrong_parent": ("pstree",),
                "core_proc_illegal_instances": ("psscan",),
                "core_proc_masquerade_name": ("pslist",),
            },
        ),
        Correlation(
            "corr_credential_theft", "Corroborated credential access",
            "Credential Access", "T1003.001", "LSASS Memory",
            members=frozenset({"lsass_handle", "token_sedebug", "malfind_rwx_private"}),
            min_count=2, bonus=6.0, confidence_boost=0.85,
            member_sources={
                "lsass_handle": ("handles",),
                "token_sedebug": ("privileges",),
                "malfind_rwx_private": ("malfind",),
            },
        ),
    ]
