"""Known-good baselines for Windows core system processes.

Masquerading (T1036) and core-process abuse are best caught by comparing an
observed process against what the OS guarantees about its critical processes:
where they live, who starts them, how many may exist, and which account runs
them. The table below encodes the widely-published DFIR "known normal" baseline
(SANS *Hunt Evil* poster, Microsoft process documentation) for the Windows
processes attackers most often impersonate or hollow.

Only facts that hold across modern Windows (7–11 / Server) are asserted here;
version-specific quirks are intentionally omitted so the rules stay
low-false-positive.
"""
from __future__ import annotations

from dataclasses import dataclass, field

SYSTEM32 = r"\windows\system32"
SYSWOW64 = r"\windows\syswow64"


@dataclass(frozen=True)
class Baseline:
    name: str
    # Legitimate parent image names (lower-case). Empty => parent not asserted.
    parents: frozenset[str] = field(default_factory=frozenset)
    # Directory the image must live under (lower-case, backslashes). None => any.
    directory: str | None = SYSTEM32
    # True when at most one instance should ever exist.
    singleton: bool = False
    # Expected security context; informational for evidence strings.
    account: str = "SYSTEM"


# Core processes most frequently abused via masquerading / hollowing.
CORE_PROCESSES: dict[str, Baseline] = {
    "smss.exe": Baseline("smss.exe", frozenset({"system"}), SYSTEM32, singleton=False),
    "csrss.exe": Baseline("csrss.exe", frozenset({"smss.exe"}), SYSTEM32),
    "wininit.exe": Baseline("wininit.exe", frozenset({"smss.exe"}), SYSTEM32, singleton=True),
    "winlogon.exe": Baseline("winlogon.exe", frozenset({"smss.exe"}), SYSTEM32),
    "services.exe": Baseline("services.exe", frozenset({"wininit.exe"}), SYSTEM32, singleton=True),
    "lsass.exe": Baseline("lsass.exe", frozenset({"wininit.exe"}), SYSTEM32, singleton=True),
    "lsaiso.exe": Baseline("lsaiso.exe", frozenset({"wininit.exe"}), SYSTEM32, singleton=True),
    "svchost.exe": Baseline("svchost.exe", frozenset({"services.exe"}), SYSTEM32),
    "spoolsv.exe": Baseline("spoolsv.exe", frozenset({"services.exe"}), SYSTEM32),
    "taskhostw.exe": Baseline("taskhostw.exe", frozenset({"svchost.exe"}), SYSTEM32),
    "explorer.exe": Baseline(
        "explorer.exe", frozenset({"userinit.exe", "winlogon.exe"}),
        r"\windows", account="user",
    ),
}

# Names that must not appear more than once host-wide.
SINGLETONS: frozenset[str] = frozenset(
    b.name for b in CORE_PROCESSES.values() if b.singleton
)


def is_core(name: str) -> bool:
    return (name or "").strip().lower() in CORE_PROCESSES


def baseline_for(name: str) -> Baseline | None:
    return CORE_PROCESSES.get((name or "").strip().lower())


# Legitimate Windows images that sit within one edit of a core name and must not
# be flagged as masquerades (e.g. taskhost.exe vs the core taskhostw.exe).
_NEVER_MASQUERADE: frozenset[str] = frozenset({"taskhost.exe"})


def osa_distance(a: str, b: str) -> int:
    """Optimal string alignment (Damerau) distance — counts an adjacent
    transposition as a single edit, so ``scvhost``→``svchost`` is distance 1."""
    a, b = a or "", b or ""
    if a == b:
        return 0
    if not a:
        return len(b)
    if not b:
        return len(a)
    d = [[0] * (len(b) + 1) for _ in range(len(a) + 1)]
    for i in range(len(a) + 1):
        d[i][0] = i
    for j in range(len(b) + 1):
        d[0][j] = j
    for i in range(1, len(a) + 1):
        for j in range(1, len(b) + 1):
            cost = 0 if a[i - 1] == b[j - 1] else 1
            d[i][j] = min(d[i - 1][j] + 1, d[i][j - 1] + 1, d[i - 1][j - 1] + cost)
            if (i > 1 and j > 1 and a[i - 1] == b[j - 2] and a[i - 2] == b[j - 1]):
                d[i][j] = min(d[i][j], d[i - 2][j - 2] + 1)
    return d[len(a)][len(b)]


def near_miss_core(name: str, max_distance: int = 1) -> str | None:
    """Return the core process a name *impersonates* (svch0st→svchost) or None.

    An exact core-process name is legitimate and never a near-miss. A name within
    ``max_distance`` edits of a core name — but not itself a known core/legit name —
    is a classic typo-squat / homoglyph / transposition masquerade (scvhost,
    lsass1, svch0st).
    """
    n = (name or "").strip().lower()
    if not n or n in CORE_PROCESSES or n in _NEVER_MASQUERADE:
        return None
    for core in CORE_PROCESSES:
        if 0 < osa_distance(n, core) <= max_distance:
            return core
    return None
