"""Normalized triage context assembled from cached raw plugin records.

The engine re-scores from cache on every tuning change, so parsing must be pure
and cheap. :func:`build_context` turns the raw Volatility ``-r=json`` records
(exactly what VolMemLyzer already writes to disk) into a process census plus
light per-plugin aggregates the rules consume. Field-name drift across Volatility
versions is absorbed by :func:`g`.

Nothing here executes anything or imports Volatility — records are treated as
untrusted data only.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any


def g(rec: dict, *keys: str, default: Any = None) -> Any:
    """First present, non-empty key among candidates (version-drift guard)."""
    for k in keys:
        if k in rec and rec[k] not in (None, ""):
            return rec[k]
    return default


def as_int(v: Any) -> int | None:
    try:
        return int(v)
    except (TypeError, ValueError):
        return None


_IMG_RE = re.compile(
    r'([a-zA-Z]:\\[^"]+?\.(?:exe|dll|sys|com|scr))', re.IGNORECASE
)


def image_path_from_cmdline(args: str) -> str:
    """Best-effort image path from a command line (quoted, or first token)."""
    s = (args or "").strip()
    if not s:
        return ""
    if s.startswith('"'):
        end = s.find('"', 1)
        if end > 0:
            return s[1:end]
    m = _IMG_RE.search(s)
    if m:
        return m.group(1)
    return s.split(" ", 1)[0]


@dataclass
class ProcInfo:
    pid: int
    name: str = ""
    ppid: int | None = None
    path: str = ""             # image path (from cmdline when available)
    cmdline: str = ""
    wow64: bool | None = None
    in_pslist: bool = False
    in_psscan: bool = False
    psxview_false: list[str] = field(default_factory=list)

    @property
    def name_l(self) -> str:
        return (self.name or "").strip().lower()


@dataclass
class TriageContext:
    """Everything the rules need, parsed once from the cached artifacts."""

    procs: dict[int, ProcInfo] = field(default_factory=dict)
    plugins: dict[str, list[dict]] = field(default_factory=dict)
    # Per-connection aggregates (mirrors VolMemLyzer's netscan context).
    pid_conn_count: dict[str, int] = field(default_factory=dict)
    remote_pub_count: dict[str, int] = field(default_factory=dict)

    # -- process helpers -------------------------------------------------
    def name_of(self, pid: int | None) -> str:
        p = self.procs.get(pid) if pid is not None else None
        return p.name_l if p else ""

    def parent(self, pid: int) -> ProcInfo | None:
        p = self.procs.get(pid)
        if not p or p.ppid is None:
            return None
        return self.procs.get(p.ppid)

    def records(self, plugin: str) -> list[dict]:
        return self.plugins.get(plugin) or []

    def label(self, pid: int) -> str:
        return f"{self.name_of(pid) or '(unknown)'} ({pid})"


# Names that carry no user VADs and are noisy sources of false positives.
_SYSTEM_OWNERS = {
    "system", "services.exe", "lsass.exe", "wininit.exe", "svchost.exe",
    "smss.exe", "csrss.exe", "spoolsv.exe",
}


def is_system_owner(name: str) -> bool:
    return (name or "").strip().lower() in _SYSTEM_OWNERS


def _merge_census(procs: dict[int, ProcInfo], records: list[dict], *, in_pslist: bool,
                  in_psscan: bool) -> None:
    for r in records or []:
        pid = as_int(g(r, "PID", "Pid", "pid"))
        if pid is None:
            continue
        p = procs.get(pid)
        if p is None:
            p = ProcInfo(pid=pid)
            procs[pid] = p
        name = g(r, "ImageFileName", "Name", "Process", "name")
        if name and not p.name:
            p.name = str(name).strip()
        ppid = as_int(g(r, "PPID", "Ppid", "ppid"))
        if ppid is not None and p.ppid is None:
            p.ppid = ppid
        w = g(r, "Wow64", "wow64")
        if w is not None and p.wow64 is None:
            p.wow64 = bool(w)
        if in_pslist:
            p.in_pslist = True
        if in_psscan:
            p.in_psscan = True


def build_context(records: dict[str, list[dict]]) -> TriageContext:
    """Assemble a :class:`TriageContext` from raw records keyed by plugin name.

    Recognized plugin keys: ``pslist pstree psscan psxview cmdline malfind
    ldrmodules handles privileges threads netscan svcscan scheduled_tasks
    userassist hivelist hivescan``. Unknown keys are carried through verbatim so
    new rules can reach them without touching this function.
    """
    ctx = TriageContext(plugins={k: (v or []) for k, v in (records or {}).items()})

    _merge_census(ctx.procs, records.get("pslist"), in_pslist=True, in_psscan=False)
    _merge_census(ctx.procs, records.get("psscan"), in_pslist=False, in_psscan=True)

    # pstree fills parent/name gaps only (never overrides pslist truth).
    for r in records.get("pstree") or []:
        pid = as_int(g(r, "PID", "Pid", "pid"))
        if pid is None or pid not in ctx.procs:
            continue
        p = ctx.procs[pid]
        if p.ppid is None:
            p.ppid = as_int(g(r, "PPID", "Ppid"))
        if not p.name:
            p.name = str(g(r, "ImageFileName", "Name", default="")).strip()

    # cmdline gives the real image path + full command line.
    for r in records.get("cmdline") or []:
        pid = as_int(g(r, "PID", "Pid", "pid"))
        if pid is None or pid not in ctx.procs:
            continue
        args = str(g(r, "Args", "CommandLine", "Cmd", default="") or "")
        p = ctx.procs[pid]
        p.cmdline = args
        if not p.path:
            p.path = image_path_from_cmdline(args)

    # psxview: record which discovery sources reported the PID as absent.
    for r in records.get("psxview") or []:
        pid = as_int(g(r, "PID", "Pid", "pid"))
        if pid is None:
            continue
        falses = [
            str(k) for k, v in r.items()
            if isinstance(v, bool) and v is False and str(k).upper() not in {"PID", "WOW64"}
        ]
        if falses:
            ctx.procs.setdefault(pid, ProcInfo(pid=pid)).psxview_false = falses

    _build_net_aggregates(ctx, records.get("netscan"))
    return ctx


def _is_private_ip(ip: str) -> bool:
    import ipaddress
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return True  # unparseable → treat as non-routable, do not alert


def _build_net_aggregates(ctx: TriageContext, rows: list[dict] | None) -> None:
    for r in rows or []:
        pid = str(g(r, "PID", "Pid", "pid", default="") or "")
        state = str(g(r, "State", default="") or "").upper()
        fa = str(g(r, "ForeignAddr", "Foreign Address", default="") or "")
        fip = fa.split(":")[0].strip() if fa else ""
        if pid:
            ctx.pid_conn_count[pid] = ctx.pid_conn_count.get(pid, 0) + 1
        if (state in {"ESTABLISHED", "SYN_SENT"} and fip
                and fip not in {"*", "0.0.0.0", "::"}  # noqa: S104  # nosec B104 — wildcard check
                and not _is_private_ip(fip)):
            ctx.remote_pub_count[fip] = ctx.remote_pub_count.get(fip, 0) + 1
