"""The MemTriage rule catalog: explainable, MITRE-aligned detections.

Each rule is a small pure predicate over a :class:`~.context.TriageContext`. Rules
are grouped by ATT&CK tactic and every one carries the data source(s) it reads, a
severity and a source confidence (which together set its default weight), and an
evidence string that quotes the artifact so a verdict is always traceable.

This catalog ports VolMemLyzer's ``OverviewAnalysis`` scorers with the fixes noted
in :mod:`.heuristics`, and adds the core-process-integrity, lineage, credential,
token and thread heuristics that VolMemLyzer did not cover.

Research anchors: SANS *Hunt Evil* process baselines, Elastic *Hunting In Memory*,
Forrest Orr / CyberArk on hollowing & unlinked modules, MITRE ATT&CK.
"""
from __future__ import annotations

import ipaddress

from . import heuristics as H
from . import windows_baselines as WB
from .context import TriageContext, as_int, g, is_system_owner
from dataclasses import replace

from .rules import (
    OBJ_CONNECTION,
    OBJ_KERNEL,
    OBJ_PERSISTENCE,
    OBJ_PROCESS,
    Hit,
    Rule,
)

SCRIPT_INTERPRETERS = {
    "cmd.exe", "powershell.exe", "pwsh.exe", "wscript.exe", "cscript.exe",
    "mshta.exe", "rundll32.exe", "regsvr32.exe",
}
OFFICE_APPS = {
    "winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe", "onenote.exe",
    "msaccess.exe", "mspub.exe",
}
LOLBIN_NET_CLIENTS = {
    "powershell.exe", "pwsh.exe", "cmd.exe", "wscript.exe", "cscript.exe",
    "mshta.exe", "rundll32.exe", "regsvr32.exe", "certutil.exe", "bitsadmin.exe",
}


# =====================================================================
# Core-process integrity / masquerading (T1036)
# =====================================================================

def _core_wrong_path(ctx: TriageContext) -> list[Hit]:
    hits: list[Hit] = []
    for p in ctx.procs.values():
        b = WB.baseline_for(p.name)
        if not b or not b.directory or not p.path:
            continue  # only judge when we actually know the image path
        if b.directory not in H._norm(p.path):
            hits.append(Hit(str(p.pid), ctx.label(p.pid),
                            f"{p.name} running from {p.path}; expected under {b.directory}",
                            pid=p.pid))
    return hits


def _core_wrong_parent(ctx: TriageContext) -> list[Hit]:
    hits: list[Hit] = []
    for p in ctx.procs.values():
        b = WB.baseline_for(p.name)
        if not b or not b.parents:
            continue
        parent = ctx.parent(p.pid)
        if parent is None or not parent.name:
            continue  # parent unknown (e.g. smss already exited) → do not guess
        if parent.name_l not in b.parents:
            hits.append(Hit(str(p.pid), ctx.label(p.pid),
                            f"{p.name} parented by {parent.name}; expected "
                            f"{sorted(b.parents)}", pid=p.pid))
    return hits


def _core_illegal_instances(ctx: TriageContext) -> list[Hit]:
    counts: dict[str, list[int]] = {}
    for p in ctx.procs.values():
        if p.name_l in WB.SINGLETONS:
            counts.setdefault(p.name_l, []).append(p.pid)
    hits: list[Hit] = []
    for name, pids in counts.items():
        if len(pids) > 1:
            for pid in pids:
                hits.append(Hit(str(pid), ctx.label(pid),
                                f"{len(pids)} instances of singleton {name} "
                                f"(PIDs {sorted(pids)})", pid=pid))
    return hits


def _core_masquerade_name(ctx: TriageContext) -> list[Hit]:
    hits: list[Hit] = []
    for p in ctx.procs.values():
        near = WB.near_miss_core(p.name)
        if near:
            hits.append(Hit(str(p.pid), ctx.label(p.pid),
                            f"'{p.name}' resembles core process '{near}' "
                            f"(possible typo-squat/homoglyph)", pid=p.pid))
    return hits


# =====================================================================
# Process discovery anomalies (T1014 / T1055)
# =====================================================================

def _hidden_process(ctx: TriageContext) -> list[Hit]:
    """A pool-scan-only process that has *not* exited.

    The original fired on every psscan-only PID and said so in its own evidence
    string — "hidden or terminated". On a live image most of those are simply
    processes that ended before capture, and scoring them as unlinked put ten
    ordinary exits in the table alongside the one finding that mattered.
    VolMemLyzer separated the two (HK vs TERM); this restores that distinction.
    """
    hits: list[Hit] = []
    for p in ctx.procs.values():
        if p.in_psscan and not p.in_pslist and not p.exited:
            hits.append(Hit(str(p.pid), ctx.label(p.pid),
                            "Present in the psscan pool scan, absent from the pslist "
                            "EPROCESS walk, and carries no exit time — unlinked rather "
                            "than terminated", pid=p.pid))
    return hits


# psxview cross-checks four discovery sources. A process that has simply exited
# is legitimately missing from one of them, so a single False is the normal case
# and not a finding; two or more disagreeing is the anomaly.
_PSXVIEW_MIN_DISAGREEING = 2


def _psxview_inconsistent(ctx: TriageContext) -> list[Hit]:
    hits: list[Hit] = []
    for p in ctx.procs.values():
        if len(p.psxview_false) >= _PSXVIEW_MIN_DISAGREEING:
            hits.append(Hit(str(p.pid), ctx.label(p.pid),
                            f"{len(p.psxview_false)} discovery sources disagree (psxview): "
                            f"{', '.join(p.psxview_false)} = False", pid=p.pid))
    return hits


def _suspicious_path(ctx: TriageContext) -> list[Hit]:
    hits: list[Hit] = []
    for p in ctx.procs.values():
        if p.path and H.is_suspicious_path(p.path):
            hits.append(Hit(str(p.pid), ctx.label(p.pid),
                            f"Image in user-writable/staging path ({p.path})", pid=p.pid))
    return hits


# =====================================================================
# Injection & hollowing (T1055) — attributed to the owning PID
# =====================================================================

def _malfind_regions(ctx: TriageContext):
    for r in ctx.records("malfind"):
        pid = g(r, "PID", "Pid", "pid")
        try:
            pid = int(pid)
        except (TypeError, ValueError):
            continue
        yield pid, r


def _is_private(row: dict) -> bool:
    pm = g(row, "PrivateMemory", "Private")
    if pm in (1, "1", True):
        return True
    return str(g(row, "File output", "FileOutput", default="")).lower() == "disabled"


def _malfind_rwx_private(ctx: TriageContext) -> list[Hit]:
    hits: list[Hit] = []
    for pid, r in _malfind_regions(ctx):
        prot = str(g(r, "Protection", default=""))
        if H.protection_is_rwx(prot) and _is_private(r):
            start = g(r, "Start VPN", "Start", default="?")
            hits.append(Hit(str(pid), ctx.label(pid),
                            f"RWX private memory region at {start} ({prot})", pid=pid))
    return hits


def _malfind_pe_header(ctx: TriageContext) -> list[Hit]:
    hits: list[Hit] = []
    for pid, r in _malfind_regions(ctx):
        if not _is_private(r):
            continue
        data = H.hexdump_to_bytes(str(g(r, "Hexdump", "hex_dump", default="")))
        if H.has_pe_header(data):
            start = g(r, "Start VPN", "Start", default="?")
            hits.append(Hit(str(pid), ctx.label(pid),
                            f"MZ/PE header inside private executable region at "
                            f"{start} (reflective PE)", pid=pid))
    return hits


def _malfind_shellcode(ctx: TriageContext) -> list[Hit]:
    hits: list[Hit] = []
    for pid, r in _malfind_regions(ctx):
        data = H.hexdump_to_bytes(str(g(r, "Hexdump", "hex_dump", default="")))
        sigs = H.shellcode_signals(data)
        if sigs:
            start = g(r, "Start VPN", "Start", default="?")
            hits.append(Hit(str(pid), ctx.label(pid),
                            f"Shellcode byte signature(s) at {start}: "
                            f"{', '.join(sigs)}", pid=pid))
    return hits


def _ldrmodules_unlinked(ctx: TriageContext) -> list[Hit]:
    hits: list[Hit] = []
    for r in ctx.records("ldrmodules"):
        pid = g(r, "PID", "Pid", "pid")
        try:
            pid = int(pid)
        except (TypeError, ValueError):
            continue
        mapped = str(g(r, "MappedPath", "Path", default="") or "")
        in_load = g(r, "InLoad")
        # Strong signal: a real DLL present in a VAD but unlinked from the load
        # order list (classic reflective/hollowing hiding). The main EXE legit-
        # imately misses InInit, so we key on InLoad and require a .dll path.
        if in_load is False and mapped.lower().endswith(".dll"):
            hits.append(Hit(str(pid), ctx.label(pid),
                            f"{mapped} unlinked from the InLoad module list "
                            "(hidden DLL)", pid=pid))
    return hits


# =====================================================================
# Suspicious lineage / LOLBIN spawn (T1059)
# =====================================================================

def _lineage(ctx: TriageContext, parents: set[str], children: set[str], why: str) -> list[Hit]:
    hits: list[Hit] = []
    for p in ctx.procs.values():
        if p.name_l not in children:
            continue
        parent = ctx.parent(p.pid)
        if parent and parent.name_l in parents:
            hits.append(Hit(str(p.pid), ctx.label(p.pid),
                            f"{parent.name} spawned {p.name} — {why}", pid=p.pid))
    return hits


def _lolbin_from_office(ctx: TriageContext) -> list[Hit]:
    return _lineage(ctx, OFFICE_APPS, SCRIPT_INTERPRETERS,
                    "Office application spawning a script interpreter")


def _lolbin_from_service_host(ctx: TriageContext) -> list[Hit]:
    return _lineage(ctx, {"services.exe", "svchost.exe"},
                    {"powershell.exe", "pwsh.exe", "cmd.exe", "wscript.exe",
                     "cscript.exe", "mshta.exe"},
                    "service host spawning a script interpreter")


# =====================================================================
# Credential access (T1003) / privilege (T1134) / threads (T1055)
# =====================================================================

def _lsass_handle(ctx: TriageContext) -> list[Hit]:
    hits: list[Hit] = []
    for r in ctx.records("handles"):
        if str(g(r, "Type", default="")).lower() != "process":
            continue
        target = str(g(r, "Name", default="") or "").lower()
        if "lsass" not in target:
            continue
        pid = g(r, "PID", "Pid", "pid")
        try:
            pid = int(pid)
        except (TypeError, ValueError):
            continue
        holder = ctx.name_of(pid) or str(g(r, "Process", default=""))
        if is_system_owner(holder) or "lsass" in (holder or "").lower():
            continue  # legitimate system access
        access = g(r, "GrantedAccess", "Access", default="")
        hits.append(Hit(str(pid), ctx.label(pid),
                        f"{holder or 'process'} holds a handle to lsass.exe "
                        f"(access {access})", pid=pid))
    return hits


def _token_sedebug(ctx: TriageContext) -> list[Hit]:
    sensitive = {"sedebugprivilege", "setcbprivilege", "seloaddriverprivilege"}
    hits: list[Hit] = []
    for r in ctx.records("privileges"):
        priv = str(g(r, "Privilege", default="") or "").lower()
        if priv not in sensitive:
            continue
        attrs = str(g(r, "Attributes", default="") or "").lower()
        if "enabled" not in attrs:
            continue
        pid = g(r, "PID", "Pid", "pid")
        try:
            pid = int(pid)
        except (TypeError, ValueError):
            continue
        holder = ctx.name_of(pid)
        if is_system_owner(holder):
            continue
        hits.append(Hit(str(pid), ctx.label(pid),
                        f"{holder or 'process'} has {priv} enabled", pid=pid))
    return hits


def _thread_unbacked(ctx: TriageContext) -> list[Hit]:
    hits: list[Hit] = []
    for plugin in ("threads", "thrdscan"):
        for r in ctx.records(plugin):
            start = g(r, "StartAddress", "Start Address", "Win32StartAddress")
            if start in (None, ""):
                continue
            owner = g(r, "Owner", "StartModule", "MappedPath", "Module")
            unbacked_flag = g(r, "Unbacked", "Suspicious")
            # Fire when the start address resolves to no backing module, or the
            # plugin explicitly flagged the region as unbacked/private.
            owner_missing = owner in (None, "") and "owner" in {k.lower() for k in r}
            if unbacked_flag in (True, 1, "1") or owner_missing:
                pid = g(r, "PID", "Pid", "pid")
                try:
                    pid = int(pid)
                except (TypeError, ValueError):
                    continue
                hits.append(Hit(str(pid), ctx.label(pid),
                                f"Thread start address {start} in unbacked/private "
                                "memory", pid=pid))
    return hits


# =====================================================================
# Network (T1071 / T1571) — connection objects
# =====================================================================

_SUSPICIOUS_PORTS = {4444, 1337, 6969, 2222, 9001, 6667, 6666, 31337}
_COMMON_PORTS = {
    80, 443, 53, 123, 25, 110, 995, 143, 993, 3389, 445, 139, 22, 21, 23,
    587, 465, 389, 636, 135, 137, 138, 3306, 1433, 1521, 5432, 27017, 8080, 8443,
}


def _is_public(ip: str) -> bool:
    if not ip or ip in {"*", "0.0.0.0", "::"}:  # noqa: S104  # nosec B104 — matching a wildcard, not binding
        return False
    try:
        return not ipaddress.ip_address(ip).is_private
    except ValueError:
        return False


def _conn(row: dict) -> dict:
    proto = str(g(row, "Proto", "Protocol", default="") or "")
    fa = str(g(row, "ForeignAddr", "Foreign Address", default="") or "")
    la = str(g(row, "LocalAddr", "Local Address", default="") or "")
    try:
        lp = int(g(row, "LocalPort", "Local Port", default=0) or 0)
    except (TypeError, ValueError):
        lp = 0
    try:
        fp = int(g(row, "ForeignPort", "Foreign Port", default=0) or 0)
    except (TypeError, ValueError):
        fp = 0
    fip = fa.split(":")[0].strip() if fa else ""
    return {
        "proto": proto, "state": str(g(row, "State", default="") or "").upper(),
        "la": la, "lp": lp, "fa": fa, "fp": fp, "fip": fip,
        "owner": str(g(row, "Owner", "Process", default="") or "").lower(),
        "pid": g(row, "PID", "Pid", "pid"),
        "key": f"{proto}|{la}:{lp}|{fa}:{fp}",
        "label": f"{proto} {la}:{lp} → {fa}:{fp}",
    }


def _net_rule(pred, ev):
    def _eval(ctx: TriageContext) -> list[Hit]:
        hits: list[Hit] = []
        for row in ctx.records("netscan"):
            c = _conn(row)
            reason = pred(c, ctx)
            if reason:
                pid = c["pid"] if isinstance(c["pid"], int) else None
                hits.append(Hit(c["key"], c["label"], reason, pid=pid))
        return hits
    return _eval


def _p_public_no_pid(c, ctx):
    if (c["proto"].upper().startswith("TCP") and c["state"] == "ESTABLISHED"
            and _is_public(c["fip"]) and c["pid"] in (None, "", 0)):
        return f"Public ESTABLISHED connection to {c['fip']} with no owning PID"
    return None


def _p_admin_outbound(c, ctx):
    if (c["state"] in {"ESTABLISHED", "SYN_SENT"} and _is_public(c["fip"])
            and c["fp"] in {445, 3389, 23}):
        return f"Outbound to admin/service port {c['fp']} on public {c['fip']}"
    return None


def _p_lolbin_outbound(c, ctx):
    if (c["state"] in {"ESTABLISHED", "SYN_SENT"} and _is_public(c["fip"])
            and c["owner"] in LOLBIN_NET_CLIENTS):
        return f"{c['owner']} connecting outbound to public {c['fip']}"
    return None


def _p_bad_port(c, ctx):
    if (c["state"] in {"ESTABLISHED", "SYN_SENT"} and _is_public(c["fip"])
            and c["fp"] in _SUSPICIOUS_PORTS):
        return f"Known implant/C2 destination port {c['fp']} to {c['fip']}"
    return None


def _p_uncommon_port(c, ctx):
    if (c["state"] in {"ESTABLISHED", "SYN_SENT"} and _is_public(c["fip"])
            and c["fp"] and c["fp"] not in _COMMON_PORTS and c["fp"] not in _SUSPICIOUS_PORTS):
        return f"Uncommon destination port {c['fp']} to public {c['fip']}"
    return None


def _p_unexpected_listener(c, ctx):
    if (c["proto"].upper().startswith("TCP") and c["state"] in {"LISTENING", "LISTEN"}
            and c["lp"] in {3389, 445, 139} and not is_system_owner(c["owner"])):
        return f"{c['owner'] or 'non-system process'} listening on sensitive port {c['lp']}"
    return None


def _p_high_port_listener(c, ctx):
    lip = c["la"].split(":")[0].strip() if c["la"] else ""
    is_loop = lip in {"127.0.0.1", "::1"}
    if (c["proto"].upper().startswith("TCP") and c["state"] in {"LISTENING", "LISTEN"}
            and c["lp"] >= 49152 and c["owner"] and not is_system_owner(c["owner"])
            and not is_loop):
        return f"High-port listener {c['lp']} owned by {c['owner']}"
    return None


def _p_fanout(c, ctx):
    if _is_public(c["fip"]) and ctx.remote_pub_count.get(c["fip"], 0) >= 8:
        return f"{ctx.remote_pub_count[c['fip']]} sockets to the same remote {c['fip']}"
    return None


# =====================================================================
# Persistence & user activity (T1053 / T1204 / T1547)
# =====================================================================

def _score_scheduled_task(row: dict) -> tuple[int, list[str]]:
    act = str(g(row, "Action", default="") or "")
    args = str(g(row, "Action Arguments", "Arguments", default="") or "")
    la, aa = act.lower(), args.lower()
    score, why = 0, []
    lolbins = ("powershell", "pwsh", "cmd.exe", "wscript", "cscript", "mshta",
               "rundll32", "regsvr32", "msbuild", "wmic", "bitsadmin")
    risky = ("-enc", "-encodedcommand", "frombase64string", "iex ", "-nop",
             "-w hidden", "-windowstyle hidden", "-ep bypass", "-executionpolicy bypass",
             "http://", "https://", "bitsadmin /transfer")
    scripts = (".ps1", ".vbs", ".js", ".jse", ".wsf", ".hta", ".bat", ".cmd", ".psm1")
    is_lolbin = any(x in la for x in lolbins)
    has_risky = any(x in aa for x in risky)
    has_script = any(ext in aa for ext in scripts)
    payload = (act + " " + args)
    non_system = H.not_system_path(payload) and H.is_suspicious_path(payload)
    if has_risky:
        score += 12
        why.append("Obfuscated/remote-content command")
    if has_script:
        score += 10
        why.append("Script payload")
    if non_system:
        score += 10
        why.append("Non-system/user-writable payload path")
    if is_lolbin and (has_risky or has_script or non_system):
        score += 8
        why.append(f"LOLBIN action with risky content ({act})")
    return score, why


def _scheduled_task(ctx: TriageContext) -> list[Hit]:
    hits: list[Hit] = []
    for r in ctx.records("scheduled_tasks"):
        score, why = _score_scheduled_task(r)
        if score >= 10:
            name = str(g(r, "Task Name", "TaskName", default="") or "(task)")
            act = str(g(r, "Action", default="") or "")
            hits.append(Hit(f"task:{name.lower()}", name,
                            f"{name}: {'; '.join(why)} [{act}]"))
    return hits


def _score_userassist(name: str) -> tuple[int, list[str]]:
    import re
    n = (name or "").replace("/", "\\")
    nl = n.lower()
    if not (re.match(r"^[a-z]:\\", nl) or nl.startswith("\\\\")
            or re.search(r"\.(exe|dll|com|bat|cmd|ps1|vbs|js|hta)$", nl)):
        return 0, []
    score, why = 0, []
    tools = ("mimikatz", "psexec", "procdump", "bloodhound", "sharphound", "rubeus",
             "cobaltstrike", "metasploit", "lazagne", "winpeas", "nc.exe", "ncat")
    if any(t in nl for t in tools):
        score += 12
        why.append("Known offensive tool name")
    for tok, w, label in (("\\temp\\", 10, "Temp directory"),
                          ("\\downloads\\", 10, "Downloads directory"),
                          ("\\desktop\\", 8, "Desktop directory"),
                          ("\\users\\public\\", 8, "Public directory"),
                          ("\\appdata\\", 6, "AppData directory")):
        if tok in nl:
            score += w
            why.append(label)
    if H.not_system_path(n):
        score += 6
        why.append("Non-system path")
    return score, why


def _userassist(ctx: TriageContext) -> list[Hit]:
    hits: list[Hit] = []
    for r in ctx.records("userassist"):
        name = str(g(r, "Name", "Value", default="") or "")
        score, why = _score_userassist(name)
        if score >= 6:
            hits.append(Hit(f"ua:{name.lower()}", name,
                            f"{name}: {'; '.join(why)}"))
    return hits


def _hive_orphan(ctx: TriageContext) -> list[Hit]:
    def offs(recs):
        out = set()
        for r in recs:
            v = g(r, "Offset", "offset")
            try:
                out.add(int(v))
            except (TypeError, ValueError):
                pass
        return out
    listed = offs(ctx.records("hivelist"))
    scanned = offs(ctx.records("hivescan"))
    hits: list[Hit] = []
    for off in sorted(scanned - listed):
        hits.append(Hit(f"hive:{off}", f"Hive @ {hex(off)}",
                        f"Hive at offset {hex(off)} found by hivescan but absent "
                        "from hivelist (unlinked hive)"))
    return hits


# =====================================================================
# Registry / catalog assembly
# =====================================================================


# =====================================================================
# Loader behaviour (T1055) and kernel dispatch integrity (T1014)
#
# Ported from VolMemLyzer's OverviewAnalysis, which tested these and the
# catalog did not. Both thresholds are raised from the originals — see
# heuristics.walks_peb_loader_lists and heuristics.api_hash_pushes.
# =====================================================================

def _malfind_peb_walk(ctx: TriageContext) -> list[Hit]:
    hits: list[Hit] = []
    for pid, r in _malfind_regions(ctx):
        data = H.hexdump_to_bytes(str(g(r, "Hexdump", "hex_dump", default="")))
        if H.walks_peb_loader_lists(data):
            start = g(r, "Start VPN", "Start", default="?")
            hits.append(Hit(str(pid), ctx.label(pid),
                            f"Region at {start} walks the PEB loader lists, the way "
                            f"code with no import table finds its imports", pid=pid))
    return hits


def _malfind_api_hashing(ctx: TriageContext) -> list[Hit]:
    hits: list[Hit] = []
    for pid, r in _malfind_regions(ctx):
        data = H.hexdump_to_bytes(str(g(r, "Hexdump", "hex_dump", default="")))
        found = H.api_hash_pushes(data)
        if found >= 2:
            start = g(r, "Start VPN", "Start", default="?")
            hits.append(Hit(str(pid), ctx.label(pid),
                            f"{found} pushes of hash-like constants at {start}, typical "
                            f"of resolving imports by hash", pid=pid))
    return hits


def _ssdt_foreign_module(ctx: TriageContext) -> list[Hit]:
    """An SSDT entry resolving outside the kernel baseline.

    Incomplete attribution is missing data, not a hook: an unresolved module,
    an empty symbol or a null address is skipped rather than scored.
    """
    hits: list[Hit] = []
    for r in ctx.records("ssdt"):
        module = str(g(r, "Module", "module", default="") or "").strip()
        symbol = str(g(r, "Symbol", "symbol", default="") or "").strip()
        address = as_int(g(r, "Address", "address"))
        if not module or not symbol or address is None or address <= 0:
            continue
        if not H.ssdt_foreign_module(module):
            continue
        hits.append(Hit(f"ssdt:{symbol.lower()}", f"SSDT {symbol}",
                        f"SSDT target {symbol} resolves to non-baseline module {module}"))
    return hits


def _rules() -> list[Rule]:
    """The raw catalog, before calibration metadata is applied."""
    R = Rule
    return [
        # --- masquerading / core process integrity (T1036) ---
        R("core_proc_wrong_path", "Core process wrong image path", "Defense Evasion",
          "T1036", "Masquerading", ("pslist", "cmdline"), OBJ_PROCESS, 4, 0.9,
          _core_wrong_path, rationale="Core processes always load from System32."),
        R("core_proc_wrong_parent", "Core process wrong parent", "Defense Evasion",
          "T1036", "Masquerading", ("pslist", "pstree"), OBJ_PROCESS, 4, 0.85,
          _core_wrong_parent, rationale="Core processes have a fixed parent lineage."),
        R("core_proc_illegal_instances", "Illegal instance count of singleton",
          "Defense Evasion", "T1036", "Masquerading", ("pslist", "psscan"),
          OBJ_PROCESS, 3, 0.8, _core_illegal_instances,
          rationale="lsass/wininit/services are singletons."),
        R("core_proc_masquerade_name", "Near-miss core process name", "Defense Evasion",
          "T1036.005", "Match Legitimate Name or Location", ("pslist",), OBJ_PROCESS,
          3, 0.7, _core_masquerade_name, rationale="Typo-squat of a core name."),
        # --- discovery anomalies ---
        R("hidden_process", "Hidden / unlinked process", "Defense Evasion",
          "T1014", "Rootkit", ("pslist", "psscan"), OBJ_PROCESS, 3, 0.75,
          _hidden_process, rationale="psscan-only PIDs are hidden or terminated."),
        R("psxview_inconsistent", "Cross-source process inconsistency",
          "Defense Evasion", "T1014", "Rootkit", ("psxview",), OBJ_PROCESS, 3, 0.7,
          _psxview_inconsistent),
        R("suspicious_process_path", "Process image in user-writable path",
          "Defense Evasion", "T1036", "Masquerading", ("cmdline",), OBJ_PROCESS,
          2, 0.5, _suspicious_path),
        # --- injection & hollowing (T1055) ---
        R("malfind_rwx_private", "RWX private memory region", "Defense Evasion",
          "T1055", "Process Injection", ("malfind",), OBJ_PROCESS, 4, 0.7,
          _malfind_rwx_private, rationale="Strongest single injection indicator."),
        R("malfind_pe_header", "PE header in private executable region",
          "Defense Evasion", "T1055.001", "Dynamic-link Library Injection",
          ("malfind",), OBJ_PROCESS, 4, 0.75, _malfind_pe_header,
          rationale="Reflectively loaded PE."),
        R("malfind_shellcode", "Shellcode byte signature", "Defense Evasion",
          "T1055", "Process Injection", ("malfind",), OBJ_PROCESS, 3, 0.55,
          _malfind_shellcode, rationale="Genuine shellcode byte patterns (fixed)."),
        R("ldrmodules_unlinked", "Unlinked / hidden DLL", "Defense Evasion",
          "T1055", "Process Injection", ("ldrmodules",), OBJ_PROCESS, 3, 0.7,
          _ldrmodules_unlinked),
        # --- lineage / LOLBIN (T1059) ---
        R("lolbin_from_office", "Office spawned a script interpreter", "Execution",
          "T1059", "Command and Scripting Interpreter", ("pstree", "cmdline"),
          OBJ_PROCESS, 4, 0.8, _lolbin_from_office),
        R("lolbin_from_service_host", "Service host spawned a script interpreter",
          "Execution", "T1059", "Command and Scripting Interpreter",
          ("pstree",), OBJ_PROCESS, 3, 0.6, _lolbin_from_service_host),
        # --- credential / privilege / thread ---
        R("lsass_handle", "Handle to lsass.exe from non-system process",
          "Credential Access", "T1003.001", "LSASS Memory", ("handles",),
          OBJ_PROCESS, 4, 0.75, _lsass_handle),
        R("token_sedebug", "Sensitive privilege enabled", "Privilege Escalation",
          "T1134", "Access Token Manipulation", ("privileges",), OBJ_PROCESS,
          3, 0.55, _token_sedebug),
        R("thread_unbacked_start", "Thread start in unbacked memory",
          "Defense Evasion", "T1055", "Process Injection", ("threads",),
          OBJ_PROCESS, 3, 0.6, _thread_unbacked),
        # --- network (T1071 / T1571) ---
        R("net_public_no_pid", "Public connection with no owning PID",
          "Command and Control", "T1571", "Non-Standard Port", ("netscan",),
          OBJ_CONNECTION, 4, 0.7, _net_rule(_p_public_no_pid, None)),
        R("net_admin_port_outbound", "Outbound to admin/service port",
          "Command and Control", "T1571", "Non-Standard Port", ("netscan",),
          OBJ_CONNECTION, 4, 0.7, _net_rule(_p_admin_outbound, None)),
        R("net_lolbin_outbound", "LOLBIN outbound to public host", "Command and Control",
          "T1071", "Application Layer Protocol", ("netscan",), OBJ_CONNECTION,
          3, 0.7, _net_rule(_p_lolbin_outbound, None)),
        R("net_bad_port", "Known implant/C2 destination port", "Command and Control",
          "T1571", "Non-Standard Port", ("netscan",), OBJ_CONNECTION, 4, 0.75,
          _net_rule(_p_bad_port, None)),
        R("net_uncommon_port", "Uncommon public destination port", "Command and Control",
          "T1571", "Non-Standard Port", ("netscan",), OBJ_CONNECTION, 2, 0.55,
          _net_rule(_p_uncommon_port, None)),
        R("net_unexpected_listener", "Sensitive-port listener by non-system process",
          "Command and Control", "T1571", "Non-Standard Port", ("netscan",),
          OBJ_CONNECTION, 3, 0.65, _net_rule(_p_unexpected_listener, None)),
        R("net_high_port_listener", "High-port listener by non-system process",
          "Command and Control", "T1571", "Non-Standard Port", ("netscan",),
          OBJ_CONNECTION, 2, 0.5, _net_rule(_p_high_port_listener, None)),
        R("net_fanout", "Many sockets to one remote", "Command and Control",
          "T1071", "Application Layer Protocol", ("netscan",), OBJ_CONNECTION,
          2, 0.5, _net_rule(_p_fanout, None)),
        # --- persistence & user activity ---
        R("scheduled_task_suspicious", "Suspicious scheduled task", "Persistence",
          "T1053.005", "Scheduled Task", ("scheduled_tasks",), OBJ_PERSISTENCE,
          3, 0.7, _scheduled_task),
        R("userassist_suspicious", "Suspicious UserAssist execution", "Execution",
          "T1204.002", "Malicious File", ("registry.userassist",), OBJ_PERSISTENCE,
          2, 0.6, _userassist),
        R("hive_orphan", "Unlinked registry hive", "Persistence", "T1547.001",
          "Registry Run Keys / Startup Folder", ("registry.hivelist", "registry.hivescan"),
          OBJ_PERSISTENCE, 2, 0.5, _hive_orphan),
        # --- loader behaviour, from VolMemLyzer's injection scorer ---
        R("malfind_peb_walk", "PEB loader-list walk", "Defense Evasion",
          "T1055", "Process Injection", ("malfind",), OBJ_PROCESS, 3, 0.6,
          _malfind_peb_walk,
          rationale="Three PEB/Ldr field reads together; compiler output reaches "
                    "struct fields the same way, so two was not enough."),
        R("malfind_api_hashing", "Imports resolved by hash", "Defense Evasion",
          "T1027", "Obfuscated Files or Information", ("malfind",), OBJ_PROCESS,
          3, 0.6, _malfind_api_hashing,
          rationale="Repeated push of non-ASCII hash-like immediates. ASCII "
                    "immediates are rejected: 0x68 is 'h', so \"http\" matched before."),
        # --- kernel dispatch integrity ---
        R("ssdt_foreign_module", "SSDT entry outside the kernel baseline",
          "Defense Evasion", "T1014", "Rootkit", ("ssdt",), OBJ_KERNEL, 4, 0.8,
          _ssdt_foreign_module,
          rationale="A resolved syscall target outside ntoskrnl/win32k is a hook. "
                    "Unresolved attribution is missing data and is not scored."),
    ]


# --- calibration -------------------------------------------------------
#
# The hypothesis each rule tests. Rules that share a family are two ways of
# observing one fact, so only the strongest of them scores: "runs from %TEMP%"
# and "not under a system root" are both `location`, and counting both put a
# single misplaced binary ahead of an object with two independent signals.
_FAMILIES: dict[str, str] = {
    # process — identity, where it lives, who started it, how it was found
    "core_proc_wrong_path": "location",
    "suspicious_process_path": "location",
    "core_proc_wrong_parent": "lineage",
    "lolbin_from_office": "lineage",
    "lolbin_from_service_host": "lineage",
    "core_proc_illegal_instances": "identity",
    "core_proc_masquerade_name": "identity",
    "hidden_process": "discovery",
    "psxview_inconsistent": "discovery",
    # process — what is in its memory, and what it reached for
    "malfind_rwx_private": "memory_shape",
    "malfind_pe_header": "payload",
    "malfind_shellcode": "payload",
    "ldrmodules_unlinked": "loader_behavior",
    "thread_unbacked_start": "thread_origin",
    "lsass_handle": "credential_access",
    "token_sedebug": "privilege",
    # connection
    "net_public_no_pid": "attribution",
    "net_admin_port_outbound": "remote_service",
    "net_bad_port": "remote_service",
    "net_uncommon_port": "remote_service",
    "net_lolbin_outbound": "process_behavior",
    "net_unexpected_listener": "listener",
    "net_high_port_listener": "listener",
    "net_fanout": "volume",
    # persistence
    "scheduled_task_suspicious": "task_payload",
    "userassist_suspicious": "tool_identity",
    "hive_orphan": "hive",
    # loader behaviour shares the family ldrmodules_unlinked already owns: all
    # three test "this code resolves its own imports", so the strongest counts.
    "malfind_peb_walk": "loader_behavior",
    "malfind_api_hashing": "loader_behavior",
    # kernel
    "ssdt_foreign_module": "dispatch_integrity",
}

# Base-rate signals: they describe what ordinary software does, so on their own
# they rank the busiest process first rather than the most anomalous one. They
# still corroborate a real signal and still lift confidence — they just never
# carry an object over the surfacing floor by themselves.
#
#   net_high_port_listener  any app with an ephemeral listener
#   net_fanout              a browser talking to one CDN
#   psxview_inconsistent    thrdscan and csrss legitimately miss many live
#                           processes; against the reference image this alone
#                           accounted for 18 of 25 surfaced rows. VolMemLyzer
#                           reached the same place by weighting it 8 under a
#                           threshold of 9, so it could never surface by itself
#                           either — this states that intent directly instead of
#                           leaving it to arithmetic.
_CONTEXT_ONLY: frozenset[str] = frozenset({
    "net_high_port_listener",
    "net_fanout",
    "psxview_inconsistent",
})


def default_rules() -> list[Rule]:
    """The calibrated default rule set (all enabled)."""
    return [
        replace(rule,
                family=_FAMILIES.get(rule.id, rule.id),
                context_only=rule.id in _CONTEXT_ONLY)
        for rule in _rules()
    ]
