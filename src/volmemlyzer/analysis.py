from __future__ import annotations
from typing import Dict, Any, List, Optional, Iterable
import ntpath, os, copy, re
from .extractors import extract_winInfo_features
from .utilities import load_records_any, cheap_image_hash
from .pipeline import Pipeline
from .scoring import MAX_RISK_SCORE, TuningProfile, score_records
from .scoring.catalog import connection_key
from .scoring.rules import OBJ_CONNECTION, OBJ_KERNEL, OBJ_PERSISTENCE, OBJ_PROCESS
from .scoring.service import normalize_plugin_key
from .terminalUI import TerminalUI
TerminalUI.RICH_BOX = "SIMPLE"
TerminalUI.RICH_SHOW_LINES = True
TerminalUI.RICH_SHOW_EDGE = True

class OverviewAnalysis:
    """Sequential memory-forensics workflow with step-by-step functions.

    Steps (match your Workflow.docx numbering):
      0) Hygiene & Bearings (windows.info)
      1) Process Census (pslist/pstree/psscan/psxview) + anomaly scoring
      2) Memory Injections (malfind)
      3) Networking (netscan deep)
      4) Persistence & User Activity (hives, run keys, tasks, userassist)
      5) Kernel Dispatch Integrity (SSDT deep)

    This class orchestrates and renders; it does not score. Every verdict comes
    from :mod:`volmemlyzer.scoring`, which owns the rules, the ATT&CK
    attribution, the risk bands and the surfacing thresholds. It used to carry a
    second, parallel implementation of all of that, which meant a finding could
    be labelled one way here and another way in every other consumer of the same
    artifacts.
    """

    # Bands, thresholds and the maximum are the tuning profile's, not this
    # class's. Kept as a name only so callers that reported the ceiling keep
    # working; the ladder itself has exactly one definition.
    MAX_RISK_SCORE = MAX_RISK_SCORE

    # The bands --min-risk may name. The floor each one maps to is read from the
    # active profile, so changing a preset moves the flag with it.
    MIN_RISK_LEVELS = ("low", "medium", "high", "critical")

    def __init__(self, min_risk: str = "low", profile: Optional[Dict[str, Any]] = None):
        self._min_risk = (min_risk or "low").lower()
        # The tuning profile the engine scores under. None is the balanced
        # preset, which is what the CLI has always effectively used.
        self._profile = profile
        self._tuning = TuningProfile.from_dict(profile)
        # name -> artifact path, filled by _prefetch. The steps read from here
        # instead of asking for the plugin again: a plugin that failed leaves an
        # unusable file behind, so a cache lookup would miss and we would run the
        # whole thing a second time to fail identically.
        self._prefetched: Dict[str, str] = {}
        # Filled by _score, once per run_steps call.
        self._records: Dict[str, List[dict]] = {}
        self._scored: Dict[str, Any] = {}

    # Which plugins each step reads. Used to collect everything the requested
    # steps need into one scheduled run, before any step starts interpreting.
    # Quick mode deliberately avoids plugins that pool-scan physical memory.
    # Those plugins are valuable cross-checks but can take orders of magnitude
    # longer than structure-walking plugins, so they are explicit --deep work.
    STEP_PLUGINS = {
        0: ("info",),
        1: ("pslist", "pstree"),
        2: ("malfind",),
        3: (),
        4: ("registry.hivelist", "scheduled_tasks", "registry.userassist"),
    }
    # psscan, netscan and hivescan are pool scanners. psxview also invokes psscan,
    # thrdscan and a csrss handle sweep. Keep all four behind one clear boundary.
    DEEP_PLUGINS = {
        1: ("psscan", "psxview"),
        3: ("netscan",),
        4: ("registry.hivescan",),
        5: ("ssdt",),
    }

    def run_steps(
        self,
        *,
        pipe: Pipeline,
        image_path: str,
        artifacts_dir: Optional[str] = None,
        steps: Optional[Iterable[int]] = None,
        use_cache: bool = True,
        high_level: bool = False,
        concurrency: int = 1,
        deep: bool = False,
        min_risk: Optional[str] = None
    ) -> Dict[str, Any]:
        # --high-level was always "only show me the strong signals", which is the
        # same knob as --min-risk high; keep both spellings, prefer the explicit one.
        self._min_risk = (min_risk or ("high" if high_level else self._min_risk)).lower()
        TerminalUI.banner("FORENSIC OVERVIEW – STEPWISE")
        TerminalUI.note("Findings below surface signal for review; they are not detections.")
        if self._min_risk != "low":
            TerminalUI.note(f"Showing {self._min_risk} risk and above.")
        artifacts_dir = artifacts_dir or pipe._default_artifacts_dir(image_path)
        results: Dict[str, Any] = {"image": os.path.basename(image_path),
                                   "quick_hash": cheap_image_hash(image_path),
                                   "scoring": {
                                       "kind": "bounded ordinal evidence",
                                       "maximum": MAX_RISK_SCORE,
                                       "not_a_probability": True,
                                   }}
        wanted = list(steps) if steps is not None else [0, 1, 2, 3, 4, 5]
        self._prefetch(pipe, image_path, artifacts_dir, wanted, use_cache, concurrency, deep)
        self._score()

        executed = []
        for s in wanted:
            if s == 0:
                results["step0"] = self.step0_bearings(pipe, image_path, artifacts_dir, use_cache)
                executed.append(0)
            elif s == 1:
                results["step1"] = self.step1_processes(pipe, image_path, artifacts_dir, use_cache, high_level,
                                                        concurrency=concurrency, deep=deep)
                executed.append(1)
            elif s == 2:
                results["step2"] = self.step2_injections(pipe, image_path, artifacts_dir, use_cache, high_level)
                executed.append(2)
            elif s == 3:
                results["step3"] = self.step3_network(pipe, image_path, artifacts_dir, use_cache,
                                                      high_level, deep=deep)
                executed.append(3)
            elif s == 4:
                results["step4"] = self.step4_persistence(pipe, image_path, artifacts_dir, use_cache,
                                                          high_level, deep=deep)
                executed.append(4)
            elif s == 5:
                results["step5"] = self.step5_kernel(pipe, image_path, artifacts_dir, use_cache,
                                                      high_level, deep=deep)
                executed.append(5)
        results["executed_steps"] = executed
        # The whole scored view, so a caller gets the ATT&CK roll-up, the effective
        # profile and the sources no rule could read, not only the per-step tables.
        results["scoring"].update({
            "profile": self._scored.get("profile", {}),
            "risk_summary": self._scored.get("risk_summary", {}),
            "attack_techniques": self._scored.get("attack_techniques", []),
            "unevaluated_sources": self._scored.get("unevaluated_sources", []),
        })
        return results

    def _plugins_for(self, steps: Iterable[int], deep: bool) -> List[str]:
        wanted: List[str] = []
        for s in steps:
            wanted.extend(self.STEP_PLUGINS.get(s, ()))
            if deep:
                wanted.extend(self.DEEP_PLUGINS.get(s, ()))
        # preserve first-seen order, drop duplicates
        seen, out = set(), []
        for n in wanted:
            if n not in seen:
                seen.add(n); out.append(n)
        return out

    def _prefetch(self, pipe: Pipeline, image_path: str, artifacts_dir: str,
                  steps: Iterable[int], use_cache: bool, concurrency: int, deep: bool) -> None:
        """Produce every artifact the requested steps will read, in one scheduled run.

        Without this the steps run one plugin at a time: each step calls
        _ensure_one for its own plugin and blocks there, so malfind, netscan and
        the four registry plugins queue up behind each other no matter what -j
        says. Collecting them here lets the scheduler overlap them, and each step
        then reads from cache.
        """
        wanted = [n for n in self._plugins_for(steps, deep) if pipe.registry.has(n)]
        if not wanted:
            return
        TerminalUI.note(f"Collecting {len(wanted)} plugin artifact(s) with {concurrency} worker(s)")
        result = pipe.run_plugin_raw(image_path=image_path, enable=set(wanted), renderer="json",
                                     outdir=artifacts_dir, concurrency=concurrency,
                                     use_cache=use_cache, strict=True)
        self._prefetched = dict((result.artifacts or {}).get("plugins") or {})

    # ---------------- Scoring ----------------

    def _score(self) -> None:
        """Score every prefetched artifact once, for all steps together.

        Deliberately one call, not one per step and emphatically not one per row.
        The rules read across objects -- a process's parent, how many sockets a
        PID owns, whether a singleton name appears twice, how many sources agree
        a process exists -- so a context assembled from a single step's records,
        or from a single row, silently disables them and quietly lowers scores
        instead of failing. One context per image is the shape the rules were
        written against.
        """
        records: Dict[str, List[dict]] = {}
        for name, path in self._prefetched.items():
            records[normalize_plugin_key(name)] = load_records_any(path) or []
        self._records = records
        self._scored = score_records(records, self._profile, plugins=list(records))

    def _min_risk_floor(self) -> int:
        """The score the --min-risk band names, on the active profile's ladder."""
        if self._min_risk in ("", "low"):
            return 0
        return int(self._tuning.risk_bands.get(self._min_risk, 0))

    def _threshold(self, object_type: str) -> int:
        """Score an object of this type must reach to be shown.

        The profile's own surfacing threshold for the type, raised to the
        --min-risk floor when the caller asked for one. Both come from the
        profile, so there is one ladder and this only combines it with the flag.
        """
        return max(self._tuning.surface_threshold(object_type), self._min_risk_floor())

    def _surfaced(self, object_type: str) -> List[Dict[str, Any]]:
        """Scored objects of one type that clear the threshold, strongest first."""
        floor = self._threshold(object_type)
        return [o for o in self._scored.get("scored_objects", [])
                if o["object_type"] == object_type and o["score"] >= floor]

    @staticmethod
    def _contributions(obj: Dict[str, Any], *, scoring_only: bool = True) -> List[dict]:
        """The rules that fired on an object.

        ``scoring_only`` drops the ones a stronger rule in the same family
        outscored. They are still real observations -- the analyst should see
        them where the row is about that observation -- they simply did not add
        to the score, so a summary line must not repeat them.
        """
        return [c for c in obj.get("contributions", [])
                if not (scoring_only and c.get("superseded"))]

    @classmethod
    def _flags(cls, obj: Dict[str, Any]) -> List[str]:
        return [c["rule_id"] for c in cls._contributions(obj)]

    @classmethod
    def _rationale(cls, obj: Dict[str, Any]) -> str:
        seen = dict.fromkeys(c["evidence"] for c in cls._contributions(obj))
        return " | ".join(seen) or "—"

    @staticmethod
    def _techniques(obj: Dict[str, Any]) -> str:
        return ", ".join(obj.get("techniques") or []) or "—"

    # ---------------- Step 0 ----------------
    def step0_bearings(self, pipe: Pipeline, image_path: str, artifacts_dir: str, use_cache: bool) -> Dict[str, Any]:
        TerminalUI.section("Step 0 · Hygiene & bearings")
        try:
            info_path = self._ensure_one(pipe, image_path, artifacts_dir, "info", use_cache)
            if not info_path or not os.path.isfile(info_path) or os.path.getsize(info_path) == 0:
                raise ValueError("windows.info produced no usable artifact")
            with open(info_path, 'r', encoding='utf-8') as f:
                _, res = extract_winInfo_features(f)
        except Exception as exc:
            TerminalUI.note(f"windows.info unavailable; continuing without bearings ({exc}).")
            return {"ok": False, "error": str(exc)}

        win = f"Windows {res.get('info.NtMajorVersion')} version {res.get('info.winBuild')}"
        arch = "64-bit" if res.get("info.Is64") else "32-bit"

        TerminalUI.kv([
            ("Kernel Base Address", res.get("info.KernelBase")),
            ("Build", win),
            ("Architecture", arch),
            ("SystemTime", res.get("info.SystemTime")),
        ])
        return {"ok": True}

    # ---------------- Step 1 ----------------
    def step1_processes(self, pipe: Pipeline, image_path: str, artifacts_dir: str, use_cache: bool,
                        high_level: bool, concurrency: int = 1, deep: bool = False) -> Dict[str, Any]:
        enabled = ["pslist", "pstree"] + (["psscan", "psxview"] if deep else [])
        TerminalUI.section(f"Step 1 · Process census ({'/'.join(enabled)})")

        out_path = {n: p for n, p in self._prefetched.items() if n in enabled}
        missing = [n for n in enabled if n not in out_path]
        if missing:
            action_result = pipe.run_plugin_raw(image_path=image_path, enable=set(missing), use_cache=use_cache,
                                                renderer="json", outdir=artifacts_dir,
                                                concurrency=concurrency, strict=True)
            out_path.update(action_result.artifacts.get("plugins") or {})

        pslist  = load_records_any(out_path.get("pslist"))
        pstree  = load_records_any(out_path.get("pstree"))
        psscan  = load_records_any(out_path.get("psscan")) if deep else None
        psxview = load_records_any(out_path.get("psxview")) if deep else None

        census = self._build_census(pslist, pstree)
        summary = self._census_summary(census, psscan, psxview)

        TerminalUI.kv([
            ("pslist processes", summary.get("pslist_count")),
            ("psscan processes", summary.get("psscan_count")
             if summary.get("psscan_count") is not None else "not checked (use --deep)"),
            ("psscan-only, no exit time (hidden)", summary.get("hidden_count")
             if summary.get("hidden_count") is not None else "not checked (use --deep)"),
            ("psscan-only, exited (ordinary churn)", summary.get("terminated_count")
             if summary.get("terminated_count") is not None else "not checked (use --deep)"),
            ("orphans (ppid missing)", summary.get("orphans")),
            ("processes with a resolved path", summary.get("with_path")),
            # None, not 0: psxview was not run, so this is unknown rather than clean.
            ("psxview inconsistencies", summary.get("psxview_inconsistent")
             if summary.get("psxview_inconsistent") is not None else "not checked (use --deep)"),
        ])

        suspicious = []
        rows = []
        for obj in self._surfaced(OBJ_PROCESS):
            pid = obj.get("pid")
            base = census.get(pid) or {}
            name = (base.get("name") or "").strip() or self._name_from_label(obj["label"])
            ppid = base.get("ppid")
            flags = self._flags(obj)
            rationale = self._rationale(obj)
            rows.append([str(pid), name, str(ppid or ""), obj["risk"],
                         ",".join(flags), self._techniques(obj), rationale])
            suspicious.append({
                "pid": pid, "name": name, "ppid": ppid,
                "Risk": obj["risk"], "score": obj["score"], "score_max": MAX_RISK_SCORE,
                "confidence": obj["confidence"], "techniques": obj.get("techniques") or [],
                "flags": ",".join(flags), "rationale": rationale,
            })

        shown = TerminalUI.table(["PID","Name","PPID","Risk","Flags","ATT&CK","Rationale"],
                                 rows, max_rows=25)
        return {"summary": summary, "suspicious": suspicious[:len(shown)] if shown else suspicious}

    def _census_summary(self, census: Dict[int, Dict[str, Any]], psscan: Optional[List[dict]],
                        psxview: Optional[List[dict]]) -> Dict[str, Any]:
        """Descriptive counts for the census.

        Counts only. The two judgements here -- what counts as hidden, and what
        counts as a discovery disagreement -- are the engine's, read back from
        the scored view, so this cannot drift from the rules that produced the
        table underneath it.
        """
        pid_set = set(census.keys())
        psscan_exited: Dict[int, bool] = {}
        for r in psscan or []:
            pid = self._as_int(r.get("PID") or r.get("pid"))
            if pid is None:
                continue
            exit_time = r.get("ExitTime") or r.get("Exit Time")
            psscan_exited[pid] = bool(exit_time) and str(exit_time).strip() not in ("", "N/A")
        psscan_pids = set(psscan_exited)

        fired = self._pids_flagged("hidden_process")
        inconsistent = self._pids_flagged("psxview_inconsistent")
        return {
            "pslist_count": len(pid_set),
            "psscan_count": len(psscan_pids) if psscan is not None else None,
            "hidden_count": len(fired) if psscan is not None else None,
            "terminated_count": (len([1 for pid in psscan_pids
                                      if pid not in pid_set and psscan_exited.get(pid)])
                                 if psscan is not None else None),
            "orphans": len([1 for pid, b in census.items()
                            if b.get("ppid") not in (None, 0) and b.get("ppid") not in pid_set]),
            "psxview_inconsistent": len(inconsistent) if psxview is not None else None,
            "with_path": len([1 for b in census.values() if b.get("path")]),
        }

    def _pids_flagged(self, rule_id: str) -> List[int]:
        """PIDs the engine says a given rule fired on."""
        return [pid for pid, entry in (self._scored.get("process_risk") or {}).items()
                if rule_id in (entry.get("flags") or [])]

    @staticmethod
    def _name_from_label(label: str) -> str:
        """"evil.exe (1337)" -> "evil.exe"; the engine's label when census has none."""
        return (label or "").rsplit(" (", 1)[0].strip()

    # ---------------- Step 2 ----------------
    def step2_injections(self, pipe: Pipeline, image_path: str, artifacts_dir: str, use_cache: bool, high_level: bool = False) -> Dict[str, Any]:
        TerminalUI.section("Step 2 · Memory injections (malfind)")

        if not pipe.registry.has("malfind"):
            TerminalUI.note("malfind not registered; skipping")
            return {"ok": False}
        mal_path = self._ensure_one(pipe, image_path, artifacts_dir, "malfind", use_cache)
        rows = load_records_any(mal_path)

        # The engine attributes an injected region to the process that owns it --
        # there is no per-region object -- so the score and band on each row below
        # are the owning process's. What is per-region is *which* rules fired, and
        # the contributions carry that: each one names the region it read.
        #
        # Superseded contributions are kept here on purpose. Family dedup decides
        # what scores, not what was observed, and a process with six RWX regions
        # records six hits of which five are superseded. Dropping them would show
        # one region and silently hide the other five.
        per_region: Dict[tuple, List[dict]] = {}
        owner: Dict[str, Dict[str, Any]] = {}
        for obj in self._surfaced(OBJ_PROCESS):
            for c in self._contributions(obj, scoring_only=False):
                if not c.get("subject"):
                    continue  # speaks about the process as a whole, not a region
                per_region.setdefault((obj["key"], c["subject"]), []).append(c)
                owner[obj["key"]] = obj

        # A virtual address is only unique inside a process, and Volatility
        # renderers can repeat a row, so identity is (PID, Start VPN).
        findings: List[Dict[str, Any]] = []
        seen = set()
        for row in rows:
            pid = row.get("PID")
            start_vpn = self._region_subject(row)
            key = (str(pid), start_vpn)
            contribs = per_region.get(key)
            if not contribs or key in seen:
                continue
            seen.add(key)
            obj = owner[str(pid)]
            evidence = dict.fromkeys(c["evidence"] for c in contribs)
            findings.append({
                "process": row.get("Process"),
                "pid": pid,
                "start_vpn": row.get("Start VPN"),
                "vad_tag": row.get("Tag", ""),
                "notes": row.get("Notes", ""),
                "commit_charge": row.get("CommitCharge"),
                "protection": row.get("Protection"),
                "disasm": row.get("Disasm"),
                "hex_dump": row.get("Hexdump"),
                # The owning process's verdict; the region is why it holds.
                "score": obj["score"],
                "score_max": MAX_RISK_SCORE,
                "risk": obj["risk"],
                "confidence": obj["confidence"],
                "techniques": obj.get("techniques") or [],
                "flags": ", ".join(dict.fromkeys(c["rule_id"] for c in contribs)),
                "rationale": " | ".join(evidence) or "—",
            })

        findings.sort(key=lambda f: (-float(f["score"]), str(f["pid"])))
        display = [
            [str(f["pid"]), f["process"], str(f["commit_charge"]), str(f["start_vpn"]),
             str(f["vad_tag"]), str(f["notes"]), f["risk"], f["rationale"]]
            for f in findings
        ]
        TerminalUI.table(
            ["PID", "Process", "CommitCharge", "Start VPN", "Vad Tag", "Notes",
             "Process risk", "Rationale"],
            display, max_rows=25)
        return {"suspicious_injections": findings}

    @staticmethod
    def _region_subject(row: Dict[str, Any]) -> str:
        """The region identity the malfind rules record on their contributions."""
        for field in ("Start VPN", "Start"):
            value = row.get(field)
            if value not in (None, ""):
                return str(value)
        return "?"

    # ---------------- Step 3 · Networking (netscan deep, DFIR-backed) ----------------

    def step3_network(self, pipe: Pipeline, image_path: str, artifacts_dir: str, use_cache: bool,
                      high_level: bool, deep: bool = False) -> Dict[str, Any]:
        TerminalUI.section("Step 3 · Networking (netscan deep, DFIR-backed)")

        if not deep:
            TerminalUI.note("Skipped in quick mode; netscan pool-scans physical memory (use --deep).")
            return {"ok": True, "skipped": True, "reason": "deep_only"}

        if not pipe.registry.has("netscan"):
            TerminalUI.note("netscan not registered; skipping deep view")
            return {"ok": False}

        net_path = self._ensure_one(pipe, image_path, artifacts_dir, "netscan", use_cache)
        rows = load_records_any(net_path) or []

        # The per-PID and per-remote aggregates the rules read are built once by
        # the engine's context, over every row. They used to be recomputed here,
        # against a differently de-duplicated row set, so the two disagreed.
        by_key = {o["key"]: o for o in self._surfaced(OBJ_CONNECTION)}
        state_of: Dict[str, str] = {}
        for row in rows:
            key = connection_key(row)
            if key in by_key and key not in state_of:
                state_of[key] = str(row.get("State") or "")

        suspicious: List[Dict[str, Any]] = []
        for obj in self._surfaced(OBJ_CONNECTION):
            proto, local, foreign = self._split_connection_key(obj["key"])
            la, lp = self._split_endpoint(local)
            fa, fp = self._split_endpoint(foreign)
            suspicious.append({
                "local_address": la, "foreign_address": fa,
                "local_port": lp, "foreign_port": fp,
                "proto": proto, "state": state_of.get(obj["key"], ""),
                "owner": None, "pid": obj.get("pid"),
                "score": obj["score"], "score_max": MAX_RISK_SCORE,
                "risk": obj["risk"], "confidence": obj["confidence"],
                "techniques": obj.get("techniques") or [],
                "flags": self._flags(obj), "rationale": self._rationale(obj),
            })

        rows_to_display = [
            [s["local_address"], s["foreign_address"], str(s["local_port"]),
             str(s["foreign_port"]), s["proto"], str(s["pid"] or "—"), s["state"],
             s["risk"], ", ".join(s["techniques"]) or "—", s["rationale"]]
            for s in suspicious
        ]
        TerminalUI.table(
            ["Local Address", "Foreign Address", "Local Port", "Foreign Port",
            "Proto", "PID", "State", "Risk", "ATT&CK", "Rationale"],
            rows_to_display, max_rows=30)

        return {
            "ok": True,
            "suspicious_connections": suspicious,
            "counts": {"total_rows": len(rows), "unique_scored": len(suspicious)}
        }

    @staticmethod
    def _split_connection_key(key: str) -> tuple:
        """Unpack "proto|local:port|foreign:port" back into its three parts."""
        parts = (key or "").split("|")
        while len(parts) < 3:
            parts.append("")
        return parts[0], parts[1], parts[2]

    @staticmethod
    def _split_endpoint(text: str) -> tuple:
        """"1.2.3.4:443" -> ("1.2.3.4", 443); IPv6 keeps everything but the port."""
        host, sep, port = (text or "").rpartition(":")
        if not sep:
            return text or "", 0
        try:
            return host, int(port)
        except ValueError:
            return text or "", 0

    # ---------------- Step 4 ----------------

    def step4_persistence(self, pipe: Pipeline, image_path: str, artifacts_dir: str, use_cache: bool,
                          high_level: bool, deep: bool = False) -> Dict[str, Any]:
        TerminalUI.section("Step 4 · Persistence & user activity (registry & tasks)")
        out: Dict[str, Any] = {}

        # --- Hives: list vs scan. Pool-scan-only hive pages are commonly stale
        # allocations, so the count is deep-mode context; the engine decides
        # whether an unlinked hive is worth surfacing.
        hl = hs = []
        if pipe.registry.has("registry.hivelist"):
            hl = load_records_any(self._ensure_one(pipe, image_path, artifacts_dir, "registry.hivelist", use_cache))
            out["hivelist"] = len(hl)
        if deep and pipe.registry.has("registry.hivescan"):
            hs = load_records_any(self._ensure_one(pipe, image_path, artifacts_dir, "registry.hivescan", use_cache))
            out["hivescan"] = len(hs)
        elif not deep:
            out["hivescan"] = None

        if hl or hs:
            set_list = {int(x.get("Offset")) for x in hl if "Offset" in x}
            set_scan = {int(x.get("Offset")) for x in hs if "Offset" in x}
            out["orphaned"] = len(sorted(set_scan - set_list))

        if pipe.registry.has("scheduled_tasks"):
            tasks = load_records_any(self._ensure_one(pipe, image_path, artifacts_dir, "scheduled_tasks", use_cache))
            out["tasks"] = len(tasks)

        if pipe.registry.has("registry.userassist"):
            ua_tree = load_records_any(self._ensure_one(pipe, image_path, artifacts_dir, "registry.userassist", use_cache))
            ua_vals = [r for r in self._flatten_UA_with_context(ua_tree) if r.get("Type") == "Value"]
            out["userassist"] = len(ua_vals)

        # The engine already deduplicates: a task keys on its name, a UserAssist
        # entry on its path, so the "keep the best row per key" bookkeeping this
        # step used to do is the grouping the engine does by construction.
        iocs = []
        for obj in self._surfaced(OBJ_PERSISTENCE):
            source, itype = self._persistence_kind(obj)
            iocs.append({
                "type": itype, "indicator": obj["label"],
                "score": obj["score"], "score_max": MAX_RISK_SCORE,
                "risk": obj["risk"], "confidence": obj["confidence"],
                "techniques": obj.get("techniques") or [],
                "why": self._rationale(obj), "source": source,
            })

        TerminalUI.kv([("scheduled tasks", out.get("tasks", 0)),
                       ("userassist values", out.get("userassist", 0)),
                       ("persistence indicators", len(iocs))])
        TerminalUI.table(
            ["Type", "Indicator", "Risk", "ATT&CK", "Rationale", "Source"],
            [[d["type"], d["indicator"], d["risk"], ", ".join(d["techniques"]) or "—",
              d["why"], d["source"]] for d in iocs],
            max_rows=25)

        out["ioc_count"] = len(iocs)
        out["iocs"] = iocs
        return out

    # Which artifact a persistence object came from, by the rule that found it.
    _PERSISTENCE_KINDS = {
        "scheduled_task_suspicious": ("scheduled_tasks", "scheduled_task"),
        "userassist_suspicious": ("registry.userassist", "userassist.exec"),
        "hive_orphan": ("registry.hivescan", "registry_hive"),
    }

    @classmethod
    def _persistence_kind(cls, obj: Dict[str, Any]) -> tuple:
        for c in cls._contributions(obj):
            kind = cls._PERSISTENCE_KINDS.get(c["rule_id"])
            if kind:
                return kind
        return ("", "persistence")

    # ---------------- Step 5 · Kernel dispatch integrity (SSDT deep) -------

    def step5_kernel(self, pipe: Pipeline, image_path: str, artifacts_dir: str,
                     use_cache: bool, high_level: bool, deep: bool = False) -> Dict[str, Any]:
        """Surface SSDT targets attributed outside expected Windows kernel modules.

        This is deliberately deep-only. A foreign target is a kernel-dispatch
        integrity lead, not proof of a rootkit: security software and acquisition
        artifacts remain alternative explanations. Repeated entries are grouped by
        module so one hook hypothesis cannot flood the table.
        """
        TerminalUI.section("Step 5 · Kernel dispatch integrity (SSDT deep)")

        if not deep:
            TerminalUI.note("Skipped in quick mode; use --deep for the SSDT integrity view.")
            return {"ok": True, "skipped": True, "reason": "deep_only"}
        if not pipe.registry.has("ssdt"):
            TerminalUI.note("ssdt not registered; skipping deep view")
            return {"ok": False}

        ssdt_path = self._ensure_one(pipe, image_path, artifacts_dir, "ssdt", use_cache)
        rows = load_records_any(ssdt_path) or []

        # One object per hooked symbol; the contribution records the module it
        # resolved to, which is what an analyst groups by -- a single driver
        # taking twenty entries is one hypothesis, not twenty findings.
        grouped: Dict[str, Dict[str, Any]] = {}
        for obj in self._surfaced(OBJ_KERNEL):
            for c in self._contributions(obj, scoring_only=False):
                module = c.get("subject") or ""
                if not module:
                    continue
                key = ntpath.basename(module.replace("/", "\\")).lower()
                finding = grouped.setdefault(key, {
                    "module": module, "entry_count": 0, "sample_symbols": [],
                    "score": obj["score"], "score_max": MAX_RISK_SCORE,
                    "risk": obj["risk"], "confidence": obj["confidence"],
                    "techniques": obj.get("techniques") or [],
                    "flags": [c["rule_id"]], "rationale": c["evidence"],
                })
                finding["entry_count"] += 1
                if obj["score"] > finding["score"]:
                    finding["score"] = obj["score"]
                    finding["risk"] = obj["risk"]
                symbol = self._name_from_label(obj["label"]).replace("SSDT ", "").strip()
                if symbol and symbol not in finding["sample_symbols"] and len(finding["sample_symbols"]) < 5:
                    finding["sample_symbols"].append(symbol)

        findings = sorted(grouped.values(), key=lambda i: (-float(i["score"]), i["module"].lower()))
        TerminalUI.table(
            ["Target module", "Entries", "Risk", "Sample symbols", "Rationale"],
            [[i["module"], str(i["entry_count"]), i["risk"],
              ", ".join(i["sample_symbols"]) or "—", i["rationale"]] for i in findings],
            max_rows=25,
        )
        return {
            "ok": True,
            "total_entries": len(rows),
            "foreign_module_count": len(findings),
            "findings": findings,
        }

    # --------------------------- helper primitives -------------------------

    def _ensure_one(self, pipe: Pipeline, image_path: str, artifacts_dir: str, name: str, use_cache: bool) -> str:
        hit = self._prefetched.get(name)
        if hit:
            return hit
        res = pipe.run_plugin_raw(image_path=image_path, enable={name}, renderer="json",
                                outdir=artifacts_dir, concurrency=1, use_cache=use_cache, strict= True)
        mp = (res.artifacts or {}).get("plugins") or {}
        return mp.get(name, os.path.join(artifacts_dir, f"{name}.json"))

    @staticmethod
    def _flatten_tree(rows: Optional[List[dict]]) -> List[dict]:
        """Every node of a Volatility tree, not just its roots.

        pstree renders as a hierarchy: the JSON is a list of root processes with
        their descendants nested under `__children`. Iterating the top level alone
        therefore only ever saw the handful of processes with no visible parent,
        which is why the path Volatility supplies never reached the census and
        every path-based rule below was unreachable.
        """
        out: List[dict] = []
        stack = list(rows or [])
        while stack:
            node = stack.pop()
            if not isinstance(node, dict):
                continue
            out.append(node)
            children = node.get("__children")
            if isinstance(children, list):
                stack.extend(children)
        return out

    def _build_census(self, pslist: List[dict], pstree: List[dict]) -> Dict[int, Dict[str, Any]]:
        census: Dict[int, Dict[str, Any]] = {}
        for r in pslist or []:
            pid = self._as_int(r.get("PID") or r.get("Pid") or r.get("pid"))
            if pid is None:
                continue
            # pslist emits a null ImageFileName for processes whose EPROCESS could
            # not be read; .strip() on that raised AttributeError.
            name = (r.get("ImageFileName") or "").strip()
            ppid = self._as_int(r.get("PPID") or r.get("ppid"))
            wow64 = self._as_bool(r.get("Wow64")) if r.get("Wow64") is not None else None
            start = r.get("CreateTime") or r.get("StartTime") or r.get("Start")
            census[pid] = {"pid": pid, "name": name, "ppid": ppid, "wow64": wow64,
                           "start": start, "path": ""}

        for r in self._flatten_tree(pstree):
            pid = self._as_int(r.get("PID") or r.get("Pid") or r.get("pid"))
            if pid is None:
                continue
            entry = census.setdefault(pid, {"pid": pid, "name": "", "ppid": None,
                                            "wow64": None, "start": None, "path": ""})
            if entry.get("ppid") is None:
                entry["ppid"] = self._as_int(r.get("PPID"))
            if not entry.get("path"):
                # Path is the image path; Cmd is the full command line, which is a
                # usable stand-in when the PEB gave us no path.
                entry["path"] = (r.get("Path") or r.get("Cmd") or "").strip()
            if not entry.get("name"):
                entry["name"] = (r.get("ImageFileName") or "").strip()
            if entry.get("wow64") is None and r.get("Wow64") is not None:
                entry["wow64"] = self._as_bool(r.get("Wow64"))
        return census

    def _flatten_UA_with_context(self, rows):
        """
        DFS over plugin rows, yielding each row with lightweight breadcrumbs:
        __key_path   : best-effort registry key path for this row
        __ua_guid    : UserAssist GUID (if key path matches UA pattern)
        __hive_offset: nearest Hive Offset (row or ancestor)
        """
        UA_RE = re.compile(r"UserAssist\\\{([0-9A-Fa-f-]+)\}\\Count")

        stack = [(r, r.get("Key") or r.get("Path") or None,
                r.get("Hive Offset"), None) for r in rows]
        while stack:
            r, key_path, hive_off, ua_guid = stack.pop()

            # Prefer row key/path; otherwise inherit
            row_key = r.get("Key") or r.get("Path")
            if row_key:
                key_path = row_key

            # Hive offset: inherit if missing
            if r.get("Hive Offset") is not None:
                hive_off = r.get("Hive Offset")

            # Infer UA GUID from key path when present
            if key_path:
                m = UA_RE.search(key_path)
                if m:
                    ua_guid = m.group(1)

            out = copy.copy(r)
            if key_path: out["__key_path"] = key_path
            if ua_guid:  out["__ua_guid"] = ua_guid
            if hive_off is not None:
                try:
                    out["__hive_offset"] = int(hive_off)
                except Exception:
                    out["__hive_offset"] = hive_off

            yield out

            ch = r.get("__children")
            if isinstance(ch, list) and ch:
                for c in ch:
                    stack.append((c, key_path, hive_off, ua_guid))

    @staticmethod
    def _as_bool(value: Any, default: bool = False) -> bool:
        if value is None:
            return default
        if isinstance(value, bool):
            return value
        if isinstance(value, (int, float)):
            return value != 0
        text = str(value).strip().lower()
        if text in {"true", "yes", "y", "1", "enabled"}:
            return True
        if text in {"false", "no", "n", "0", "disabled", ""}:
            return False
        return default

    @staticmethod
    def _as_int(v) -> Optional[int]:
        try:
            return int(v)
        except Exception:
            return None
