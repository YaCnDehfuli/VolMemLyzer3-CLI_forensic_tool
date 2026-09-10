from __future__ import annotations
from typing import Dict, Any, List, Optional, Tuple, Iterable
import ipaddress, ntpath, os, copy, re
from .extractors import extract_winInfo_features
from .utilities import load_records_any, not_system_path, cheap_image_hash, canonical_path_key, in_user_install_dir
from .utilities import char_entropy, is_non_ascii, is_suspicious_path, write_json
from .pipeline import Pipeline
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
    """
    # One ladder, used everywhere. A row's score maps to a band, and a row is only
    # tabled when it clears its surface threshold.
    #
    # These surface signal for an analyst to look at. They are not detections and
    # carry no notion of malicious; a Critical row means "several things about this
    # are unusual at once", not "this is malware".
    # This is a bounded ordinal evidence score, not a probability or a claim that
    # an artifact is malicious. Each scorer keeps only the strongest observation
    # from a hypothesis family (identity, location, lineage, and so on), then sums
    # independent families. That prevents one underlying fact from being counted
    # repeatedly under several correlated rules.
    MAX_RISK_SCORE = 30
    RISK_BANDS = (("Critical", 20), ("High", 14), ("Medium", 9), ("Low", 0))

    # Lowest band a row may occupy and still be shown, by name.
    MIN_RISK = {"low": 0, "medium": 9, "high": 14, "critical": 20}

    # Score at or above which a finding is worth putting in front of someone.
    # Every one sits on the Medium floor of the ladder above, so surfacing takes
    # one major signal or a couple of corroborating minor ones, and a row that is
    # shown is never labelled below the band it cleared. The previous values -- 3
    # for scheduled tasks, 2 for userassist, 4 for netscan -- sat below the weight
    # of a single minor flag, so every task with a logon trigger and every socket
    # belonging to a busy process was tabled.
    SURFACE_THRESHOLDS = {
        "process": 9,
        "malfind": 9,
        "netscan": 9,
        "scheduled_tasks": 9,
        "userassist": 9,
        "ssdt": 9,
    }
    # Retained so callers that reached into the old name keep working.
    BASELINE_SCORES = SURFACE_THRESHOLDS

    def __init__(self, min_risk: str = "low"):
        self._min_risk = (min_risk or "low").lower()
        # name -> artifact path, filled by _prefetch. The steps read from here
        # instead of asking for the plugin again: a plugin that failed leaves an
        # unusable file behind, so a cache lookup would miss and we would run the
        # whole thing a second time to fail identically.
        self._prefetched: Dict[str, str] = {}

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
                                       "maximum": self.MAX_RISK_SCORE,
                                       "not_a_probability": True,
                                   }}
        wanted = list(steps) if steps is not None else [0, 1, 2, 3, 4, 5]
        self._prefetch(pipe, image_path, artifacts_dir, wanted, use_cache, concurrency, deep)

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
        # `summary`, not `flags`: the comprehension below binds a loop variable of
        # that name, and the returned payload used to carry the last row's flag
        # string where the summary belonged.
        summary, susp = self._score_processes(census, psscan, psxview)

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
        rows = [[str(pid), name or "", str(ppid or ""), str(risk), flag_str, rationale]
                for pid, name, ppid, risk, flag_str, rationale in susp]
        rows = self._keep(rows, 3)

        shown = TerminalUI.table(["PID","Name","PPID","Risk","Flags","Rationale"], rows, max_rows=25)
        return {"summary": summary, "suspicious": [
            {"pid": int(r[0]), "name": r[1], "ppid": (int(r[2]) if r[2] else None),
             "Risk": str(r[3]), "flags": r[4], "rationale": r[5]} for r in rows[:len(shown)]
        ]}

    # ---------------- Step 2 ----------------
    def step2_injections(self, pipe: Pipeline, image_path: str, artifacts_dir: str, use_cache: bool, high_level: bool = False) -> Dict[str, Any]:
        TerminalUI.section("Step 2 · Memory injections (malfind)")

        if not pipe.registry.has("malfind"):
            TerminalUI.note("malfind not registered; skipping")
            return {"ok": False}
        mal_path = self._ensure_one(pipe, image_path, artifacts_dir, "malfind", use_cache)
        rows = load_records_any(mal_path)

        # A virtual address is only unique inside a process. Volatility renderers
        # can also repeat a row, so use (PID, address) and keep the strongest copy;
        # never add duplicate scores together.
        suspicious_regions: Dict[Tuple[Any, Any], Dict[str, Any]] = {}
        for row in rows:
            score, flags, rationale = self._score_injections(row)

            if score >= self._threshold("malfind"):
                start_vpn = row.get("Start VPN")
                region_key = (row.get("PID"), start_vpn)
                finding = {
                        "process": row.get("Process"),
                        "pid": row.get("PID"),
                        "vad_tag": row.get("Tag", ""),
                        "notes": row.get("Notes", ""),
                        "commit_charge": row.get("CommitCharge"),
                        "protection": row.get("Protection"),
                        "disasm": row.get("Disasm"),
                        "hex_dump": row.get("Hexdump"),
                        "score": score,
                        "score_max": self.MAX_RISK_SCORE,
                        "risk": self._risk_from_score(score),
                        "flags": flags,
                        "rationale": rationale
                }
                previous = suspicious_regions.get(region_key)
                if previous is None or score > int(previous.get("score", 0)):
                    suspicious_regions[region_key] = finding

        rows_to_display = [
            [
                str(row["pid"]),
                row["process"],
                str(row["commit_charge"]),
                str(start_vpn),
                str(row["vad_tag"]),
                str(row["notes"]),
                int(row["score"]),
                row["rationale"]
            ]
            for (_, start_vpn), row in suspicious_regions.items()
        ]
        
        # rows_to_display[]
        rows_to_display.sort(key=lambda r: (-r[-2], r[0]))
        rows_to_display = [self._score_map(row, -2) for row in rows_to_display]

        rows_to_display = self._keep(rows_to_display, -2)

        TerminalUI.table(["PID", "Process", "CommitCharge", "Start VPN", "Vad Tag" , "Notes" ,"Risk", "Rationale"], rows_to_display, max_rows=25)
        return {"suspicious_injections": list(suspicious_regions.values())}

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

        # ---------- light aggregations for context ----------
        per_pid: Dict[str, set] = {}
        per_remote_pub: Dict[str, set] = {}
        counted = set()
        skip_states = {"CLOSED", "CLOSE_WAIT", "TIME_WAIT", "FIN_WAIT1", "FIN_WAIT2", "LAST_ACK"}
        for r in rows:
            pid = str(r.get("PID") or "")
            state = str(r.get("State") or "").upper()
            fa = str(r.get("ForeignAddr") or "")
            fip = self._ip_from_endpoint(fa)
            proto = str(r.get("Proto") or "").upper()
            la = str(r.get("LocalAddr") or "")
            try: lp_i = int(r.get("LocalPort") or 0)
            except (TypeError, ValueError): lp_i = 0
            try: fp_i = int(r.get("ForeignPort") or 0)
            except (TypeError, ValueError): fp_i = 0
            key = (pid, la, lp_i, fa, fp_i, proto, state)
            if state in skip_states or key in counted:
                continue
            counted.add(key)
            if pid:
                per_pid.setdefault(pid, set()).add(key)
            if state in {"ESTABLISHED", "SYN_SENT"} and self._is_public_ip(fip):
                per_remote_pub.setdefault(fip, set()).add(key)

        # ---------- score unique sockets ----------
        seen = set()
        suspicious: List[Dict[str, Any]] = []

        for row in rows:
            proto = str(row.get("Proto") or "")
            state = str(row.get("State") or "").upper()
            la = str(row.get("LocalAddr") or "")
            lp = str(row.get("LocalPort") or "")
            fa = str(row.get("ForeignAddr") or "")
            fp = str(row.get("ForeignPort") or "")
            owner = str(row.get("Owner") or "")
            pid = row.get("PID")

            # normalize int/str ports
            try: lp_i = int(lp)
            except: lp_i = 0
            try: fp_i = int(fp)
            except: fp_i = 0

            # PID is part of socket identity. Two processes can legitimately reuse
            # the same endpoint tuple at different times in one memory image.
            key = (pid, owner.lower(), la, lp_i, fa, fp_i, proto.upper(), state)
            if state in skip_states or key in seen:
                continue
            seen.add(key)

            scored_row = dict(row)
            scored_row["_pid_conn_count"] = len(per_pid.get(str(pid or ""), ()))
            fip = self._ip_from_endpoint(fa)
            scored_row["_same_remote_count"] = len(per_remote_pub.get(fip, ()))

            score, flags, rationale = self._score_network_connections(
                scored_row, self._is_private_ip, self._is_loopback)
            if score >= self._threshold("netscan"):
                suspicious.append({
                    "local_address": la,
                    "foreign_address": fa,
                    "local_port": lp_i,
                    "foreign_port": fp_i,
                    "proto": proto,
                    "state": state,
                    "owner": owner or None,
                    "pid": pid,
                    "score": int(score),
                    "score_max": self.MAX_RISK_SCORE,
                    "risk": self._risk_from_score(score),
                    "flags": flags,
                    "rationale": rationale,
                })

        # ---------- render ----------
        suspicious.sort(key=lambda s: (-int(s.get("score", 0)),
                                    str(s.get("foreign_address") or ""),
                                    str(s.get("local_address") or "")))

        rows_to_display = []
        for s in suspicious:
            # The shared ladder, not a second private one -- this step used to
            # label with its own bands, so the same score read as a different risk
            # here than it did in every other step.
            risk_label = self._risk_from_score(int(s["score"]))
            indicator = self._indicator_from_flags(s.get("flags", []))
            rows_to_display.append([
                s.get("local_address"),
                s.get("foreign_address"),
                str(s.get("local_port")),
                str(s.get("foreign_port")),
                s.get("proto"),
                str(s.get("pid") or "—"),      
                s.get("state"),
                risk_label,
                indicator,                      
                s.get("rationale"),
            ])

        rows_to_display = self._keep(rows_to_display, 7)

        TerminalUI.table(
            ["Local Address", "Foreign Address", "Local Port", "Foreign Port",
            "Proto", "PID", "State", "Risk", "Indicator", "Rationale"],
            rows_to_display, max_rows=30)
        
        return {
            "ok": True,
            "suspicious_connections": suspicious,
            "counts": {"total_rows": len(rows), "unique_scored": len(suspicious)}
        }



    def step4_persistence(self, pipe: Pipeline, image_path: str, artifacts_dir: str, use_cache: bool,
                          high_level: bool, deep: bool = False) -> Dict[str, Any]:
        TerminalUI.section("Step 4 · Persistence & user activity (registry & tasks)")
        out: Dict[str, Any] = {}
        #Collecting *best* IoC per canonical key here to avoid duplicates.
        best: dict[str, dict] = {}

        def add_or_update(key: str, *, itype: str, indicator: str, score: int, rationale: list[str],
                        source: str, tiebreak: tuple = (0, 0)) -> None:
            """Keep the highest-score row per key; tie-break by (Count, Focus) for UA."""
            row = {
                "type": itype,
                "indicator": indicator,
                "score": int(score),
                "score_max": self.MAX_RISK_SCORE,
                "risk": self._risk_from_score(score),
                "why": " | ".join([w for w in rationale if w]),
                "source": source,
                "_tb": tiebreak,  # tiebreak tuple kept internal
            }
            prev = best.get(key)
            if not prev:
                best[key] = row
                return
            if row["score"] > prev["score"]:
                best[key] = row
                return
            if row["score"] == prev["score"] and row["_tb"] > prev.get("_tb", (0, 0)):
                best[key] = row

        # --- Hives: list vs scan → orphan offsets become IoCs (rare, but keep them)
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
            missing = sorted(set_scan - set_list)
            out["orphaned"] = len(missing)
            # Pool-scan-only hive pages are commonly stale allocations. Preserve
            # the count as deep-mode context, but do not promote an uncorroborated
            # carved page to an IOC.

        # --- Scheduled tasks (uses not_system_path in scorer; dedupe by name or action+args)
        if pipe.registry.has("scheduled_tasks"):
            tasks = load_records_any(self._ensure_one(pipe, image_path, artifacts_dir, "scheduled_tasks", use_cache))
            out["tasks"] = len(tasks)
            flagged = 0

            for t in tasks:
                s, why = self._score_scheduled_task(t)
                if s >= self._threshold("scheduled_tasks"):
                    flagged += 1
                    name = str(t.get("Task Name") or "")
                    act  = str(t.get("Action") or "")
                    args = str(t.get("Action Arguments") or "")

                    # Primary key = stable task name; fallback = canonical path of action+args
                    task_name_key = name.strip().lower()
                    if task_name_key:
                        key = f"task:{task_name_key}"
                    else:
                        key = f"task:{canonical_path_key(f'{act} {args}') or (act.strip().lower() or 'unknown')}"

                    add_or_update(
                        key=key,
                        itype="scheduled_task",
                        indicator=f"{name} :: {act} {args}".strip(),
                        score=s,
                        rationale=why,
                        source="scheduled_tasks",
                    )

            TerminalUI.kv([("scheduled tasks", len(tasks)), ("suspicious tasks", flagged)])

        # --- UserAssist (executions) — dedupe by canonical path; tie-break by (Count, Focus)
        if pipe.registry.has("registry.userassist"):
            ua_tree = load_records_any(self._ensure_one(pipe, image_path, artifacts_dir, "registry.userassist", use_cache))
            ua_all  = list(self._flatten_UA_with_context(ua_tree))
            ua_vals = [r for r in ua_all if r.get("Type") == "Value"]  # actual entries

            out["userassist"] = len(ua_vals)
            flagged = 0

            for r in ua_vals:
                name = str(r.get("Name") or "")
                # Skip classic UEME noise unless it looks path-like
                if name.startswith("UEME_") and not self._seems_pathlike(name):
                    continue

                cnt  = int(r.get("Count") or 0)
                fcnt = int(r.get("Focus") or r.get("Focus Count") or 0)

                s, why = self._score_userassist_name(name)
                # Frequency is analyst context and a dedupe tie-break, not risk.
                # Frequently launched software is usually *more* likely to be
                # ordinary, and count-based points let a benign shortcut cross a
                # threshold without any new suspicious property.
                if cnt:  why.append(f"Count={cnt}")
                if fcnt: why.append(f"Focus={fcnt}")

                if s >= self._threshold("userassist") and self._seems_pathlike(name):
                    flagged += 1
                    key = f"ua:{canonical_path_key(name) or name.strip().lower()}"
                    add_or_update(
                        key=key,
                        itype="userassist.exec",
                        indicator=name,
                        score=s,
                        rationale=why,
                        source="registry.userassist",
                        tiebreak=(cnt, fcnt),
                    )
            TerminalUI.kv([("userassist values", len(ua_vals)), ("suspicious user executions", flagged)])

        # --- Present & return (single combined table, deduped)
        iocs_sorted = sorted(best.values(), key=lambda d: (-d["score"], d["type"], d["indicator"]))
        rows = [[d["type"], d["indicator"], d["risk"], d["why"], d["source"]] for d in iocs_sorted]
        
        rows = self._keep(rows, 2)

        TerminalUI.table(["Type","Indicator","Risk","Rationale","Source"], rows, max_rows=25)

        out["ioc_count"] = len(iocs_sorted)
        out["iocs"] = iocs_sorted
        return out

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
        grouped: Dict[str, Dict[str, Any]] = {}

        for row in rows:
            score, flag, rationale = self._score_ssdt_entry(row)
            if score < self._threshold("ssdt"):
                continue
            module = str(row.get("Module") or "").strip()
            key = ntpath.basename(module.replace("/", "\\")).lower()
            finding = grouped.setdefault(key, {
                "module": module,
                "entry_count": 0,
                "sample_symbols": [],
                "score": int(score),
                "score_max": self.MAX_RISK_SCORE,
                "risk": self._risk_from_score(score),
                "flags": [flag],
                "rationale": rationale,
            })
            finding["entry_count"] += 1
            symbol = str(row.get("Symbol") or "").strip()
            if symbol and symbol not in finding["sample_symbols"] and len(finding["sample_symbols"]) < 5:
                finding["sample_symbols"].append(symbol)

        findings = sorted(grouped.values(), key=lambda item: (-item["score"], item["module"].lower()))
        display = [
            [
                item["module"],
                str(item["entry_count"]),
                item["risk"],
                ", ".join(item["sample_symbols"]) or "—",
                item["rationale"],
            ]
            for item in findings
        ]
        display = self._keep(display, 2)
        TerminalUI.table(
            ["Target module", "Entries", "Risk", "Sample symbols", "Rationale"],
            display,
            max_rows=25,
        )
        return {
            "ok": True,
            "total_entries": len(rows),
            "foreign_module_count": len(findings),
            "findings": findings,
        }


    # ------------------------- Scorer functions --------------------------

    # Binaries whose name alone carries authority, which is exactly why malware
    # borrows it. Used two ways: a near-miss spelling, and the real name in a
    # place the real binary never lives.
    SYSTEM_BINARIES = frozenset({
        "svchost.exe", "services.exe", "lsass.exe", "csrss.exe", "smss.exe",
        "wininit.exe", "winlogon.exe", "explorer.exe", "spoolsv.exe", "conhost.exe",
        "taskhostw.exe", "dllhost.exe", "rundll32.exe", "dwm.exe", "userinit.exe",
        "lsm.exe", "searchindexer.exe", "runtimebroker.exe", "sihost.exe",
    })

    # What each of these is actually supposed to start. A child outside the set is
    # worth a look; a child inside it is the operating system working normally.
    EXPECTED_CHILDREN = {
        "smss.exe":     {"csrss.exe", "wininit.exe", "winlogon.exe", "smss.exe"},
        "wininit.exe":  {"services.exe", "lsass.exe", "lsm.exe", "fontdrvhost.exe"},
        "winlogon.exe": {"userinit.exe", "dwm.exe", "fontdrvhost.exe", "logonui.exe"},
        "lsass.exe":    set(),
    }

    # The four discovery sources psxview cross-checks.
    PSXVIEW_SOURCES = ("pslist", "psscan", "thrdscan", "csrss")

    # SSDT entries normally resolve into one of these Windows kernel modules.
    # Normalize optional .exe/.sys suffixes before comparison. An empty or
    # unresolved module is unknown evidence and is not scored.
    TRUSTED_SSDT_MODULES = frozenset({
        "ntoskrnl", "win32k", "win32kbase", "win32kfull",
    })

    @staticmethod
    def _record_evidence(evidence: Dict[str, Tuple[int, str, str]], family: str,
                         weight: int, flag: str, rationale: str) -> None:
        """Keep the strongest observation that tests one investigative hypothesis."""
        previous = evidence.get(family)
        if previous is None or weight > previous[0]:
            evidence[family] = (int(weight), flag, rationale)

    @classmethod
    def _finish_evidence(cls, evidence: Dict[str, Tuple[int, str, str]]) -> Tuple[int, List[str], List[str]]:
        """Combine independent hypothesis families on a documented bounded scale."""
        score = min(cls.MAX_RISK_SCORE, sum(item[0] for item in evidence.values()))
        flags = [item[1] for item in evidence.values() if item[1]]
        reasons = [item[2] for item in evidence.values() if item[2]]
        return int(score), flags, reasons

    def _score_processes(self, census: Dict[int, Dict[str, Any]], psscan: Optional[List[dict]],
                         psxview: Optional[List[dict]]) -> Tuple[Dict[str, Any], List[Tuple]]:
        pid_set = set(census.keys())
        psscan_ran = psscan is not None
        # Keep the exit time alongside the PID. A process found by pool scan but
        # absent from the linked list is usually just one that has exited and not
        # yet been reaped -- an image has dozens -- so treating every psscan-only
        # PID as hidden made the strongest signal in this step indistinguishable
        # from ordinary process churn.
        psscan_exited: Dict[int, bool] = {}
        for r in psscan or []:
            pid = self._as_int(r.get("PID") or r.get("pid"))
            if pid is None:
                continue
            exit_time = r.get("ExitTime") or r.get("Exit Time")
            psscan_exited[pid] = bool(exit_time) and str(exit_time).strip() not in ("", "N/A")
        psscan_pids = set(psscan_exited)

        # None means psxview was not run at all, which is not the same as psxview
        # having found nothing; the summary must not claim a clean cross-check.
        psxview_ran = psxview is not None
        psx_false: Dict[int, List[str]] = {}
        for r in psxview or []:
            pid = self._as_int(r.get("PID") or r.get("Pid") or r.get("pid"))
            if pid is None:
                continue
            # Only the four discovery columns, and only when at least two of them
            # disagree. Sweeping every boolean column flagged Wow64=False, and a
            # process that has simply exited is legitimately missing from one
            # source, so a single False is the normal case rather than a finding.
            missing = [k for k in self.PSXVIEW_SOURCES if r.get(k) is False]
            if len(missing) >= 2:
                psx_false[pid] = missing

        rows: List[Tuple] = []
        emitted: set = set()

        for pid in sorted(pid_set | psscan_pids):
            b = census.get(pid) or {"pid": pid, "name": "(not in pslist)", "ppid": None,
                                    "path": "", "wow64": None}
            name = (b.get("name") or "").strip()
            path = (b.get("path") or "").strip()
            ppid = b.get("ppid")
            wow64 = b.get("wow64")
            evidence: Dict[str, Tuple[int, str, str]] = {}

            try:
                non_system_location = bool(path) and not_system_path(path)
            except Exception:
                non_system_location = False
            try:
                vendor_install = non_system_location and in_user_install_dir(path)
            except Exception:
                vendor_install = False
            try:
                explicit_suspicious = bool(path) and is_suspicious_path(path)
            except Exception:
                explicit_suspicious = False
            # is_suspicious_path is intentionally narrow; add non-system roots
            # (external drives, shares, user-writable locations) while de-noising
            # conventional per-user vendor install directories.
            suspicious_path = bool(path) and (
                explicit_suspicious or (non_system_location and not vendor_install)
            )

            # --- disagreement between discovery methods -----------------------
            if pid in psscan_pids and pid not in pid_set:
                if psscan_exited.get(pid):
                    self._record_evidence(
                        evidence, "discovery", 2, "TERM",
                        "Found by pool scan only, but it has an exit time: "
                        "a terminated process not yet reaped.")
                else:
                    self._record_evidence(
                        evidence, "discovery", 10, "HK",
                        "Found by pool scan (psscan) with no exit time, yet absent "
                        "from the EPROCESS list (pslist).")
            if pid in psx_false:
                self._record_evidence(
                    evidence, "discovery", 8, "XV",
                    f"Missing from {len(psx_false[pid])} discovery sources (psxview): "
                    f"{', '.join(psx_false[pid])}.")

            # --- parent missing from the census (scored once) -----------------
            # This used to be scored twice by two rules testing the same condition,
            # so every orphan carried 12-14 points and a duplicated flag.
            # PID 0 is the kernel root, not a missing user-mode parent.
            if ppid not in (None, 0) and ppid not in pid_set:
                self._record_evidence(
                    evidence, "lineage", 4, "ZB",
                    "Parent PID is not present in the census (orphan).")

            # --- where it is running from -------------------------------------
            if suspicious_path:
                self._record_evidence(
                    evidence, "location", 7, "OP",
                    f"Executable in a user-writable, non-system path ({path}).")
                if wow64:
                    self._record_evidence(
                        evidence, "context", 2, "WOW",
                        "32-bit executable on 64-bit Windows, from that same path.")
            elif vendor_install:
                self._record_evidence(
                    evidence, "location", 2, "USERINSTALL",
                    f"Executable in a conventional per-user install directory ({path}).")

            # --- what it is called --------------------------------------------
            if name:
                lower = name.lower()
                if lower in self.SYSTEM_BINARIES and path and not_system_path(path):
                    self._record_evidence(
                        evidence, "identity", 8, "IMP",
                        f"Carries the name of a system binary but runs from {path}.")
                twin = self._lookalike_of(lower)
                if twin:
                    self._record_evidence(
                        evidence, "identity", 8, "LOOK",
                        f"Name is one character away from the system binary {twin}.")
                if is_non_ascii(name):
                    self._record_evidence(
                        evidence, "identity", 4 if suspicious_path else 2, "UNI",
                        "Process name contains non-ASCII characters.")

            # --- parentage -----------------------------------------------------
            parent = (census.get(ppid, {}).get("name") or "").lower() if ppid else ""
            expected = self.EXPECTED_CHILDREN.get(parent)
            if expected is not None and name:
                if name.lower() not in expected:
                    self._record_evidence(
                        evidence, "lineage", 4, "WP",
                        f"Unexpected child of {parent}.")

            # A script interpreter launching a native executable from an external
            # volume or UNC share is materially stronger than either fact alone.
            # Keep it in the lineage family so it cannot stack with a second rule
            # describing the same parent/child relationship.
            external_path = bool(re.match(r"^[d-z]:\\", path.lower())) or path.startswith("\\\\")
            native_child = ntpath.splitext(ntpath.basename(path.strip().strip('"\'')))[1].lower() \
                in {".exe", ".com", ".scr"}
            script_parents = {
                "powershell.exe", "pwsh.exe", "cmd.exe", "wscript.exe",
                "cscript.exe", "mshta.exe",
            }
            if parent in script_parents and external_path and native_child:
                self._record_evidence(
                    evidence, "lineage", 6, "SCRIPT_CHILD_EXTERNAL",
                    f"{parent} launched a native executable from an external or network path.")

            score, flags, reasons = self._finish_evidence(evidence)

            if score > 0 and pid is not None and pid not in emitted:
                emitted.add(pid)
                rows.append((pid, name, ppid, score, ",".join(flags), " ".join(reasons)))

        summary = {
            "pslist_count": len(pid_set),
            "psscan_count": len(psscan_pids) if psscan_ran else None,
            "hidden_count": (len([1 for pid in psscan_pids
                                  if pid not in pid_set and not psscan_exited.get(pid)])
                             if psscan_ran else None),
            "terminated_count": (len([1 for pid in psscan_pids
                                      if pid not in pid_set and psscan_exited.get(pid)])
                                 if psscan_ran else None),
            "orphans": len([1 for pid, b in census.items()
                            if b.get("ppid") not in (None, 0) and b.get("ppid") not in pid_set]),
            "psxview_inconsistent": len(psx_false) if psxview_ran else None,
            "with_path": len([1 for b in census.values() if b.get("path")]),
        }
        rows.sort(key=lambda r: (-r[3], r[0]))
        threshold = self._threshold("process")
        rows = [r for r in rows if r[3] >= threshold]
        rows = [self._score_map(row, -3) for row in rows]
        return summary, rows

    @classmethod
    def _lookalike_of(cls, name: str) -> Optional[str]:
        """A system binary this name is one edit away from, without being it.

        Catches svch0st.exe and lsasss.exe. Replaces a Shannon-entropy rule that
        could not work: entropy over a filename is essentially a length proxy, and
        real Windows binaries sit at the top of the range -- ApplicationFrameHost
        scores 3.82 and backgroundTaskHost 3.73, above every randomised name we
        tested, so the old 3.5 bar flagged the operating system and missed the
        thing it was looking for.
        """
        if name in cls.SYSTEM_BINARIES:
            return None
        for known in cls.SYSTEM_BINARIES:
            if abs(len(known) - len(name)) <= 1 and cls._within_one_edit(name, known):
                return known
        return None

    @staticmethod
    def _within_one_edit(a: str, b: str) -> bool:
        if a == b:
            return False
        if len(a) == len(b):
            diff = [i for i, (x, y) in enumerate(zip(a, b)) if x != y]
            if len(diff) == 1:
                return True
            # Adjacent transposition: scvhost.exe for svchost.exe.
            if len(diff) == 2 and diff[1] == diff[0] + 1:
                i, j = diff
                return a[i] == b[j] and a[j] == b[i]
            return False
        short, long = (a, b) if len(a) < len(b) else (b, a)
        if len(long) - len(short) != 1:
            return False
        i = 0
        for j, ch in enumerate(long):
            if i < len(short) and short[i] == ch:
                i += 1
            elif j - i:      # a second mismatch
                return False
        return True

    def _score_ssdt_entry(self, row: Dict[str, Any]) -> Tuple[int, str, str]:
        """Score one resolved SSDT target without treating missing data as a hook."""
        module = str(row.get("Module") or "").strip()
        symbol = str(row.get("Symbol") or "").strip()
        address = self._as_int(row.get("Address"))
        if not module or not symbol or address is None or address <= 0:
            return 0, "", "Incomplete SSDT attribution"

        module_name = ntpath.basename(module.replace("/", "\\")).lower()
        module_stem = ntpath.splitext(module_name)[0]
        if module_stem in self.TRUSTED_SSDT_MODULES:
            return 0, "", "Expected Windows kernel target"

        return (
            10,
            "SSDT_FOREIGN_MODULE",
            f"SSDT target {symbol} resolves to non-baseline module {module}",
        )

    ###############################################################

    def _score_injections(self, row: Dict[str, Any]) -> Tuple[int, str, str]:
        """Score one malfind region from what the region actually contains.

        Deliberately scored from the bytes rather than the disassembly. Volatility
        renders the Disasm column with Capstone *if it happens to be installed*,
        and falls back to a plain byte dump if not -- capstone is an optional
        extra, not a dependency. Keying off assembly mnemonics therefore made this
        scorer behave completely differently on two installs of the same tool: it
        matched nothing at all without capstone, and with capstone the old pattern
        list (which included a bare `call|jmp`) matched essentially every region,
        so every row scored the same and the threshold decided nothing.

        The Hexdump column is always present and always the same shape, so that is
        what we read. Volatility gives us the first 64 bytes of the region.
        """
        evidence: Dict[str, Tuple[int, str, str]] = {}

        data = self._hexdump_bytes(row.get("Hexdump"))
        prot = str(row.get("Protection") or "").upper()
        private = self._as_bool(row.get("PrivateMemory"), default=False)
        commit = self._as_int(row.get("CommitCharge"))

        executable = "EXECUTE" in prot
        writable = "WRITE" in prot  # covers WRITECOPY too

        # An unbacked region that is writable and executable at once is the
        # classic shape of injected code; on its own it is still only a shape.
        if executable and writable and private == 1:
            self._record_evidence(
                evidence, "memory_shape", 8, "RWX",
                f"Private region that is both writable and executable ({prot or 'unknown'})")
        elif executable and private == 1:
            self._record_evidence(
                evidence, "memory_shape", 4, "PRV",
                "Executable private region with no file backing")

        if data[:2] == b"MZ":
            self._record_evidence(
                evidence, "payload", 8, "PE",
                "PE header at the start of an unbacked executable region")
        if re.search(rb"\x90{8,}", data):
            self._record_evidence(evidence, "payload", 6, "SLED", "NOP sled of 8 or more bytes")
        if self._shellcode_prologue(data):
            self._record_evidence(
                evidence, "payload", 8, "STUB",
                "Byte sequence matching a known shellcode prologue")
        if self._peb_access(data):
            self._record_evidence(
                evidence, "loader_behavior", 4, "PEB",
                "Direct PEB/TEB access, typical of position-independent code")
        if self._peb_walk(data):
            self._record_evidence(
                evidence, "loader_behavior", 6, "LDRWALK",
                "Walks the PEB loader lists, the way code with no import table finds its imports")
        # One push-immediate is ordinary compiler output and does not test the API
        # hashing hypothesis. Require repetition even within the 64-byte window.
        hashes = self._api_hashing(data)
        if hashes >= 2:
            self._record_evidence(
                evidence, "loader_behavior", 6, "APIHASH",
                "Repeated push of hash-like constants, typical of resolving imports by hash")
        if self._segment_tricks(data):
            self._record_evidence(
                evidence, "loader_behavior", 4, "SEG",
                "Segment register manipulation (push fs / pop ds)")

        # Context, never enough on its own.
        if commit is not None and commit > 32:
            self._record_evidence(
                evidence, "size_context", 2, "BIGCOMMIT", f"Large commit charge ({commit})")

        # A region of nothing is not injected code, whatever its protection says.
        # Volatility reports plenty of these and they were previously scored as if
        # they held a payload.
        if data and not data.strip(b"\x00"):
            return 0, "", "Region is entirely zero bytes"

        score, flags, why = self._finish_evidence(evidence)
        return int(score), ", ".join(flags), " | ".join(why) if why else "—"

    @staticmethod
    def _hexdump_bytes(value) -> bytes:
        """Volatility's Hexdump column as bytes, tolerating the absent cases.

        In JSON the column is space-separated hex pairs ("4d 5a 90 00"). When the
        region could not be read Volatility writes the literal string "N/A", and a
        missing column arrives from pandas as NaN or None. Feeding either of those
        to bytes.fromhex raises ValueError, which previously escaped
        step2_injections and took the whole step down with it.
        """
        if not isinstance(value, str):
            return b""
        cleaned = value.strip()
        if not cleaned or cleaned.upper() == "N/A":
            return b""
        try:
            return bytes.fromhex(re.sub(r"[\s]", "", cleaned))
        except ValueError:
            return b""

    # The x86 walk from the PEB to the loader's module lists. Position-independent
    # code has to find its own imports, and this is how it does it:
    #   mov eax,[eax+0x0c]   PEB->Ldr
    #   mov esi,[eax+0x1c]   InInitializationOrderModuleList
    #   mov eax,[esi+0x08]   DllBase
    #   mov edi,[esi+0x20]   BaseDllName
    #   mov esi,[esi]        next entry
    # Compiler output reaches structure fields the same way in general, so one of
    # these on its own means nothing; several together is the walk.
    _PEB_WALK_OPS = (
        b"\x8b\x40\x0c", b"\x8b\x70\x1c", b"\x8b\x46\x08",
        b"\x8b\x7e\x20", b"\x8b\x36", b"\x8b\x5e\x08", b"\x8b\x4e\x20",
    )

    @classmethod
    def _peb_walk(cls, data: bytes) -> bool:
        return sum(1 for op in cls._PEB_WALK_OPS if op in data) >= 2

    @staticmethod
    def _api_hashing(data: bytes) -> int:
        """Repeated `push <32-bit constant>` where the constants look like hashes.

        Shellcode resolves imports by hashing the export names and comparing, so
        the hashes appear inline as immediates. Ordinary code pushes small
        constants -- addresses, lengths, flags -- which leave most of the four
        bytes zero, so requiring three distinct non-zero bytes separates them.

        Returns how many were found, since one and several mean different things.
        """
        hits = 0
        for m in re.finditer(rb"\x68(....)", data, re.DOTALL):
            imm = m.group(1)
            if len(set(imm)) >= 3 and imm.count(0) <= 1:
                hits += 1
        return hits

    @staticmethod
    def _segment_tricks(data: bytes) -> bool:
        """push fs / pop ds and friends: reaching for a segment register at all is
        unusual outside of hand-written code."""
        return bool(re.search(rb"\x0f\xa0.{0,4}\x1f", data, re.DOTALL)) or \
               bool(re.search(rb"\x0f\xa8.{0,4}\x1f", data, re.DOTALL))

    @staticmethod
    def _shellcode_prologue(data: bytes) -> bool:
        """Prologues specific enough to be worth a flag on their own."""
        prologues = (
            rb"\xfc\xe8[\x00-\xff]{2}\x00\x00",   # metasploit/meterpreter stager
            rb"\xfc\x48\x83\xe4\xf0\xe8",        # x64 stager (cld; and rsp, -16; call)
            rb"\xe8\x00\x00\x00\x00[\x58-\x5f]",  # call $+5 then pop -- get EIP
        )
        return any(re.search(p, data) for p in prologues)

    @staticmethod
    def _peb_access(data: bytes) -> bool:
        """Reading the PEB/TEB straight out of fs/gs, as shellcode does."""
        patterns = (
            rb"\x64\xa1\x30\x00\x00\x00",                    # mov eax, fs:[0x30]
            rb"\x64\x8b[\x00-\xff]\x30\x00\x00\x00",        # mov reg, fs:[0x30]
            rb"\x65\x48\x8b[\x00-\xff]\x25\x60\x00\x00\x00",  # mov rax, gs:[0x60]
        )
        return any(re.search(p, data) for p in patterns)

    ###############################################################

    def _score_network_connections(
        self,
        row: Dict[str, Any],
        is_private_ip,
        is_loopback
    ) -> Tuple[int, List[str], str]:
        """
        DFIR-backed scoring for netscan output
        """
        evidence: Dict[str, Tuple[int, str, str]] = {}

        state = str(row.get("State") or "").upper()
        proto = str(row.get("Proto") or "")
        la = str(row.get("LocalAddr") or "")
        fa = str(row.get("ForeignAddr") or "")
        lp = str(row.get("LocalPort") or "")
        fp = str(row.get("ForeignPort") or "")
        owner = (row.get("Owner") or row.get("Process") or "") or ""
        pid = row.get("PID")

        try: lp_i = int(lp)
        except: lp_i = 0
        try: fp_i = int(fp)
        except: fp_i = 0

        lip = self._ip_from_endpoint(la)
        fip = self._ip_from_endpoint(fa)
        public_remote = self._is_public_ip(fip)

        conn_count = int(row.get("_pid_conn_count") or 0)
        same_remote_count = int(row.get("_same_remote_count") or 0)
        owner_l = owner.lower()

        system_owners = {"system", "services.exe", "lsass.exe", "wininit.exe", "svchost.exe", "spoolsv.exe"}
        lolbin_clients = {"powershell.exe", "cmd.exe", "wscript.exe", "cscript.exe", "mshta.exe", "rundll32.exe", "regsvr32.exe"}
        # Common "okay" ports (for de-noising uncommon test)
        common_ports = {
            80, 443, 53, 123, 25, 110, 995, 143, 993, 3389, 445, 139, 22, 21, 23,
            587, 465, 389, 636, 135, 137, 138, 3306, 1433, 1521, 5432, 27017, 8080, 8443
        }
        # Ports that often show up in implants / red team demos
        suspicious_ports = {4444, 1337, 6969, 2222, 9001, 6667, 6666}

        # ---- TCP rules ----
        if proto.upper().startswith("TCP"):
            # Major: listener exposure or unexpected listener by non-system
            if state in {"LISTENING", "LISTEN"}:
                if lp_i in {3389, 445, 139} and owner_l not in system_owners:
                    self._record_evidence(
                        evidence, "listener", 8, "UnexpectedListener",
                        f"{owner or 'Unknown'} listening on sensitive port {lp_i}")
                # High ephemeral listener by non-system, not loopback
                if lp_i >= 49152 and owner_l and owner_l not in system_owners and not is_loopback(lip):
                    self._record_evidence(
                        evidence, "listener", 6, "HighPortListener",
                        f"High-port listener {lp_i} by {owner}")

            # Missing attribution is an evidence-quality warning, not a threat
            # behavior. Pool residue and process teardown produce many of these,
            # so it cannot surface an otherwise ordinary public connection.
            if state == "ESTABLISHED" and public_remote and (pid in (None, "", 0)):
                self._record_evidence(
                    evidence, "attribution", 3, "PublicNoPID",
                    f"Public ESTABLISHED with no PID to {fip}")

            # Outbound to admin/service ports on the public internet (workstations usually shouldn't)
            if state in {"ESTABLISHED", "SYN_SENT"} and public_remote and fp_i in {445, 3389, 23}:
                self._record_evidence(
                    evidence, "remote_service", 8, "AdminPortOutbound",
                    f"Outbound to {fp_i} on public {fip}")

            # LOLBIN outbound to public
            if state in {"ESTABLISHED", "SYN_SENT"} and public_remote and owner_l in lolbin_clients:
                self._record_evidence(
                    evidence, "process_behavior", 8, "LOLBINOutbound",
                    f"{owner} connecting to public {fip}")

            # Non-standard destination ports to public (MITRE T1571) vs uncommon-but-common set
            if state in {"ESTABLISHED", "SYN_SENT"} and public_remote and fp_i:
                if fp_i in suspicious_ports:
                    self._record_evidence(
                        evidence, "remote_service", 7, "BadPort",
                        f"Destination port {fp_i} is commonly used in implant demonstrations")
                elif fp_i not in common_ports:
                    # Weighted low on purpose: plenty of ordinary traffic (QUIC,
                    # CDNs, game and chat clients) lands outside the common set, so
                    # on its own this is an observation rather than a finding. It
                    # used to score 8, which cleared the old threshold by itself.
                    self._record_evidence(
                        evidence, "remote_service", 3, "UncommonPort",
                        f"Uncommon destination port {fp_i} to public {fip}")

            # Public/established is context, not a second major signal. Missing
            # attribution already depends on the same public connection, so it is
            # not independent corroboration and cannot unlock these points.
            behavioral_evidence = any(
                family in evidence
                for family in ("listener", "remote_service", "process_behavior")
            )
            if state == "ESTABLISHED" and public_remote and behavioral_evidence:
                self._record_evidence(
                    evidence, "connection_context", 2, "EstablishedPublic",
                    f"Established to public IP {fip}")

        # ---- UDP rules ----
        if proto.upper().startswith("UDP"):
            # De-noise typical Windows UDP listeners
            benign_udp = {5353, 5355, 1900, 123}
            if lp_i in benign_udp and owner_l in {"svchost.exe", "system"}:
                pass  # ignore
            else:
                # UDP "any/*" sockets bound to 0.0.0.0 by odd owners get minor weight
                if la in {"0.0.0.0", "::"} and lp_i >= 49152 and owner_l and owner_l not in system_owners:
                    self._record_evidence(
                        evidence, "listener", 4, "UDPAnyHighPort",
                        f"Wildcard UDP high-port {lp_i} by {owner}")

        # Volume is only corroboration. Busy browsers, update clients, and servers
        # routinely exceed these counts, so volume cannot create a finding alone.
        primary = any(
            family in evidence
            for family in ("listener", "remote_service", "process_behavior")
        )
        if primary:
            if conn_count >= 50:
                self._record_evidence(
                    evidence, "volume", 4, "ConnBurst", f"Process has {conn_count} active sockets")
            elif conn_count >= 15:
                self._record_evidence(
                    evidence, "volume", 3, "ManyConns", f"Process has {conn_count} active sockets")
            if public_remote and same_remote_count >= 8:
                self._record_evidence(
                    evidence, "volume", 5, "ToSameRemote",
                    f"Multiple active sockets to {fip}")

        # Minor: loopback pair on uncommon ports (often IPC)
        if is_loopback(lip) and fip and is_loopback(fip) and lp_i and fp_i and lp_i not in common_ports and fp_i not in common_ports:
            self._record_evidence(
                evidence, "connection_context", 2, "LoopbackPair",
                "Loopback pair on uncommon ports")

        score, flags, why = self._finish_evidence(evidence)
        return int(score), flags, " | ".join(why) if why else "—"

    ################################################################
       
    def _score_scheduled_task(self, row: dict) -> tuple[int, list[str]]:
        """
        DFIR-informed scheduled-task scoring by independent hypothesis family:
        payload semantics, payload location, execution method, and task context.
        Only the strongest observation in each family contributes.
        """
        evidence: Dict[str, Tuple[int, str, str]] = {}
        name  = str(row.get("Task Name") or "")
        act   = str(row.get("Action") or "")
        args  = str(row.get("Action Arguments") or "")
        trig  = str(row.get("Trigger Type") or "")
        princ = (str(row.get("Principal ID") or "") or str(row.get("Author") or ""))
        enabled = self._as_bool(row.get("Enabled", True), default=True)

        la = (act or "").lower()
        aa = (args or "").lower()
        na = name.lower()

        # --- classifiers ---
        lolbins = ("powershell.exe","pwsh.exe","cmd.exe","wscript.exe","cscript.exe","mshta.exe",
                "rundll32.exe","regsvr32.exe","msbuild.exe","wmic.exe","bitsadmin.exe","schtasks.exe")
        argument_patterns = (
            (r"(?:^|\s)-(?:enc|encodedcommand)(?:\s|$)", 10, "ENCODED",
             "Encoded command argument"),
            (r"\bfrombase64string\b", 9, "DECODE",
             "Base64 decoding primitive in arguments"),
            (r"(?:^|\s)iex(?:\s|\()", 8, "IEX",
             "PowerShell Invoke-Expression alias in arguments"),
            (r"(?:^|\s)-(?:nop|noprofile)(?:\s|$)", 2, "NOPROFILE",
             "PowerShell profile loading disabled"),
            (r"(?:^|\s)-(?:w|windowstyle)\s+hidden(?:\s|$)", 4, "HIDDEN",
             "Hidden-window argument"),
            (r"(?:^|\s)-(?:executionpolicy|ep)\s+bypass(?:\s|$)", 4,
             "POLICY_BYPASS", "PowerShell execution-policy bypass argument"),
        )

        action_name    = ntpath.basename(la.strip().strip('"\''))
        action_stem    = ntpath.splitext(action_name)[0]
        is_lolbin      = action_stem in {ntpath.splitext(name)[0] for name in lolbins}
        argument_matches = [
            (weight, flag, rationale)
            for pattern, weight, flag, rationale in argument_patterns
            if re.search(pattern, aa)
        ]
        # Scheduled-task renderers separate Action from Action Arguments. Accept
        # both the canonical split form (bitsadmin.exe + /transfer ...) and a
        # wrapper form (cmd.exe + bitsadmin /transfer ...), without treating a
        # bare bitsadmin invocation as a transfer.
        bits_transfer = (
            action_stem == "bitsadmin"
            and bool(re.search(r"(?:^|\s)/transfer(?:\s|$)", aa))
        ) or bool(re.search(r"\bbitsadmin(?:\.exe)?\s+/transfer(?:\s|$)", aa))
        if bits_transfer:
            argument_matches.append(
                (9, "BITS_TRANSFER", "BITS transfer command in arguments"))
        has_argument_signal = bool(argument_matches)
        has_major_argument = any(weight >= 8 for weight, _, _ in argument_matches)
        has_script     = bool(re.search(r"\.(?:ps1|vbs|js|jse|wsf|hta|bat|cmd|psm1)(?:['\"]?\s|$)", aa))
        has_remote_url = ("http://" in aa) or ("https://" in aa)

        def _looks_pathlike(s: str) -> bool:
            s = (s or "").lower()
            if re.match(r"^[a-z]:\\", s): return True
            if s.startswith("\\\\"): return True
            # contains a backslash and a known file extension somewhere
            if ("\\" in s or "/" in s) and re.search(r"\.(exe|dll|sys|cpl|bat|cmd|ps1|psm1|vbs|js|hta|msi|scr|com)\b", s):
                return True
            return False

        data = (act + " " + args).strip()
        try:
            non_system_payload = bool(data) and _looks_pathlike(data) and not_system_path(data)
        except Exception:
            non_system_payload = False
        # A per-user install root is not a system path, but it is where a lot of
        # ordinary software lives, so an auto-start task pointing into one is the
        # product updating itself rather than a finding.
        try:
            vendor_install = non_system_payload and in_user_install_dir(data)
        except Exception:
            vendor_install = False

        in_profile_hint = any(t in ((la + aa)) for t in ("\\appdata\\","\\temp\\","\\users\\public\\","\\downloads\\","\\desktop\\"))
        autostart = any(x in trig.lower() for x in ("logon","startup","boot"))
        priv_prin = any(x in (princ or "").lower() for x in ("system","administrator","adm","local service","network service"))
        rundll_dll = action_stem == "rundll32" and (".dll" in aa or ".dll" in la)
        regsvr_dll = action_stem == "regsvr32" and ".dll" in aa

        is_microsoft_default   = na.startswith("\\microsoft\\windows\\")
        looks_system32_action  = ("\\windows\\system32" in la) or ("system32\\" in la)

        # --- MAJOR ---
        for weight, flag, rationale in argument_matches:
            self._record_evidence(
                evidence, "payload", weight, flag, rationale)
        if has_remote_url:
            self._record_evidence(
                evidence, "payload", 9, "REMOTE",
                "Command arguments reference remote content")
        if has_script:
            self._record_evidence(evidence, "payload", 6, "SCRIPT", "Script payload")
        if non_system_payload and not vendor_install:
            self._record_evidence(
                evidence, "location", 8, "USERPATH", "Non-system/user-writable path")
        elif vendor_install:
            self._record_evidence(
                evidence, "location", 1, "USERINSTALL", "Per-user install directory")

        # --- Synergy ---
        if is_lolbin and (has_argument_signal or has_remote_url):
            self._record_evidence(
                evidence, "execution", 6, "LOLBIN",
                f"LOLBin used with suspicious content ({act})")
        else:
            if is_lolbin:
                self._record_evidence(
                    evidence, "execution", 1, "LOLBIN", f"LOLBin action: {act}")

        # --- MINOR ---
        context = []
        if in_profile_hint: context.append("User profile path")
        if autostart: context.append(f"Auto-start trigger: {trig}")
        if priv_prin: context.append(f"Privileged principal: {princ}")
        if context:
            self._record_evidence(
                evidence, "context", min(3, len(context)), "CONTEXT", "; ".join(context))
        if rundll_dll:
            self._record_evidence(
                evidence, "execution", 3, "RUNDLL32", "DLL executed via rundll32")
        if regsvr_dll:
            self._record_evidence(
                evidence, "execution", 3, "REGSVR32", "DLL executed via regsvr32")

        score, _, why = self._finish_evidence(evidence)

        # --- Benign Microsoft/system32 cap (no major => cap to Low) ---
        no_major = not (
            has_major_argument or has_script or has_remote_url
            or (non_system_payload and not vendor_install)
        )
        if is_microsoft_default and looks_system32_action and no_major:
            score = min(score, 4)
            if "Microsoft default/system32 baseline" not in why:
                why.append("Microsoft default/system32 baseline")

        # Disabled note (no negative scoring)
        if (not enabled) and no_major:
            if "Disabled" not in why:
                why.append("Disabled")

        return max(0, int(score)), why

    ########################################################

    def _score_userassist_name(self, name: str) -> tuple[int, list[str]]:
        """
        Heuristic UserAssist scorer by independent hypothesis family: exact tool
        identity, execution location, payload type, and filename shape.
        """
        evidence: Dict[str, Tuple[int, str, str]] = {}
        n = (name or '').strip()
        if not n:
            return 0, []

        n_norm = n.replace("/", "\\")
        n_lower = n_norm.lower()

        # Path-likeness
        pathlike = False
        if re.match(r"^[a-zA-Z]:\\", n_norm) or n_lower.startswith("\\\\") or n_lower.startswith("\\??\\"):
            pathlike = True
        if not pathlike and ("\\" in n_norm or "/" in n_norm):
            if re.search(r"\.(exe|dll|com|bat|cmd|ps1|vbs|js|hta|lnk)$", n_lower):
                pathlike = True
        if not pathlike:
            return 0, []

        # --- Known-Folder GUIDs that actually map to system Program Files roots (treat as system) ---
        system_kf_guids = (
            "{6d809377-6af0-444b-8957-a3773f02200e}",
            "{7c5a40ef-a0fb-4bfc-874a-c0f2e0b9fa8e}",
        )
        has_system_kf_prefix = any(n_lower.startswith(g + "\\") for g in system_kf_guids)

        # --- helpers ---
        def base_name(path: str) -> str:
            return ntpath.splitext(ntpath.basename(path))[0]

        def ext_name(path: str) -> str:
            return ntpath.splitext(path)[1].lower()

        def any_in(hay: str, tokens: tuple[str, ...]) -> bool:
            L = hay.lower()
            return any(t in L for t in tokens)

        # MAJOR: known tools
        known_rt = {
            "mimikatz","psexec","procdump","bloodhound","sharphound","rubeus","seatbelt",
            "powersploit","empire","crackmapexec","cme","koadic","evil-winrm","lazagne",
            "winpeas","nc","ncat","netcat","plink","pscp","beacon","cobaltstrike",
            "metasploit","msfvenom","pafish","sharpdpapi","sharpup","sharproast",
            "hashdump","pwdump","adfind","wce","mimidrv","lsassy","kerberoast"
        }
        bn = base_name(n_lower)
        tool_stem = re.sub(r"(?:32|64)$", "", bn)
        if tool_stem in known_rt:
            self._record_evidence(
                evidence, "tool_identity", 12, "KNOWN_TOOL",
                f"Executable name matches known dual-use/red-team tooling ({ntpath.basename(n_norm)})")

        # MAJOR: location heuristics
        TEMP_TOKENS = (
            "\\temp\\", "\\appdata\\local\\temp\\", "\\tmp\\", "\\cache\\",
            "\\microsoft\\windows\\temporary internet files\\",
        )
        DOWNLOAD_TOKENS = ("\\downloads\\",)
        DESKTOP_TOKENS  = ("\\desktop\\",)
        PUBLIC_TOKENS   = ("\\users\\public\\", "\\public\\")
        RECYCLE_TOKENS  = ("\\$recycle.bin\\",)
        STARTUP_TOKENS  = ("\\start menu\\programs\\startup\\",)

        if any_in(n_lower, TEMP_TOKENS):
            self._record_evidence(evidence, "location", 7, "TEMP", "Temp-like directory")
        if any_in(n_lower, DOWNLOAD_TOKENS):
            self._record_evidence(evidence, "location", 7, "DOWNLOADS", "Downloads directory")
        if any_in(n_lower, DESKTOP_TOKENS):
            self._record_evidence(evidence, "location", 5, "DESKTOP", "Desktop directory")
        if any_in(n_lower, PUBLIC_TOKENS):
            self._record_evidence(evidence, "location", 7, "PUBLIC", "Public user directory")
        if any_in(n_lower, RECYCLE_TOKENS):
            self._record_evidence(evidence, "location", 8, "RECYCLE", "$Recycle.Bin directory")
        if any_in(n_lower, STARTUP_TOKENS):
            self._record_evidence(evidence, "location", 8, "STARTUP", "Startup folder")

        # MAJOR: non-system or network
        if (re.match(r"^[d-z]:\\", n_lower) or n_lower.startswith("\\\\")) and not has_system_kf_prefix:
            self._record_evidence(
                evidence, "location", 7, "NONSYSTEM", "Non-system or network location")

        # MAJOR: generic non-system
        try:
            if not has_system_kf_prefix and not_system_path(n_norm):
                if "location" not in evidence:
                    self._record_evidence(evidence, "location", 5, "NONSYSTEM", "Non-system path")
        except Exception:
            pass

        ext = ext_name(n_lower)
        location_major_present = "location" in evidence

        is_non_system = False
        try:
            if not has_system_kf_prefix:
                is_non_system = not_system_path(n_norm)
        except Exception:
            pass

        if ext in (".ps1", ".psm1", ".vbs", ".js", ".jse", ".wsf", ".hta", ".bat", ".cmd"):
            # Scripts are major only when non-system/user-writable; otherwise minor
            if is_non_system or location_major_present:
                self._record_evidence(evidence, "payload_type", 6, "SCRIPT", "Script path")
            else:
                self._record_evidence(
                    evidence, "payload_type", 2, "SCRIPT", "Script path (system)")
        elif ext in (".exe",".dll",".com"):
            # UserAssist already means the executable was launched; an executable
            # extension is not an independent suspicious property.
            pass

        # Minor filename hints
        name_hints = []
        if re.search(r"[a-f0-9]{8,}", bn):
            name_hints.append("Hex-like name segment")
        ent = char_entropy(re.sub(r"[^a-z0-9]", "", bn))
        if len(bn) >= 6 and ent >= 4.0:
            name_hints.append("High-entropy basename")
        if name_hints:
            self._record_evidence(
                evidence, "name_shape", min(2, len(name_hints)), "NAME_SHAPE",
                "; ".join(name_hints))

        score, _, why = self._finish_evidence(evidence)
        return int(score), why



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

    
    def _indicator_from_flags(self, flags: list[str]) -> str:
        # order by importance; we’ll show at most 2
        priority = [
            "PublicNoPID", "AdminPortOutbound", "UnexpectedListener", "HighPortListener",
            "LOLBINOutbound", "BadPort", "UncommonPort", "ToSameRemote",
            "ConnBurst", "ManyConns", "UDPAnyHighPort", "LoopbackPair"
        ]
        display = {
            "PublicNoPID": "NOPID🌐",
            "AdminPortOutbound": "ADMIN↗",
            "UnexpectedListener": "SENS-LISTEN",
            "HighPortListener": "LISTEN↑",
            "LOLBINOutbound": "LOLBIN↗",
            "BadPort": "PORT⚠",
            "UncommonPort": "PORT?",
            "ToSameRemote": "FANOUT",
            "ConnBurst": "BURST",
            "ManyConns": "MANY",
            "UDPAnyHighPort": "UDP*↑",
            "LoopbackPair": "LOOP"
        }
        chosen = [display[f] for f in priority if f in (flags or [])]
        return ", ".join(chosen[:2]) if chosen else "—"


    @classmethod        
    def _score_map(cls, row: tuple, index: int) -> tuple:
        score = row[index]
        risk = cls._risk_from_score(score)
        row_list = list(row)
        row_list[index] = risk
        return tuple(row_list)

    @classmethod        
    def _risk_from_score(cls, s: int) -> str:
        for label, floor in cls.RISK_BANDS:
            if s >= floor:
                return label
        return "Low"

    def _threshold(self, surface: str) -> int:
        """Score a `surface` row must reach to be shown.

        The per-surface default, raised if the caller asked for a higher band.
        """
        base = self.SURFACE_THRESHOLDS.get(surface, 9)
        return max(base, self.MIN_RISK.get(self._min_risk, 0))

    def _keep(self, rows: List[Any], risk_index: int) -> List[Any]:
        """Filter already-labelled rows down to the requested minimum band."""
        floor = self.MIN_RISK.get(self._min_risk, 0)
        if floor <= 0:
            return rows
        allowed = {label for label, f in self.RISK_BANDS if f >= floor}
        return [r for r in rows if str(r[risk_index]) in allowed]

    @staticmethod
    def _ip_from_endpoint(value: Any) -> str:
        """Return a canonical IP from plain, bracketed, or host:port text."""
        text = str(value or "").strip()
        if not text or text in {"*", "0.0.0.0", "::"}:
            return text
        if text.startswith("[") and "]" in text:
            text = text[1:text.index("]")]
        text = text.split("%", 1)[0]  # IPv6 scope identifier
        try:
            return str(ipaddress.ip_address(text))
        except ValueError:
            pass
        # Some renderers combine IPv4 and port despite exposing a port column.
        if text.count(":") == 1:
            host, port = text.rsplit(":", 1)
            if port.isdigit():
                try:
                    return str(ipaddress.ip_address(host))
                except ValueError:
                    pass
        return ""

    @classmethod
    def _is_public_ip(cls, value: Any) -> bool:
        ip = cls._ip_from_endpoint(value)
        try:
            return ipaddress.ip_address(ip).is_global
        except ValueError:
            return False

    @staticmethod
    def _is_private_ip(ip: str) -> bool:
        try:
            return ipaddress.ip_address(ip).is_private
        except Exception:
            return True 

    @staticmethod        
    def _is_loopback(ip: str) -> bool:
        try:
            addr = ipaddress.ip_address(ip)
            return addr.is_loopback
        except Exception:
            return ip in {"::1"}
    
    @staticmethod        
    def _seems_pathlike(s: str) -> bool:
        if not s: return False
        ls = s.lower()
        return (
            bool(re.match(r"^[a-z]:\\", ls)) or
            ls.startswith("\\??\\") or
            ("\\" in s and any(ext in ls for ext in (
                ".exe", ".dll", ".com", ".lnk", ".ps1", ".psm1", ".vbs",
                ".js", ".jse", ".wsf", ".hta", ".bat", ".cmd")))
        )

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
