"""The forensic facts the scorers must keep getting right.

These assertions used to run against ``OverviewAnalysis._score_*``. That code is
gone -- the unified engine in ``volmemlyzer.scoring`` is the only scorer now --
so each one is re-pointed at ``score_records``, which is what actually decides
these verdicts today. The facts are unchanged; only the caller moved.

These rules surface signal for an analyst. They are not detections, and none of
these tests assert that something is or is not malicious -- only that the noisy
cases stay below the surfacing threshold and the distinctive ones clear it.
"""
from __future__ import annotations

import pytest

from volmemlyzer.analysis import OverviewAnalysis
from volmemlyzer.scoring import score_records
from volmemlyzer.scoring import heuristics as H
from volmemlyzer.utilities import is_suspicious_path


def hexdump(data: bytes) -> str:
    """Volatility's JSON form for a LayerData column: space-separated hex pairs."""
    return " ".join(f"{b:02x}" for b in data)


@pytest.fixture
def eng():
    return OverviewAnalysis()


# --- helpers that ask the engine the question a scorer used to be asked ------

def _score(records: dict, profile: dict | None = None) -> dict:
    return score_records(records, profile or {"preset": "balanced"})


def _objects(out: dict, object_type: str) -> list[dict]:
    return [o for o in out["scored_objects"] if o["object_type"] == object_type]


def _flags(out: dict, pid: int) -> set[str]:
    """Every rule that fired on a PID, superseded or not."""
    return set((out["process_risk"].get(pid) or {}).get("flags") or [])


def _score_of(out: dict, pid: int) -> float:
    return float((out["process_risk"].get(pid) or {}).get("score") or 0)


def _region(data: bytes, pid: int = 1000, **over) -> dict:
    row = {"PID": pid, "Process": "t.exe", "Protection": "PAGE_EXECUTE_READWRITE",
           "PrivateMemory": 1, "CommitCharge": 1, "Start VPN": 0x1000,
           "Hexdump": hexdump(data)}
    row.update(over)
    return row


def _malfind(*rows: dict, pid: int = 1000) -> dict:
    """malfind rows plus the census entry their PID needs.

    The engine attributes a region to the process that owns it, and a process it
    has never seen in pslist or psscan is not in the inventory at all -- so
    without this the flags come back empty for the wrong reason.
    """
    return {"pslist": [_proc(pid, "t.exe", 700)], "malfind": list(rows)}


def _proc(pid: int, name: str, ppid: int | None, path: str = "") -> dict:
    return {"PID": pid, "PPID": ppid, "ImageFileName": name, "Wow64": False,
            **({"Path": path} if path else {})}


def _cmd(pid: int, path: str) -> dict:
    return {"PID": pid, "Args": path}


SYS = "C:\\Windows\\System32"


# --------------------------------------------------------------------------
# malfind: what separates an injected region from a JIT allocation
# --------------------------------------------------------------------------

def test_an_unreadable_region_does_not_take_the_step_down():
    """Volatility writes the literal "N/A" when it could not read the region."""
    out = _score(_malfind(_region(b"", Hexdump="N/A", Protection="PAGE_NOACCESS")))
    assert _flags(out, 1000) == set()


@pytest.mark.parametrize("value", ["", "N/A", "not hex at all"])
def test_a_missing_hexdump_is_not_an_error(value):
    assert H.hexdump_to_bytes(value) == b""


def test_a_real_hexdump_round_trips():
    assert H.hexdump_to_bytes(hexdump(b"MZ\x90\x00")) == b"MZ\x90\x00"


def test_an_empty_region_is_not_a_finding():
    """Volatility reports plenty of these; they were scored as if they held code."""
    out = _score(_malfind(_region(b"\x00" * 64)))
    assert "malfind_pe_header" not in _flags(out, 1000)
    assert "malfind_shellcode" not in _flags(out, 1000)


@pytest.mark.parametrize("data,rule", [
    (b"MZ\x90\x00" + b"\x41" * 60, "malfind_pe_header"),
    (b"\x90" * 16 + b"\xcc" * 48, "malfind_shellcode"),
    (b"\xfc\xe8\x8f\x00\x00\x00" + b"\x60" * 58, "malfind_shellcode"),
])
def test_distinctive_region_contents_surface(data, rule):
    out = _score(_malfind(_region(data)))
    assert rule in _flags(out, 1000)
    assert _objects(out, "process"), "a region with a payload signature must surface"


def test_scoring_does_not_depend_on_capstone():
    """Capstone is an optional extra, so the Disasm column may be assembly text or
    a byte dump depending on the install. Scoring must not change either way."""
    data = b"MZ\x90\x00" + b"\x41" * 60
    with_asm = _score(_malfind(_region(
        data, Disasm="\n0x0:\tpush\tebp\n0x1:\tmov\tebp, esp")))
    without = _score(_malfind(_region(data, Disasm="4d 5a 90 00")))
    assert _flags(with_asm, 1000) == _flags(without, 1000)
    assert _score_of(with_asm, 1000) == _score_of(without, 1000)


@pytest.mark.parametrize("data,label", [
    # PID 5292, SearchHost.exe: mov rax,imm64 / jmp rax trampolines, cc padding.
    (bytes.fromhex("48b800000010 9a01000048ffe0cccccc48b800100010 9a01000048ffe0cccccc"
                   .replace(" ", "")), "mov rax,imm64 / jmp rax trampolines"),
    # PID 5292: an ordinary x64 prologue spilling its arguments.
    (bytes.fromhex("48895424104889 4c24084c89442418 4c894c2420488b4128488b4808488b5150"
                   .replace(" ", "")), "an ordinary x64 prologue"),
    # PID 3768, powershell.exe: a table of heap pointers, not code at all.
    (bytes.fromhex("000000000000000010773a286902000010773a2869020000"
                   "00003a2869020000b00dd02969020000"), "a table of heap pointers"),
])
def test_ordinary_private_executable_regions_do_not_surface(data, label):
    """A JIT engine produces these by the dozen in every browser and .NET host."""
    fired = _flags(_score(_malfind(_region(data))), 1000)
    assert not (fired - {"malfind_rwx_private"}), f"{label} fired {fired}"


def test_the_protection_flags_alone_never_reach_a_payload_verdict():
    """Otherwise every malfind row surfaces, since malfind only reports these."""
    fired = _flags(_score(_malfind(_region(b"\x33\xc0" + b"\x90" * 4 + b"\x11" * 58))), 1000)
    assert fired == {"malfind_rwx_private"}


def test_a_peb_walk_needs_more_than_a_pair_of_field_accesses():
    """Compiled code reaches structure fields the same way; two is meaningless.

    The original threshold was two, and the merged engine raised it to three
    after two -- one of which is the two-byte ``8b 36`` -- fired on ordinary
    compiled functions. The fact under test is unchanged: one field read is not
    a walk.
    """
    assert H.walks_peb_loader_lists(bytes.fromhex("8b400c") + b"\x00" * 32) is False
    assert H.walks_peb_loader_lists(bytes.fromhex("8b400c8b701c")) is False
    assert H.walks_peb_loader_lists(bytes.fromhex("8b400c8b701c8b4608")) is True


def test_small_pushed_constants_are_not_read_as_hashes():
    """push 0x10, push 0x100 -- lengths and flags, mostly zero bytes."""
    assert H.api_hash_pushes(bytes.fromhex("6810000000") * 3) == 0
    assert H.api_hash_pushes(bytes.fromhex("68b2f2e2f4")) == 1


def test_the_shellcode_region_surfaces():
    """PID 2580, malware.exe: the PEB->Ldr walk followed by a pushed API hash."""
    shellcode = bytes.fromhex(
        "558bec81c4e8feffff6083ec04832424001e0fa01f33c040d1e040c1e0048b001f"
        "8b400c8b701c33c98b46088b7e208b3666394f1875f268b2f2e2f46832749100")
    out = _score(_malfind(_region(shellcode, CommitCharge=2)))
    assert "malfind_peb_walk" in _flags(out, 1000)
    assert _objects(out, "process"), "the shellcode region must reach the table"


# --------------------------------------------------------------------------
# process census
# --------------------------------------------------------------------------

def _boot(*extra: dict) -> dict:
    procs = [
        _proc(4, "System", None), _proc(400, "smss.exe", 4),
        _proc(500, "csrss.exe", 400), _proc(600, "wininit.exe", 400),
        _proc(700, "services.exe", 600), _proc(800, "lsass.exe", 600),
        _proc(900, "svchost.exe", 700), _proc(1000, "RuntimeBroker.exe", 900),
        _proc(1100, "ApplicationFrameHost.exe", 900),
    ]
    cmds = [_cmd(p["PID"], f"{SYS}\\{p['ImageFileName']}") for p in procs if p["PID"] != 4]
    return {"pslist": procs + list(extra), "cmdline": cmds}


def test_a_normal_windows_boot_produces_no_findings():
    """The false-positive guard. If this fails, fix the rule, not the test."""
    out = _score(_boot())
    assert _objects(out, "process") == [], (
        f"the operating system booting normally was flagged: "
        f"{[o['label'] for o in _objects(out, 'process')]}")


def test_services_exe_under_wininit_is_not_a_finding():
    """It used to score 8 with a rationale claiming a suspicious path."""
    out = _score(_boot())
    assert _flags(out, 700) == set()


def test_pid_zero_is_the_kernel_root_not_an_orphan(eng):
    census = eng._build_census([_proc(4, "System", 0)], [])
    eng._scored = {"process_risk": {}}
    assert eng._census_summary(census, psscan=None, psxview=None)["orphans"] == 0


def test_a_live_process_only_pool_scan_can_see_surfaces():
    """psscan sees it, pslist does not, and it carries no exit time."""
    recs = _boot()
    recs["psscan"] = [{"PID": 6666, "PPID": 700, "ImageFileName": "x.exe", "ExitTime": None}]
    assert "hidden_process" in _flags(_score(recs), 6666)


def test_a_terminated_process_is_ordinary_churn():
    """Every image has dozens of these; they must not read like hidden processes."""
    recs = _boot()
    recs["psscan"] = [{"PID": 6666, "PPID": 700, "ImageFileName": "x.exe",
                       "ExitTime": "2024-01-01T00:00:00"}]
    assert "hidden_process" not in _flags(_score(recs), 6666)


def test_a_system_name_outside_a_system_path_surfaces():
    recs = _boot(_proc(1234, "svchost.exe", 900))
    recs["cmdline"].append(_cmd(1234, "C:\\Users\\alice\\AppData\\Local\\Temp\\svchost.exe"))
    assert "core_proc_wrong_path" in _flags(_score(recs), 1234)


def test_a_near_miss_system_name_surfaces():
    recs = _boot(_proc(1234, "svch0st.exe", 900))
    recs["cmdline"].append(_cmd(1234, f"{SYS}\\svch0st.exe"))
    assert "core_proc_masquerade_name" in _flags(_score(recs), 1234)


def test_a_singleton_running_twice_surfaces():
    recs = _boot(_proc(1234, "lsass.exe", 600))
    recs["cmdline"].append(_cmd(1234, f"{SYS}\\lsass.exe"))
    assert "core_proc_illegal_instances" in _flags(_score(recs), 1234)


def test_one_psxview_disagreement_is_not_enough():
    """A process that has exited is legitimately absent from one source."""
    recs = _boot()
    recs["psxview"] = [{"PID": 900, "pslist": True, "psscan": True,
                        "thrdscan": False, "csrss": True}]
    assert "psxview_inconsistent" not in _flags(_score(recs), 900)


def test_two_psxview_disagreements_surface():
    recs = _boot()
    recs["psxview"] = [{"PID": 900, "pslist": False, "psscan": True,
                        "thrdscan": False, "csrss": True}]
    assert "psxview_inconsistent" in _flags(_score(recs), 900)


def test_wow64_false_is_not_read_as_a_discovery_disagreement():
    """The old rule swept every boolean column, Wow64 included."""
    recs = _boot()
    recs["psxview"] = [{"PID": 900, "pslist": True, "psscan": True, "thrdscan": True,
                        "csrss": True, "Wow64": False}]
    assert "psxview_inconsistent" not in _flags(_score(recs), 900)


def test_a_discovery_disagreement_cannot_surface_a_process_on_its_own():
    """thrdscan and csrss legitimately miss many live processes.

    Against the reference image this rule alone accounted for 18 of 25 surfaced
    rows, so it corroborates but never surfaces by itself.
    """
    recs = {"pslist": [_proc(900, "svchost.exe", 700)],
            "psxview": [{"PID": 900, "pslist": False, "psscan": False,
                         "thrdscan": False, "csrss": True}]}
    out = _score(recs)
    assert "psxview_inconsistent" in _flags(out, 900)
    assert _objects(out, "process") == []


# --------------------------------------------------------------------------
# census construction (orchestration, not scoring -- still OverviewAnalysis')
# --------------------------------------------------------------------------

def test_the_census_reaches_processes_nested_in_the_tree(eng):
    """pstree nests descendants under __children; only roots used to be read, so
    the path Volatility supplies never reached any path-based rule."""
    tree = [{"PID": 4, "PPID": 0, "ImageFileName": "System", "Path": None, "__children": [
        {"PID": 400, "PPID": 4, "ImageFileName": "smss.exe", "Path": f"{SYS}\\smss.exe",
         "__children": [
             {"PID": 500, "PPID": 400, "ImageFileName": "csrss.exe",
              "Path": f"{SYS}\\csrss.exe", "__children": []}]}]}]
    pslist = [{"PID": p, "PPID": q, "ImageFileName": n}
              for p, q, n in [(4, 0, "System"), (400, 4, "smss.exe"), (500, 400, "csrss.exe")]]
    census = eng._build_census(pslist, tree)
    assert census[500]["path"] == f"{SYS}\\csrss.exe"


def test_a_null_image_name_does_not_raise(eng):
    census = eng._build_census([{"PID": 9, "PPID": 1, "ImageFileName": None}], [])
    assert census[9]["name"] == ""


def test_the_command_line_stands_in_when_there_is_no_path(eng):
    tree = [{"PID": 7, "PPID": 1, "ImageFileName": "x.exe", "Path": None,
             "Cmd": "C:\\Users\\u\\Downloads\\x.exe -q", "__children": []}]
    census = eng._build_census([{"PID": 7, "PPID": 1, "ImageFileName": "x.exe"}], tree)
    assert "Downloads" in census[7]["path"]


# --------------------------------------------------------------------------
# paths
# --------------------------------------------------------------------------

@pytest.mark.parametrize("path", [
    "C:\\Windows\\System32\\svchost.exe",
    "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",
    "C:\\Program Files (x86)\\Thing\\thing.exe",
    "C:\\Users\\alice\\AppData\\Local\\Programs\\Microsoft VS Code\\Code.exe",
    "C:\\Users\\alice\\AppData\\Local\\Microsoft\\Teams\\current\\Teams.exe",
])
def test_software_where_software_lives_is_not_suspicious(path):
    assert is_suspicious_path(path) is False


@pytest.mark.parametrize("path", [
    "C:\\Users\\alice\\AppData\\Local\\Temp\\x.exe",
    "C:\\Users\\alice\\Downloads\\invoice.exe",
    "C:\\Users\\Public\\a.exe",
    "C:\\Windows\\Temp\\x.exe",
    "C:\\$Recycle.Bin\\S-1-5-21\\x.exe",
])
def test_user_writable_scratch_space_is_suspicious(path):
    assert is_suspicious_path(path) is True


def test_an_empty_path_is_not_suspicious():
    assert is_suspicious_path("") is False


# --------------------------------------------------------------------------
# the ladder itself -- the --min-risk / --high-level CLI contract
#
# The ladder now has one definition, the tuning profile. These pin that the CLI
# flag still means what it meant when OverviewAnalysis owned its own copy.
# --------------------------------------------------------------------------

@pytest.mark.parametrize("score,band", [
    (0, "Low"), (8, "Low"), (9, "Medium"), (13, "Medium"),
    (14, "High"), (19, "High"), (20, "Critical"), (99, "Critical"),
])
def test_the_ladder_maps_scores_to_bands(eng, score, band):
    assert eng._tuning.band(score) == band


OBJECT_TYPES = ("process", "connection", "persistence", "kernel")


def test_min_risk_raises_every_threshold():
    low, high = OverviewAnalysis("low"), OverviewAnalysis("high")
    for object_type in OBJECT_TYPES:
        assert high._threshold(object_type) >= low._threshold(object_type)
        assert high._threshold(object_type) >= high._tuning.risk_bands["high"]


def test_min_risk_admits_exactly_the_bands_at_or_above_it():
    """The floor --min-risk names is the band floor, so nothing below it shows."""
    high = OverviewAnalysis("high")
    assert high._min_risk_floor() == high._tuning.risk_bands["high"]
    for object_type in OBJECT_TYPES:
        floor = high._threshold(object_type)
        assert high._tuning.band(floor) == "High"
        assert high._tuning.band(floor - 1) != "High"


def test_low_is_the_profile_threshold_and_never_raises_it():
    low = OverviewAnalysis("low")
    assert low._min_risk_floor() == 0
    for object_type in OBJECT_TYPES:
        assert low._threshold(object_type) == low._tuning.surface_threshold(object_type)


def test_high_level_is_the_same_knob_as_min_risk_high():
    eng = OverviewAnalysis()
    eng._min_risk = "high"
    for object_type in OBJECT_TYPES:
        assert eng._threshold(object_type) == OverviewAnalysis("high")._threshold(object_type)


def test_the_ladder_has_one_definition():
    """OverviewAnalysis reports the engine's ceiling rather than its own copy."""
    from volmemlyzer.scoring import MAX_RISK_SCORE
    assert OverviewAnalysis.MAX_RISK_SCORE == MAX_RISK_SCORE


# --------------------------------------------------------------------------
# network attribution and independent corroboration
# --------------------------------------------------------------------------

def _connection(**over) -> dict:
    row = {"State": "ESTABLISHED", "Proto": "TCPv4",
           "LocalAddr": "10.0.0.5", "LocalPort": 50000,
           "ForeignAddr": "8.8.8.8", "ForeignPort": 443, "Owner": "", "PID": None}
    row.update(over)
    return row


def _conn_flags(out: dict) -> set[str]:
    return {c["rule_id"] for o in _objects(out, "connection") for c in o["contributions"]}


def test_public_connection_without_pid_is_context_not_a_finding():
    """Missing attribution is an evidence-quality warning, not a threat behaviour.

    It surfaces as Low on its own -- the engine lets a lone severity-4 signal
    reach the table -- but it must not be joined by a behavioural rule it did
    not earn.
    """
    out = _score({"netscan": [_connection()]})
    assert _conn_flags(out) == {"net_public_no_pid"}


def test_unattributed_public_admin_connection_has_independent_corroboration():
    out = _score({"netscan": [_connection(ForeignPort=445)]})
    assert {"net_public_no_pid", "net_admin_port_outbound"} <= _conn_flags(out)


def test_a_private_destination_is_not_a_public_connection():
    assert _conn_flags(_score({"netscan": [_connection(ForeignAddr="10.0.0.9")]})) == set()


def test_a_known_implant_port_surfaces():
    assert "net_bad_port" in _conn_flags(_score({"netscan": [_connection(ForeignPort=4444)]}))


# --------------------------------------------------------------------------
# scheduled tasks, against rows taken from a real Windows 10 image
#
# The machine these came from surfaced 286 of its 323 scheduled tasks as
# indicators. Almost all of them were Windows' own maintenance tasks, flagged
# because "%windir%\system32\..." could not be resolved on the analysis host and
# so read as a non-system path.
# --------------------------------------------------------------------------

def _task(name, action, args="", trigger="", principal="", enabled=True) -> dict:
    return {"Task Name": name, "Action": action, "Action Arguments": args,
            "Trigger Type": trigger, "Principal ID": principal, "Enabled": enabled}


def _persist_flags(out: dict) -> set[str]:
    return {c["rule_id"] for o in _objects(out, "persistence") for c in o["contributions"]}


STOCK_TASKS = [
    _task("PcaWallpaperAppDetect", "%windir%\\system32\\rundll32.exe",
          "%windir%\\system32\\PcaSvc.dll,PcaWallpaperAppDetect", "Time", "Users"),
    _task("PcaPatchDbTask", "%windir%\\system32\\rundll32.exe",
          "%windir%\\system32\\PcaSvc.dll,PcaPatchSdbTask", "Time"),
    _task("Pre-staged app cleanup", "%windir%\\system32\\rundll32.exe",
          "%windir%\\system32\\AppxDeploymentClient.dll,AppxPreStageCleanupRunTask", "Logon"),
    _task("Proxy", "%windir%\\system32\\rundll32.exe",
          "/d acproxy.dll,PerformAutochkOperations", "Boot"),
    _task("BfeOnServiceStartTypeChange", "%windir%\\system32\\rundll32.exe",
          "bfe.dll,BfeOnServiceStartTypeChange"),
    _task("Recovery-Check", "%SystemRoot%\\System32\\dsregcmd.exe",
          "/checkrecovery", "Logon", "InteractiveUsers"),
    _task("StartupAppTask", "%windir%\\system32\\rundll32.exe",
          "Startupscan.dll,SusRunTask", "", "Users", enabled=False),
    _task("Automatic-Device-Join", "%SystemRoot%\\System32\\dsregcmd.exe",
          "$(Arg0) $(Arg1) $(Arg2)", "Logon"),
]


@pytest.mark.parametrize("row", STOCK_TASKS, ids=lambda r: r["Task Name"])
def test_windows_own_maintenance_tasks_do_not_surface(row):
    out = _score({"scheduled_tasks": [row]})
    assert _objects(out, "persistence") == [], (
        f"{row['Task Name']} would be tabled")


def test_a_per_user_vendor_updater_does_not_surface():
    """OneDrive genuinely installs under LocalAppData and updates on a schedule."""
    row = _task("OneDrive Reporting Task-S-1-5-21-2515051972",
                "%localappdata%\\Microsoft\\OneDrive\\OneDriveStandaloneUpdater.exe",
                "", "Time")
    assert _objects(_score({"scheduled_tasks": [row]}), "persistence") == []


@pytest.mark.parametrize("name,script", [
    ("LOG", "C:\\Workspace\\export_logs.ps1"),
    ("PID", "C:\\Workspace\\log_pid.ps1"),
    ("UTG", "C:\\Workspace\\UTG\\launch.ps1"),
])
def test_a_powershell_script_run_at_logon_surfaces(name, script):
    out = _score({"scheduled_tasks": [_task(name, "PowerShell", script, "Logon", "Author")]})
    assert "scheduled_task_suspicious" in _persist_flags(out)
    why = " ".join(c["evidence"] for o in _objects(out, "persistence")
                   for c in o["contributions"])
    assert "Script payload" in why


def test_an_encoded_powershell_task_surfaces():
    out = _score({"scheduled_tasks": [
        _task("Updater", "powershell.exe", "-nop -w hidden -enc SQBFAFgA", "Logon")]})
    assert "scheduled_task_suspicious" in _persist_flags(out)


def test_a_bits_transfer_task_surfaces():
    out = _score({"scheduled_tasks": [
        _task("Updater", "cmd.exe", "bitsadmin /transfer job https://example.test/a x")]})
    assert "scheduled_task_suspicious" in _persist_flags(out)


def test_a_task_is_identified_by_its_name():
    """One task is one object however many rules describe it."""
    out = _score({"scheduled_tasks": [
        _task("LOG", "PowerShell", "C:\\Workspace\\export_logs.ps1", "Logon")]})
    assert [o["key"] for o in _objects(out, "persistence")] == ["task:log"]


# --------------------------------------------------------------------------
# UserAssist: execution location is corroboration, not a verdict
# --------------------------------------------------------------------------

def _ua(name: str) -> dict:
    return {"userassist": [{"Name": name, "Type": "Value", "Count": 1}]}


@pytest.mark.parametrize("path", [
    "D:\\virtio-win-guest-tools.exe",
    "C:\\Users\\alice\\Downloads\\setup.exe",
    "C:\\Users\\alice\\AppData\\Local\\Temp\\updater.exe",
])
def test_userassist_location_alone_stays_below_the_surface_threshold(path):
    """Ordinary software is downloaded, unpacked and run from these directories."""
    out = _score(_ua(path))
    objs = _objects(out, "persistence")
    assert all(o["risk"] == "Low" for o in objs)
    assert all(o["score"] < out["profile"]["risk_bands"]["medium"] for o in objs)


def _ua_why(name: str) -> str:
    return " ".join(c["evidence"] for o in _objects(_score(_ua(name)), "persistence")
                    for c in o["contributions"])


@pytest.mark.parametrize("name", [
    "D:\\Packed\\pafish64.exe", "C:\\Users\\a\\Downloads\\mimikatz.exe",
    "D:\\tools\\nc.exe", "C:\\Temp\\PsExec64.exe", "D:\\seatbelt.exe",
])
def test_userassist_names_a_known_tool_as_one(name):
    """The tool is called out by name, not merely as a file in an odd place."""
    assert "Known offensive tool name" in _ua_why(name)


@pytest.mark.parametrize("name", [
    "D:\\Packed\\setup.exe", "C:\\Users\\a\\Downloads\\concat.exe",
    "D:\\incenter.exe",
])
def test_an_ordinary_name_is_not_read_as_a_tool(name):
    """Matched on the basename stem, so "nc" inside "concat" is not netcat."""
    assert "Known offensive tool name" not in _ua_why(name)


# --------------------------------------------------------------------------
# SSDT integrity (deep-only)
# --------------------------------------------------------------------------

def _ssdt(module: str, symbol: str = "NtOpenProcess", address: int = 0xFFFFF80000001000) -> dict:
    return {"ssdt": [{"Address": address, "Index": 1, "Module": module, "Symbol": symbol}]}


@pytest.mark.parametrize("module", [
    "ntoskrnl", "ntoskrnl.exe", "win32k.sys", "win32kbase.sys", "win32kfull.sys",
])
def test_expected_windows_ssdt_target_is_not_a_finding(module):
    assert _objects(_score(_ssdt(module)), "kernel") == []


def test_foreign_ssdt_target_surfaces():
    out = _score(_ssdt("thirdparty.sys"))
    objs = _objects(out, "kernel")
    assert objs and objs[0]["contributions"][0]["rule_id"] == "ssdt_foreign_module"
    assert "thirdparty.sys" in objs[0]["contributions"][0]["evidence"]


def test_unresolved_ssdt_target_is_unknown_not_a_hook():
    assert _objects(_score({"ssdt": [{"Module": "N/A", "Symbol": "", "Address": None}]}),
                    "kernel") == []


def test_an_ssdt_finding_records_the_module_it_resolved_to():
    """Step 5 groups by target module, so it must not parse it out of the prose."""
    objs = _objects(_score(_ssdt("thirdparty.sys")), "kernel")
    assert objs[0]["contributions"][0]["subject"] == "thirdparty.sys"


def test_ssdt_is_only_scheduled_for_deep_kernel_analysis(eng):
    assert eng._plugins_for([5], deep=False) == []
    assert eng._plugins_for([5], deep=True) == ["ssdt"]


# --------------------------------------------------------------------------
# path classification must not depend on the machine running the analysis
# --------------------------------------------------------------------------

@pytest.mark.parametrize("path,expected", [
    ("%windir%\\system32\\rundll32.exe", False),
    ("%SystemRoot%\\System32\\dsregcmd.exe", False),
    ("%ProgramFiles%\\Thing\\thing.exe", False),
    ("%ProgramData%\\Thing\\thing.exe", False),
    ("%LOCALAPPDATA%\\Temp\\evil.exe", True),
    ("C:\\Workspace\\export_logs.ps1", True),
])
def test_windows_variables_resolve_without_a_windows_host(path, expected):
    """%windir% has no meaning in the environment of a macOS or Linux analyst, so
    resolving it from os.environ made the verdict depend on the analysis host."""
    from volmemlyzer.utilities import not_system_path
    assert not_system_path(path) is expected


def test_the_host_environment_cannot_change_the_verdict(monkeypatch):
    from volmemlyzer.utilities import not_system_path
    before = not_system_path("%windir%\\system32\\rundll32.exe")
    for var, value in [("WINDIR", "E:\\Windows"), ("SystemRoot", "E:\\Windows"),
                       ("SystemDrive", "E:"), ("ProgramFiles", "E:\\Program Files")]:
        monkeypatch.setenv(var, value)
    assert not_system_path("%windir%\\system32\\rundll32.exe") == before


# --------------------------------------------------------------------------
# the region a malfind finding came from
#
# The engine scores a process, not each of its regions, but step 2 reports one
# row per region -- so a contribution has to say which region it read, or the
# step has to re-derive it and becomes a second scorer.
# --------------------------------------------------------------------------

def test_a_malfind_contribution_records_the_region_it_read():
    out = _score(_malfind(_region(b"MZ\x90\x00" + b"\x41" * 60, **{"Start VPN": 0x7ffd000})))
    proc = _objects(out, "process")[0]
    assert {c["subject"] for c in proc["contributions"]} == {str(0x7ffd000)}


def test_every_region_of_a_process_is_recorded_even_when_outscored():
    """Six RWX regions in one process are six observations and one score.

    Family dedup decides what counts toward the score, not what was seen. If the
    superseded ones were dropped, step 2 would show one region and silently hide
    the other five -- which is what the reference image's SearchHost.exe does.
    """
    starts = [0x1000, 0x2000, 0x3000, 0x4000, 0x5000, 0x6000]
    rows = [_region(b"\x33\xc0" + b"\x11" * 62, **{"Start VPN": s}) for s in starts]
    proc = _objects(_score(_malfind(*rows)), "process")[0]
    rwx = [c for c in proc["contributions"] if c["rule_id"] == "malfind_rwx_private"]
    assert {c["subject"] for c in rwx} == {str(s) for s in starts}
    assert len([c for c in rwx if not c["superseded"]]) == 1
