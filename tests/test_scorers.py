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
