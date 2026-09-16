"""The unified scoring engine: family dedup, the bounded ladder, calibration.

These cover the properties the merge introduced, not the individual rules —
the per-rule behaviour is exercised by test_scorers.py against the same
catalog.
"""
import pytest

from volmemlyzer.scoring import MAX_RISK_SCORE, score_records
from volmemlyzer.scoring.catalog import default_rules
from volmemlyzer.scoring.heuristics import (
    api_hash_pushes,
    ssdt_foreign_module,
    walks_peb_loader_lists,
)


def _obj(out, object_type="process"):
    return next(o for o in out["scored_objects"] if o["object_type"] == object_type)


def _contrib(obj, rule_id):
    return next(c for c in obj["contributions"] if c["rule_id"] == rule_id)


# --- family dedup --------------------------------------------------------

def test_one_fact_seen_two_ways_is_counted_once():
    """A binary under %TEMP% trips both location rules.

    Summing them put a single misplaced file ahead of an object carrying two
    genuinely independent signals, which is what the hypothesis families fix.
    Both observations are still reported; only the stronger one scores.
    """
    records = {
        "pslist": [{"PID": 900, "PPID": 600, "ImageFileName": "svchost.exe"}],
        "cmdline": [{"PID": 900, "Process": "svchost.exe",
                     "Args": r"C:\Users\v\AppData\Local\Temp\svchost.exe"}],
    }
    obj = _obj(score_records(records))

    strong = _contrib(obj, "core_proc_wrong_path")
    weak = _contrib(obj, "suspicious_process_path")
    assert strong["family"] == weak["family"] == "location"
    assert strong["superseded"] is False
    assert weak["superseded"] is True
    # The score is the surviving observation alone, not the sum of the two.
    assert obj["score"] == pytest.approx(strong["weight"])


def test_independent_families_still_add_up():
    """Dedup must not flatten genuinely separate evidence."""
    records = {
        "pslist": [{"PID": 900, "PPID": 600, "ImageFileName": "svchost.exe"}],
        "cmdline": [{"PID": 900, "Process": "svchost.exe",
                     "Args": r"C:\Users\v\AppData\Local\Temp\svchost.exe"}],
        "malfind": [{"PID": 900, "Process": "svchost.exe", "Start VPN": 4096,
                     "Protection": "PAGE_EXECUTE_READWRITE", "PrivateMemory": 1,
                     "Hexdump": "4d 5a 90 00 03 00 00 00"}],
    }
    obj = _obj(score_records(records))
    scoring = {c["family"] for c in obj["contributions"] if not c["superseded"]}
    assert {"location", "memory_shape", "payload"} <= scoring
    assert obj["score"] > 14  # independent families lift it past one signal


def test_the_ladder_is_bounded():
    rules = default_rules()
    assert MAX_RISK_SCORE == 30
    # No single rule can carry an object to the top of the ladder on its own;
    # the band has to be earned by independent families.
    assert max(r.base_weight for r in rules) < MAX_RISK_SCORE


# --- calibration ---------------------------------------------------------

def test_context_rules_corroborate_but_never_surface_alone():
    """An ephemeral listener plus a busy socket count is what a browser looks
    like. Before the calibration those two cleared the floor by themselves."""
    records = {
        "pslist": [{"PID": 1500, "PPID": 900, "ImageFileName": "chrome.exe"}],
        "netscan": [
            {"PID": 1500, "Owner": "chrome.exe", "Proto": "TCPv4", "State": "LISTENING",
             "LocalAddr": "192.168.1.10", "LocalPort": 51000},
        ] + [
            {"PID": 1500, "Owner": "chrome.exe", "Proto": "TCPv4", "State": "ESTABLISHED",
             "LocalAddr": "192.168.1.10", "LocalPort": 50000 + i,
             "ForeignAddr": "93.184.216.34", "ForeignPort": 443}
            for i in range(12)
        ],
    }
    out = score_records(records)
    assert not [o for o in out["scored_objects"] if o["object_type"] == "connection"]


def test_every_rule_declares_a_family_and_a_technique():
    """The blanket-technique regression: a verdict may only carry ATT&CK ids
    that the rules which fired actually supplied."""
    for rule in default_rules():
        assert rule.hypothesis, rule.id
        assert rule.technique_id.startswith("T"), rule.id
        assert rule.technique_name, rule.id


# --- ported byte-level primitives ---------------------------------------

def test_api_hashing_no_longer_fires_on_text():
    """0x68 is ASCII 'h'. Two links in a region used to read as API hashing."""
    assert api_hash_pushes(b"see http://a.example and http://b.example now") == 0
    # Non-ASCII immediates with three distinct bytes are the real shape.
    assert api_hash_pushes(b"\x68\x4c\x77\x26\x07\x68\xe5\x53\xa4\x1b") == 2


def test_peb_walk_needs_more_than_a_pair_of_struct_reads():
    two = b"\x8b\x40\x0c" + b"\x00" * 8 + b"\x8b\x36"
    assert walks_peb_loader_lists(two) is False
    three = two + b"\x00" * 4 + b"\x8b\x7e\x20"
    assert walks_peb_loader_lists(three) is True


@pytest.mark.parametrize("module,foreign", [
    (r"\SystemRoot\system32\ntoskrnl.exe", False),
    ("win32kbase.sys", False),
    (r"C:\drivers\rootkit.sys", True),
    ("", False),  # unresolved attribution is missing data, not a hook
])
def test_ssdt_baseline(module, foreign):
    assert ssdt_foreign_module(module) is foreign


def test_ssdt_entries_are_scored_as_kernel_objects():
    records = {"ssdt": [
        {"Symbol": "NtOpenProcess", "Module": r"C:\drivers\rootkit.sys", "Address": 0xFFFF1234},
        {"Symbol": "NtClose", "Module": "ntoskrnl.exe", "Address": 0xFFFF5678},
        {"Symbol": "NtReadFile", "Module": "", "Address": 0},
    ]}
    out = score_records(records)
    kernel = [o for o in out["scored_objects"] if o["object_type"] == "kernel"]
    assert len(kernel) == 1
    assert "rootkit.sys" in kernel[0]["contributions"][0]["evidence"]
    assert kernel[0]["techniques"] == ["T1014"]
