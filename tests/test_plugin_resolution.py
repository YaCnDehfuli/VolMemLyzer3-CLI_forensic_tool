"""Plugin names must be looked up, not constructed.

Volatility resolves what you type by substring against its full plugin names, so
"windows.pslist" happens to find "windows.pslist.PsList". That stops working in
two ways: a name that is a prefix of another ("windows.windows" is a substring of
"windows.windowstations") is rejected as ambiguous and never runs, and plugins
that move house ("windows.malfind" -> "windows.malware.malfind") keep working only
until their compatibility shim is deleted.
"""
from __future__ import annotations

import pytest

from volmemlyzer.core import PluginSpec
from volmemlyzer.extractor_registry import ExtractorRegistry
from volmemlyzer.pipeline import Pipeline
from volmemlyzer.runner import VolRunner


# A slice of a real `vol -h` listing, including both halves of each relocation.
CATALOGUE = [
    "windows.info.Info",
    "windows.pslist.PsList",
    "windows.psscan.PsScan",
    "windows.malfind.Malfind",
    "windows.malware.malfind.Malfind",
    "windows.psxview.PsXView",
    "windows.malware.psxview.PsXView",
    "windows.amcache.Amcache",
    "windows.registry.amcache.Amcache",
    "windows.windows.Windows",
    "windows.windowstations.WindowStations",
    "windows.shimcachemem.ShimcacheMem",
    "windows.skeleton_key_check.Skeleton_Key_Check",
    "windows.malware.skeleton_key_check.Skeleton_Key_Check",
]

match = VolRunner._match_plugin


# --------------------------------------------------------------------------
# name matching
# --------------------------------------------------------------------------

def test_a_short_name_finds_its_only_plugin():
    assert match("windows.pslist", (), CATALOGUE) == "windows.pslist.PsList"


def test_the_windows_plugin_is_ambiguous_without_a_candidate():
    # "windows.windows" is a substring of "windows.windowstations" too, which is
    # why this plugin has never actually run.
    assert match("windows.windows", (), CATALOGUE) is None


def test_a_candidate_disambiguates_the_windows_plugin():
    assert match("windows", ("windows.windows.Windows",), CATALOGUE) == "windows.windows.Windows"


@pytest.mark.parametrize("name,candidates,expected", [
    ("malfind", ("windows.malware.malfind.Malfind", "windows.malfind.Malfind"),
     "windows.malware.malfind.Malfind"),
    ("psxview", ("windows.malware.psxview.PsXView", "windows.psxview.PsXView"),
     "windows.malware.psxview.PsXView"),
    ("amcache", ("windows.registry.amcache.Amcache", "windows.amcache.Amcache"),
     "windows.registry.amcache.Amcache"),
    ("skeleton_key", ("windows.malware.skeleton_key_check.Skeleton_Key_Check",
                      "windows.skeleton_key_check.Skeleton_Key_Check"),
     "windows.malware.skeleton_key_check.Skeleton_Key_Check"),
])
def test_relocated_plugins_prefer_their_current_home(name, candidates, expected):
    """Not the deprecated shim that still answers to the old name."""
    assert match(name, candidates, CATALOGUE) == expected


def test_it_falls_back_to_the_shim_when_the_new_home_is_absent():
    older = [c for c in CATALOGUE if not c.startswith("windows.malware.")]
    got = match("malfind", ("windows.malware.malfind.Malfind", "windows.malfind.Malfind"), older)
    assert got == "windows.malfind.Malfind"


def test_an_unknown_plugin_resolves_to_nothing():
    assert match("windows.nosuchplugin", (), CATALOGUE) is None


def test_an_unreadable_catalogue_does_not_block_the_run():
    """`vol -h` failing must not stop us running; prefer the most current name."""
    assert match("malfind", ("windows.malware.malfind.Malfind",), []) == "windows.malware.malfind.Malfind"
    assert match("windows.pslist", (), []) == "windows.pslist"


# --------------------------------------------------------------------------
# the shipped table
# --------------------------------------------------------------------------

def test_every_registered_plugin_declares_where_it_lives():
    from volmemlyzer.plugins import build_registry
    missing = [s.name for s in build_registry().specs() if not s.candidates]
    assert missing == [], f"these still rely on a constructed name: {missing}"


def test_every_registered_plugin_resolves_against_the_catalogue_it_names():
    """Each declared name must be well-formed enough to match itself."""
    from volmemlyzer.plugins import build_registry
    specs = build_registry().specs()
    catalogue = [s.candidates[0] for s in specs]
    for s in specs:
        assert match(s.name, s.candidates, catalogue) == s.candidates[0], s.name


def test_the_windows_and_windowstations_entries_do_not_collide():
    from volmemlyzer.plugins import build_registry
    names = {s.name: s.candidates[0] for s in build_registry().specs()}
    assert names["windows"] == "windows.windows.Windows"
    assert names["windowstations"] == "windows.windowstations.WindowStations"


def test_scheduled_tasks_is_wired_to_its_own_extractor():
    """It used to be pointed at the netscan extractor by a copy-paste."""
    from volmemlyzer.plugins import PLUGIN_SPECIFICS
    by_name = {row[0]: row[1] for row in PLUGIN_SPECIFICS}
    assert by_name["scheduled_tasks"].__name__ == "extract_scheduled_tasks_features"
    assert by_name["netscan"].__name__ == "extract_netscan_features"


def test_extractors_with_dependencies_accept_the_context_they_are_given():
    """A dependency is passed as a keyword, so the extractor must accept one."""
    import inspect
    from volmemlyzer.plugins import PLUGIN_SPECIFICS
    for name, func, deps, *_ in PLUGIN_SPECIFICS:
        if not deps:
            continue
        params = inspect.signature(func).parameters.values()
        assert any(p.kind is inspect.Parameter.VAR_KEYWORD for p in params), (
            f"{name} declares deps {deps} but {func.__name__} takes no **kwargs")


# --------------------------------------------------------------------------
# preflight
# --------------------------------------------------------------------------

class _Runner:
    """Stands in for VolRunner with a fixed idea of what exists."""
    def __init__(self, available):
        self.available = set(available)

    def resolve_plugin(self, name, candidates=()):
        for c in candidates:
            if c in self.available:
                return c
        return None


def _registry(*names):
    reg = ExtractorRegistry()
    for n in names:
        reg.register(PluginSpec(name=n, fqname=f"windows.{n}", candidates=(f"windows.{n}.X",)),
                     lambda path, *, context: None)
    return reg


def test_preflight_drops_plugins_this_build_does_not_have():
    pipe = Pipeline(_Runner(["windows.pslist.X"]), _registry("pslist", "gonesoon"))
    assert pipe.preflight({"pslist", "gonesoon"}) == {"pslist"}


def test_preflight_says_why_a_plugin_was_skipped():
    pipe = Pipeline(_Runner([]), _registry("gonesoon"))
    pipe.preflight({"gonesoon"})
    assert "not available" in pipe.failed_plugins["gonesoon"]
