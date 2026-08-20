"""A slow plugin must not hold up the ones that do not depend on it.

The pipeline used to walk topological layers, opening a ThreadPoolExecutor per
layer and draining it before starting the next. One plugin that ran for hours --
psxview, in practice -- therefore held its layer's barrier shut and every
unrelated plugin waited behind it. These tests pin the replacement: a plugin
starts as soon as its own dependencies are done, and waits for nothing else.
"""
from __future__ import annotations

import threading
import time

import pytest

from volmemlyzer.core import PluginSpec
from volmemlyzer.extractor_registry import ExtractorRegistry
from volmemlyzer.pipeline import Pipeline


SLOW = 0.60      # stands in for a pool scanner
QUICK = 0.02


def _pipeline(specs):
    reg = ExtractorRegistry()
    for s in specs:
        reg.register(s, lambda path, *, context: None)
    return Pipeline(runner=None, registry=reg)


def _spec(name, deps=(), cost="fast"):
    return PluginSpec(name=name, fqname=f"windows.{name}", deps=tuple(deps),
                      candidates=(f"windows.{name}.X",), cost=cost)


def _timed_runner(durations):
    """Returns (run_one, finished) where finished records completion times."""
    start = time.perf_counter()

    def run_one(name):
        time.sleep(durations.get(name, QUICK))
        return name, time.perf_counter() - start

    return run_one


# --------------------------------------------------------------------------
# the regression this branch exists for
# --------------------------------------------------------------------------

def test_a_slow_plugin_does_not_delay_the_others():
    pipe = _pipeline([_spec("psxview", cost="heavy"), _spec("pslist"),
                      _spec("pstree"), _spec("malfind"), _spec("netscan")])
    done = {}
    pipe._run_graph(["psxview", "pslist", "pstree", "malfind", "netscan"],
                    _timed_runner({"psxview": SLOW}), concurrency=2,
                    on_done=lambda n, r: done.__setitem__(r[0], r[1]))

    others = [t for n, t in done.items() if n != "psxview"]
    assert len(done) == 5
    # Everything else is finished long before psxview is, on two workers.
    assert max(others) < done["psxview"] / 2


def test_a_slow_plugin_does_not_delay_a_later_independent_plugin():
    """The layer barrier used to make this wait; nothing here depends on psxview."""
    pipe = _pipeline([_spec("pslist"), _spec("psscan", deps=("pslist",)),
                      _spec("psxview", cost="heavy")])
    done = {}
    pipe._run_graph(["pslist", "psscan", "psxview"],
                    _timed_runner({"psxview": SLOW}), concurrency=3,
                    on_done=lambda n, r: done.__setitem__(r[0], r[1]))

    assert done["psscan"] < done["psxview"]


# --------------------------------------------------------------------------
# correctness the old scheduler also had, and must not lose
# --------------------------------------------------------------------------

def test_a_dependent_runs_only_after_its_dependency():
    pipe = _pipeline([_spec("pslist"), _spec("psscan", deps=("pslist",))])
    order = []
    pipe._run_graph(["psscan", "pslist"], lambda n: (n, None), concurrency=4,
                    on_done=lambda n, r: order.append(r[0]))
    assert order == ["pslist", "psscan"]


def test_context_from_a_dependency_is_available_to_its_dependent():
    """on_done must land before the dependent is submitted, not after."""
    pipe = _pipeline([_spec("pslist"), _spec("psscan", deps=("pslist",))])
    context = {}

    def run_one(name):
        if name == "psscan":
            assert "pslist" in context, "psscan started before pslist's context existed"
        return name, f"ctx-{name}"

    pipe._run_graph(["pslist", "psscan"], run_one, concurrency=4,
                    on_done=lambda n, r: context.__setitem__(r[0], r[1]))
    assert set(context) == {"pslist", "psscan"}


def test_a_dependency_outside_the_selection_does_not_deadlock():
    """Asking for psscan alone must run it, not wait forever for pslist."""
    pipe = _pipeline([_spec("pslist"), _spec("psscan", deps=("pslist",))])
    done = []
    pipe._run_graph(["psscan"], lambda n: (n, None), concurrency=2,
                    on_done=lambda n, r: done.append(r[0]))
    assert done == ["psscan"]


def test_every_selected_plugin_runs_exactly_once():
    names = [f"p{i}" for i in range(12)]
    pipe = _pipeline([_spec(n) for n in names])
    seen = []
    pipe._run_graph(names, lambda n: (n, None), concurrency=5,
                    on_done=lambda n, r: seen.append(r[0]))
    assert sorted(seen) == sorted(names)


# --------------------------------------------------------------------------
# ordering and isolation
# --------------------------------------------------------------------------

def test_sequential_runs_are_deterministic_and_heaviest_first():
    """Submission order is start order, so the long jobs go in first."""
    specs = [_spec("netscan", cost="scan"), _spec("info"),
             _spec("psxview", cost="heavy"), _spec("cmdline")]
    order = []
    _pipeline(specs)._run_graph(
        ["info", "cmdline", "netscan", "psxview"], lambda n: (n, None),
        concurrency=1, on_done=lambda n, r: order.append(r[0]))
    assert order == ["psxview", "netscan", "cmdline", "info"]


def test_the_heaviest_plugin_is_submitted_first_when_workers_are_scarce():
    specs = [_spec("psxview", cost="heavy")] + [_spec(f"f{i}") for i in range(4)]
    started = []
    lock = threading.Lock()

    def run_one(name):
        with lock:
            started.append(name)
        time.sleep(QUICK)
        return name, None

    _pipeline(specs)._run_graph(
        [s.name for s in specs], run_one, concurrency=1, on_done=lambda n, r: None)
    assert started[0] == "psxview"


def test_a_plugin_that_raises_does_not_abort_the_run():
    pipe = _pipeline([_spec("boom"), _spec("ok1"), _spec("ok2")])
    done = []

    def run_one(name):
        if name == "boom":
            raise RuntimeError("scanner exploded")
        return name, None

    pipe._run_graph(["boom", "ok1", "ok2"], run_one, concurrency=3,
                    on_done=lambda n, r: done.append(r[0]))

    assert sorted(done) == ["ok1", "ok2"]
    assert "scanner exploded" in pipe.failed_plugins["boom"]


def test_a_raising_dependency_still_releases_its_dependents():
    """A failed pslist leaves psscan with no context, which it already handles."""
    pipe = _pipeline([_spec("pslist"), _spec("psscan", deps=("pslist",))])
    done = []

    def run_one(name):
        if name == "pslist":
            raise RuntimeError("nope")
        return name, None

    pipe._run_graph(["pslist", "psscan"], run_one, concurrency=2,
                    on_done=lambda n, r: done.append(r[0]))
    assert done == ["psscan"]


def test_an_empty_selection_is_a_no_op():
    _pipeline([])._run_graph([], lambda n: None, concurrency=4, on_done=lambda n, r: None)


def test_a_dependency_cycle_is_reported():
    pipe = _pipeline([_spec("a", deps=("b",)), _spec("b", deps=("a",))])
    with pytest.raises(ValueError, match="cycle"):
        pipe._run_graph(["a", "b"], lambda n: (n, None), concurrency=2,
                        on_done=lambda n, r: None)


def test_concurrency_actually_overlaps_work():
    """Five 0.6s plugins on five workers must not take five times 0.6s."""
    names = [f"s{i}" for i in range(5)]
    pipe = _pipeline([_spec(n, cost="scan") for n in names])
    t0 = time.perf_counter()
    pipe._run_graph(names, _timed_runner({n: SLOW for n in names}), concurrency=5,
                    on_done=lambda n, r: None)
    assert time.perf_counter() - t0 < SLOW * 2


# --------------------------------------------------------------------------
# the analysis workflow feeds every step from one scheduled run
# --------------------------------------------------------------------------

class _RecordingPipe:
    """Counts how many times each plugin is actually asked for."""
    def __init__(self, names):
        self.registry = _pipeline([_spec(n) for n in names]).registry
        self.launches = []

    def _default_artifacts_dir(self, image_path):
        return "/tmp/does-not-matter"

    def run_plugin_raw(self, *, image_path, enable, renderer="json", outdir=None,
                       concurrency=1, use_cache=True, strict=False):
        from volmemlyzer.core import ActionResult
        self.launches.extend(sorted(enable))
        return ActionResult(artifacts={"plugins": {n: f"{outdir}/{n}.json" for n in enable}})


def test_the_steps_do_not_re_run_what_prefetch_already_collected():
    """A failed plugin leaves an unusable file, so a cache lookup would miss and
    the step would run the whole thing again just to fail the same way."""
    from volmemlyzer.analysis import OverviewAnalysis

    eng = OverviewAnalysis()
    pipe = _RecordingPipe(["pslist", "pstree", "psscan", "malfind"])
    eng._prefetch(pipe, "img.raw", "/out", steps=[1, 2], use_cache=True,
                  concurrency=4, deep=False)

    assert sorted(pipe.launches) == ["malfind", "pslist", "psscan", "pstree"]
    # malfind is what step 2 reads; it must come from the prefetch, not a new run.
    assert eng._ensure_one(pipe, "img.raw", "/out", "malfind", True) == "/out/malfind.json"
    assert sorted(pipe.launches) == ["malfind", "pslist", "psscan", "pstree"]


def test_prefetch_collects_every_requested_step_in_one_run():
    from volmemlyzer.analysis import OverviewAnalysis
    eng = OverviewAnalysis()
    names = ["info", "pslist", "pstree", "psscan", "malfind", "netscan",
             "registry.hivelist", "registry.hivescan", "scheduled_tasks",
             "registry.userassist"]
    pipe = _RecordingPipe(names)
    eng._prefetch(pipe, "img.raw", "/out", steps=[0, 1, 2, 3, 4], use_cache=True,
                  concurrency=4, deep=False)
    assert sorted(pipe.launches) == sorted(names)


def test_psxview_is_only_collected_with_deep():
    from volmemlyzer.analysis import OverviewAnalysis
    eng = OverviewAnalysis()
    assert "psxview" not in eng._plugins_for([1], deep=False)
    assert "psxview" in eng._plugins_for([1], deep=True)
