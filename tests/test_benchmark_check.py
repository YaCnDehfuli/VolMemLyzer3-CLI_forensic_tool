"""Threshold checks for the extract benchmark must fail on drift."""
from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "benchmarks" / "run_benchmark.py"


def _load():
    spec = importlib.util.spec_from_file_location("run_benchmark", SCRIPT)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _payload(serial=2.0, parallel=1.0, warm=0.2, plugins=10, n_ok=3, n_failed=0):
    def block(median):
        return {
            "n_ok": n_ok,
            "n_failed": n_failed,
            "wall_s": {"median": median, "min": median, "max": median, "n": n_ok},
        }
    return {
        "plugin_count": plugins,
        "summary": {
            "serial": block(serial),
            "parallel": block(parallel),
            "cache_warm": block(warm),
        },
    }


THRESHOLDS = {
    "min_runs_per_config": 3,
    "plugin_count": 10,
    "max_serial_median_s": 60.0,
    "max_parallel_over_serial": 1.25,
    "max_cache_warm_over_serial": 0.5,
    "require_all_runs_ok": True,
}


def test_check_passes_on_a_healthy_stub_shape():
    bench = _load()
    assert bench._check(_payload(), THRESHOLDS) == []


def test_check_fails_when_plugin_count_drifts():
    bench = _load()
    errors = bench._check(_payload(plugins=9), THRESHOLDS)
    assert any("plugin_count" in e for e in errors)


def test_check_fails_when_parallel_is_slower_than_serial():
    bench = _load()
    errors = bench._check(_payload(serial=1.0, parallel=2.0), THRESHOLDS)
    assert any("parallel" in e for e in errors)


def test_check_fails_when_cache_warm_is_not_cheaper():
    bench = _load()
    errors = bench._check(_payload(serial=1.0, warm=0.9), THRESHOLDS)
    assert any("cache-warm" in e for e in errors)


def test_check_fails_when_a_run_is_missing():
    bench = _load()
    errors = bench._check(_payload(n_ok=2), THRESHOLDS)
    assert any("successful runs" in e for e in errors)


def test_pinned_plugins_match_yaml_and_threshold():
    bench = _load()
    yaml_plugins = bench._load_plugin_list(ROOT / "benchmarks" / "plugins.yaml")
    assert yaml_plugins == bench.PINNED_PLUGINS
    thresholds = json.loads((ROOT / "benchmarks" / "ci_thresholds.json").read_text(encoding="utf-8"))
    assert thresholds["plugin_count"] == len(bench.PINNED_PLUGINS)
    assert len(bench.PINNED_PLUGINS) == 10
