"""A plugin that cannot run must fail loudly, in one place, and only once.

These cover the path that produced `ValueError: Expected object or value` from
`pd.read_json`: Volatility exits non-zero, the output file was already created so
a zero-byte JSON is left behind, and every extractor then tried to parse it.
"""
from __future__ import annotations

import json
import os
import sys
import textwrap

import pytest

from volmemlyzer.core import PluginRunResult, PluginSpec
from volmemlyzer.extractors import _legacy_adapter, _usable_json
from volmemlyzer.runner import VolRunner


# --------------------------------------------------------------------------
# input validation shared by every extractor
# --------------------------------------------------------------------------

def test_missing_file_is_not_usable(tmp_path):
    ok, reason = _usable_json(str(tmp_path / "nope.json"))
    assert ok is False and "no output file" in reason


def test_empty_file_is_not_usable_and_says_the_plugin_failed(tmp_path):
    path = tmp_path / "empty.json"
    path.write_text("")
    ok, reason = _usable_json(str(path))
    assert ok is False and "empty" in reason and "failed" in reason


def test_blank_file_is_not_usable(tmp_path):
    path = tmp_path / "blank.json"
    path.write_text("\n   \n")
    ok, reason = _usable_json(str(path))
    assert ok is False and "blank" in reason


def test_non_json_output_is_reported_with_a_snippet(tmp_path):
    path = tmp_path / "text.json"
    path.write_text("Unable to validate the plugin requirements: ['x']\n")
    ok, reason = _usable_json(str(path))
    assert ok is False
    assert "not JSON" in reason and "Unable to validate" in reason


def test_empty_path_is_not_usable():
    assert _usable_json("")[0] is False
    assert _usable_json(None)[0] is False


@pytest.mark.parametrize("body", ["[]", '[{"a": 1}]', '{"rows": []}', "  \n [] "])
def test_valid_json_is_usable(tmp_path, body):
    path = tmp_path / "good.json"
    path.write_text(body)
    assert _usable_json(str(path)) == (True, "")


# --------------------------------------------------------------------------
# the adapter skips instead of raising
# --------------------------------------------------------------------------

def _extractor(name="extract_demo_features"):
    def fn(jsondump, **kwargs):
        import pandas as pd

        df = pd.read_json(jsondump)  # the call that used to blow up
        return {"demo.n": len(df)}

    fn.__name__ = name
    return _legacy_adapter(fn)


def test_adapter_skips_an_empty_file_without_raising(tmp_path, caplog):
    path = tmp_path / "modules.json"
    path.write_text("")
    result = _extractor()(str(path), context={})

    assert result.features == {}
    assert "skipped" in result.metrics
    # A warning, not an exception with a traceback.
    assert not any(r.exc_info for r in caplog.records)


def test_adapter_still_runs_a_healthy_extractor(tmp_path):
    path = tmp_path / "modules.json"
    path.write_text(json.dumps([{"Name": "a"}, {"Name": "b"}]))
    result = _extractor()(str(path), context={})
    assert result.features == {"demo.n": 2}


def test_a_genuine_extractor_bug_is_still_reported(tmp_path, caplog):
    path = tmp_path / "modules.json"
    path.write_text("[]")

    def broken(jsondump, **kwargs):
        raise KeyError("Path")

    broken.__name__ = "extract_broken_features"
    result = _legacy_adapter(broken)(str(path), context={})
    assert result.features == {}
    assert result.metrics.get("error") == "exception"


# --------------------------------------------------------------------------
# offline symbol support
# --------------------------------------------------------------------------

def test_symbol_dirs_and_offline_precede_the_plugin_name(tmp_path):
    runner = VolRunner(vol_path=_fake_vol(tmp_path, rc=0),
                       symbol_dirs=str(tmp_path / "symbols"), offline=True)
    cmd = runner.build_command("/images/host.raw", "json", "windows.modules")

    assert cmd[-1] == "windows.modules"
    assert "-s" in cmd and "--offline" in cmd
    # Volatility only accepts global options before the plugin.
    assert cmd.index("-s") < cmd.index("windows.modules")
    assert cmd.index("--offline") < cmd.index("windows.modules")
    assert cmd[cmd.index("-s") + 1] == str(tmp_path / "symbols")


def test_no_symbol_options_when_none_configured(tmp_path):
    cmd = VolRunner(vol_path=_fake_vol(tmp_path, rc=0)).build_command(
        "/images/host.raw", "json", "windows.pslist")
    assert "-s" not in cmd and "--offline" not in cmd


@pytest.mark.parametrize(
    ("given", "count"),
    [("/a;/b", 2), (["/a", "/b", "/c"], 3), ("/only", 1), (None, 0), ("", 0)],
)
def test_symbol_dirs_accept_list_or_separated_string(given, count):
    assert len(VolRunner._normalize_symbol_dirs(given)) == count


def test_symbol_dirs_are_absolute():
    assert VolRunner._normalize_symbol_dirs("relative/symbols")[0].startswith("/")


def test_failure_explanation_points_at_the_symbol_server(tmp_path):
    stderr = ("WARNING volatility3...pdbutil: Symbol file could not be downloaded "
              "from remote server\nUnable to validate the plugin requirements: "
              "['plugins.Modules.kernel.symbol_table_name']\n")
    explanation = VolRunner._explain_failure(stderr, None)
    assert "symbol" in explanation.lower()
    assert "symbol_dirs" in explanation


# --------------------------------------------------------------------------
# the runner and pipeline surface the failure
# --------------------------------------------------------------------------

def _fake_vol(tmp_path, *, rc: int, stderr: str = "", stdout: str = "") -> str:
    """A stand-in for the vol console script with a fixed exit code."""
    script = tmp_path / "fake_vol.py"
    script.write_text(textwrap.dedent(f"""
        import sys
        sys.stdout.write({stdout!r})
        sys.stderr.write({stderr!r})
        sys.exit({rc})
    """))
    return str(script)


def test_failed_plugin_leaves_an_empty_file_and_a_stderr_file(tmp_path):
    stderr = "Unable to validate the plugin requirements: ['x']\n"
    runner = VolRunner(vol_path=_fake_vol(tmp_path, rc=1, stderr=stderr))
    outdir = tmp_path / "artifacts"
    result = runner.run_plugin(str(tmp_path / "host.raw"),
                               PluginSpec(name="modules", fqname="windows.modules"),
                               output_dir=str(outdir))

    assert result.rc == 1 and result.ok is False
    assert os.path.getsize(result.output_path) == 0
    assert result.stderr_path and stderr in open(result.stderr_path).read()
    # and the empty file it left behind is exactly what the adapter now skips
    assert _usable_json(result.output_path)[0] is False


def test_output_lands_in_the_requested_directory(tmp_path):
    """Regression: the path was split on backslashes, so on POSIX the whole
    absolute image path became the 'name' and os.path.join discarded outdir."""
    runner = VolRunner(vol_path=_fake_vol(tmp_path, rc=0, stdout="[]"))
    outdir = tmp_path / "artifacts"
    result = runner.run_plugin(str(tmp_path / "dumps" / "dump_0"),
                               PluginSpec(name="pslist", fqname="windows.pslist"),
                               output_dir=str(outdir))

    assert os.path.dirname(result.output_path) == str(outdir)
    assert os.path.basename(result.output_path) == "dump_0_pslist.json"


def test_successful_run_is_reported_ok(tmp_path):
    runner = VolRunner(vol_path=_fake_vol(tmp_path, rc=0, stdout="[]"))
    result = runner.run_plugin(str(tmp_path / "host.raw"),
                               PluginSpec(name="pslist", fqname="windows.pslist"),
                               output_dir=str(tmp_path / "out"))
    assert result.ok is True
    assert _usable_json(result.output_path) == (True, "")


def test_plugin_run_result_ok_tracks_the_return_code():
    assert PluginRunResult(rc=0, runtime_s=0.1, output_path="x").ok is True
    assert PluginRunResult(rc=1, runtime_s=0.1, output_path="x").ok is False


# --------------------------------------------------------------------------
# the caller can tell "no such artifacts" from "Volatility could not run"
# --------------------------------------------------------------------------

def _pipeline(vol_path):
    from volmemlyzer.pipeline import Pipeline
    from volmemlyzer.plugins import build_registry

    return Pipeline(VolRunner(vol_path=vol_path), build_registry())


def test_raw_run_reports_which_plugins_failed(tmp_path):
    stderr = ("Symbol file could not be downloaded from remote server\n"
              "Unable to validate the plugin requirements: "
              "['plugins.PsList.kernel.symbol_table_name']\n")
    pipe = _pipeline(_fake_vol(tmp_path, rc=1, stderr=stderr))
    assert pipe.registry.has("pslist"), "the registry should carry the core plugins"

    result = pipe.run_plugin_raw(image_path=str(tmp_path / "host.raw"),
                                 enable={"pslist"}, outdir=str(tmp_path / "artifacts"),
                                 use_cache=False)

    failed = result.artifacts.get("failed_plugins") or {}
    assert failed, "a non-zero rc must be reported to the caller"
    assert all("vol exited 1" in why for why in failed.values())
    assert all("stderr" in why for why in failed.values())


def test_feature_row_carries_the_failures_so_absence_is_explainable(tmp_path):
    pipe = _pipeline(_fake_vol(tmp_path, rc=1, stderr="boom\n"))
    row = pipe.run_extract_features(image_path=str(tmp_path / "host.raw"),
                                    enable={"pslist"},
                                    artifacts_dir=str(tmp_path / "artifacts"),
                                    use_cache=False)

    assert row.failed_plugins, "an empty feature row must say why it is empty"
    assert not row.features or all(v is None for v in row.features.values())


def test_a_healthy_run_reports_no_failures(tmp_path):
    pipe = _pipeline(_fake_vol(tmp_path, rc=0, stdout="[]"))
    row = pipe.run_extract_features(image_path=str(tmp_path / "host.raw"),
                                    enable={"pslist"},
                                    artifacts_dir=str(tmp_path / "artifacts"),
                                    use_cache=False)
    assert row.failed_plugins == {}


# --------------------------------------------------------------------------
# locating the vol CLI
# --------------------------------------------------------------------------

def test_vol_is_found_beside_the_interpreter_without_PATH(tmp_path, monkeypatch):
    """A venv whose bin/ is not on PATH is the normal case when this is used as
    a library, and it used to fall through to an invocation that cannot work."""
    bindir = tmp_path / "bin"
    bindir.mkdir()
    (bindir / "python").write_text("")
    vol = bindir / "vol"
    vol.write_text("#!/bin/sh\nexit 0\n")
    vol.chmod(0o755)

    monkeypatch.setattr(sys, "executable", str(bindir / "python"))
    monkeypatch.setenv("PATH", "")
    monkeypatch.delenv("VOL_PATH", raising=False)

    assert VolRunner().resolve_volatility_command() == [str(vol)]


def test_module_fallback_uses_a_runnable_entry_point(tmp_path, monkeypatch):
    """`python -m volatility3` raises "cannot be directly executed" - the package
    has no __main__, and neither does volatility3.cli."""
    empty = tmp_path / "bin"
    empty.mkdir()
    (empty / "python").write_text("")
    monkeypatch.setattr(sys, "executable", str(empty / "python"))
    monkeypatch.setenv("PATH", "")
    monkeypatch.delenv("VOL_PATH", raising=False)

    cmd = VolRunner().resolve_volatility_command()
    assert "-m" not in cmd, "the -m form is not executable for volatility3"
    if "-c" in cmd:
        assert "from volatility3.cli import main" in cmd[cmd.index("-c") + 1]


def test_resolver_does_not_print_to_stdout(tmp_path, monkeypatch, capsys):
    """A library writing to stdout corrupts any caller parsing it."""
    empty = tmp_path / "bin"
    empty.mkdir()
    (empty / "python").write_text("")
    monkeypatch.setattr(sys, "executable", str(empty / "python"))
    monkeypatch.setenv("PATH", "")
    monkeypatch.delenv("VOL_PATH", raising=False)
    try:
        VolRunner().resolve_volatility_command()
    except Exception:
        pass
    assert capsys.readouterr().out == ""


# --------------------------------------------------------------------------
# stderr capture keeps the diagnostics without the progress animation
# --------------------------------------------------------------------------

def test_repeated_progress_updates_collapse_to_the_last_one():
    """Volatility redraws this line thousands of times a second behind a carriage
    return. Written to a file, nothing overwrites anything: one plugin on a large
    image left a 10 MB .stderr.txt that was almost entirely one repeated line."""
    raw = "Volatility 3 Framework 2.28.0\n" + "".join(
        f"\rProgress: {i / 100:7.2f}\t\tScanning memory_layer" for i in range(5000))
    out = VolRunner._condense_stderr(raw)
    assert out.count("Scanning memory_layer") == 1
    assert "Progress:   49.99\t\tScanning memory_layer" in out
    assert "Volatility 3 Framework 2.28.0" in out
    assert len(out) < len(raw) / 100


def test_each_phase_keeps_its_own_last_update():
    raw = ("\rProgress:  10.00\t\tPhase one"
           "\rProgress:  90.00\t\tPhase one"
           "\rProgress:  20.00\t\tPhase two"
           "\rProgress: 100.00\t\tPhase two")
    out = VolRunner._condense_stderr(raw).strip().splitlines()
    assert out == ["Progress:  90.00\t\tPhase one", "Progress: 100.00\t\tPhase two"]


def test_real_diagnostics_are_never_dropped():
    raw = ("\rProgress:  50.00\t\tScanning\n"
           "Unsatisfied requirement plugins.PsList.kernel.symbol_table_name\n"
           "Traceback (most recent call last):\n  File \"x\", line 1\n")
    out = VolRunner._condense_stderr(raw)
    for line in ("Unsatisfied requirement", "Traceback", 'File "x", line 1'):
        assert line in out


def test_a_failure_explanation_still_works_on_condensed_output():
    raw = "\rProgress: 100.00\t\tPDB scanning finished\nSymbol file could not be downloaded\n"
    condensed = VolRunner._condense_stderr(raw)
    assert "symbol" in VolRunner._explain_failure(condensed, None).lower()
