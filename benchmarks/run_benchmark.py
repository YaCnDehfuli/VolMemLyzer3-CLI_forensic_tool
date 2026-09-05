#!/usr/bin/env python3
"""Measure VolMemLyzer extract wall-clock: serial, parallel, and cache-warm.

Invokes the packaged CLI (`volmemlyzer extract`) on one image and one pinned
plugin list. Serial and parallel runs use `--no-cache` and a fresh outdir so
they do real plugin work. Cache-warm reuses artifacts from a completed populate.

Usage (hardware run):

    python benchmarks/run_benchmark.py --image /path/to/image.vmem

Usage (CI stub):

    python benchmarks/run_benchmark.py --ci --check
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import shutil
import statistics
import subprocess
import sys
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

HERE = Path(__file__).resolve().parent
REPO = HERE.parent
DEFAULT_PLUGINS = HERE / "plugins.yaml"
DEFAULT_THRESHOLDS = HERE / "ci_thresholds.json"
DEFAULT_STUB_IMAGE = HERE / "fixtures" / "stub_image.bin"
DEFAULT_STUB_VOL = HERE / "fixtures" / "vol.py"

# Confirmed local dump (not redistributed). Recorded when --image matches.
CONFIRMED_SHA256 = "777d71d7106e5ded19592c075058da12049bfcd658221e70f0579ad4bbd9cff4"
CONFIRMED_SIZE = 4412228315

# Requested triage set that exists in PLUGIN_SPECIFICS and finishes in minutes
# on the confirmed 4.4GB image. sessions is not registered. psscan and netscan
# timed out at 480s with empty artifacts. Byte-walk / dump / pool-wide
# scanners are not in this list.
PINNED_PLUGINS = [
    "pslist",
    "pstree",
    "dlllist",
    "cmdline",
    "registry.hivelist",
    "modules",
    "svcscan",
    "getsids",
    "privileges",
    "envars",
]


def _load_plugin_list(path: Path) -> List[str]:
    text = path.read_text(encoding="utf-8")
    names: List[str] = []
    in_list = False
    for raw in text.splitlines():
        line = raw.split("#", 1)[0].rstrip()
        if not line.strip():
            continue
        if line.strip() == "plugins:":
            in_list = True
            continue
        if in_list and line.lstrip().startswith("- "):
            names.append(line.lstrip()[2:].strip())
            continue
        if in_list and not line.startswith((" ", "\t")):
            break
    if not names:
        raise SystemExit(f"no plugins listed in {path}")
    return names


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _host_spec() -> Dict[str, Any]:
    cpu = platform.processor() or ""
    ram_bytes: Optional[int] = None
    macos_version = None
    if sys.platform == "darwin":
        try:
            cpu = subprocess.check_output(
                ["sysctl", "-n", "machdep.cpu.brand_string"], text=True
            ).strip() or cpu
        except Exception:
            pass
        try:
            ram_bytes = int(
                subprocess.check_output(["sysctl", "-n", "hw.memsize"], text=True).strip()
            )
        except Exception:
            pass
        try:
            macos_version = subprocess.check_output(
                ["sw_vers", "-productVersion"], text=True
            ).strip()
        except Exception:
            macos_version = None
    elif sys.platform.startswith("linux"):
        try:
            for line in Path("/proc/cpuinfo").read_text(encoding="utf-8", errors="replace").splitlines():
                if line.lower().startswith("model name"):
                    cpu = line.split(":", 1)[1].strip()
                    break
        except Exception:
            pass
        try:
            for line in Path("/proc/meminfo").read_text(encoding="utf-8").splitlines():
                if line.startswith("MemTotal:"):
                    ram_bytes = int(line.split()[1]) * 1024
                    break
        except Exception:
            pass
    logical = os.cpu_count() or 1
    return {
        "os": platform.platform(),
        "system": platform.system(),
        "release": platform.release(),
        "cpu": cpu,
        "cpu_logical": logical,
        "ram_bytes": ram_bytes,
        "python": sys.version.split()[0],
        "macos_version": macos_version if sys.platform == "darwin" else None,
    }


def _host_spec_sentence(host: Dict[str, Any]) -> str:
    cpu = host.get("cpu") or "unknown CPU"
    cores = host.get("cpu_logical")
    ram = host.get("ram_bytes")
    if host.get("macos_version"):
        os_label = f"macOS {host['macos_version']}"
    else:
        os_label = f"{host.get('system') or 'unknown OS'} {host.get('release') or ''}".strip()
    parts = [cpu]
    if cores:
        parts.append(f"{cores} logical cores")
    if isinstance(ram, int) and ram > 0:
        parts.append(f"{ram} bytes RAM")
    parts.append(os_label)
    return ", ".join(parts)


def _volatility_version(python_exe: str) -> str:
    code = (
        "from importlib.metadata import version, PackageNotFoundError\n"
        "try:\n"
        "    print(version('volatility3'))\n"
        "except PackageNotFoundError:\n"
        "    print('unknown')\n"
    )
    try:
        out = subprocess.check_output([python_exe, "-c", code], text=True).strip()
        return out or "unknown"
    except Exception:
        return "unknown"


def _registry_counts(python_exe: str) -> Dict[str, int]:
    code = (
        "from volmemlyzer.plugins import build_registry, PLUGIN_SPECIFICS\n"
        "from volmemlyzer import extractors\n"
        "reg = build_registry()\n"
        "n_fn = sum(1 for n in dir(extractors) if n.startswith('extract_'))\n"
        "print(len(reg.names()), len(PLUGIN_SPECIFICS), n_fn)\n"
    )
    try:
        out = subprocess.check_output(
            [python_exe, "-c", code], text=True, cwd=str(REPO)
        ).strip()
        n_reg, n_spec, n_fn = (int(x) for x in out.split())
        return {
            "registered_plugins": n_reg,
            "plugin_specs": n_spec,
            "extractor_functions": n_fn,
        }
    except Exception:
        return {
            "registered_plugins": None,
            "plugin_specs": None,
            "extractor_functions": None,
        }


def _default_jobs() -> int:
    return max(1, (os.cpu_count() or 2) // 2)


def _median(values: List[float]) -> Optional[float]:
    if not values:
        return None
    return float(statistics.median(values))


def _rss_kb(pid: int) -> Optional[int]:
    try:
        out = subprocess.check_output(
            ["ps", "-o", "rss=", "-p", str(pid)], text=True
        ).strip()
        if out:
            return int(out.split()[0])
    except Exception:
        return None
    return None


def _descendant_pids(root: int) -> List[int]:
    try:
        out = subprocess.check_output(["ps", "-ax", "-o", "pid=", "-o", "ppid="], text=True)
    except Exception:
        return [root]
    children: Dict[int, List[int]] = {}
    for line in out.splitlines():
        parts = line.split()
        if len(parts) < 2:
            continue
        try:
            pid, ppid = int(parts[0]), int(parts[1])
        except ValueError:
            continue
        children.setdefault(ppid, []).append(pid)
    found = [root]
    stack = [root]
    seen = {root}
    while stack:
        cur = stack.pop()
        for kid in children.get(cur, []):
            if kid not in seen:
                seen.add(kid)
                found.append(kid)
                stack.append(kid)
    return found


def _peak_rss_bytes(root_pid: int, stop: threading.Event, bucket: List[int], interval: float = 0.2) -> None:
    peak = 0
    while not stop.is_set():
        total = 0
        for pid in _descendant_pids(root_pid):
            kb = _rss_kb(pid)
            if kb:
                total += kb
        if total > peak:
            peak = total
        stop.wait(interval)
    # one last sample
    total = 0
    for pid in _descendant_pids(root_pid):
        kb = _rss_kb(pid)
        if kb:
            total += kb
    if total > peak:
        peak = total
    bucket.append(peak * 1024)


def _run_cli(
    *,
    python_exe: str,
    image: Path,
    outdir: Path,
    plugins: List[str],
    jobs: int,
    timeout: int,
    use_cache: bool,
    vol_path: Optional[str],
) -> Dict[str, Any]:
    cmd = [
        python_exe, "-m", "volmemlyzer.cli",
        "--timeout", str(timeout),
        "--jobs", str(jobs),
        "--log-level", "WARNING",
    ]
    if vol_path:
        cmd += ["--vol-path", vol_path]
    cmd += [
        "extract",
        "--image", str(image),
        "--outdir", str(outdir),
        "--format", "json",
        "--plugins", ",".join(plugins),
    ]
    if not use_cache:
        cmd.append("--no-cache")

    outdir.mkdir(parents=True, exist_ok=True)
    env = os.environ.copy()
    env["PYTHONUNBUFFERED"] = "1"

    t0 = time.perf_counter()
    proc = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        cwd=str(REPO),
        env=env,
    )
    stop = threading.Event()
    rss_box: List[int] = []
    sampler = threading.Thread(
        target=_peak_rss_bytes, args=(proc.pid, stop, rss_box), daemon=True
    )
    sampler.start()
    try:
        stdout, stderr = proc.communicate()
    finally:
        stop.set()
        sampler.join(timeout=5)
    wall = time.perf_counter() - t0
    peak = rss_box[0] if rss_box else None
    return {
        "command": cmd,
        "returncode": proc.returncode,
        "wall_s": wall,
        "peak_rss_bytes": peak,
        "stdout_tail": (stdout or "")[-2000:],
        "stderr_tail": (stderr or "")[-4000:],
    }


def _summarize(runs: List[Dict[str, Any]]) -> Dict[str, Any]:
    ok = [r for r in runs if r.get("ok")]
    walls = [float(r["wall_s"]) for r in ok]
    rss = [int(r["peak_rss_bytes"]) for r in ok if r.get("peak_rss_bytes") is not None]
    return {
        "n_ok": len(ok),
        "n_failed": len(runs) - len(ok),
        "wall_s": {
            "median": _median(walls),
            "min": min(walls) if walls else None,
            "max": max(walls) if walls else None,
            "n": len(walls),
        },
        "peak_rss_bytes": {
            "median": int(statistics.median(rss)) if rss else None,
            "min": min(rss) if rss else None,
            "max": max(rss) if rss else None,
        },
    }


def _ratio(serial: Optional[float], parallel: Optional[float]) -> Optional[float]:
    if serial is None or parallel is None or parallel == 0:
        return None
    return serial / parallel


def _readme_sentence(payload: Dict[str, Any]) -> str:
    n = payload["plugin_count"]
    size = payload["image"]["size_bytes"]
    serial = payload["summary"]["serial"]["wall_s"]["median"]
    parallel = payload["summary"]["parallel"]["wall_s"]["median"]
    workers = payload["parallel_jobs"]
    z = _ratio(serial, parallel)
    host = payload["host_spec_sentence"]
    if serial is None or parallel is None or z is None:
        return (
            f"Extracting `{n}` plugins from a `{size}`-byte Windows image: "
            "[[NEEDS NUMBER]] (one or more configurations produced no successful runs). "
            f"Median of 3 runs on `{host}`. Full method and raw results in `benchmarks/`."
        )
    return (
        f"Extracting `{n}` plugins from a `{size}`-byte Windows image takes "
        f"`{serial:.2f}`s serially and `{parallel:.2f}`s with `{workers}` workers "
        f"— a `{z:.1f}×` reduction in wall-clock. Median of 3 runs on `{host}`. "
        f"Full method and raw results in `benchmarks/`."
    )


def _results_md(payload: Dict[str, Any]) -> str:
    lines = [
        "# VolMemLyzer extract benchmark",
        "",
        payload["readme_sentence"],
        "",
        "## Method",
        "",
        "Command: `volmemlyzer extract` on one image and the plugin list in `plugins.yaml`.",
        "Serial and parallel use `--no-cache` and a fresh outdir each run.",
        "Cache-warm is a timed re-run against artifacts from a completed populate.",
        "Each configuration is three runs. Summary is median with min/max of successful runs.",
        "The local image is not redistributed.",
        "",
        f"- Plugins ({payload['plugin_count']}): `{', '.join(payload['plugins'])}`",
        f"- Extractor functions in tree: `{payload['registry']['extractor_functions']}`",
        f"- Registered plugins: `{payload['registry']['registered_plugins']}`",
        f"- Volatility 3: `{payload['volatility3_version']}`",
        f"- Image SHA-256: `{payload['image']['sha256']}`",
        f"- Image size (bytes): `{payload['image']['size_bytes']}`",
        f"- Image redistributed: `{payload['image']['redistributed']}`",
        f"- Host: `{payload['host_spec_sentence']}`",
        "",
        "## Wall-clock (seconds)",
        "",
        "| config | workers | cache | n ok | median | min | max |",
        "|---|---:|---|---:|---:|---:|---:|",
    ]
    for key, label, workers, cache in (
        ("serial", "serial", payload["serial_jobs"], "off"),
        ("parallel", "parallel", payload["parallel_jobs"], "off"),
        ("cache_warm", "cache-warm", payload["parallel_jobs"], "on"),
    ):
        w = payload["summary"][key]["wall_s"]
        n_ok = payload["summary"][key]["n_ok"]
        def _fmt(v):
            return "—" if v is None else f"{v:.4f}" if v < 10 else f"{v:.2f}"
        lines.append(
            f"| {label} | {workers} | {cache} | {n_ok} | {_fmt(w['median'])} | {_fmt(w['min'])} | {_fmt(w['max'])} |"
        )
    lines += [
        "",
        "## Peak RSS (bytes)",
        "",
        "| config | median | min | max |",
        "|---|---:|---:|---:|",
    ]
    for key, label in (("serial", "serial"), ("parallel", "parallel"), ("cache_warm", "cache-warm")):
        r = payload["summary"][key]["peak_rss_bytes"]
        def _i(v):
            return "—" if v is None else str(v)
        lines.append(f"| {label} | {_i(r['median'])} | {_i(r['min'])} | {_i(r['max'])} |")
    failed = [run for cfg in payload["runs"].values() for run in cfg if not run.get("ok")]
    if failed:
        lines += ["", "## Failed runs", ""]
        for run in failed:
            lines.append(
                f"- `{run['config']}` run {run['index']}: rc={run.get('returncode')} "
                f"wall_s={run.get('wall_s')}"
            )
    lines.append("")
    return "\n".join(lines)


def _check(payload: Dict[str, Any], thresholds: Dict[str, Any]) -> List[str]:
    errors: List[str] = []
    min_runs = int(thresholds.get("min_runs_per_config", 3))
    want_plugins = int(thresholds.get("plugin_count", 10))
    if payload["plugin_count"] != want_plugins:
        errors.append(
            f"plugin_count drifted: measured {payload['plugin_count']} != {want_plugins}"
        )
    for name in ("serial", "parallel", "cache_warm"):
        block = payload["summary"][name]
        if block["n_ok"] < min_runs:
            errors.append(f"{name}: {block['n_ok']} successful runs < {min_runs}")
        if thresholds.get("require_all_runs_ok") and block["n_failed"]:
            errors.append(f"{name}: {block['n_failed']} failed run(s)")
    serial = payload["summary"]["serial"]["wall_s"]["median"]
    parallel = payload["summary"]["parallel"]["wall_s"]["median"]
    warm = payload["summary"]["cache_warm"]["wall_s"]["median"]
    max_serial = float(thresholds.get("max_serial_median_s", 60))
    if serial is not None and serial > max_serial:
        errors.append(f"serial median {serial:.4f}s exceeds {max_serial}s")
    if serial and parallel:
        limit = float(thresholds.get("max_parallel_over_serial", 1.25))
        if parallel > serial * limit:
            errors.append(
                f"parallel median {parallel:.4f}s > serial {serial:.4f}s * {limit}"
            )
    if serial and warm:
        limit = float(thresholds.get("max_cache_warm_over_serial", 0.5))
        if warm > serial * limit:
            errors.append(
                f"cache-warm median {warm:.4f}s > serial {serial:.4f}s * {limit}"
            )
    return errors


def run_benchmark(args: argparse.Namespace) -> Dict[str, Any]:
    plugins_path = Path(args.plugins_file)
    if args.plugins:
        plugins = [p.strip() for p in args.plugins.split(",") if p.strip()]
    elif plugins_path.resolve() == DEFAULT_PLUGINS.resolve():
        yaml_plugins = _load_plugin_list(plugins_path)
        if yaml_plugins != PINNED_PLUGINS:
            raise SystemExit(
                f"{plugins_path} drifted from PINNED_PLUGINS in run_benchmark.py: "
                f"{yaml_plugins} != {PINNED_PLUGINS}"
            )
        plugins = list(PINNED_PLUGINS)
    else:
        plugins = _load_plugin_list(plugins_path)

    image = Path(args.image).resolve()
    if not image.is_file():
        raise SystemExit(f"--image is not a file: {image}")

    python_exe = args.python or sys.executable
    host = _host_spec()
    vol_ver = _volatility_version(python_exe)
    registry = _registry_counts(python_exe)
    size = image.stat().st_size
    sha = "ci-stub" if args.ci and args.skip_hash else _sha256_file(image)
    if args.ci and args.skip_hash:
        sha = hashlib.sha256(image.read_bytes()).hexdigest()

    parallel_jobs = args.jobs if args.jobs is not None else _default_jobs()
    if parallel_jobs < 1:
        raise SystemExit("--jobs must be >= 1")
    ncpu = os.cpu_count() or 1
    if parallel_jobs > ncpu:
        raise SystemExit(f"--jobs {parallel_jobs} exceeds cpu_count {ncpu}")

    work_root = Path(args.work_dir).resolve()
    if args.clean_work and work_root.exists():
        shutil.rmtree(work_root)
    work_root.mkdir(parents=True, exist_ok=True)

    runs: Dict[str, List[Dict[str, Any]]] = {"serial": [], "parallel": [], "cache_warm": []}

    def one(config: str, jobs: int, use_cache: bool, outdir: Path, index: int) -> Dict[str, Any]:
        print(f"[benchmark] {config} run {index}/{args.runs} jobs={jobs} cache={use_cache} outdir={outdir}",
              flush=True)
        result = _run_cli(
            python_exe=python_exe,
            image=image,
            outdir=outdir,
            plugins=plugins,
            jobs=jobs,
            timeout=args.timeout,
            use_cache=use_cache,
            vol_path=args.vol_path,
        )
        record = {
            "config": config,
            "index": index,
            "jobs": jobs,
            "use_cache": use_cache,
            "outdir": str(outdir),
            "ok": result["returncode"] == 0,
            "returncode": result["returncode"],
            "wall_s": result["wall_s"],
            "peak_rss_bytes": result["peak_rss_bytes"],
            "plugin_count": len(plugins),
            "extractor_count": registry.get("extractor_functions"),
            "command": result["command"],
        }
        if result["returncode"] != 0:
            record["stderr_tail"] = result["stderr_tail"]
            print(f"[benchmark] FAILED {config} run {index} rc={result['returncode']}", flush=True)
            if result["stderr_tail"]:
                print(result["stderr_tail"][-1500:], flush=True)
        else:
            print(f"[benchmark] {config} run {index} wall_s={result['wall_s']:.4f} "
                  f"peak_rss_bytes={result['peak_rss_bytes']}", flush=True)
        return record

    for i in range(1, args.runs + 1):
        outdir = work_root / "serial" / f"run_{i}"
        if outdir.exists():
            shutil.rmtree(outdir)
        runs["serial"].append(one("serial", 1, False, outdir, i))

    for i in range(1, args.runs + 1):
        outdir = work_root / "parallel" / f"run_{i}"
        if outdir.exists():
            shutil.rmtree(outdir)
        runs["parallel"].append(one("parallel", parallel_jobs, False, outdir, i))

    cache_dir = work_root / "cache_warm" / "store"
    if cache_dir.exists():
        shutil.rmtree(cache_dir)
    print("[benchmark] cache-warm populate (untimed)", flush=True)
    populate = _run_cli(
        python_exe=python_exe,
        image=image,
        outdir=cache_dir,
        plugins=plugins,
        jobs=parallel_jobs,
        timeout=args.timeout,
        use_cache=False,
        vol_path=args.vol_path,
    )
    if populate["returncode"] != 0:
        print("[benchmark] cache-warm populate failed; timed runs will miss cache", flush=True)
        print((populate.get("stderr_tail") or "")[-1500:], flush=True)
    for i in range(1, args.runs + 1):
        runs["cache_warm"].append(one("cache_warm", parallel_jobs, True, cache_dir, i))

    payload: Dict[str, Any] = {
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "mode": "ci-stub" if args.ci else "hardware",
        "image": {
            "path": str(image),
            "path_note": "local-only; not redistributed with this repository",
            "sha256": sha,
            "size_bytes": size,
            "redistributed": False,
            "matches_confirmed_dump": (
                sha == CONFIRMED_SHA256 and size == CONFIRMED_SIZE
            ),
        },
        "host": host,
        "host_spec_sentence": _host_spec_sentence(host),
        "volatility3_version": vol_ver,
        "registry": registry,
        "plugins": plugins,
        "plugin_count": len(plugins),
        "plugins_file": str(plugins_path),
        "serial_jobs": 1,
        "parallel_jobs": parallel_jobs,
        "runs_requested": args.runs,
        "timeout_s": args.timeout,
        "vol_path": args.vol_path,
        "cli": "volmemlyzer extract",
        "runs": runs,
        "summary": {
            "serial": _summarize(runs["serial"]),
            "parallel": _summarize(runs["parallel"]),
            "cache_warm": _summarize(runs["cache_warm"]),
        },
    }
    z = _ratio(
        payload["summary"]["serial"]["wall_s"]["median"],
        payload["summary"]["parallel"]["wall_s"]["median"],
    )
    payload["wall_clock_reduction_x"] = z
    payload["readme_sentence"] = _readme_sentence(payload)
    return payload


def _write_outputs(payload: Dict[str, Any], json_path: Path, md_path: Path) -> None:
    json_path.parent.mkdir(parents=True, exist_ok=True)
    json_path.write_text(json.dumps(payload, indent=2, sort_keys=False) + "\n", encoding="utf-8")
    md_path.write_text(_results_md(payload), encoding="utf-8")


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--image", default=None, help="Memory image path")
    p.add_argument("--plugins-file", default=str(DEFAULT_PLUGINS), help="YAML list of plugin names")
    p.add_argument("--plugins", default=None, help="Comma list overriding --plugins-file")
    p.add_argument("--jobs", type=int, default=None,
                   help="Parallel worker count (default: CLI default, half the CPUs)")
    p.add_argument("--runs", type=int, default=3, help="Runs per configuration")
    p.add_argument("--timeout", type=int, default=1800, help="Per-plugin timeout seconds")
    p.add_argument("--vol-path", default=None, help="Path to vol or vol.py")
    p.add_argument("--python", default=None, help="Python that has volmemlyzer installed")
    p.add_argument("--work-dir", default=str(HERE / "work"), help="Per-run artifact root")
    p.add_argument("--json-out", default=str(HERE / "results.json"))
    p.add_argument("--md-out", default=str(HERE / "results.md"))
    p.add_argument("--clean-work", action="store_true", help="Delete --work-dir first")
    p.add_argument("--ci", action="store_true",
                   help="Use the checked-in stub image and stub vol.py")
    p.add_argument("--skip-hash", action="store_true", help="Skip SHA-256 of a large image")
    p.add_argument("--check", action="store_true",
                   help="Fail if results miss thresholds in ci_thresholds.json")
    p.add_argument("--thresholds", default=str(DEFAULT_THRESHOLDS))
    return p


def main(argv: Optional[List[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    if args.runs < 1:
        print("--runs must be >= 1", file=sys.stderr)
        return 2
    if args.ci:
        args.image = args.image or str(DEFAULT_STUB_IMAGE)
        args.vol_path = args.vol_path or str(DEFAULT_STUB_VOL)
        if args.json_out == str(HERE / "results.json"):
            args.json_out = str(HERE / "ci_results.json")
        if args.md_out == str(HERE / "results.md"):
            args.md_out = str(HERE / "ci_results.md")
        args.work_dir = args.work_dir if args.work_dir != str(HERE / "work") else str(HERE / "work_ci")
        os.environ.setdefault("VOL_STUB_SLEEP", "0.12")
    if not args.image:
        print("--image is required (or pass --ci)", file=sys.stderr)
        return 2

    payload = run_benchmark(args)
    _write_outputs(payload, Path(args.json_out), Path(args.md_out))
    print(payload["readme_sentence"])
    print(f"wrote {args.json_out}")
    print(f"wrote {args.md_out}")

    if args.check:
        thresholds = json.loads(Path(args.thresholds).read_text(encoding="utf-8"))
        errors = _check(payload, thresholds)
        if errors:
            print("benchmark check failed:", file=sys.stderr)
            for e in errors:
                print(f"  - {e}", file=sys.stderr)
            return 1
        print("benchmark check passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
