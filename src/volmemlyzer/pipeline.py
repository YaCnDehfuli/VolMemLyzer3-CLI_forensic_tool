# File: pipeline.py
from __future__ import annotations
import os, logging, json, csv, re, threading
from functools import partial
from typing import Dict, Any, Set, List, Optional, Iterable, Callable
from concurrent.futures import ThreadPoolExecutor, FIRST_COMPLETED, wait
from .core import FeatureRow, ExtractResult, ActionResult
from .runner import VolRunner
from .extractor_registry import ExtractorRegistry
from .utilities import to_builtin, renderer_to_ext, cheap_image_hash
from .converters import convert_artifact

logger = logging.getLogger(__name__)

class Pipeline:
    def __init__(self, runner: VolRunner, registry: ExtractorRegistry):
        self.runner = runner
        self.registry = registry
        # name -> why it failed, for the most recent run on this Pipeline.
        # Written from worker threads, so every touch goes through the lock.
        self._failed_plugins: Dict[str, str] = {}
        self._failed_lock = threading.Lock()

    @property
    def failed_plugins(self) -> Dict[str, str]:
        with self._failed_lock:
            return dict(self._failed_plugins)

    # ---------- Public API ----------

    def run_plugin_raw(
        self,
        image_path: str,
        *,
        enable: Set[str] | None = None,
        drop: Set[str] | None = None,
        renderer: str = "json",
        outdir: Optional[str] = None,
        concurrency: int = 1,
        use_cache: bool = True,
        strict: bool = False
    ) -> ActionResult:
        outdir = outdir or self._default_artifacts_dir(image_path)
        os.makedirs(outdir, exist_ok=True)
        artifact_map: Dict[str, str] = {}
        with self._failed_lock:
            self._failed_plugins = {}
        selected = self.preflight(self._select(enable, drop))

        want_ext = renderer_to_ext(renderer)
        img_name = os.path.basename(image_path)

        def _run_one(name: str) -> tuple[str, str]:
            spec, _ = self.registry.get(name)
            # 1) exact cache hit?
            if use_cache:
                chk = self.check_cache(outdir, spec.name, img_name, require_format=want_ext, strict=strict)
                if chk["ok"]:
                    src_path = chk["path"]
                    src_format = chk["format"]
                    if src_format == want_ext:
                        logger.info("Using the cached %s plugin output in the %s directory. Re-run avoided", spec.name, outdir)
                        return name, src_path
                    dst_path = os.path.join(outdir, f"{spec.name}.{want_ext}")
                    decision, out_path, used = convert_artifact(src_path, src_format, dst_path, want_ext)
                    if decision == "convert" and out_path:
                        logger.info("Converted %s: %s -> %s via %s. Re-run avoided", spec.name, src_format, want_ext, used)
                        return name, out_path

            # 3) no hit or not convertible -> run plugin with requested renderer
            run = self.runner.run_plugin(image_path, spec, renderer=renderer, output_dir=outdir)
            # VolRunner returns PluginRunResult; prefer its output path if present
            out_path = getattr(run, "output_path", os.path.join(outdir, f"{spec.name}.{want_ext}"))
            if getattr(run, "rc", 0) != 0:
                self._note_failure(spec.name, run)
            return name, out_path

        def _collect(name: str, result) -> None:
            artifact_map[result[0]] = result[1]

        self._run_graph(selected, _run_one, concurrency, _collect)

        self._warn_if_widely_failed(len(selected))
        return ActionResult(artifacts={"raw_dir": outdir, "plugins": artifact_map,
                                       "failed_plugins": self.failed_plugins})

    def run_extract_features(
        self,
        image_path: str,
        *,
        enable: Set[str] | None = None,
        drop: Set[str] | None = None,
        concurrency: int = 1,
        artifacts_dir: Optional[str] = None,
        use_cache: bool = True,
    ) -> FeatureRow:
        artifacts_dir = artifacts_dir or self._default_artifacts_dir(image_path)
        os.makedirs(artifacts_dir, exist_ok=True)

        features: Dict[str, Any] = {}
        context_map: Dict[str, Any] = {}
        with self._failed_lock:
            self._failed_plugins = {}
        selected = self.preflight(self._select(enable, drop))

        def _task(name: str):
            spec, extractor = self.registry.get(name)

            # Always feed extractors JSON, reuse convertible cache or run -r=json.
            json_path = self._run_or_fetch_plugin_output(
                image_path, spec, artifacts_dir, target_renderer="json", use_cache=use_cache)

            dep_ctx = {dep: context_map.get(dep) for dep in spec.deps}
            extr: ExtractResult = extractor(json_path, context=dep_ctx)
            return name, extr

        def _collect(name: str, result) -> None:
            k, extr = result
            if extr.context is not None:
                context_map[k] = extr.context
            features.update(extr.features or {})

        self._run_graph(selected, _task, concurrency, _collect)

        self._warn_if_widely_failed(len(selected))
        row = FeatureRow(
            image_name=os.path.basename(image_path),
            features={k: to_builtin(v) for k, v in features.items()},
            image_hash=cheap_image_hash(image_path),
            vol_version=self.runner.get_version(),
            failed_plugins=self.failed_plugins,
        )
        return row

    def _warn_if_widely_failed(self, attempted: int) -> None:
        """A handful of failures is normal; nearly all of them means one cause."""
        current = self.failed_plugins
        failed = len(current)
        if not failed:
            return
        logger.warning("%d of %d plugins produced no usable output: %s",
                       failed, attempted, ", ".join(sorted(current)))
        if attempted and failed >= max(3, int(attempted * 0.5)):
            logger.error(
                "Most plugins failed, which usually means one shared cause rather than "
                "%d separate ones - most often an unresolvable kernel symbol table. "
                "Check a .stderr.txt file next to the artifacts; if it mentions the "
                "Microsoft symbol server, supply pre-fetched symbols via symbol_dirs.",
                failed)


    def run_analysis_steps(
        self,
        *,
        image_path: str,
        artifacts_dir: Optional[str] = None,
        steps: Optional[Iterable[int]] = None,
        use_cache: bool = True,
        high_level: bool = False
    ) -> Dict[str, Any]:
        from .analysis import OverviewAnalysis
        eng = OverviewAnalysis()
        return eng.run_steps(
            pipe=self,
            image_path=image_path,
            artifacts_dir=artifacts_dir,
            steps=steps,
            use_cache=use_cache,
            high_level= high_level
        )

    # ---------- Scheduling ----------

    def _run_graph(self, names: Iterable[str], run_one: Callable[[str], Any],
                   concurrency: int, on_done: Callable[[str, Any], None]) -> None:
        """Run `names` in dependency order, without layer barriers.

        This used to walk topological layers, opening a fresh ThreadPoolExecutor
        per layer and draining it completely before starting the next. One slow
        plugin therefore held its layer's barrier shut and everything else queued
        behind it, related or not: a psxview that runs for three hours stalled the
        entire analysis even though nothing depends on psxview.

        Here a plugin starts the moment its own dependencies are satisfied and
        waits for nothing else. Completions are reaped one at a time
        (FIRST_COMPLETED) rather than in batches, so a fast plugin finishing
        behind a slow one is handed back immediately.

        `on_done` is called on the calling thread, in completion order, before any
        dependent is submitted -- extractors read their dependency's context from
        it, so that ordering is a correctness requirement, not a convenience.
        """
        names = [n.lower() for n in names]
        if not names:
            return

        unmet, dependents = self.registry.ready_graph(set(names))
        rank = {n: i for i, n in enumerate(self.registry.cost_sorted(names))}
        in_order = lambda seq: sorted(seq, key=lambda n: rank[n])

        def release(finished: str) -> List[str]:
            """Dependencies satisfied by `finished` -> whoever is now ready."""
            freed = []
            for dep in dependents.get(finished, ()):
                waiting = unmet.get(dep)
                if waiting is None:
                    continue
                waiting.discard(finished)
                if not waiting:
                    freed.append(dep)
                    unmet.pop(dep, None)
            return in_order(freed)

        ready = in_order([n for n in names if not unmet.get(n)])
        for n in ready:
            unmet.pop(n, None)
        started = set(ready)

        if concurrency <= 1:
            # Same graph, same order, one at a time -- kept deterministic so a
            # sequential run is reproducible when something needs debugging.
            queue = list(ready)
            while queue:
                name = queue.pop(0)
                logger.info("Running plugin %s", name)
                self._settle(name, partial(run_one, name), on_done)
                freed = [n for n in release(name) if n not in started]
                started.update(freed)
                queue = in_order(queue + freed)
        else:
            with ThreadPoolExecutor(max_workers=concurrency, thread_name_prefix="volmemlyzer") as pool:
                futures = {}

                def submit(batch: List[str]) -> None:
                    for name in batch:
                        logger.info("Running plugin %s", name)
                        futures[pool.submit(run_one, name)] = name

                submit(ready)
                while futures:
                    done, _ = wait(list(futures), return_when=FIRST_COMPLETED)
                    freed: List[str] = []
                    for fut in done:
                        name = futures.pop(fut)
                        self._settle(name, fut.result, on_done)
                        freed.extend(n for n in release(name) if n not in started)
                    started.update(freed)
                    submit(in_order(freed))

        if unmet:
            # ready_graph already drops deps outside the selection, so anything
            # left here is a genuine cycle in the plugin table.
            raise ValueError(f"Dependency cycle among plugins: {sorted(unmet)}")

    def _settle(self, name: str, produce: Callable[[], Any], on_done: Callable[[str, Any], None]) -> None:
        """Deliver one plugin's result, or record why it produced none.

        A raising worker must not take the run down with it: the remaining
        plugins are independent of it and their output is still worth having.
        """
        try:
            value = produce()
        except Exception as exc:
            logger.exception("Plugin %s raised", name)
            with self._failed_lock:
                self._failed_plugins[name] = f"raised {type(exc).__name__}: {exc}"
            return
        on_done(name, value)

    def preflight(self, selected: Set[str]) -> Set[str]:
        """Drop plugins this Volatility install does not have, and say which.

        Worth doing before the first run rather than after: an unavailable plugin
        otherwise costs a full launch to discover, once per plugin, and reports
        itself as an ordinary failure among the real ones.
        """
        usable, missing = set(), []
        for name in selected:
            spec, _ = self.registry.get(name)
            if self.runner.resolve_plugin(spec.name, spec.candidates):
                usable.add(name)
            else:
                missing.append(name)
        if missing:
            logger.warning(
                "Skipping %d plugin(s) this Volatility does not provide: %s",
                len(missing), ", ".join(sorted(missing)))
            with self._failed_lock:
                for name in missing:
                    self._failed_plugins[name] = "not available in this Volatility build"
        return usable

    # ---------- Core helpers ----------

    def _run_or_fetch_plugin_output(
        self,
        image_path: str,
        spec,
        artifacts_dir: str,
        target_renderer: str,
        use_cache: bool,
    ) -> str:
        """
        Return a path for `spec` rendered as `target_renderer`.
        1) If exact cached output exists -> use it.
        2) Else, if a convertible cached format exists (json/jsonl/csv) -> convert and return.
        3) Else, run the plugin with the requested renderer and return the new path.
        """
        want_ext = renderer_to_ext(target_renderer)
        img_name = os.path.basename(image_path)
        base = os.path.join(artifacts_dir, f"{img_name}_{spec.name}")

        # 1) exact format hit
        if use_cache:
            chk = self.check_cache(artifacts_dir, spec.name, img_name, require_format=want_ext, strict= True)
            if chk["ok"]:
                logger.info("Using the cached %s plugin output in the %s directory. Re-run avoided", spec.name, artifacts_dir)
                return chk["path"]

        # 3) no cache or not convertible -> run once with desired renderer
        run = self.runner.run_plugin(image_path, spec, renderer=target_renderer, output_dir=artifacts_dir)
        path = getattr(run, "output_path", f"{base}.{want_ext}")
        if getattr(run, "rc", 0) != 0:
            self._note_failure(spec.name, run)
        return path

    def _note_failure(self, name: str, run) -> None:
        """Record a plugin that exited non-zero, with a pointer to its stderr."""
        detail = f"vol exited {getattr(run, 'rc', '?')}"
        stderr_path = getattr(run, "stderr_path", None)
        if stderr_path:
            detail += f"; see {stderr_path}"
        with self._failed_lock:
            self._failed_plugins[name] = detail


    # ---------- Cache validation (single source of truth) ----------

    def check_cache(
        self,
        artifacts_dir: str,
        plugin_name: str,
        img_name: str,
        *,
        require_format: Optional[str] = None,  # "json","jsonl","csv","txt"
        strict: bool = False
    ) -> Dict[str, Any]:
        import json as _json, csv as _csv, re as _re

        def _stderr_has_critical(p: str) -> bool:
            sp = p + ".stderr.txt"
            if not os.path.exists(sp): return False
            try:
                t = open(sp, "r", encoding="utf-8", errors="replace").read()
            except Exception:
                return False
            return bool(_re.search(r"(Traceback|ERROR|Exception|No suitable address space|failed)", t, _re.I))

        def _ok_json(p: str) -> bool:
            try:
                with open(p, "r", encoding="utf-8") as f:
                    data = _json.load(f)
                if isinstance(data, list): return len(data) > 0
                if isinstance(data, dict) and isinstance(data.get("rows"), list): return len(data["rows"]) > 0
                return False
            except Exception:
                return False

        def _ok_jsonl(p: str) -> bool:
            try:
                n = 0
                with open(p, "r", encoding="utf-8", errors="replace") as f:
                    for i, ln in zip(range(100), f):
                        s = ln.strip()
                        if not s: 
                            continue
                        _json.loads(s)
                        n += 1
                return n > 0
            except Exception:
                return False

        def _ok_csv(p: str) -> bool:
            try:
                with open(p, "r", encoding="utf-8", errors="replace") as f:
                    r = _csv.DictReader(f)
                    for i, row in zip(range(2), r):
                        if row: 
                            return True
                return False
            except Exception:
                return False

        def _ok_txt(p: str) -> bool:
            try:
                lines = []
                with open(p, "r", encoding="utf-8", errors="replace") as f:
                    for i, ln in zip(range(100), f):
                        s = ln.strip()
                        if s: lines.append(s)
                if not lines: return False
                joined = "\n".join(lines)
                if any(x in joined for x in ("Traceback","ERROR","Exception","No suitable address space")):
                    return False
                return True
            except Exception:
                return False

        if strict:
            candidates = [require_format]
        else:
            if require_format == 'json' or require_format == 'csv' or require_format == 'jsonl':
                candidates = ["json", "jsonl", "csv"]
            else:
                candidates = ["txt"]

        for ext in candidates:
            p = os.path.join(artifacts_dir, f"{img_name}_{plugin_name}.{ext}")
            if not os.path.exists(p): 
                continue
            ok = (ext=="json" and _ok_json(p)) or \
                 (ext=="jsonl" and _ok_jsonl(p)) or \
                 (ext=="csv" and _ok_csv(p)) or \
                 (ext in ("txt","log") and _ok_txt(p))
            if ok and not _stderr_has_critical(p):
                return {"ok": True, "path": p, "format": ext}

        return {"ok": False, "path": None, "format": None}

    # ---------- Small utilities ----------

    def _select(self, enable: Set[str] | None, drop: Set[str] | None) -> Set[str]:
        """Apply enable/drop to the registered plugin names."""
        names: Set[str] = set(self.registry.names())
        if enable:
            names &= set(enable)
        if drop:
            names -= set(drop)
        return names

    def _default_artifacts_dir(self, memory_dump_path: str) -> str:
        base = os.path.dirname(os.path.abspath(memory_dump_path))
        return os.path.join(base, ".volmemlyzer")
