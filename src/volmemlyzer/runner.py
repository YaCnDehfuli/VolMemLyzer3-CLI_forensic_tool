from __future__ import annotations
import logging, os, subprocess
import importlib, time, sys, re
from typing import Optional, List, Union
from pathlib import Path
from shutil import which

from .core import PluginSpec, PluginRunResult
from .utilities import renderer_to_ext

logger = logging.getLogger(__name__)

class VolRunner:
    def __init__(self, vol_path: Optional[str] = None, 
                 python_path: Optional[str] = None,
                 default_timeout_s: Optional[int] = None,
                 default_renderer: str = "json",
                 symbol_dirs: Optional[Union[str, List[str]]] = None,
                 offline: bool = False,
                 extra_args: Optional[List[str]] = None):
        self._vol_hint = vol_path
        self.vol_path = self._vol_cmd()
        self.default_renderer = default_renderer
        self.default_timeout_s = default_timeout_s
        self.symbol_dirs = self._normalize_symbol_dirs(symbol_dirs)
        self.offline = offline
        self.extra_args = list(extra_args or [])
        self.version = None

    @staticmethod
    def _normalize_symbol_dirs(symbol_dirs: Optional[Union[str, List[str]]]) -> List[str]:
        """Accept a list, or the semicolon/colon separated forms vol itself takes."""
        if not symbol_dirs:
            return []
        if isinstance(symbol_dirs, str):
            parts = [p for chunk in symbol_dirs.split(";") for p in chunk.split(os.pathsep)]
        else:
            parts = list(symbol_dirs)
        return [os.path.abspath(os.path.expanduser(p)) for p in parts if p]

    def global_args(self) -> List[str]:
        """Volatility options that must precede the plugin name.

        ``--symbol-dirs`` is what makes an air-gapped run possible: Volatility
        otherwise reaches out to msdl.microsoft.com for the kernel PDB, and every
        windows.* plugin fails with an unsatisfied
        ``plugins.<Plugin>.kernel.symbol_table_name`` requirement when it cannot.
        ``--offline`` additionally stops it from spending the timeout trying.
        """
        args: List[str] = []
        if self.symbol_dirs:
            args += ["-s", ";".join(self.symbol_dirs)]
        if self.offline:
            args.append("--offline")
        args += self.extra_args
        return args


    def _vol_cmd(self) -> str:
        return self.resolve_volatility_command(self._vol_hint)
    
    def build_command(self, image_path: str, renderer: str, plugin: str) -> List[str]:
        vol = self.resolve_volatility_command(self._vol_hint)
        # Every option here is global and must come before the plugin name.
        return vol + self.global_args() + ["-f", image_path, f"-r={renderer}", plugin]

    def run_plugin(self, memory_dump_path: str, plugin_specs: PluginSpec,
                    *, renderer: Optional[str] = None, output_dir: Optional[str] = None) -> PluginRunResult:
        """Invoke a single plugin with the chosen renderer; persist stdout to a file."""
        plugin = plugin_specs.fqname
        renderer = (renderer or plugin_specs.renderer or self.default_renderer).lower()
        ext = renderer_to_ext(renderer)
        outdir = output_dir or self._default_outdir(memory_dump_path)
        os.makedirs(outdir, exist_ok=True)
        img_name = os.path.basename(memory_dump_path)
        out_path = os.path.join(outdir, f"{img_name}_{plugin_specs.name}.{ext}")

        err_path = out_path + ".stderr.txt"

        cmd = self.build_command(memory_dump_path, renderer, plugin) 
        logger.debug("Command: %s", " ".join(cmd))

        t0 = time.perf_counter()
        rc = 0
        stderr_text = ""
        try:
            with open(out_path, "w", encoding="utf-8") as out:
                proc = subprocess.run(
                    cmd,
                    stdout=out,
                    stderr=subprocess.PIPE,
                    text=True,
                    timeout=(plugin_specs.timeout_s or self.default_timeout_s)
                )
            rc = proc.returncode
            stderr_text = proc.stderr or ""
        except subprocess.TimeoutExpired as e:
            rc = 124
            stderr_text = f"TIMEOUT after {plugin_specs.timeout_s or self.default_timeout_s}s\n{e}\n"
            logger.error("Plugin %s timed out after %ss", plugin_specs.name, plugin_specs.timeout_s or self.default_timeout_s)
        except Exception as e:
            rc = 2
            logger.exception("Plugin %s crashed", plugin_specs.name)
            stderr_text = f"Unhandled exception: {e}\n"

        if stderr_text:
            if not self.version:
                self.version = self._parse_version(stderr_text)
            with open(err_path, "w", encoding="utf-8") as ef:
                ef.write(stderr_text)
        else:
            err_path = None

        runtime = time.perf_counter() - t0
        if rc != 0:
            # The output file was opened before vol ran, so a failure leaves a
            # zero-byte JSON behind. Say so here rather than letting a downstream
            # parser discover it as a confusing "Expected object or value".
            logger.error("Plugin %s failed (rc=%s). %s", plugin_specs.name, rc,
                         self._explain_failure(stderr_text, err_path))
        logger.info("Finished %s rc=%s in %.2fs", plugin_specs.name, rc, runtime)
        return PluginRunResult(rc=rc, runtime_s=runtime, output_path=out_path, stderr_path=err_path,
                            meta={"cmd": cmd, "renderer": renderer})

    @staticmethod
    def _explain_failure(stderr_text: str, err_path: Optional[str]) -> str:
        """Turn Volatility's stderr into one actionable line."""
        text = stderr_text or ""
        if "symbol_table_name" in text or "Symbol file could not be downloaded" in text:
            return ("Volatility could not resolve the kernel symbol table. It tried to "
                    "download the PDB from the Microsoft symbol server; if this host has "
                    "no outbound access, pre-fetch the symbols on a networked machine and "
                    "pass their directory as symbol_dirs (vol -s).")
        if "Unable to validate the plugin requirements" in text:
            return "Volatility rejected the plugin's requirements for this image."
        if text.startswith("TIMEOUT") or "TIMEOUT after" in text:
            return "The plugin exceeded its timeout."
        if err_path:
            return f"See {err_path} for Volatility's output."
        return "No stderr was captured."

    def list_plugins(self) -> List[str]:
        """Parse vol.py -h output to get available plugins (best-effort)."""
        try:
            # print(self.vol_path) 
            cmd = self.resolve_volatility_command() + ["-h"]
            proc = subprocess.run(cmd,capture_output=True, text=True, check=True)
            plugins = []
            for line in proc.stdout.splitlines():
                s = line.strip()
                if s.startswith("windows."):
                    plugins.append(s.split()[0])
            return sorted(set(plugins))
        except Exception as e:
            logger.warning("Could not list plugins: %s", e)
            return []

    def _default_outdir(self, memory_dump_path: str) -> str:
        base = os.path.dirname(os.path.abspath(memory_dump_path))
        return os.path.join(base, ".volmemlyzer")

    def get_version(self) -> str:
        return self.version if self.version else "Unknown"
   
    def resolve_volatility_command(self, explicit: Optional[str] = None) -> List[str]:
        """
        Return a command list suitable for subprocess, e.g.:
        ["vol"]                         # console script
        ["C:\\...\\Scripts\\vol.exe"]   # Windows console script
        [sys.executable, "C:\\...\\vol.py"]  # run vol.py with the current Python
        Raises FileNotFoundError with guidance if not found.
        """
        def _from_hint(hint: str) -> Optional[List[str]]:
            p = Path(hint)
            if p.is_dir():
                p = p / "vol.py"
            if p.exists():
                return [sys.executable, str(p)] if p.suffix.lower() == ".py" else [str(p)]
            return None

        if explicit:
            cmd = _from_hint(explicit)
            if cmd:
                return cmd

        env = os.environ.get("VOL_PATH")
        if env:
            cmd = _from_hint(env)
            if cmd:
                return cmd

        for name in ("vol", "vol.py"):
            found = which(name)
            if found:
                return [found] if not found.endswith(".py") else [sys.executable, found]
        # pip installs the `vol` console script beside the interpreter running us.
        # Look there before anything else volatility3-related: inside a venv whose
        # bin/ is not on PATH (a very common way to invoke this as a library) it is
        # the only reliable handle on the CLI.
        bindir = Path(sys.executable).parent
        for name in ("vol", "vol.exe", "vol.py"):
            candidate = bindir / name
            if candidate.exists():
                return ([sys.executable, str(candidate)] if candidate.suffix == ".py"
                        else [str(candidate)])

        if importlib.util.find_spec("volatility3") is not None:
            # `python -m volatility3` does NOT work: the package has no __main__,
            # and neither does volatility3.cli. Invoking its entry point directly
            # is the only module-based route that actually runs.
            return [sys.executable, "-c",
                    "import sys; from volatility3.cli import main; sys.exit(main())"]

        home = Path.home()
        quick = [
            Path.cwd() / "volatility3" / "vol.py",
            Path.cwd() / "Tools" / "volatility3" / "vol.py",
            Path.cwd() / "tools" / "volatility3" / "vol.py",
            home / "volatility3" / "vol.py",
            home / "Tools" / "volatility3" / "vol.py",
            home / "tools" / "volatility3" / "vol.py",
        ]
        for c in quick:
            if c.exists():
                return [sys.executable, str(c)]

        def _shallow_scan(base: Path, max_depth: int = 3) -> Optional[List[str]]:
            try:
                for path in base.rglob("vol.py"):
                    if len(path.relative_to(base).parts) <= max_depth and path.is_file():
                        return [sys.executable, str(path)]
            except Exception:
                pass
            return None

        for base in [Path.cwd(), home]:
            for root in [base, base / "tools", base / "Tools"]:
                if root.exists():
                    cmd = _shallow_scan(root)
                    if cmd:
                        return cmd

        raise FileNotFoundError(
            "Volatility 3 not found. Install it with `pip install volatility3` "
            "so the `vol` command is available, or provide --vol-path / VOL_PATH "
            "pointing to 'vol' or 'vol.py'."
        )

    @staticmethod
    def _parse_version(stderr_text: str) -> str:
        match = re.search(r"Volatility 3 Framework \d+\.\d+\.\d+", stderr_text)
        if match:
            return match.group(0)   # e.g. "Volatility 3 Framework 2.26.2"
        return None 



