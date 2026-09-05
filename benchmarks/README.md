# Extract parallelism benchmark

Measures wall-clock of `volmemlyzer extract` on one image and the plugin list
in `plugins.yaml` / `PINNED_PLUGINS` (the requested triage set that exists
in the registry). Byte-walk, dump, and pool-wide scanners stay out —
see the comments in `plugins.yaml`.

Configurations, each repeated three times:

1. **serial** — `--jobs 1 --no-cache`, fresh outdir
2. **parallel** — default worker count (`max(1, cpu_count // 2)`), `--no-cache`, fresh outdir
3. **cache-warm** — re-run after a completed populate so plugin artifacts hit cache

Summary is median with min/max of successful runs. Failed runs are logged and
left out of the median; they are not replaced.

The hardware image used for `results.json` is a local dump. It is not in this
repository and must not be committed.

## Re-run

```bash
python -m pip install -e .
python benchmarks/run_benchmark.py --image /path/to/image.vmem --runs 3
```

CLI flags: `--image`, `--jobs`, `--runs`, `--plugins-file`, `--plugins`,
`--timeout`, `--vol-path`, `--work-dir`.

CI uses the stub image and `fixtures/vol.py`:

```bash
python benchmarks/run_benchmark.py --ci --check --runs 3 --jobs 2
```
