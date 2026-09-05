# VolMemLyzer extract benchmark

Extracting `10` plugins from a `4412228315`-byte Windows image takes `172.16`s serially and `71.12`s with `4` workers — a `2.4×` reduction in wall-clock. Median of 3 runs on `Intel(R) Core(TM) i7-1068NG7 CPU @ 2.30GHz, 8 logical cores, 17179869184 bytes RAM, macOS 26.6.2`. Full method and raw results in `benchmarks/`.

## Method

Command: `volmemlyzer extract` on one image and the plugin list in `plugins.yaml`.
Serial and parallel use `--no-cache` and a fresh outdir each run.
Cache-warm is a timed re-run against artifacts from a completed populate.
Each configuration is three runs. Summary is median with min/max of successful runs.
The local image is not redistributed.

- Plugins (10): `pslist, pstree, dlllist, cmdline, registry.hivelist, modules, svcscan, getsids, privileges, envars`
- Extractor functions in tree: `72`
- Registered plugins: `56`
- Volatility 3: `2.28.0`
- Image SHA-256: `777d71d7106e5ded19592c075058da12049bfcd658221e70f0579ad4bbd9cff4`
- Image size (bytes): `4412228315`
- Image redistributed: `False`
- Host: `Intel(R) Core(TM) i7-1068NG7 CPU @ 2.30GHz, 8 logical cores, 17179869184 bytes RAM, macOS 26.6.2`

## Wall-clock (seconds)

| config | workers | cache | n ok | median | min | max |
|---|---:|---|---:|---:|---:|---:|
| serial | 1 | off | 3 | 172.16 | 166.57 | 173.79 |
| parallel | 4 | off | 3 | 71.12 | 69.49 | 73.50 |
| cache-warm | 4 | on | 3 | 3.1517 | 3.1483 | 3.4141 |

## Peak RSS (bytes)

| config | median | min | max |
|---|---:|---:|---:|
| serial | 305246208 | 304570368 | 306839552 |
| parallel | 613306368 | 612306944 | 616222720 |
| cache-warm | 110272512 | 110198784 | 111624192 |
