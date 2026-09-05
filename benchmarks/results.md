# VolMemLyzer extract benchmark

Extracting `11` plugins from a `4412228315`-byte Windows image takes `90.81`s serially and `30.06`s with `4` workers — a `3.0×` reduction in wall-clock. Median of 3 runs on `Intel(R) Core(TM) i7-1068NG7 CPU @ 2.30GHz, 8 logical cores, 17179869184 bytes RAM, macOS 26.6.2`. Full method and raw results in `benchmarks/`.

## Method

Command: `volmemlyzer extract` on one image and the plugin list in `plugins.yaml`.
Serial and parallel use `--no-cache` and a fresh outdir each run.
Cache-warm is a timed re-run against artifacts from a completed populate.
Each configuration is three runs. Summary is median with min/max of successful runs.
The local image is not redistributed.

- Plugins (11): `info, pslist, pstree, cmdline, modules, envars, getsids, privileges, registry.hivelist, registry.userassist, scheduled_tasks`
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
| serial | 1 | off | 3 | 90.81 | 87.16 | 123.96 |
| parallel | 4 | off | 3 | 30.06 | 30.02 | 32.21 |
| cache-warm | 4 | on | 3 | 1.4265 | 1.4220 | 1.4309 |

## Peak RSS (bytes)

| config | median | min | max |
|---|---:|---:|---:|
| serial | 200589312 | 199884800 | 201408512 |
| parallel | 503681024 | 498274304 | 510971904 |
| cache-warm | 106688512 | 106278912 | 107880448 |
