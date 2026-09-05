# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project uses [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Extract-parallelism benchmark (`benchmarks/`) with serial, parallel, and cache-warm
  configurations, raw `results.json`, and a CI stub job that fails on harness drift.
- GitHub Actions workflow for unit tests and the stub benchmark.

### Changed

- README first screen now shows the three-config extract wall-clock figure
  generated from `benchmarks/results.json`.

### Fixed

- `extract -f json` no longer fails when a feature is a pandas `Timestamp`
  (`info.SystemTime` and similar).

## [3.0.1] - 2026-09-05

GitHub snapshot aligned with the published PyPI package `volmemlyzer==3.0.1`.
This is not a new PyPI upload.

### Added

- Packaged `volmemlyzer` CLI: `analyze`, `run`, `extract`, `list`.
- `src/` layout, extractor registry, FEATURES.md catalog.
- Parallel plugin execution with timeouts, renderers, and artifact cache.
- DFIR overview steps (bearings, processes, injections, network, persistence, kernel, report).
- Legacy `main.py` compatibility shim.
- GPL-3.0-or-later license clarification and CLI help screenshot.

### Changed

- Plugins scheduled on a dependency graph instead of lockstep layers (`f129420` and following).
- Plugin names resolved against the installed Volatility (including `windows.malware.*` relocations).
- Analysis steps scored on one risk ladder; `--deep` gates `psxview`.
- Injected-code scoring separated from JIT output.
- `pyproject.toml` version restored to 3.0.1 so it matches `__version__` and the published PyPI line.

### Fixed

- Survive a failed plugin; air-gapped symbol directories.
- Locate the `vol` CLI without printing plugin output to stdout.
- Windows paths resolved as the image wrote them, not as the host spells them.
- Progress bar no longer archived as an artifact.

[3.0.1]: https://github.com/YaCnDehfuli/VolMemLyzer3-CLI_forensic_tool/releases/tag/v3.0.1
