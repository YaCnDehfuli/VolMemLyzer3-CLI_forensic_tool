# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project uses [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [4.0.0] - 2026-09-16

One scoring engine. `OverviewAnalysis` used to carry a complete second
implementation of scoring beside `volmemlyzer.scoring`, so the same image could
be scored by different rules depending on which entry point you came through.
That implementation is gone and the analysis steps read the engine.

### Added

- `--preset conservative|balanced|aggressive` on `analyze`, exposing the tuning
  profile's sensitivity: risk-band cut-offs, the confidence floor, and
  per-category surfacing thresholds move together.
- `Hit.subject` / `Contribution.subject` — the artifact row a rule fired on (a
  malfind region's Start VPN, an SSDT entry's target module). A per-region view
  no longer has to recover it by parsing the evidence prose. Additive.
- `volmemlyzer.scoring.catalog.connection_key`, so a caller holding raw netscan
  rows can join them to the scored object without respelling its identity.
- Step results carry the engine's ATT&CK roll-up, the effective profile, and the
  plugins no rule could read (`unevaluated_sources`).

### Changed

- Findings carry the ATT&CK technique of the rule that produced them, rather
  than one constant per category. A process flagged for an lsass handle is no
  longer reported as Masquerading.
- `--min-risk` and `--high-level` are implemented against the tuning profile.
  They mean what they meant; the ladder now has one definition.
- UserAssist tool matching is by basename stem with a trailing 32/64 stripped,
  restoring the full 35-name list the scoring merge had cut to twelve — pafish,
  seatbelt, plink, adfind and pwdump are recognised again. More precise than the
  substring test it replaces: "nc" inside "concat" is not netcat.

### Removed

- **Breaking.** `OverviewAnalysis` no longer scores: every `_score_*` method,
  `SURFACE_THRESHOLDS`, `RISK_BANDS`, `MIN_RISK`, `_risk_from_score`,
  `_score_map`, `_keep` and their private helpers. `MAX_RISK_SCORE` and the
  bands come from `volmemlyzer.scoring`. Step payloads keep their shapes and
  gain per-row score, confidence and techniques; step 2 findings gain
  `start_vpn`.

### Notes

The engine itself landed in 3.2.0 (merged rule model, MITRE attribution) and was
calibrated in 3.3.0 against a reference image; neither was published. Scoring is
unchanged by this release: `score_records` over the reference artifacts is
identical per object, contribution and weight.

## [3.1.0] - 2026-09-10

This release makes the analyst-facing triage layer bounded, inspectable, and
explicit about the limits of its validation evidence.

### Added

- Extract-parallelism benchmark (`benchmarks/`) with serial, parallel, and cache-warm
  configurations, raw `results.json`, and a CI stub job that fails on harness drift.
- GitHub Actions workflow for unit tests and the stub benchmark.
- Exact rule specification covering input fields, regular expressions, byte
  patterns, evidence families, thresholds, score weights, false-positive
  controls, and appropriately qualified ATT&CK mappings.
- Cache-only validation of the completed `2580_5.vmem` artifact set, including
  the observed PowerShell → `Z:\malware.exe` PID 7936 example.
- Self-contained interactive evidence report with searchable views of the
  analysis rules and all 520 extracted features.
- Deep-only SSDT foreign-module surfacing with duplicate findings grouped by
  module.

### Changed

- README first screen now shows the three-config extract wall-clock figure
  generated from `benchmarks/results.json`.
- Scores use evidence-family correlation, a 9-point review threshold, and a
  hard 30-point ceiling. Values are ordinal review priorities, not probability
  or malware verdicts.
- Quick analysis excludes high-cost scanning plugins; deep-only evidence stays
  explicitly unavailable when an artifact is absent or failed.
- Published validation now includes only the completed `2580_5.vmem` cache.
  Additional images can be added after their required artifacts are complete.

### Fixed

- `extract -f json` no longer fails when a feature is a pandas `Timestamp`
  (`info.SystemTime` and similar).
- Correlated or duplicate observations no longer inflate severity, and normal
  cross-view agreement no longer earns suspiciousness points.

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

[Unreleased]: https://github.com/YaCnDehfuli/VolMemLyzer3-CLI_forensic_tool/compare/v4.0.0...HEAD
[4.0.0]: https://github.com/YaCnDehfuli/VolMemLyzer3-CLI_forensic_tool/releases/tag/v4.0.0
[3.1.0]: https://github.com/YaCnDehfuli/VolMemLyzer3-CLI_forensic_tool/releases/tag/v3.1.0
[3.0.1]: https://github.com/YaCnDehfuli/VolMemLyzer3-CLI_forensic_tool/releases/tag/v3.0.1
