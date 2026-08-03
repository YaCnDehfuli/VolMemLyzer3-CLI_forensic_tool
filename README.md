# VolMemLyzer

[![License: GPL v3+](https://img.shields.io/badge/License-GPLv3%2B-blue.svg)](LICENSE)
![Python](https://img.shields.io/badge/Python-3.9%2B-blue)
![Volatility](https://img.shields.io/badge/Volatility-3.x-black)

VolMemLyzer is a memory-forensics toolkit built around Volatility 3. It provides a command-line interface and Python API for repeatable plugin execution, feature extraction, and analyst-oriented DFIR triage.

## Capabilities

- Run Volatility 3 plugins concurrently with configurable timeouts and renderers.
- Reuse cached artifacts and convert compatible output formats when possible.
- Extract stable, flat features to CSV or JSON for research and machine-learning workflows.
- Analyze system context, processes, possible code injection, network activity, and persistence indicators.
- Process a single memory image or a directory of images.

The complete feature schema is documented in [FEATURES.md](FEATURES.md). 

![VolMemLyzer-v3 CLI Help Page (Published to PyPI : `https://pypi.org/project/volmemlyzer/`)](examples/VolMemLyzer.png)

## Requirements

- Python 3.9 or later
- A supported Volatility 3 installation

VolMemLyzer resolves Volatility in this order: an explicit `--vol-path` or `VOL_PATH` value, the installed `volatility3` Python module, the `vol` command on `PATH`, and common local `vol.py` locations.

## Installation

Clone the V3 development repository and install the package:

```bash
git clone https://github.com/YaCnDehfuli/VolMemLyzer3-CLI_forensic_tool.git
cd VolMemLyzer3-CLI_forensic_tool
python -m pip install -e .
```

Confirm that the CLI is available:

```bash
volmemlyzer --help
```

## Quick start

Analyze a memory image with the default workflow:

```bash
volmemlyzer analyze -i /cases/host.vmem
```

Run selected Volatility plugins:

```bash
volmemlyzer run -i /cases/host.vmem --plugins pslist,pstree,psscan
```

Extract features from one image:

```bash
volmemlyzer extract -i /cases/host.vmem -f csv
```

Extract features recursively from a directory:

```bash
volmemlyzer extract -i /cases -f json
```

List registered extractors and available Volatility plugins:

```bash
volmemlyzer list
```

## CLI reference

Global options must appear before the subcommand:

```text
--vol-path PATH     Path to vol or vol.py; auto-detected when omitted
--renderer NAME     json, jsonl, csv, pretty, quick, or none
--timeout SECONDS   Per-plugin timeout; 0 disables the timeout
-j, --jobs N        Number of parallel workers
--log-level LEVEL   CRITICAL, ERROR, WARNING, INFO, or DEBUG
```

### `analyze`

Runs the DFIR overview for a single image.

```bash
volmemlyzer \
  --vol-path /opt/volatility3/vol.py \
  --renderer json \
  --timeout 600 \
  -j 4 \
  analyze \
  -i /cases/host.vmem \
  -o /cases/.volmemlyzer \
  --steps 0,1,2,3,4 \
  --json
```

Use `--no-cache` to force fresh plugin runs. Supported step aliases include `bearings`, `processes`, `injections`, `network`, `persistence`, `kernel`, and `report`.

### `run`

Runs raw Volatility plugins and stores their artifacts.

```bash
volmemlyzer \
  --renderer json \
  -j 4 \
  run \
  -i /cases/host.vmem \
  -o /cases/.volmemlyzer \
  --plugins pslist,pstree,psscan
```

Use either `--plugins` to include specific plugins or `--drop` to exclude plugins; do not combine them.

### `extract`

Runs the required plugins and writes ML-ready features.

```bash
volmemlyzer \
  -j 4 \
  extract \
  -i /cases \
  -o /cases/.volmemlyzer \
  -f csv \
  --drop netscan
```

For directory input, VolMemLyzer scans supported memory-image extensions recursively and writes one feature file per image under `<outdir>/features/`.

### `list`

Shows registered feature extractors, detected Volatility plugins, or both.

```bash
volmemlyzer list --registry
volmemlyzer list --vol --grep process
```

Run `volmemlyzer <command> --help` for the complete option list.

## Legacy compatibility command

`main.py` remains available for scripts written for earlier releases. It can process a file or directory and produce one aggregated feature file:

```bash
python main.py \
  -f /cases \
  -o /cases/output \
  -V /opt/volatility3/vol.py \
  -F csv
```

New integrations should use the packaged `volmemlyzer` command.

## Outputs and caching

- Raw plugin artifacts are written under the selected output directory.
- Extracted features are written under `<outdir>/features/`.
- Existing artifacts are reused unless `--no-cache` is supplied.
- JSON is the recommended renderer for downstream feature extraction.

## Troubleshooting

- If Volatility cannot be found, pass `--vol-path` or set `VOL_PATH`.
- If an artifact cannot be written, confirm that `--outdir` names a writable directory.
- Quote paths that contain spaces, especially on Windows.
- If a cached artifact cannot be converted to the requested format, VolMemLyzer reruns the plugin with the selected renderer.

## Citation

For background on VolMemLyzer V1 and V2, cite:

> A. H. Lashkari, B. Li, T. L. Carrier, and G. Kaur, “VolMemLyzer: Volatile Memory Analyzer for Malware Classification using Feature Engineering,” 2021 RDAAPS, pp. 1–8. DOI: [10.1109/RDAAPS48126.2021.9452028](https://doi.org/10.1109/RDAAPS48126.2021.9452028).

## Team

- [Arash Habibi Lashkari](http://ahlashkari.com/index.asp) — founder and project owner
- [Yasin Dehfouli](https://github.com/YaCnDehfuli) — V3 developer and maintainer
- [Abhay Pratap Singh](https://github.com/Abhay-Sengar) — V2 researcher and developer
- [Beiqi Li](https://github.com/beiqil) — V1 developer
- [Tristan Carrier](https://github.com/TristanCarrier) — V1 researcher and developer
- [Gurdip Kaur](https://www.linkedin.com/in/gurdip-kaur-738062164/) — researcher

## Acknowledgments

This project received support from the Natural Sciences and Engineering Research Council of Canada (NSERC), grant RGPIN-2020-04701 awarded to Arash Habibi Lashkari, and from the Mitacs Globalink Research Internship program.

## License

VolMemLyzer is free software licensed under the [GNU General Public License, version 3 or later](LICENSE). This license applies to the repository; Volatility and other dependencies remain subject to their own licenses.
