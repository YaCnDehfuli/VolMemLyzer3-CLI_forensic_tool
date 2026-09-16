#!/usr/bin/env python3
# Run DFIR overview steps and inspect the returned summary dict.

import os
from volmemlyzer.runner import VolRunner
from volmemlyzer.plugins import build_registry
from volmemlyzer.pipeline import Pipeline
from volmemlyzer.analysis import OverviewAnalysis


# --- fill these in ---
VOL_PATH = "/opt/volatility3/vol.py"
IMAGE    = "/cases/win10.raw"
OUTDIR   = "/cases/.volmemlyzer"

runner = VolRunner(vol_path=VOL_PATH, default_renderer="json", default_timeout_s=600)
pipe = Pipeline(runner, build_registry())

# `profile` is the scoring engine's tuning profile: a preset, and optionally
# per-rule overrides. Omit it for Balanced, which is what the CLI defaults to.
analysis = OverviewAnalysis(profile={"preset": "balanced"})
summary = analysis.run_steps(
    pipe=pipe,
    image_path=IMAGE,
    artifacts_dir=OUTDIR,
    steps=[0, 1, 2, 3, 4],   # bearings, processes, injections, network, persistence
    use_cache=True,
    high_level=False,
    concurrency=4,     # plugins overlap; each starts when its own inputs are ready
    deep=False,        # True also runs psxview, which dominates the wall clock
)

# Every step renders one engine's output, so a finding carries the rules that
# produced it and their ATT&CK mapping rather than a per-step constant.
print("ATT&CK techniques:", [t["technique_id"]
                             for t in summary["scoring"]["attack_techniques"]])
print("Risk summary:", summary["scoring"]["risk_summary"])
# Plugins a rule wanted to read but this run has no evidence from -- a rule that
# could not fire is a different claim from one that fired and found nothing.
print("Unevaluated sources:", summary["scoring"]["unevaluated_sources"])

for row in summary.get("step1", {}).get("suspicious", []):
    print(f"{row['pid']:>6}  {row['Risk']:<9} {row['score']:>5}  "
          f"{row['name']:<24} {row['flags']}")

# print("[+] Summary keys:", ", ".join(sorted(summary.keys())))
# for step, data in summary.items():
#     print(f"\n=== {step} ===")
#     if isinstance(data, dict):
#         for k, v in list(data.items())[:10]:
#             print(f"{k}: {v}")
#     else:
#         print(repr(data))
