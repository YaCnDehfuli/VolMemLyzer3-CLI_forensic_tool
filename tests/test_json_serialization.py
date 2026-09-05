"""extract -f json must accept pandas timestamps from windows.info."""
from __future__ import annotations

import json
from pathlib import Path

import pandas as pd

from volmemlyzer.utilities import to_builtin, write_json


def test_to_builtin_turns_a_timestamp_into_an_iso_string():
    ts = pd.to_datetime("2024-01-02T03:04:05Z", utc=True)
    assert to_builtin(ts) == ts.isoformat()


def test_to_builtin_turns_nat_into_none():
    assert to_builtin(pd.NaT) is None


def test_write_json_accepts_a_feature_row_with_system_time(tmp_path: Path):
    path = tmp_path / "row.json"
    write_json(str(path), {
        "features": {"info.SystemTime": pd.to_datetime("2024-06-01T12:00:00Z", utc=True)},
    })
    data = json.loads(path.read_text(encoding="utf-8"))
    assert "2024-06-01" in data["features"]["info.SystemTime"]
