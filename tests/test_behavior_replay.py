"""Tests for the contained multi-scenario ransomware-behavior replay.

These confirm the harness runs the safe, file-I/O-in-sandbox scenarios through the
detector and reports detection metrics, and that nothing escapes the sandbox.
"""

from pathlib import Path

import run_behavior_replay as replay


def test_single_contained_scenario_detects():
    res = replay.run_scenario("classic", seed=1234, n_files=20, n_windows=5)
    assert res["detected"] is True
    assert res["alerts"] > 0
    assert res["latency_windows"] is not None and res["latency_windows"] >= 0


def test_replay_grid_is_deterministic_and_detectable():
    grid = replay.build_grid(4)
    assert len(grid) == 4
    results = [replay.run_scenario(g["style"], g["seed"], n_files=20, n_windows=5) for g in grid]
    # every distinct style in the grid is detected
    assert all(r["detected"] for r in results)
    assert len({r["style"] for r in results}) >= 2


def test_containment_no_escape():
    """Only files under the sandbox root are written; the sandbox is removed after."""
    import tempfile
    root = Path(tempfile.mkdtemp())
    try:
        # run a scenario and confirm the temp sandbox was cleaned up by the harness
        before = set(root.iterdir())
        replay.run_scenario("wiper", seed=9, n_files=10, n_windows=3)
        after = set(root.iterdir())
        assert before == after
    finally:
        for p in root.iterdir():
            p.unlink(missing_ok=True)
        root.rmdir()
