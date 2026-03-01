"""Unit tests for prevalence sketch (conservative update, threshold)."""

import pytest
from earlybird.prevalence import PrevalenceSketch


def test_conservative_update_single_key() -> None:
    sketch = PrevalenceSketch(depth=4, width=256, window_sec=60.0, port_mode="dst")
    ts = 1000.0
    for _ in range(5):
        sketch.add("udp", 12345, 53, 0xDEAD, ts)
    assert sketch.estimate("udp", 12345, 53, 0xDEAD, ts) >= 5


def test_threshold_crossing() -> None:
    sketch = PrevalenceSketch(depth=4, width=256, window_sec=60.0, port_mode="dst")
    ts = 1000.0
    threshold = 3
    assert sketch.add_and_check("udp", 1, 53, 0xA, ts, threshold) is False
    assert sketch.add_and_check("udp", 1, 53, 0xA, ts, threshold) is False
    assert sketch.add_and_check("udp", 1, 53, 0xA, ts, threshold) is True
    assert sketch.add_and_check("udp", 1, 53, 0xA, ts, threshold) is True


def test_different_keys_different_counts() -> None:
    sketch = PrevalenceSketch(depth=4, width=256, window_sec=60.0, port_mode="dst")
    ts = 1000.0
    for _ in range(2):
        sketch.add("udp", 1, 53, 0xAAA, ts)
    for _ in range(4):
        sketch.add("udp", 1, 53, 0xBBB, ts)
    assert sketch.estimate("udp", 1, 53, 0xAAA, ts) >= 2
    assert sketch.estimate("udp", 1, 53, 0xBBB, ts) >= 4
