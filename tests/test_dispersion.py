"""Unit tests for dispersion (scaled bitmap monotonicity, distinct count)."""

import pytest
from earlybird.dispersion import DispersionTracker, ScaledBitmap, scaled_bitmap_estimate


def test_scaled_bitmap_estimate_monotonic() -> None:
    # More bits set -> higher estimate
    prev = 0
    for n in range(1, 100, 10):
        est = scaled_bitmap_estimate(n, 2048)
        assert est >= prev
        assert est >= n
        prev = est


def test_scaled_bitmap_distinct_sanity() -> None:
    bm = ScaledBitmap(256)
    bm.add("1.2.3.4", 0)
    bm.add("1.2.3.4", 0)  # same IP
    bm.add("5.6.7.8", 0)
    assert bm.bits_set <= 2
    assert bm.estimate() >= 1


def test_dispersion_tracker_add_and_estimates() -> None:
    dt = DispersionTracker(bitmap_bits=512, ad_ttl_sec=3600.0)
    key = ("udp", 53, 0xABC)
    ts = 1000.0
    src_est, dst_est = dt.add(key, "1.1.1.1", "2.2.2.2", ts)
    assert src_est >= 1 and dst_est >= 1
    dt.add(key, "1.1.1.1", "3.3.3.3", ts)  # same src, new dst
    src_est2, dst_est2 = dt.get_estimates(key)
    assert dst_est2 >= 2
