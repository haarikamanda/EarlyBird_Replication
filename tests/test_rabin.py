"""Unit tests for Rabin rolling fingerprint."""

import pytest
from earlybird.rabin import (
    base_power_for_length,
    iter_substring_fingerprints,
    passes_value_sampling,
    rabin_from_bytes,
    rabin_roll,
    value_sampling_mask,
)


def test_rabin_from_bytes_deterministic() -> None:
    data = b"hello world"
    assert rabin_from_bytes(data) == rabin_from_bytes(data)


def test_rabin_roll_vs_recompute() -> None:
    # Rolling update should match full recompute for the same window
    data = b"abcdefghij"
    beta = 4
    base_pow = base_power_for_length(beta)
    # First window
    h0 = rabin_from_bytes(data[:beta])
    assert h0 == rabin_from_bytes(b"abcd")
    # Roll: drop 'a', add 'e'
    h1 = rabin_roll(h0, ord("a"), ord("e"), base_pow)
    assert h1 == rabin_from_bytes(b"bcde")
    # Roll: drop 'b', add 'f'
    h2 = rabin_roll(h1, ord("b"), ord("f"), base_pow)
    assert h2 == rabin_from_bytes(b"cdef")
    # Full sequence
    h = rabin_from_bytes(data[:beta])
    for i in range(beta, len(data)):
        h = rabin_roll(h, data[i - beta], data[i], base_pow)
        assert h == rabin_from_bytes(data[i - beta + 1 : i + 1])


def test_value_sampling_mask() -> None:
    assert value_sampling_mask(0) == 0
    assert value_sampling_mask(6) == (1 << 6) - 1  # 63


def test_passes_value_sampling() -> None:
    # fingerprint with low 6 bits zero
    fp = 0x40  # 64
    assert passes_value_sampling(fp, 6) is True
    assert passes_value_sampling(fp + 1, 6) is False
    assert passes_value_sampling(0, 6) is True


def test_iter_substring_fingerprints_value_sampling() -> None:
    # Only substrings passing value sampling are returned
    data = b"x" * 50
    hashes = iter_substring_fingerprints(data, beta=40, sample_pow=6)
    # All returned hashes should pass sampling
    for h in hashes:
        assert passes_value_sampling(h, 6)
    # Short payload returns empty
    assert iter_substring_fingerprints(b"short", beta=40, sample_pow=6) == []
