"""Rabin rolling fingerprint for substring content hashing.

Paper: substring hashing via Rabin fingerprints; value sampling uses
fingerprint & ((1<<k)-1) == 0.
"""

from __future__ import annotations

# 64-bit prime for modular arithmetic (avoids overflow in 64-bit)
_RABIN_PRIME = (1 << 61) - 1
_RABIN_BASE = 256


def _mod_mul(a: int, b: int, m: int) -> int:
    """(a * b) % m without overflow (for 64-bit-friendly values)."""
    return (a * b) % m


def rabin_init() -> int:
    """Return initial fingerprint value (empty string)."""
    return 0


def rabin_from_bytes(data: bytes) -> int:
    """Compute Rabin fingerprint for entire byte string (no rolling)."""
    h = 0
    for b in data:
        h = (h * _RABIN_BASE + b) % _RABIN_PRIME
    return h


def rabin_roll(
    current: int,
    out_byte: int,
    in_byte: int,
    base_power: int,
) -> int:
    """Roll fingerprint: drop out_byte, add in_byte.
    base_power must be base^(length-1) % prime for the window length.
    """
    # current = hash(s[0..L-1])
    # new = (current - out_byte * base^(L-1)) * base + in_byte
    term = _mod_mul(out_byte, base_power, _RABIN_PRIME)
    h = (current - term) % _RABIN_PRIME
    h = (h * _RABIN_BASE + in_byte) % _RABIN_PRIME
    return h


def base_power_for_length(length: int) -> int:
    """Precompute base^(length-1) % prime for rolling window of given length."""
    if length <= 0:
        return 1
    p = 1
    for _ in range(length - 1):
        p = _mod_mul(p, _RABIN_BASE, _RABIN_PRIME)
    return p


def value_sampling_mask(k: int) -> int:
    """Return (1<<k)-1 for value sampling: accept when (fp & mask)==0."""
    if k <= 0:
        return 0
    return (1 << k) - 1


def passes_value_sampling(fingerprint: int, k: int) -> bool:
    """True iff fingerprint & ((1<<k)-1) == 0 (sample rate 1/2^k)."""
    if k <= 0:
        return True
    return (fingerprint & value_sampling_mask(k)) == 0


def iter_substring_fingerprints(
    payload: bytes,
    beta: int,
    sample_pow: int,
) -> list[int]:
    """Yield Rabin fingerprints for every substring of length beta in payload.
    Only includes substrings that pass value sampling (fingerprint & ((1<<k)-1)==0).
    Returns list of hashes (for prevalence key use).
    """
    if len(payload) < beta:
        return []
    out: list[int] = []
    base_pow = base_power_for_length(beta)
    # First window
    h = rabin_from_bytes(payload[:beta])
    if passes_value_sampling(h, sample_pow):
        out.append(h)
    for i in range(beta, len(payload)):
        h = rabin_roll(
            h,
            payload[i - beta],
            payload[i],
            base_pow,
        )
        if passes_value_sampling(h, sample_pow):
            out.append(h)
    return out
