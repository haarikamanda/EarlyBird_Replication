"""Address dispersion: approximate distinct source/destination IP counts (scaled bitmap)."""

from __future__ import annotations

import math
from typing import Any

def _ip_hash(ip: str | bytes, seed: int) -> int:
    if isinstance(ip, bytes):
        if len(ip) >= 4:
            v = int.from_bytes(ip[:4], "big")
        else:
            v = hash(ip) & 0xFFFFFFFF
    else:
        parts = ip.split(".")
        v = sum(int(p) << (8 * (3 - i)) for i, p in enumerate(parts[:4]))
    return (v * (31 + seed)) & 0xFFFFFFFF_FFFFFFFF


def scaled_bitmap_estimate(bits_set: int, bitmap_bits: int) -> int:
    if bits_set <= 0:
        return 0
    if bits_set >= bitmap_bits:
        return bits_set
    ratio = bits_set / bitmap_bits
    est = -bitmap_bits * math.log1p(-ratio)
    return max(bits_set, int(round(est)))


class ScaledBitmap:
    def __init__(self, num_bits: int) -> None:
        self.bits = num_bits
        self.bitmap = bytearray((num_bits + 7) // 8)
        self.bits_set = 0

    def add(self, ip: str | bytes, seed: int = 0) -> bool:
        h = _ip_hash(ip, seed) % self.bits
        byte_idx = h // 8
        bit_idx = h % 8
        mask = 1 << bit_idx
        if self.bitmap[byte_idx] & mask:
            return False
        self.bitmap[byte_idx] |= mask
        self.bits_set += 1
        return True

    def estimate(self) -> int:
        return scaled_bitmap_estimate(self.bits_set, self.bits)


class DispersionTracker:
    def __init__(self, bitmap_bits: int, ad_ttl_sec: float) -> None:
        self.bitmap_bits = bitmap_bits
        self.ad_ttl_sec = ad_ttl_sec
        self.src_bitmaps: dict[tuple[Any, ...], ScaledBitmap] = {}
        self.dst_bitmaps: dict[tuple[Any, ...], ScaledBitmap] = {}
        self.last_seen: dict[tuple[Any, ...], float] = {}

    def _get_or_create_src(self, content_key: tuple[Any, ...], now: float) -> ScaledBitmap:
        if content_key not in self.src_bitmaps:
            self.src_bitmaps[content_key] = ScaledBitmap(self.bitmap_bits)
            self.last_seen[content_key] = now
        else:
            self.last_seen[content_key] = now
        return self.src_bitmaps[content_key]

    def _get_or_create_dst(self, content_key: tuple[Any, ...], now: float) -> ScaledBitmap:
        if content_key not in self.dst_bitmaps:
            self.dst_bitmaps[content_key] = ScaledBitmap(self.bitmap_bits)
            self.last_seen[content_key] = now
        else:
            self.last_seen[content_key] = now
        return self.dst_bitmaps[content_key]

    def add(
        self,
        content_key: tuple[Any, ...],
        src_ip: str | bytes,
        dst_ip: str | bytes,
        timestamp: float,
    ) -> tuple[int, int]:
        src_bm = self._get_or_create_src(content_key, timestamp)
        dst_bm = self._get_or_create_dst(content_key, timestamp)
        src_bm.add(src_ip, 0)
        dst_bm.add(dst_ip, 1)
        return src_bm.estimate(), dst_bm.estimate()

    def get_estimates(self, content_key: tuple[Any, ...]) -> tuple[int, int]:
        src_est = self.src_bitmaps[content_key].estimate() if content_key in self.src_bitmaps else 0
        dst_est = self.dst_bitmaps[content_key].estimate() if content_key in self.dst_bitmaps else 0
        return src_est, dst_est
