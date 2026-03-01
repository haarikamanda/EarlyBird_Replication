"""Content prevalence (heavy-hitter) via count-min sketch with conservative update.

Paper: multi-stage filter / count-min-ish sketch; conservative update.
"""

from __future__ import annotations

from typing import Any

from earlybird.config import Config, PortMode


def _hash_key(key: tuple[Any, ...], seed: int, width: int) -> int:
    """Stable hash of key to [0, width-1]."""
    h = seed
    for x in key:
        h = (h * 31 + hash(x)) & 0xFFFFFFFF_FFFFFFFF
    return (h % width + width) % width


class PrevalenceSketch:
    """Count-min style sketch with conservative update.
    Keys: (proto, port_info, content_hash) per port_mode.
    """

    __slots__ = (
        "depth",
        "width",
        "counters",
        "window_start",
        "window_sec",
        "port_mode",
    )

    def __init__(
        self,
        depth: int,
        width: int,
        window_sec: float,
        port_mode: PortMode,
    ) -> None:
        self.depth = depth
        self.width = width
        self.counters: list[list[int]] = [[0] * width for _ in range(depth)]
        self.window_start: float = 0.0  # set from first packet timestamp
        self.window_sec = window_sec
        self.port_mode = port_mode

    def _content_key(
        self,
        proto: str,
        src_port: int,
        dst_port: int,
        content_hash: int,
    ) -> tuple[Any, ...]:
        if self.port_mode == "dst":
            return (proto, dst_port, content_hash)
        if self.port_mode == "src":
            return (proto, src_port, content_hash)
        return (proto, (dst_port, src_port), content_hash)

    def _indices(self, key: tuple[Any, ...]) -> list[int]:
        return [_hash_key(key, s, self.width) for s in range(self.depth)]

    def _maybe_reset(self, now: float) -> None:
        if self.window_start == 0.0:
            self.window_start = now
        elif now - self.window_start >= self.window_sec:
            for row in self.counters:
                for j in range(self.width):
                    row[j] = 0
            self.window_start = now

    def add(
        self,
        proto: str,
        src_port: int,
        dst_port: int,
        content_hash: int,
        timestamp: float,
    ) -> None:
        """Record one occurrence; conservative update: only increment minimum counter."""
        self._maybe_reset(timestamp)
        key = self._content_key(proto, src_port, dst_port, content_hash)
        idx = self._indices(key)
        vals = [self.counters[i][idx[i]] for i in range(self.depth)]
        min_val = min(vals)
        for i in range(self.depth):
            if self.counters[i][idx[i]] == min_val:
                self.counters[i][idx[i]] += 1
                # conservative: increment every counter that has the minimum (so estimate stays correct)

    def estimate(
        self,
        proto: str,
        src_port: int,
        dst_port: int,
        content_hash: int,
        timestamp: float,
    ) -> int:
        """Return minimum of the d counters (count-min estimate)."""
        self._maybe_reset(timestamp)
        key = self._content_key(proto, src_port, dst_port, content_hash)
        idx = self._indices(key)
        return min(self.counters[i][idx[i]] for i in range(self.depth))

    def add_and_check(
        self,
        proto: str,
        src_port: int,
        dst_port: int,
        content_hash: int,
        timestamp: float,
        threshold: int,
    ) -> bool:
        """Add one occurrence and return True if estimated count >= threshold after update."""
        self.add(proto, src_port, dst_port, content_hash, timestamp)
        return self.estimate(proto, src_port, dst_port, content_hash, timestamp) >= threshold
