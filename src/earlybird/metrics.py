"""Payload usability and processing rate metrics."""

from __future__ import annotations

import time
from dataclasses import dataclass, field


@dataclass
class PayloadStats:
    """Payload length stats for usability (Witty partial payloads)."""

    total: int = 0
    zero_len: int = 0
    below_beta: int = 0
    sizes: list[int] = field(default_factory=list)  # optional histogram; we keep last N or sample

    def __post_init__(self) -> None:
        self._beta: int = 40  # set via set_beta

    def set_beta(self, beta: int) -> None:
        self._beta = beta

    def record(self, payload_len: int) -> None:
        self.total += 1
        if payload_len == 0:
            self.zero_len += 1
        if payload_len < self._beta:
            self.below_beta += 1
        # Keep a bounded sample of sizes for distribution (e.g. first 100k)
        if len(self.sizes) < 100_000:
            self.sizes.append(payload_len)

    @property
    def frac_zero(self) -> float:
        if self.total == 0:
            return 0.0
        return self.zero_len / self.total

    @property
    def frac_below_beta(self) -> float:
        if self.total == 0:
            return 0.0
        return self.below_beta / self.total

    def to_dict(self) -> dict:
        return {
            "total_packets": self.total,
            "payload_zero_count": self.zero_len,
            "payload_below_beta_count": self.below_beta,
            "frac_payload_zero": round(self.frac_zero, 6),
            "frac_payload_below_beta": round(self.frac_below_beta, 6),
        }


@dataclass
class RunMetrics:
    """Processing rate and run summary."""

    packets_processed: int = 0
    bytes_processed: int = 0
    start_time: float = field(default_factory=time.monotonic)
    alarms_count: int = 0
    first_alarm_time: float | None = None

    @property
    def elapsed_sec(self) -> float:
        return time.monotonic() - self.start_time

    @property
    def packets_per_sec(self) -> float:
        if self.elapsed_sec <= 0:
            return 0.0
        return self.packets_processed / self.elapsed_sec

    @property
    def bytes_per_sec(self) -> float:
        if self.elapsed_sec <= 0:
            return 0.0
        return self.bytes_processed / self.elapsed_sec
