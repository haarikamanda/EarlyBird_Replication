"""Configuration for EarlyBird detection pipeline."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal

PortMode = Literal["dst", "src", "both"]
ContentMode = Literal["whole", "substring"]


@dataclass
class Config:
    """Detection parameters (paper-aligned defaults)."""

    # Content extraction
    mode: ContentMode = "substring"
    beta: int = 40  # substring length (bytes)
    sample_pow: int = 6  # value sampling: 1/2^k

    # Prevalence (heavy-hitter)
    prevalence_th: int = 3
    prevalence_window_sec: float = 60.0
    # Sketch dimensions (count-min style)
    sketch_depth: int = 4
    sketch_width: int = 4096

    # Dispersion
    src_disp_th: int = 10
    dst_disp_th: int = 10
    ad_ttl_sec: float = 3600.0 * 2  # 2 hours
    # Scaled bitmap size for distinct count
    bitmap_bits: int = 2048

    # Port binding
    port_mode: PortMode = "dst"

    # Partial payload / truncation
    truncate: int | None = None  # cap payload to N bytes if set

    # Bounded run (smoke / eval)
    max_files: int = 1
    max_packets: int = 50_000

    def __post_init__(self) -> None:
        if self.beta < 1:
            raise ValueError("beta must be >= 1")
        if self.sample_pow < 0 or self.sample_pow > 16:
            raise ValueError("sample_pow must be in 0..16")
        if self.prevalence_th < 1:
            raise ValueError("prevalence_th must be >= 1")
        if self.sketch_depth < 1 or self.sketch_width < 1:
            raise ValueError("sketch dimensions must be positive")
        if self.bitmap_bits < 64:
            raise ValueError("bitmap_bits must be >= 64")
