"""Content key extraction: whole payload and substring (Rabin) with value sampling."""

from __future__ import annotations

import hashlib
from typing import Any

from earlybird.config import Config, PortMode
from earlybird.rabin import iter_substring_fingerprints, rabin_from_bytes


def hash_whole(payload: bytes) -> int:
    """Hash entire payload (for whole mode). Use first 8 bytes of SHA256 as int."""
    if not payload:
        return 0
    h = hashlib.sha256(payload).digest()
    return int.from_bytes(h[:8], "big")


def content_key(
    port_mode: PortMode,
    proto: str,
    src_port: int,
    dst_port: int,
    content_hash: int,
) -> tuple[Any, ...]:
    """Build content key tuple for prevalence/dispersion."""
    if port_mode == "dst":
        return (proto, dst_port, content_hash)
    if port_mode == "src":
        return (proto, src_port, content_hash)
    return (proto, (dst_port, src_port), content_hash)


def extract_whole(payload: bytes) -> list[int]:
    """Extract single content hash for whole payload. Returns empty list if no payload."""
    if not payload:
        return []
    return [hash_whole(payload)]


def extract_substrings(
    payload: bytes,
    beta: int,
    sample_pow: int,
) -> list[int]:
    """Extract content hashes for substrings (Rabin, value-sampled). If len(payload) < beta, return []."""
    if len(payload) < beta:
        return []
    return list(
        iter_substring_fingerprints(payload, beta, sample_pow)
    )


def extract_content_hashes(
    payload: bytes,
    mode: str,
    beta: int,
    sample_pow: int,
) -> list[int]:
    """Extract content hashes for the given mode. Applies truncation externally (caller caps payload)."""
    if mode == "whole":
        return extract_whole(payload)
    return extract_substrings(payload, beta, sample_pow)
