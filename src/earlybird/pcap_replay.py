"""Pcap discovery and replay in timestamp order per file."""

from __future__ import annotations

import gzip
import os
import socket
from pathlib import Path
from typing import Generator

import dpkt

from earlybird.metrics import PayloadStats


def _ip_bytes_to_str(ip_bytes: bytes) -> str:
    """Convert 4-byte IPv4 or 16-byte IPv6 to dotted string."""
    if len(ip_bytes) == 4:
        return socket.inet_ntoa(ip_bytes)
    if len(ip_bytes) == 16:
        return socket.inet_ntop(socket.AF_INET6, ip_bytes)
    return str(ip_bytes)


def _open_pcap(path: str | Path):
    path = Path(path)
    if path.suffix == ".gz" or path.name.endswith(".pcap.gz"):
        return gzip.open(path, "rb")
    return open(path, "rb")


def discover_pcaps(pcap_dir: str | Path) -> list[Path]:
    """Recursively find *.pcap and *.pcap.gz under pcap_dir. Sorted by path for determinism."""
    out: list[Path] = []
    root = Path(pcap_dir)
    if not root.is_dir():
        return out
    for p in root.rglob("*"):
        if p.is_file() and (p.suffix == ".pcap" or p.name.endswith(".pcap.gz")):
            out.append(p)
    return sorted(out)


def _payload_and_ports(pkt: bytes) -> tuple[bytes, str, int, int, str, str] | None:
    """Extract payload, proto, src_port, dst_port, src_ip, dst_ip. Returns None if not IP or no transport."""
    try:
        eth = dpkt.ethernet.Ethernet(pkt)
        if not isinstance(eth.data, dpkt.ip.IP):
            return None
        ip = eth.data
        src_ip = _ip_bytes_to_str(ip.src)
        dst_ip = _ip_bytes_to_str(ip.dst)
        if isinstance(ip.data, dpkt.udp.UDP):
            udp = ip.data
            return (
                bytes(udp.data),
                "udp",
                udp.sport,
                udp.dport,
                src_ip,
                dst_ip,
            )
        if isinstance(ip.data, dpkt.tcp.TCP):
            tcp = ip.data
            return (
                bytes(tcp.data),
                "tcp",
                tcp.sport,
                tcp.dport,
                src_ip,
                dst_ip,
            )
    except Exception:
        pass
    return None


def replay_pcap(
    path: str | Path,
    *,
    max_packets: int | None = None,
    truncate: int | None = None,
    stats: PayloadStats | None = None,
) -> Generator[
    tuple[float, bytes, bytes, str, int, int, str, str],
    None,
    None,
]:
    """Yield (timestamp, raw_pkt, payload, proto, src_port, dst_port, src_ip, dst_ip).
    Payload may be truncated by truncate if set. Updates stats if provided.
    """
    opened = _open_pcap(path)
    try:
        reader = dpkt.pcap.Reader(opened)
        for n, (ts, pkt) in enumerate(reader):
            if max_packets is not None and n >= max_packets:
                break
            parsed = _payload_and_ports(pkt)
            if parsed is None:
                continue
            payload, proto, sport, dport, src_ip, dst_ip = parsed
            if truncate is not None and len(payload) > truncate:
                payload = payload[:truncate]
            if stats is not None:
                stats.record(len(payload))
            yield (ts, pkt, payload, proto, sport, dport, src_ip, dst_ip)
    finally:
        opened.close()
