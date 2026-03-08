"""Split PCAPs into per-flow PCAPs and filter to HTTP-only. Uses dpkt only."""

from __future__ import annotations

import socket
from pathlib import Path
from typing import Any

import dpkt

from earlybird.pcap_replay import _open_pcap, discover_pcaps


def _ip_bytes_to_str(ip_bytes: bytes) -> str:
    """Convert 4-byte IPv4 or 16-byte IPv6 to dotted string."""
    if len(ip_bytes) == 4:
        return socket.inet_ntoa(ip_bytes)
    if len(ip_bytes) == 16:
        return socket.inet_ntop(socket.AF_INET6, ip_bytes)
    return str(ip_bytes)


def _flow_key_from_packet(pkt: bytes) -> tuple[str, str, int, int, str] | None:
    """
    Extract 5-tuple (src_ip, dst_ip, sport, dport, proto) from packet using dpkt.
    Returns canonical flow key (smaller endpoint first) so both directions map to the same flow.
    Returns None if not IP+TCP/UDP.
    """
    try:
        eth = dpkt.ethernet.Ethernet(pkt)
        if not isinstance(eth.data, dpkt.ip.IP):
            return None
        ip = eth.data
        src_ip = _ip_bytes_to_str(ip.src)
        dst_ip = _ip_bytes_to_str(ip.dst)
        if isinstance(ip.data, dpkt.udp.UDP):
            udp = ip.data
            sport, dport = udp.sport, udp.dport
            proto = "udp"
        elif isinstance(ip.data, dpkt.tcp.TCP):
            tcp = ip.data
            sport, dport = tcp.sport, tcp.dport
            proto = "tcp"
        else:
            return None
        if (src_ip, sport) <= (dst_ip, dport):
            return (src_ip, dst_ip, sport, dport, proto)
        return (dst_ip, src_ip, dport, sport, proto)
    except Exception:
        return None


def split_pcap_into_flows(
    pcap_path: str | Path,
    output_dir: str | Path,
    input_root: str | Path | None = None,
) -> dict[str, Any]:
    """
    Read a single PCAP and write one PCAP per flow into output_dir.
    Flows are 5-tuple (src_ip, dst_ip, sport, dport, proto); both directions in one flow.
    Returns dict with flow_count, packet_count, skipped_count, output_paths.
    """
    pcap_path = Path(pcap_path)
    output_dir = Path(output_dir)
    input_root = Path(input_root) if input_root else pcap_path.parent

    try:
        rel_parent = pcap_path.parent.relative_to(input_root)
        out_subdir = output_dir / rel_parent
    except ValueError:
        out_subdir = output_dir / pcap_path.parent.name
    out_subdir.mkdir(parents=True, exist_ok=True)

    stem = pcap_path.stem
    if stem.endswith(".pcap"):
        stem = stem[:-5]

    flows: dict[tuple[str, str, int, int, str], list[tuple[float, bytes]]] = {}
    packet_count = 0
    skipped_count = 0

    opened = _open_pcap(pcap_path)
    try:
        reader = dpkt.pcap.Reader(opened)
        for ts, pkt in reader:
            key = _flow_key_from_packet(pkt)
            if key is None:
                skipped_count += 1
                continue
            packet_count += 1
            if key not in flows:
                flows[key] = []
            flows[key].append((ts, pkt))
    finally:
        opened.close()

    for key in flows:
        flows[key].sort(key=lambda x: x[0])

    output_paths = []
    for idx, (key, packets) in enumerate(
        sorted(flows.items(), key=lambda x: (x[0][4], x[0][0], x[0][1], x[0][2], x[0][3]))
    ):
        out_path = out_subdir / f"{stem}_flow_{idx:05d}.pcap"
        with open(out_path, "wb") as f:
            writer = dpkt.pcap.Writer(f)
            for ts, pkt in packets:
                writer.writepkt(pkt, ts=ts)
        output_paths.append(str(out_path))

    return {
        "flow_count": len(flows),
        "packet_count": packet_count,
        "skipped_count": skipped_count,
        "output_paths": output_paths,
    }


HTTP_PORT = 80


def _is_http_flow_key(key: tuple[str, str, int, int, str]) -> bool:
    """True if flow is TCP and uses port 80 (unencrypted HTTP)."""
    if key[4] != "tcp":
        return False
    sport, dport = key[2], key[3]
    return sport == HTTP_PORT or dport == HTTP_PORT


def filter_pcap_to_http_only(
    pcap_path: str | Path,
    output_dir: str | Path,
    input_root: str | Path | None = None,
) -> dict[str, Any]:
    """
    Read a PCAP and write one PCAP per HTTP flow (TCP port 80) into output_dir.
    Each HTTP flow is a separate pcap file. Non-HTTP traffic is discarded.
    Returns dict with flow_count, packet_count, skipped_count, output_paths.
    """
    pcap_path = Path(pcap_path)
    output_dir = Path(output_dir)
    input_root = Path(input_root) if input_root else pcap_path.parent

    try:
        rel_parent = pcap_path.parent.relative_to(input_root)
        out_subdir = output_dir / rel_parent
    except ValueError:
        out_subdir = output_dir / pcap_path.parent.name
    out_subdir.mkdir(parents=True, exist_ok=True)

    stem = pcap_path.stem
    if stem.endswith(".pcap"):
        stem = stem[:-5]

    http_flows: dict[tuple[str, str, int, int, str], list[tuple[float, bytes]]] = {}
    packet_count = 0
    skipped_count = 0

    opened = _open_pcap(pcap_path)
    try:
        reader = dpkt.pcap.Reader(opened)
        for ts, pkt in reader:
            key = _flow_key_from_packet(pkt)
            if key is None:
                skipped_count += 1
                continue
            if not _is_http_flow_key(key):
                skipped_count += 1
                continue
            packet_count += 1
            if key not in http_flows:
                http_flows[key] = []
            http_flows[key].append((ts, pkt))
    finally:
        opened.close()

    for key in http_flows:
        http_flows[key].sort(key=lambda x: x[0])

    output_paths = []
    for idx, (key, packets) in enumerate(
        sorted(http_flows.items(), key=lambda x: (x[0][4], x[0][0], x[0][1], x[0][2], x[0][3]))
    ):
        out_path = out_subdir / f"{stem}_http_flow_{idx:05d}.pcap"
        with open(out_path, "wb") as f:
            writer = dpkt.pcap.Writer(f)
            for ts, pkt in packets:
                writer.writepkt(pkt, ts=ts)
        output_paths.append(str(out_path))

    return {
        "flow_count": len(http_flows),
        "packet_count": packet_count,
        "skipped_count": skipped_count,
        "output_paths": output_paths,
    }
