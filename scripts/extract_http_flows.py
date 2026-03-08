#!/usr/bin/env python3
"""
Extract only HTTP (TCP port 80) flows from PCAPs; discard all other traffic.
Processes PCAPs in parallel. Uses dpkt only.
"""

from __future__ import annotations

import argparse
import os
import sys
from concurrent.futures import ProcessPoolExecutor, as_completed
from pathlib import Path

EARLYBIRD_ROOT = Path(__file__).resolve().parent.parent
WORKSPACE_ROOT = EARLYBIRD_ROOT.parent
if str(EARLYBIRD_ROOT) not in sys.path:
    sys.path.insert(0, str(EARLYBIRD_ROOT))

from earlybird.pcap_processing import discover_pcaps, filter_pcap_to_http_only


def _process_one(pcap_path: Path, output_dir: Path, input_root: Path) -> dict:
    """Worker: write one pcap per HTTP flow (top-level for pickling)."""
    result = filter_pcap_to_http_only(pcap_path, output_dir, input_root=input_root)
    result["input_path"] = str(pcap_path)
    return result


def main() -> None:
    default_input = WORKSPACE_ROOT / "data" / "ucsb_data"
    default_output = WORKSPACE_ROOT / "data" / "ucsb_data_http_only"

    ap = argparse.ArgumentParser(description="Extract HTTP-only flows from PCAPs.")
    ap.add_argument("input_dir", type=Path, nargs="?", default=default_input)
    ap.add_argument("output_dir", type=Path, nargs="?", default=default_output)
    ap.add_argument(
        "-j", "--jobs", type=int, default=None,
        help="Parallel jobs (default: min(num_pcaps, CPU count))",
    )
    args = ap.parse_args()

    if not args.input_dir.is_dir():
        print(f"Error: not a directory: {args.input_dir}", file=sys.stderr)
        sys.exit(1)

    pcaps = discover_pcaps(args.input_dir)
    if not pcaps:
        print("No PCAP files found.", file=sys.stderr)
        sys.exit(0)

    n_jobs = args.jobs or min(len(pcaps), os.cpu_count() or 4)

    print(f"Input:  {args.input_dir}")
    print(f"Output: {args.output_dir}")
    print(f"Found {len(pcaps)} PCAP(s), extracting HTTP-only in parallel (jobs={n_jobs})...\n")

    results = []
    done = 0
    with ProcessPoolExecutor(max_workers=n_jobs) as executor:
        future_to_info = {
            executor.submit(_process_one, p, args.output_dir, args.input_dir): (i, p)
            for i, p in enumerate(pcaps, start=1)
        }
        for future in as_completed(future_to_info):
            i, pcap_path = future_to_info[future]
            result = future.result()
            results.append(result)
            done += 1
            print(
                f"Finished pcap_{i}/{len(pcaps)}: {pcap_path.name} -> "
                f"{result['flow_count']} HTTP flow pcaps, {result['packet_count']} packets, "
                f"{result['skipped_count']} discarded  [{done}/{len(pcaps)} done]"
            )

    total_flows = sum(r["flow_count"] for r in results)
    print(
        f"\nDone: {len(results)} PCAPs -> {total_flows} HTTP flow pcap files "
        f"({sum(r['packet_count'] for r in results)} packets)"
    )


if __name__ == "__main__":
    main()
