#!/usr/bin/env python3
"""Run EarlyBird detection on a directory of pcaps. Outputs alarms.jsonl and summary.csv."""

from __future__ import annotations

import argparse
import csv
import gzip
import json
import os
import shutil
import sys
from pathlib import Path

_root = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_root / "src"))

from earlybird.pcap_replay import discover_pcaps
from earlybird.run import run


def decompress_pcaps(src_dir: str | Path, dest_dir: str | Path) -> Path:
    """Decompress all .pcap.gz under src_dir into dest_dir as .pcap. Returns dest_dir."""
    src_dir = Path(src_dir)
    dest_dir = Path(dest_dir)
    dest_dir.mkdir(parents=True, exist_ok=True)
    paths = discover_pcaps(src_dir)
    gz_paths = [p for p in paths if p.suffix == ".gz" or p.name.endswith(".pcap.gz")]
    for i, gz_path in enumerate(gz_paths):
        out_name = gz_path.name
        if out_name.endswith(".pcap.gz"):
            out_name = out_name[:-3]
        elif out_name.endswith(".gz"):
            out_name = out_name[:-3]
        out_path = dest_dir / out_name
        if out_path.exists() and out_path.stat().st_mtime >= gz_path.stat().st_mtime:
            print(f"  Skip (up to date): {gz_path.name} -> {out_path.name}")
            continue
        print(f"  Decompressing [{i+1}/{len(gz_paths)}] {gz_path.name} -> {out_path.name} ...", flush=True)
        with gzip.open(gz_path, "rb") as fin:
            with open(out_path, "wb") as fout:
                shutil.copyfileobj(fin, fout)
    print(f"  Done. Decompressed {len(gz_paths)} files to {dest_dir}")
    return dest_dir


def parse_args() -> argparse.Namespace:
    default_pcap = os.environ.get("WITTY_PCAP_DIR", "/home/haarika/imp_files/automated_worm/witty")
    p = argparse.ArgumentParser(description="EarlyBird detection on pcap directory")
    p.add_argument("--pcap_dir", type=str, default=default_pcap, help="Directory of pcaps (recursive)")
    p.add_argument("--mode", choices=["whole", "substring"], default="substring")
    p.add_argument("--beta", type=int, default=40)
    p.add_argument("--sample_pow", type=int, default=6)
    p.add_argument("--prevalence_th", type=int, default=3)
    p.add_argument("--src_disp_th", type=int, default=10)
    p.add_argument("--dst_disp_th", type=int, default=10)
    p.add_argument("--port_mode", choices=["dst", "src", "both"], default="dst")
    p.add_argument("--prevalence_window_sec", type=float, default=60.0)
    p.add_argument("--ad_ttl_sec", type=float, default=7200.0)
    p.add_argument("--truncate", type=int, default=None, help="Cap payload to N bytes")
    p.add_argument("--max_files", type=int, default=1)
    p.add_argument("--max_packets", type=int, default=50000,
                   help="Max packets total; 0 = no limit (all files)")
    p.add_argument("--out_dir", type=str, default=".", help="Write alarms.jsonl and summary.csv here")
    p.add_argument("--progress_interval", type=int, default=25000,
                   help="Print in-file progress every N packets (0=only per-file)")
    p.add_argument("--decompress_to", type=str, default=None,
                   help="Decompress .pcap.gz to this dir first, then process (faster)")
    p.add_argument("--max_packets_per_file", type=int, default=None,
                   help="Max packets to read per pcap before moving to next (e.g. 100000)")
    p.add_argument("--write_after_each_file", action="store_true", default=True,
                   help="Write results after each pcap (default: True)")
    p.add_argument("--no-write_after_each_file", action="store_false", dest="write_after_each_file",
                   help="Disable writing after each file")
    return p.parse_args()


def main() -> None:
    args = parse_args()
    out_path = Path(args.out_dir)
    out_path.mkdir(parents=True, exist_ok=True)

    pcap_dir = args.pcap_dir
    if args.decompress_to:
        print("Pre-decompressing .pcap.gz to", args.decompress_to, "...")
        pcap_dir = str(decompress_pcaps(args.pcap_dir, args.decompress_to))

    def on_file_done(stat: dict) -> None:
        tta = stat.get("time_till_first_alarm_sec")
        tta_str = f", time_till_first_alarm: {tta:.2f}s" if tta is not None else ", time_till_first_alarm: —"
        print(f"  [{stat['file_idx']+1}] {stat['file_name']}: "
              f"{stat['packets']} pkts, {stat['alarms_this_file']} alarms (total: {stat['cumulative_alarms']}){tta_str}")

    def on_progress(stat: dict) -> None:
        print(f"    [{stat['file_name']}] {stat['packets_this_file']:,} pkts in file | "
              f"{stat['total_packets']:,} total | {stat['cumulative_alarms']:,} alarms | "
              f"{stat['elapsed_sec']:.0f}s | {stat['rate_pps']:.0f} pps", flush=True)

    alarms, summary, per_file_stats = run(
        pcap_dir=pcap_dir,
        mode=args.mode,
        beta=args.beta,
        sample_pow=args.sample_pow,
        prevalence_th=args.prevalence_th,
        src_disp_th=args.src_disp_th,
        dst_disp_th=args.dst_disp_th,
        port_mode=args.port_mode,
        prevalence_window_sec=args.prevalence_window_sec,
        ad_ttl_sec=args.ad_ttl_sec,
        truncate=args.truncate,
        max_files=args.max_files,
        max_packets=args.max_packets,
        out_dir=args.out_dir,
        per_file_callback=on_file_done,
        progress_interval=args.progress_interval,
        progress_callback=on_progress if args.progress_interval else None,
        max_packets_per_file=args.max_packets_per_file,
        write_after_each_file=args.write_after_each_file,
    )

    # Write final results (if not already writing after each file, or to ensure final state)
    per_file_file = out_path / "alarms_per_file.csv"
    with open(per_file_file, "w", newline="") as f:
        fieldnames = ["file_idx", "file_name", "packets", "alarms_this_file", "cumulative_alarms", "time_till_first_alarm_sec", "error"]
        w = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore")
        w.writeheader()
        w.writerows(per_file_stats)

    alarms_file = out_path / "alarms.jsonl"
    with open(alarms_file, "w") as f:
        for a in alarms:
            f.write(json.dumps(a) + "\n")

    summary_file = out_path / "summary.csv"
    with open(summary_file, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(summary.keys()))
        w.writeheader()
        w.writerow(summary)

    print(f"\nWrote {len(alarms)} alarms to {alarms_file}")
    print(f"Wrote per-file stats to {per_file_file}")
    print(f"Wrote summary to {summary_file}")
    print(f"Total: {summary.get('packets_processed', 0)} packets, {len(alarms)} alarms, {summary.get('processing_rate_pps', 0)} pps")


if __name__ == "__main__":
    main()
