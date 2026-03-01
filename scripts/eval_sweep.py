#!/usr/bin/env python3
"""Parameter sweep for EarlyBird; outputs sweep_results.csv."""

from __future__ import annotations

import argparse
import csv
import os
import sys
from pathlib import Path

_root = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_root / "src"))

from earlybird.run import run


def main() -> None:
    default_pcap = os.environ.get("WITTY_PCAP_DIR", "/home/haarika/imp_files/automated_worm/witty")
    p = argparse.ArgumentParser()
    p.add_argument("--pcap_dir", type=str, default=default_pcap)
    p.add_argument("--max_files", type=int, default=1)
    p.add_argument("--max_packets", type=int, default=50000)
    p.add_argument("--out", type=str, default="sweep_results.csv")
    args = p.parse_args()

    prevalence_ths = [2, 3, 4]
    disp_pairs = [(2, 2), (10, 10), (30, 30)]
    betas = [16, 24, 32, 40]
    sample_pows = [4, 5, 6, 7]
    port_modes = ["dst", "src", "both"]

    rows: list[dict] = []
    total = (
        len(prevalence_ths)
        * len(disp_pairs)
        * len(betas)
        * len(sample_pows)
        * len(port_modes)
        * 2  # whole + substring
    )
    n = 0
    for mode in ["whole", "substring"]:
        for prevalence_th in prevalence_ths:
            for (src_disp_th, dst_disp_th) in disp_pairs:
                for beta in betas:
                    for sample_pow in sample_pows:
                        for port_mode in port_modes:
                            if mode == "whole":
                                # beta/sample_pow less relevant for whole
                                _beta, _k = 40, 6
                            else:
                                _beta, _k = beta, sample_pow
                            n += 1
                            print(f"[{n}/{total}] mode={mode} prevalence_th={prevalence_th} "
                                  f"disp=({src_disp_th},{dst_disp_th}) beta={_beta} k={_k} port={port_mode}")
                            alarms, summary, _ = run(
                                pcap_dir=args.pcap_dir,
                                mode=mode,
                                beta=_beta,
                                sample_pow=_k,
                                prevalence_th=prevalence_th,
                                src_disp_th=src_disp_th,
                                dst_disp_th=dst_disp_th,
                                port_mode=port_mode,
                                prevalence_window_sec=60.0,
                                ad_ttl_sec=7200.0,
                                truncate=None,
                                max_files=args.max_files,
                                max_packets=args.max_packets,
                                out_dir=os.path.dirname(args.out) or ".",
                            )
                            row = {
                                "mode": mode,
                                "prevalence_th": prevalence_th,
                                "src_disp_th": src_disp_th,
                                "dst_disp_th": dst_disp_th,
                                "beta": _beta,
                                "sample_pow": _k,
                                "port_mode": port_mode,
                                "first_alarm_time": summary.get("first_alarm_time"),
                                "num_alarms": summary.get("num_alarms", 0),
                                "processing_rate_pps": summary.get("processing_rate_pps"),
                                "packets_processed": summary.get("packets_processed", 0),
                                "frac_payload_zero": summary.get("frac_payload_zero"),
                                "frac_payload_below_beta": summary.get("frac_payload_below_beta"),
                                "payload_zero_count": summary.get("payload_zero_count"),
                                "payload_below_beta_count": summary.get("payload_below_beta_count"),
                            }
                            rows.append(row)

    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with open(out_path, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0].keys()) if rows else [])
        w.writeheader()
        w.writerows(rows)
    print(f"Wrote {len(rows)} rows to {out_path}")


if __name__ == "__main__":
    main()
