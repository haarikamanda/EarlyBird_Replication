"""Dataset-backed smoke test: run pipeline on Witty pcaps if available."""

import csv
import json
import os
import tempfile
from pathlib import Path

import pytest

# Ensure src is on path
import sys
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from earlybird.run import run


WITTY_DIR = os.environ.get("WITTY_PCAP_DIR", "/home/haarika/imp_files/automated_worm/witty")


@pytest.mark.skipif(not Path(WITTY_DIR).is_dir(), reason="Witty dataset path does not exist")
def test_witty_smoke_no_exception() -> None:
    with tempfile.TemporaryDirectory() as out_dir:
        alarms, summary, per_file_stats = run(
            pcap_dir=WITTY_DIR,
            mode="whole",
            beta=40,
            sample_pow=6,
            prevalence_th=3,
            src_disp_th=2,
            dst_disp_th=2,
            port_mode="dst",
            prevalence_window_sec=60.0,
            ad_ttl_sec=7200.0,
            truncate=None,
            max_files=1,
            max_packets=50000,
            out_dir=out_dir,
        )
        assert "error" not in summary
        assert summary["packets_processed"] > 0
        assert "frac_payload_zero" in summary
        assert "frac_payload_below_beta" in summary
        assert "payload_zero_count" in summary
        assert "payload_below_beta_count" in summary


@pytest.mark.skipif(not Path(WITTY_DIR).is_dir(), reason="Witty dataset path does not exist")
def test_witty_smoke_outputs_created() -> None:
    with tempfile.TemporaryDirectory() as out_dir:
        alarms, summary, per_file_stats = run(
            pcap_dir=WITTY_DIR,
            mode="whole",
            beta=40,
            sample_pow=6,
            prevalence_th=3,
            src_disp_th=2,
            dst_disp_th=2,
            port_mode="dst",
            prevalence_window_sec=60.0,
            ad_ttl_sec=7200.0,
            truncate=None,
            max_files=1,
            max_packets=50000,
            out_dir=out_dir,
        )
        # Write outputs as the CLI does
        with open(Path(out_dir) / "alarms.jsonl", "w") as f:
            for a in alarms:
                f.write(json.dumps(a) + "\n")
        with open(Path(out_dir) / "summary.csv", "w", newline="") as f:
            w = csv.DictWriter(f, fieldnames=list(summary.keys()))
            w.writeheader()
            w.writerow(summary)
        assert (Path(out_dir) / "alarms.jsonl").exists()
        assert (Path(out_dir) / "summary.csv").exists()
        assert summary.get("packets_processed", 0) > 0
        assert "payload_zero_count" in summary
        assert "payload_below_beta_count" in summary
