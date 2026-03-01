"""Pipeline runner: prevalence + dispersion -> alarms."""

from __future__ import annotations

import csv
import json
from pathlib import Path
from typing import Callable

from earlybird.config import Config
from earlybird.dispersion import DispersionTracker
from earlybird.metrics import PayloadStats, RunMetrics
from earlybird.pcap_replay import discover_pcaps, replay_pcap
from earlybird.prevalence import PrevalenceSketch
from earlybird.signatures import content_key, extract_content_hashes


def _write_results(
    out_path: Path,
    alarms: list[dict],
    per_file_stats: list[dict],
    pcap_dir: str,
    mode: str,
    beta: int,
    sample_pow: int,
    prevalence_th: int,
    src_disp_th: int,
    dst_disp_th: int,
    port_mode: str,
    run_metrics: RunMetrics,
    payload_stats: PayloadStats,
) -> None:
    """Write alarms.jsonl, alarms_per_file.csv, and summary.csv to out_path."""
    out_path.mkdir(parents=True, exist_ok=True)
    with open(out_path / "alarms.jsonl", "w") as f:
        for a in alarms:
            f.write(json.dumps(a) + "\n")
    with open(out_path / "alarms_per_file.csv", "w", newline="") as f:
        fieldnames = ["file_idx", "file_name", "packets", "alarms_this_file", "cumulative_alarms", "error"]
        w = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore")
        w.writeheader()
        w.writerows(per_file_stats)
    summary = {
        "pcap_dir": pcap_dir,
        "files_processed": len(per_file_stats),
        "packets_processed": run_metrics.packets_processed,
        "bytes_processed": run_metrics.bytes_processed,
        "elapsed_sec": round(run_metrics.elapsed_sec, 4),
        "processing_rate_pps": round(run_metrics.packets_per_sec, 2),
        "num_alarms": len(alarms),
        "first_alarm_time": run_metrics.first_alarm_time,
        "mode": mode,
        "beta": beta,
        "sample_pow": sample_pow,
        "prevalence_th": prevalence_th,
        "src_disp_th": src_disp_th,
        "dst_disp_th": dst_disp_th,
        "port_mode": port_mode,
        **payload_stats.to_dict(),
    }
    with open(out_path / "summary.csv", "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(summary.keys()))
        w.writeheader()
        w.writerow(summary)


def run(
    pcap_dir: str,
    mode: str,
    beta: int,
    sample_pow: int,
    prevalence_th: int,
    src_disp_th: int,
    dst_disp_th: int,
    port_mode: str,
    prevalence_window_sec: float,
    ad_ttl_sec: float,
    truncate: int | None,
    max_files: int,
    max_packets: int,
    out_dir: str,
    *,
    sketch_depth: int = 4,
    sketch_width: int = 4096,
    bitmap_bits: int = 2048,
    per_file_callback: Callable[[dict], None] | None = None,
    progress_interval: int = 0,
    progress_callback: Callable[[dict], None] | None = None,
    max_packets_per_file: int | None = None,
    write_after_each_file: bool = False,
) -> tuple[list[dict], dict, list[dict]]:
    cfg = Config(
        mode=mode,
        beta=beta,
        sample_pow=sample_pow,
        prevalence_th=prevalence_th,
        src_disp_th=src_disp_th,
        dst_disp_th=dst_disp_th,
        port_mode=port_mode,
        prevalence_window_sec=prevalence_window_sec,
        ad_ttl_sec=ad_ttl_sec,
        truncate=truncate,
        max_files=max_files,
        max_packets=max_packets,
        sketch_depth=sketch_depth,
        sketch_width=sketch_width,
        bitmap_bits=bitmap_bits,
    )
    paths = discover_pcaps(pcap_dir)
    paths = paths[: max_files]
    if not paths:
        return [], {"error": "no pcaps found", "pcap_dir": pcap_dir}, []

    payload_stats = PayloadStats()
    payload_stats.set_beta(beta)
    run_metrics = RunMetrics()
    prevalence = PrevalenceSketch(
        depth=cfg.sketch_depth,
        width=cfg.sketch_width,
        window_sec=cfg.prevalence_window_sec,
        port_mode=cfg.port_mode,
    )
    dispersion = DispersionTracker(bitmap_bits=cfg.bitmap_bits, ad_ttl_sec=cfg.ad_ttl_sec)
    alarms: list[dict] = []
    seen_alarm_keys: set[tuple] = set()
    unlimited = max_packets <= 0
    remaining = max_packets if not unlimited else None
    per_file_stats: list[dict] = []

    for file_idx, path in enumerate(paths):
        if not unlimited and remaining is not None and remaining <= 0:
            break
        alarms_before_file = len(alarms)
        packets_this_file = 0
        file_error: str | None = None
        # Per-file cap: take at most max_packets_per_file from this pcap, then move to next
        if max_packets_per_file is not None:
            file_limit = max_packets_per_file
            if not unlimited and remaining is not None:
                file_limit = min(file_limit, remaining)
        else:
            file_limit = remaining if not unlimited else None
        try:
            for ts, _raw, payload, proto, sport, dport, src_ip, dst_ip in replay_pcap(
                path,
                max_packets=file_limit,
                truncate=truncate,
                stats=payload_stats,
            ):
                run_metrics.packets_processed += 1
                run_metrics.bytes_processed += len(payload)
                packets_this_file += 1
                if not unlimited and remaining is not None:
                    remaining -= 1
                    if remaining <= 0:
                        break
                if progress_interval > 0 and progress_callback and packets_this_file % progress_interval == 0:
                    progress_callback({
                        "file_idx": file_idx,
                        "file_name": path.name,
                        "packets_this_file": packets_this_file,
                        "total_packets": run_metrics.packets_processed,
                        "cumulative_alarms": len(alarms),
                        "elapsed_sec": run_metrics.elapsed_sec,
                        "rate_pps": run_metrics.packets_per_sec,
                    })
                if truncate is not None and len(payload) > truncate:
                    payload = payload[:truncate]
                hashes = extract_content_hashes(payload, mode, beta, sample_pow)
                for h in hashes:
                    prevalence.add(proto, sport, dport, h, ts)
                    if prevalence.estimate(proto, sport, dport, h, ts) >= prevalence_th:
                        key = content_key(cfg.port_mode, proto, sport, dport, h)
                        src_est, dst_est = dispersion.add(key, src_ip, dst_ip, ts)
                        if src_est >= src_disp_th and dst_est >= dst_disp_th:
                            alarm_key = (ts, key)
                            if alarm_key not in seen_alarm_keys:
                                seen_alarm_keys.add(alarm_key)
                                if run_metrics.first_alarm_time is None:
                                    run_metrics.first_alarm_time = ts
                                alarms.append({
                                    "timestamp": ts,
                                    "key": str(key),
                                    "src_est": src_est,
                                    "dst_est": dst_est,
                                    "source_file": str(path.name),
                                    "params": {"mode": mode, "beta": beta, "sample_pow": sample_pow, "port_mode": port_mode},
                                })
                                run_metrics.alarms_count += 1
                if not unlimited and remaining is not None and remaining <= 0:
                    break
        except Exception as e:
            file_error = str(e)
            if per_file_callback:
                pass  # we'll call with file_stat below including error

        alarms_this_file = len(alarms) - alarms_before_file
        file_stat = {
            "file_idx": file_idx,
            "file_name": path.name,
            "packets": packets_this_file,
            "alarms_this_file": alarms_this_file,
            "cumulative_alarms": len(alarms),
        }
        if file_error is not None:
            file_stat["error"] = file_error
            print(f"  [SKIP] {path.name}: {file_error}", flush=True)
        per_file_stats.append(file_stat)
        if per_file_callback:
            per_file_callback(file_stat)

        if write_after_each_file and out_dir:
            _write_results(
                Path(out_dir),
                alarms,
                per_file_stats,
                pcap_dir, mode, beta, sample_pow,
                prevalence_th, src_disp_th, dst_disp_th, port_mode,
                run_metrics,
                payload_stats,
            )

    summary = {
        "pcap_dir": pcap_dir,
        "files_processed": len(paths),
        "packets_processed": run_metrics.packets_processed,
        "bytes_processed": run_metrics.bytes_processed,
        "elapsed_sec": round(run_metrics.elapsed_sec, 4),
        "processing_rate_pps": round(run_metrics.packets_per_sec, 2),
        "num_alarms": len(alarms),
        "first_alarm_time": run_metrics.first_alarm_time,
        "mode": mode,
        "beta": beta,
        "sample_pow": sample_pow,
        "prevalence_th": prevalence_th,
        "src_disp_th": src_disp_th,
        "dst_disp_th": dst_disp_th,
        "port_mode": port_mode,
        **payload_stats.to_dict(),
    }
    return alarms, summary, per_file_stats
