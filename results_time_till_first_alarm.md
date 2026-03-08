# Time-till-first-alarm: Witty worm (5 pcaps)

Runs on Witty dataset with `--max_files 5`, `--max_packets_per_file 200000`, `--prevalence_th 2`, `--port_mode dst`.

## src_disp_th=3, dst_disp_th=3

| Pcap # | File | Packets | Alarms (this file) | Time-till-first-alarm (sec) |
|--------|------|---------|---------------------|-----------------------------|
| 1 | witty.1079755300.pcap.gz | 200,000 | 71,611 | **0.21** |
| 2 | witty.1079758900.pcap.gz | 200,000 | 177,929 | **0.01** |
| 3 | witty.1079762500.pcap.gz | 200,000 | 194,366 | **0.01** |
| 4 | witty.1079766100.pcap.gz | 200,000 | 195,798 | **0.02** |
| 5 | witty.1079769700.pcap.gz | 200,000 | 195,895 | **0.01** |

- First pcap: alarm detected in **0.21 s** of processing that file.
- Subsequent pcaps (with state carried over): first alarm in **0.01–0.02 s** (signature already prevalent).

## src_disp_th=30, dst_disp_th=30

| Pcap # | File | Packets | Alarms (this file) | Time-till-first-alarm (sec) |
|--------|------|---------|---------------------|-----------------------------|
| 1 | witty.1079755300.pcap.gz | 200,000 | 0 | — (no alarm) |
| 2 | witty.1079758900.pcap.gz | 200,000 | 0 | — (no alarm) |
| 3 | witty.1079762500.pcap.gz | 200,000 | 0 | — (no alarm) |
| 4 | witty.1079766100.pcap.gz | 200,000 | 0 | — (no alarm) |
| 5 | witty.1079769700.pcap.gz | 200,000 | 0 | — (no alarm) |

- With the conservative threshold 30, **no alarms** were raised in the first 5 pcaps (1M packets total). The Witty signature was not reported within this window at this dispersion setting.

## Summary

- **Dispersion 3**: Worm signature detected within **&lt;1 s** (0.01–0.21 s) per pcap; first file ~0.21 s.
- **Dispersion 30**: No detection in the first 5 pcaps; would require more traffic (or lower threshold) to observe “up to 5 seconds” as in the Slammer-style setup.

Per-file details: `results_disp3/alarms_per_file.csv`, `results_disp30/alarms_per_file.csv`.
