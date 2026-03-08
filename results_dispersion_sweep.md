# Address dispersion threshold sweep (5, 7, 9, 11, 13, 15, 17, 19)

Witty dataset, 5 pcaps, 200k packets/file, prevalence_th=2, port_mode=dst.

## Time-till-first-alarm (seconds) per pcap

| disp_th | pcap 1 (1079755300) | pcap 2 (1079758900) | pcap 3 (1079762500) | pcap 4 (1079766100) | pcap 5 (1079769700) | Total alarms |
|--------|---------------------|---------------------|---------------------|---------------------|---------------------|--------------|
| 5      | **1.15**            | 0.01                | 0.01                | 0.02                | 0.01                | 692,765      |
| 7      | **3.86**            | 0.03                | 0.01                | 0.01                | 0.01                | 548,210      |
| 9      | **5.87**            | 0.03                | 0.01                | 0.01                | 0.00                | 403,031      |
| 11     | **8.19**            | 0.03                | 0.03                | 0.01                | 0.00                | 265,346      |
| 13     | — (no alarm)        | **2.88**            | 0.03                | 0.01                | 0.01                | 150,428      |
| 15     | — (no alarm)        | **6.07**            | 0.07                | 0.01                | 0.01                | 71,172       |
| 17     | — (no alarm)        | **7.95**            | 0.19                | 0.03                | 0.02                | 27,556       |
| 19     | — (no alarm)        | — (no alarm)        | **2.78**            | 0.08                | 0.05                | 8,583        |

— = no alarm in that pcap (dispersion never reached threshold).

## Summary

- **First pcap**: With higher thresholds, the first alarm in pcap 1 is delayed (1.15s → 3.86s → 5.87s → 8.19s) or never occurs (13+).
- **Threshold 13–19**: First alarm moves to pcap 2 or 3; time-till-first-alarm in that file grows (e.g. 2.88s, 6.07s, 7.95s, 2.78s).
- **Total alarms** drop sharply as threshold increases (692k → 8.5k from disp 5 to 19).

Per-file CSVs: `results_disp5/alarms_per_file.csv` … `results_disp19/alarms_per_file.csv`.

---

# Substring mode sweep (results_disp_substring3 … results_disp_substring30)

Same thresholds 3, 5, 7, 9, 11, 13, 15, 17, 19, 30 with **--mode substring**.

| disp_th | pcap 1 | pcap 2 | pcap 3 | pcap 4 | pcap 5 | Total alarms |
|--------|--------|--------|--------|--------|--------|--------------|
| 3      | 0.75s  | 0.00s  | 0.00s  | 0.01s  | 0.00s  | 6,854,694    |
| 5      | 4.61s  | 0.00s  | 0.00s  | 0.01s  | 0.01s  | 5,709,588    |
| 7      | 15.10s | 0.00s  | 0.01s  | 0.01s  | 0.01s  | 4,552,042    |
| 9      | 28.26s | 0.04s  | 0.00s  | 0.01s  | 0.01s  | 3,386,027    |
| 11     | 38.18s | 0.03s  | 0.01s  | 0.00s  | 0.00s  | 2,268,985    |
| 13     | none   | 12.58s | 0.03s  | 0.00s  | 0.00s  | 1,317,114    |
| 15     | none   | 27.60s | 0.27s  | 0.00s  | 0.00s  | 642,405      |
| 17     | none   | 37.80s | 0.98s  | 0.03s  | 0.02s  | 257,192      |
| 19     | none   | none   | 13.22s | 0.03s  | 0.02s  | 82,857       |
| 30     | none   | none   | none   | none   | none   | 0            |

Substring mode is slower (lower pps) and first-alarm times in pcap 1 are longer than whole mode; disp_th=30 again yields no alarms in 5 pcaps.
