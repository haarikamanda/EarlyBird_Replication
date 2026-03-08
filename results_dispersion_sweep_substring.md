# Address dispersion threshold sweep — substring mode

Witty dataset, **mode=substring**, 5 pcaps, 200k packets/file, prevalence_th=2, port_mode=dst.

## Time-till-first-alarm (seconds) per pcap

| disp_th | pcap 1 (1079755300) | pcap 2 (1079758900) | pcap 3 (1079762500) | pcap 4 (1079766100) | pcap 5 (1079769700) | Total alarms |
|--------|---------------------|---------------------|---------------------|---------------------|---------------------|--------------|
| 5      | **4.61**            | 0.00                | 0.00                | 0.01                | 0.01                | 5,709,588    |
| 7      | **15.10**           | 0.00                | 0.01                | 0.01                | 0.01                | 4,552,042    |
| 9      | **28.26**           | 0.04                | 0.00                | 0.01                | 0.01                | 3,386,027    |
| 11     | **38.18**           | 0.03                | 0.01                | 0.00                | 0.00                | 2,268,985    |
| 13     | —                   | **12.58**           | 0.03                | 0.00                | 0.00                | 1,317,114    |
| 15     | —                   | **27.60**           | 0.27                | 0.00                | 0.00                | 642,405     |
| 17     | —                   | **37.80**           | 0.98                | 0.03                | 0.02                | 257,192     |
| 19     | —                   | —                   | **13.22**           | 0.03                | 0.02                | 82,857      |
| 30     | —                   | —                   | —                   | —                   | —                   | 0            |

— = no alarm in that pcap.

## Summary

- **First pcap**: With substring mode, time to first alarm in pcap 1 grows from ~4.6 s (disp 5) to ~38 s (disp 11); for disp ≥ 13 there is no alarm in pcap 1.
- **Later pcaps**: First alarm shifts to pcap 2 or 3 as threshold increases; once state is warm, time-till-first-alarm is sub-second in later files.
- **disp_th=30**: No alarms in any of the 5 pcaps (same as whole mode on this trace set).

Output dirs: `results_disp_substring5/` … `results_disp_substring30/`. Per-file CSVs: `results_disp_substring<N>/alarms_per_file.csv`.
