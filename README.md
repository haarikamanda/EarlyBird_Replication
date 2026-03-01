# EarlyBird-Witty: Content-Sifting Worm Fingerprinting

Python implementation of the **EarlyBird / content-sifting** algorithm from *Automated Worm Fingerprinting*, evaluated on **CAIDA Witty worm** pcaps with explicit **partial payload** handling.

## Features

- **Content prevalence**: Count-min sketch with conservative update; configurable port binding (`dst` / `src` / `both`).
- **Address dispersion**: Scaled-bitmap distinct counting for source and destination IPs; alarms when both exceed thresholds.
- **Content extraction**: `whole` (hash full payload) or `substring` (Rabin rolling fingerprints, length `beta`, value sampling `1/2^k`).
- **Partial payloads**: Payload length stats (frac zero, frac &lt; beta), optional `--truncate N` to simulate truncation.
- **Offline replay**: Read pcaps in timestamp order per file; output `alarms.jsonl` and `summary.csv`.

## Requirements

- Python 3.9+
- **dpkt** for pcap parsing (lightweight, no Scapy; suitable for offline payload extraction)

## Install (local)

```bash
cd earlybird-witty
pip install -e ".[dev]"
```

## Run detection

Default pcap directory: `WITTY_PCAP_DIR` env var, or `/home/haarika/imp_files/automated_worm/witty`.

```bash
export WITTY_PCAP_DIR=/home/haarika/imp_files/automated_worm/witty
python scripts/run_detection.py --mode whole --max_files 1 --max_packets 50000
```

Full CLI:

- `--pcap_dir` — directory of pcaps (recursive `*.pcap` / `*.pcap.gz`)
- `--mode` — `whole` | `substring`
- `--beta` — substring length (default 40)
- `--sample_pow` — value sampling 1/2^k (default 6 ⇒ 1/64)
- `--prevalence_th` — prevalence threshold (default 3)
- `--src_disp_th` / `--dst_disp_th` — dispersion thresholds (default 10)
- `--port_mode` — `dst` | `src` | `both`
- `--prevalence_window_sec` — window reset (default 60)
- `--ad_ttl_sec` — dispersion entry TTL (default 7200)
- `--truncate N` — cap payload to N bytes (optional)
- `--max_files` / `--max_packets` — bounded run (default 1, 50000)
- `--out_dir` — where to write `alarms.jsonl` and `summary.csv`

## Docker

```bash
docker build -t earlybird-witty .
docker run --rm -v /path/to/witty:/data earlybird-witty --pcap_dir /data --mode whole --max_files 1 --max_packets 50000
```

## Tests

```bash
export WITTY_PCAP_DIR=/home/haarika/imp_files/automated_worm/witty
pytest -q
```

Dataset-backed smoke test skips if `WITTY_PCAP_DIR` (or default path) is missing.

## Parameter sweep

```bash
python scripts/eval_sweep.py --pcap_dir "$WITTY_PCAP_DIR" --max_files 1 --max_packets 50000 --out sweep_results.csv
```

Produces `sweep_results.csv` with `first_alarm_time`, `num_alarms`, `processing_rate_pps`, and payload usability metrics across prevalence_th, (src,dst) thresholds, beta, sample_pow, and port_mode.

## Expected behavior on Witty

- **Partial payloads**: Witty traces can include short or truncated payloads. Use `frac_payload_zero` and `frac_payload_below_beta` in the summary to tune `beta` and interpret detection.
- **Port**: Witty targets a specific UDP service; `port_mode dst` (or `both`) is most relevant.
- **Alarms**: Lower thresholds (e.g. prevalence_th=2, src_disp_th=2, dst_disp_th=2) and `whole` mode tend to surface alarms sooner; substring mode with larger `beta` may miss short payloads. Use `--truncate N` to see sensitivity to truncation.
- **Best params**: Start with `whole`, low prevalence (2–3) and dispersion (2,2); then try `substring` with beta=32–40 and sample_pow=5–6 once payload length distribution looks sufficient.

## Design

See **DESIGN.md** for mapping from the paper (content prevalence, address dispersion, Rabin fingerprints, value sampling, scaled bitmap) to this codebase and for section references.
