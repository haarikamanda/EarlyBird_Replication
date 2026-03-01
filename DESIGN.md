# EarlyBird Content-Sifting Algorithm — Design Document

This document maps the **Automated Worm Fingerprinting** paper (EarlyBird) and the project proposal into this codebase. Citations use "Paper" for *Automated Worm Fingerprinting* and "Proposal" for *Haarika_Manda_project_proposal.pdf*.

---

## 1. Pipeline Overview

The detection pipeline has two main stages (Paper: content-prevalence + address-dispersion):

1. **Content prevalence (heavy-hitter)** — Identify byte patterns that appear frequently (above a threshold) in a time window.
2. **Address dispersion** — For each prevalent content, estimate distinct source and destination IP counts; raise an **ALARM** when both exceed thresholds (worm-like spread).

Content can be keyed by:
- **Whole payload**: hash entire packet payload (baseline).
- **Substring**: fixed-length substrings via **Rabin rolling fingerprints** (Paper: substring hashing for invariant content), with **value sampling** to reduce work.

---

## 2. Data Structures (In-Memory)

We keep all state in memory (Proposal: offline replay; no external DB).

| Component | In-memory structure | Purpose |
|-----------|---------------------|---------|
| Prevalence | Count-min–style sketch with **conservative update** | Approximate counts per content key in current window (Paper: multi-stage filter / heavy-hitter). |
| Prevalence window | Timestamp of window start; periodic reset | Every `prevalence_window_sec` we reset the sketch (Paper: time-windowed prevalence). |
| Dispersion | Per-content key: two structures (src/dst) | Approximate distinct **source IP** and **destination IP** counts (Paper: address dispersion). |
| Dispersion TTL | Per-entry last-seen time | Entries expire after `ad_ttl_sec` (e.g. hours). |

---

## 3. Content Prevalence (Heavy-Hitter)

**Paper**: Content-prevalence stage to find frequently repeated content (Section on multi-stage filtering / prevalence).

**Implementation** (`src/earlybird/prevalence.py`):

- **Sketch**: Count-min–style 2D array of counters: `d` rows × `w` columns, with `d` hash functions. We use a single 2D array and hashes of the content key.
- **Conservative update** (Paper: reduces false positives): On each occurrence of key `k`, only increment the **minimum** of the `d` counters that `k` hashes to. This avoids inflating counts for colliding keys and gives better heavy-hitter accuracy.
- **Key format** (port binding modes):
  - `dst`: `(proto, dst_port, content_hash)` — content seen to a given destination port.
  - `src`: `(proto, src_port, content_hash)` — content seen from a given source port.
  - `both`: `(proto, (dst_port, src_port), content_hash)` — both ports in the key.
- **Threshold**: Configurable `prevalence_th` (default 3). When estimated count ≥ threshold, the content becomes a **candidate** for the dispersion stage.
- **Window/GC**: The prevalence sketch is **reset** every `prevalence_window_sec` (default 60 s). No TTL per key; the whole sketch is cleared so prevalence is purely over the last window.

---

## 4. Address Dispersion

**Paper**: For content that passes prevalence, track how many distinct sources and destinations send/receive that content (address dispersion); worms show high dispersion.

**Implementation** (`src/earlybird/dispersion.py`):

- **Paper-faithful mode: scaled bitmap**  
  We implement the paper’s **scaled bitmap** for distinct counting:
  - One bitmap per (content_key, src vs dst). Each IP is hashed to a bit index; the bitmap records which positions have been set.
  - “Scaled” refers to the paper’s scaling of the bitmap (or sampling) to estimate cardinality from the fraction of bits set (or similar statistic). We use a fixed-size bitmap and derive an approximate distinct count from the number of bits set and the bitmap size (linear scaling or small-table lookup).
  - Optional: an alternative (e.g. HyperLogLog) can be added later; the code must retain a **paper-faithful scaled-bitmap mode** as the default or switchable option.
- **TTL**: Each dispersion entry has a last-seen time. Entries (or their IP sets) are pruned when older than `ad_ttl_sec` (default hours).
- **Alarm**: When, for a content key, **both** `src_est >= src_disp_th` and `dst_est >= dst_disp_th`, we emit an **ALARM** (timestamp, key, src_est, dst_est, params).

---

## 5. Content Extraction and Hashing

**Paper**: Use of Rabin fingerprints for efficient substring hashing; value sampling to reduce computation.

**Implementation** (`src/earlybird/rabin.py`, `signatures.py`):

- **Whole mode** (`whole`):  
  Content key = (port info, hash(entire_payload)). Handles partial payloads by hashing whatever bytes exist (length 0: skip or log).

- **Substring mode** (`substring`):
  - **Rabin rolling fingerprint**: Length `beta` (default 40 bytes). For each offset in the payload we compute a fingerprint (rolling hash). Paper: substring hashing for invariant worm content.
  - **Value sampling** (Paper: value sampling): Only process a substring when  
    `fingerprint & ((1 << k) - 1) == 0`  
    with `k = sample_pow` (default 6 ⇒ 1/64). So we only count/update prevalence and dispersion for a **sample** of substrings, reducing CPU and memory.
  - If `len(payload) < beta`, we **skip** substring extraction for that packet (no substring key is produced); whole-mode can still run if enabled.

---

## 6. Partial Payload Handling (Witty)

**Proposal / Witty**: Witty worm traces can have partial payloads (truncation, short packets). We explicitly handle and measure this.

**Implementation**:

- **Payload length logging** (e.g. in `metrics.py` / pipeline):
  - Fraction of packets with payload length == 0.
  - Fraction with payload length < `beta` (cannot form a substring of length `beta`).
  - Distribution of payload sizes (e.g. histogram or percentiles).
- **Substring mode**: If `len(payload) < beta`, do **not** extract substrings; optionally still hash whole payload in whole mode.
- **`--truncate N`**: Simulate truncation by capping payload to N bytes before any hashing. Used to quantify sensitivity to partial payloads (e.g. sweep over N and report alarms / usability metrics).

---

## 7. Time Windows and GC

- **Prevalence**: Reset sketch every `prevalence_window_sec` (default 60 s). Use packet timestamps (from pcap replay) to decide when to advance the window.
- **Dispersion**: Per (key, src/dst) structure has TTL `ad_ttl_sec` (default hours). On each packet we can lazily evict expired entries or run a periodic GC.

---

## 8. Offline Replay and Outputs

**Proposal**: Python, Docker, offline replay, logging.

- **Replay**: Read pcap(s) from `--pcap_dir` (recursive `*.pcap`, `*.pcap.gz`), replay in **timestamp order per file** (no global merge across files unless documented).
- **Outputs**:
  - `alarms.jsonl`: one JSON object per alarm (timestamp, key, src_est, dst_est, params).
  - `summary.csv`: one row per run (e.g. run params, packets_processed, num_alarms, first_alarm_time, payload usability metrics, processing_rate_pps).
- **Libraries**: We use **dpkt** for pcap parsing (lightweight, no need for Scapy’s full protocol stack for offline payload extraction; justification in README).

---

## 9. File → Component Mapping

| File | Responsibility |
|------|----------------|
| `config.py` | All thresholds, window sizes, port mode, beta, k, paths. |
| `rabin.py` | Rabin rolling fingerprint: init, roll byte-by-byte, value-sampling predicate. |
| `prevalence.py` | Count-min–style sketch + conservative update; window reset; candidate emission. |
| `dispersion.py` | Scaled bitmap (paper-faithful) for src/dst distinct counts; TTL; alarm when thresholds met. |
| `signatures.py` | Content key construction (port modes), whole vs substring extraction, value sampling. |
| `pcap_replay.py` | Discover pcaps, read in timestamp order per file, yield (timestamp, packet, payload, 5-tuple). |
| `metrics.py` | Payload usability (len==0, len<beta, size distribution); packets/sec, bytes/sec. |
| `run_detection.py` | CLI; wire prevalence → dispersion → alarms; write alarms.jsonl + summary.csv. |
| `eval_sweep.py` | Parameter sweep; output sweep_results.csv. |

---

## 10. Citation Summary

- **Content prevalence, heavy-hitter, time window**: Paper — content prevalence / multi-stage filter section.
- **Conservative update**: Paper / count-min literature — reduces overestimation for heavy hitters.
- **Address dispersion (src/dst distinct counts)**: Paper — address dispersion section.
- **Scaled bitmap**: Paper — distinct counting for dispersion (paper-faithful mode).
- **Rabin fingerprints + value sampling**: Paper — substring hashing and sampling (k-bit sampling rate 1/2^k).
- **Port binding modes**: Proposal / Paper — key by proto+port+content.
- **Partial payloads, Witty, truncation**: Proposal — Witty dataset; partial payload handling and `--truncate`.

This design keeps the implementation **paper-faithful** while satisfying the proposal’s deliverables (Python, Docker, offline replay, logging, payload usability, and sweep over parameters).

---

## 11. Witty dataset and partial payloads

- **Witty** uses UDP; payloads may be short or truncated in captures. The pipeline logs `payload_zero_count`, `payload_below_beta_count`, and fractions so you can tune `beta` and interpret detection.
- **Recommended**: Start with `whole` mode and low thresholds (e.g. prevalence_th=2, src/dst_disp_th=2); then try `substring` with beta=32–40 once the payload length distribution shows enough packets with length ≥ beta.
- **`--truncate N`**: Use to simulate truncation and record how first_alarm_time and num_alarms change with payload length.
