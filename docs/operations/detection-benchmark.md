# Detection benchmark

How much recent malware the agent's file engines catch, and how often they fire on known-good software. Run it before and after any detection change (new rules, a new model, new engines) and put both numbers in the PR.

Nothing is executed. Samples stay in MalwareBazaar's password-protected zips and are decrypted in memory only (`agent/internal/zipcrypto`).

## What is measured

| Engine | In the benchmark |
|---|---|
| Known-malware hashes | **left out**: the samples come from the same feed, so it would find them all. The question is what the other engines catch of a variant no feed has seen yet. |
| YARA | the rules in `-rules` (default the built-in pack `yara/builtin`); `yara` = any match, `yara-hi` = a match of high or critical severity |
| Static ML | the embedded model (PE) and the ELF heuristics, as `internal/mlscan` scores them; percentages over the files it scores |

`detected` = what raises a high alert or is blocked (YARA high/critical, or ML malicious). `flagged` = anything that raises an alert at all. Results are broken down by file type and by the 15 largest families.

## Running it

Use an isolated machine or VM (no shared or synced folders); the zips are live malware.

```sh
# 1. samples: your own abuse.ch Auth-Key (https://auth.abuse.ch/)
MB_AUTH_KEY=... python3 ml/bench/fetch_malwarebazaar.py ~/detbench/samples --per-type exe=300,dll=100,elf=200

# 2. benchmark (from agent/)
go run ./cmd/detbench -rules ../yara/builtin \
  -samples ~/detbench/samples \
  -benign /usr/bin,/usr/lib/x86_64-linux-gnu,/opt/microsoft/powershell \
  -out ~/detbench/report.json
```

The fetch script resumes (already downloaded samples are skipped) and keeps MalwareBazaar's metadata in `manifest.jsonl` (family, first seen, imphash, TLSH). The JSON report lists every sample's verdict and every flagged benign file.

For a fair before/after comparison keep the same sample set and benign directories between runs; for a trend over time, fetch a fresh set (the most recent samples are what the engines have not seen).

## Results

| Date | Samples | Detected | Flagged | Benign flagged | Notes |
|---|---|---|---|---|---|
| | | | | | |
