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
| 2026-11-03 | 83 URLhaus payloads (64 zip, 7 html, 5 exe, 3 js, 2 elf, lnk, msi) | 2.4% | 2.4% | 1 / 3,287 (ophcrack: Mimikatz rule) | built-in YARA 0%; ML: both ELF (Mozi), no PE: 3 SalatStealer (Go) scored 0.62–0.69 under the 0.76 suspicious threshold, RustyStealer 0.11, SnappyClient 0.16; zips are not opened. MalwareBazaar `get_file` answered 500 for every sample that day, so URLhaus only (`--source urlhaus`). |

What the first run showed:

- Most payloads arrive in a container (zip, html, lnk): the engines see only the wrapper. Container scanning is the largest gap.
- The 2018 model misses current Go / Rust stealers: a newer training set is needed.
- The built-in YARA pack (18 rules: tools, miners, web shells, ransom notes) does not cover commodity stealers and loaders.
- Fixed on the way: Go's `debug/pe` refused PE files whose COFF symbol table points past the end of the file (the SalatStealer samples), so the model never scored them; they are now parsed without the table, as LIEF does.
