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

# or MalShare (your own API key; daily lists of hashes, 2000 downloads a day; raw files are piped
# into the same password-protected zip format and never written raw)
MALSHARE_KEY=... python3 ml/bench/fetch_malshare.py ~/detbench/malshare --days 2026-01-01,2025-12-15 --max 1500

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
| 2026-11-03 | same 83, with container scanning (`agent/internal/unpack`) | 2.4% | 4.8% | 1 / 3,287 | ML now scores the programs inside the zips: 2 of 57 suspicious, none malicious. |
| 2026-11-03 | same 83, with the EMBER2024 models (static ML v3) | 44.6% | 47.0% | - | every labelled stealer now `malicious` (SalatStealer 3/3, RustyStealer, SnappyClient, all > 0.99); 27 zips whose `zapret-discord.exe` (a 7 MB lure using zapret's name) scores malicious. Known-good survey: [static ML](static-ml.md#how-good-it-is). |
| 2026-11-16 | same 83, agent 1.29.0, built-in + 14 community YARA packs | 44.6% | 47.0% | 2 / 8,271 (ophcrack: Mimikatz rule; iodine: Sekoia iodine rule; both real hacktools) | community packs add no detection on this set; ML 0 on the known-good files |
| 2026-11-17 | HTML model (agent 1.33.0, `html_lgbm`), grouped five-fold cross-validation on the 1,353 MalShare html of 16 Nov against 42,771 Common Crawl pages | html: **71.8%** | html: **81.1%** | 3 / 3,525 Kali HTML files at `malicious`, 13 at `suspicious` or more | password-form pages 92.0% / 93.1%, redirectors 89.8% / 93.7%, obfuscated 77.0% / 84.5%; HTML smuggling: 1 sample, untested. The final model is trained on all 1,353, so a detbench run on these samples is not a test; the numbers are the held-out folds. See [static-ml.md](static-ml.md#html-pages). |
| 2026-11-16 | 1,505 MalShare samples (15 Dec 2025, 1 Jan 2026; `ml/bench/fetch_malshare.py`): 1,353 html, 56 exe, 57 elf, 8 dll, 10 archives, 21 other | 5.6% | 8.1% | - | **programs** (a year newer than the EMBER2024 training data): exe 69.6% detected / 94.6% flagged, elf 63.2% / 96.5%, dll 25% / 50% (8 files); YARA adds little (exe 7.1%, elf 3.5%). **html: 0.1%** (1 of 1,353). The html are 79% redirects, 21% posting forms, 14% password forms, 17% large base64 blobs, 16% eval/atob obfuscation: phishing kits, redirectors and smuggling pages, which no engine covers. MalShare has no family labels and its labels are not verified. |

**URLhaus labels are not a malware ground truth.** A URLhaus payload is a file a malware-distribution URL served. That day's 64 zips were mostly repackaged open-source tools (zapret DPI bypass with WinDivert, `winws.exe` and hundreds of `.bat` files), HWID spoofers and game-cheat lures, plus one `.scr`. Possibly trojanized, but mostly legitimate binaries, so a low rate on them does not mean missed malware. Use labelled MalwareBazaar samples for detection rates; use URLhaus to check what the engines say about what is actually being spread.

What the first run showed:

- Most payloads arrive in a container (zip, html, lnk): the engines see only the wrapper. Container scanning is the largest gap.
- The 2018 model misses current Go / Rust stealers: a newer training set is needed.
- The built-in YARA pack (18 rules: tools, miners, web shells, ransom notes) does not cover commodity stealers and loaders.
- Fixed on the way: Go's `debug/pe` refused PE files whose COFF symbol table points past the end of the file (the SalatStealer samples), so the model never scored them; they are now parsed without the table, as LIEF does.
