# Static ML (unknown files)

Hashes and YARA only catch what someone has seen before. The static ML check scores files nobody has a signature for, from their structure alone, like the "machine learning" engine of an EDR. It runs inside the agent, offline, on Linux and Windows alike.

| File | Engine (`ml.engine`) | How |
|---|---|---|
| Windows program (PE: exe, dll, sys, .NET) | `ember2024_lgbm` | gradient-boosted trees (LightGBM) trained on EMBER2024 (files from Sep 2023 to Dec 2024), evaluated in Go (`agent/internal/mlscore`) |
| Linux program (ELF) | `ember2024_elf_lgbm`, `elf_heuristic` | a model trained on EMBER2024's ELF files, and weighted traits (mining pool URLs, miner names, UPX packing, missing section headers, packed sections, reverse-shell and persistence strings); the higher of the two levels counts, `ml.reasons` lists the traits found |
| HTML page (`.html`, `.htm`, `.hta`, `.svg`, or content starting with markup) | `html_lgbm` | LightGBM on 58 static page features (forms and password fields, where forms post, redirects, hidden iframes, `eval`/`atob`/escapes, base64 blobs, Blob/download smuggling, brand names in the title, Telegram exfiltration, text-to-markup ratio...), read in one pass in Go (`agent/internal/mlscore/html.go`); no script runs. See [HTML pages](#html-pages) |

Both kinds are checked on both systems: a Windows dropper on a Linux file server or a Linux miner in a Windows share are worth knowing about. A file starting with `MZ` is always scored, also when its headers are broken (the byte and string features still count).

## What is scanned

Every file the on-access scanner reads: new and changed files in the YARA watched folders (`yara.watch_paths`, defaults Downloads, Temp, web roots, `/tmp`, `/dev/shm`...), up to `yara.max_file_size_mb`, whether or not YARA rules are loaded, and the files inside archives, disk images and HTML pages (see [YARA, inside containers](yara.md#inside-containers)). Unchanged files are not scored again. With `yara.disabled: true` nothing is scored. Files whose hash is in the [known-malware set](malware-hashes.md) are left to that check.

## Levels and actions

| Level | Threshold (PE and ELF models) | ELF heuristics | Rule (level) |
|---|---|---|---|
| `malicious` | score above the one where 0.1% of the benign test files score | 0.70 (at least two strong traits) | Static ML Malicious File (high); quarantined: Static ML Malicious File Quarantined (medium) |
| `suspicious` | above the 1% one | 0.45 | Static ML Suspicious File (low) |

Group policy (**Policies** page) `ml_action`:

- `detect` (default): alerts only.
- `block`: `malicious` files are quarantined like the *quarantine_file* task (restorable with *restore_file*). `suspicious` files are never quarantined.
- `off`.

Exclusions with the **Static ML** scope (path, program, SHA-256) turn it off for matching files: use them for in-house builds, installers or packers that score high. Windows users get a pop-up for `malicious` files when the policy's pop-ups are on.

## HTML pages

Phishing kits, redirectors and HTML smuggling arrive as `.html` attachments and downloads; YARA and the program models catch almost none of them (0.1% of 1,353 MalShare pages in the [benchmark](detection-benchmark.md)). The HTML model scores every page the scanner reads, with the same levels and `ml_action` as programs.

Training (`ml/html/train.py`, vectors from the agent's own extractor `agent/cmd/htmlfeat`): 1,353 MalShare HTML samples (Dec 2025, Jan 2026) against 42,771 HTML pages from two Common Crawl files (CC-MAIN-2026-39). Grouped five-fold cross-validation: crawled pages grouped by site, samples by their tag skeleton, so no site and no kit template is on both sides of a split.

| | Detected at 0.1% false positives (`malicious`) | at 1% (`suspicious` or more) |
|---|---|---|
| all 1,353 pages | 71.8% | 81.1% |
| with a password form (174) | 92.0% | 93.1% |
| redirectors (932) | 89.8% | 93.7% |
| obfuscated script (296) | 77.0% | 84.5% |

ROC AUC 0.966 to 0.984 over the five folds. On 3,525 HTML files of a Kali host (`/usr/share/doc`, `/usr/share/javascript`, Python packages), which the model never saw: 3 reach `malicious` (0.09%: an exiftool page titled "Apple", a tape example, the AWS CLI SSO page) and 13 reach `suspicious` or more (0.37%), mostly small example pages with a form or a redirect.

Limits: the malicious side is one source (MalShare), mostly redirectors; real phishing kits with password forms are 174 pages and HTML smuggling only 1, so the smuggling features are untested by real samples. Small legitimate login, OAuth redirect and example pages are where false positives come from: exclude them with a Static ML exclusion. A page that loads its whole form from the attacker's server at run time shows little to a static model.

## How good it is

Trained on EMBER2024 (Joyce et al., 2025): Win64 and .NET training files (Sep 2023 to Sep 2024) and the first six test weeks of Win32 (22 Sep to 2 Nov 2024; EMBER2024's 12 GB Win32 training file was not used), 1.06 million files, half malicious. Tested on the last six weeks (3 Nov to 14 Dec 2024), which the model never saw:

| Files | ROC AUC | Malware detected at 1% false positives (suspicious) | at 0.1% (malicious) |
|---|---|---|---|
| all PE, 209,344 | 0.998 | 96.4% | 85.5% |
| Win32, 89,760 | 0.998 | 95.9% | 82.9% |
| Win64, 59,584 | 0.999 | 97.1% | 90.4% |
| .NET, 60,000 | 0.997 | 96.5% | 84.8% |
| ELF, 12,000 (ELF test set) | 0.993 | 90.0% | 50.0% |

The ELF test set has 6,000 benign files, so its 0.1% threshold rests on 6 of them: take that column as rough.

Quarantine bar: a `malicious` file is quarantined on the model's word alone only when it scores above the 0.01% threshold (where 0.01% of the benign test files score higher). PE: 75.0% of all PE files detected at 0.01% false positives (Win64 84.9%, Win32 70.3%, .NET 72.5%), measured on 104,688 benign test files. ELF: 47.3% detected, measured on 15,928 benign files: EMBER2024's 6,000 and 9,928 ELF files from Debian 12 (bookworm, main, amd64) packages that are not in EMBER2024 (`ml/v3/elf_benign.py`). None of either set scores above it. The Debian files score lower than EMBER2024's benign files (none reaches even the 1% threshold), so they only set the 0.01% bar; the 1% and 0.1% thresholds stay those of EMBER2024's own test set.

Recent samples from malware URLs (URLhaus, 2026-11-03, `agent/cmd/detbench`): every labelled stealer was scored `malicious` (SalatStealer 3/3, RustyStealer, SnappyClient, all above 0.99), which the previous model (EMBER 2018) had scored clean; the Mozi ELF samples too.

On known-good software from a Linux workstation (2026-11, `go test -run TestSurvey ./internal/mlscan` with `MLSCAN_DIRS`):

| Files | malicious | suspicious |
|---|---|---|
| 10,702 PE, 7,418 distinct (.NET SDK, PowerShell 7, NSIS, MariaDB, mingw, Steam and Proton, VS Code) | 3 distinct (25 copies): wine-mono's two `csc.exe` stubs in Proton prefixes, NSIS's `RegTool` | 86 distinct (101 copies), mostly NSIS installer stubs and plug-ins and Steam game files |
| 20,999 ELF (/usr/bin, /usr/sbin, /usr/lib/x86_64-linux-gnu, gcc, Steam runtimes) | 0 | 0 |

So about 0.04% of distinct known-good programs reach `malicious` and 1.2% `suspicious`, in line with the thresholds. The previous model (EMBER 2018) was quieter on the same files (none malicious) but scored every current stealer above clean.

Read these honestly:

- The model is a second opinion beside hashes, YARA and behaviour rules, not a verdict.
- 0.1% of benign files is still one in a thousand: on a developer machine full of unusual binaries, expect some `malicious` scores on good software. Start with `detect`, review a week of alerts, add exclusions, then turn on `block` where it fits.
- The test weeks end in December 2024; detection drifts as malware changes. Retrain when EMBER publishes newer data (`ml/v3/train.py`).

## Features

EMBER2024's "feature version 3" groups, computed as its `thrember` package does with `pefile` and reproduced in Go (`agent/internal/mlscore/v3.go`): file size, entropy and first bytes; byte histogram; byte/entropy histogram; printable strings and 77 keyword and IOC patterns; COFF, optional and DOS headers; sections (sorted by address and aligned as pefile does), overlay; imports (pefile's name checks and ordinal names); exports; data directories; Rich header. Left out: Authenticode details (a full PKCS#7 parser) and pefile's own parse warnings. The vector (2,472 numbers, FNV-1a feature hashing, ours) is built by `ml/v3/vectorize.py` and, identically, `vector_v3.go`.

Checked on 1,500 local PE files (.NET, PowerShell, mingw, Steam, Windows tools): every group of the Go extractor equals `ml/v3/reference.py` (pefile 2024.8.26), and the Go vector equals the Python one (`ml/v3/compare.py`, `compare_vectors.py`). The Go scores equal LightGBM's on 50 test vectors per model (`TestModelMatchesLightGBM`, `TestELFModelMatchesLightGBM`).

## Rebuilding the models

```sh
python -m venv .venv && .venv/bin/pip install -r ml/requirements.txt
# EMBER2024 from Hugging Face (joyce8/EMBER2024): Win64_train, Dot_Net_train, ELF_train and the
# *_test zips (Win32_train.zip too if you can: 12 GB); put a <name>.done file next to each zip
.venv/bin/python ml/v3/train.py ember2024/ agent/internal/mlscore/model.json.gz --kind pe
# benign ELF files from Debian packages for the ELF 0.01% threshold (needs thrember from
# github.com/FutureComputing4AI/EMBER2024 installed; downloads about 3,000 packages)
.venv/bin/python ml/v3/elf_benign.py ember2024/ ember2024/Debian_ELF_benign.jsonl --target 8000
.venv/bin/python ml/v3/train.py ember2024/ agent/internal/mlscore/model_elf.json.gz --kind elf --rounds 400 --leaves 64 \
    --extra-test Debian_ELF_benign.jsonl
cd agent && go test ./internal/mlscore    # Go scores match LightGBM's
```

The PE model needs about 20 GB of RAM (1.06 million vectors) and about 30 minutes on 14 cores; the zips are read as they are (never unpacked) and vectors are cached per week.

EMBER2024 is published under the Apache-2.0 licence (dataset card on Hugging Face, `FutureComputing4AI/EMBER2024`); pefile, whose tables `pefile_consts.go` is generated from, under MIT.
