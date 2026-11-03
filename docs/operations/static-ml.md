# Static ML (unknown files)

Hashes and YARA only catch what someone has seen before. The static ML check scores files nobody has a signature for, from their structure alone, like the "machine learning" engine of an EDR. It runs inside the agent, offline, on Linux and Windows alike.

| File | Engine (`ml.engine`) | How |
|---|---|---|
| Windows program (PE: exe, dll, sys) | `ember_lgbm` | gradient-boosted trees (LightGBM) trained on EMBER 2018, evaluated in Go (`agent/internal/mlscore`) |
| Linux program (ELF) | `elf_heuristic` | weighted traits: mining pool URLs, miner names, UPX packing, missing section headers, packed sections, reverse-shell and persistence strings; `ml.reasons` lists the ones found |

Both kinds are checked on both systems: a Windows dropper on a Linux file server or a Linux miner in a Windows share are worth knowing about.

## What is scanned

Every file the on-access scanner reads: new and changed files in the YARA watched folders (`yara.watch_paths`, defaults Downloads, Temp, web roots, `/tmp`, `/dev/shm`...), up to `yara.max_file_size_mb`, whether or not YARA rules are loaded. Unchanged files are not scored again. With `yara.disabled: true` nothing is scored. Files whose hash is in the [known-malware set](malware-hashes.md) are left to that check.

## Levels and actions

| Level | PE threshold | ELF threshold | Rule (level) |
|---|---|---|---|
| `malicious` | score above the one where 0.1% of EMBER's benign test files score | 0.70 (at least two strong traits) | Static ML Malicious File (high); quarantined: Static ML Malicious File Quarantined (medium) |
| `suspicious` | above the 1% one | 0.45 | Static ML Suspicious File (low) |

Group policy (**Policies** page) `ml_action`:

- `detect` (default): alerts only.
- `block`: `malicious` files are quarantined like the *quarantine_file* task (restorable with *restore_file*). `suspicious` files are never quarantined.
- `off`.

Exclusions with the **Static ML** scope (path, program, SHA-256) turn it off for matching files: use them for in-house builds, installers or packers that score high. Windows users get a pop-up for `malicious` files when the policy's pop-ups are on.

## How good it is

Measured on EMBER 2018's test set (200,000 labelled PE files the model never saw):

| Metric | Value |
|---|---|
| ROC AUC | 0.9938 |
| Malware detected at 1% false positives (suspicious threshold) | 93.3% |
| Malware detected at 0.1% false positives (malicious threshold) | 82.9% |

On known-good software from a Linux workstation (2026-11, `go test -run TestSurvey ./internal/mlscan` with `MLSCAN_DIRS`):

| Files | malicious | suspicious |
|---|---|---|
| 9,865 PE (.NET SDK, PowerShell 7, NSIS, MariaDB, mingw, Steam, VS Code) | 0 | 1 (a Steam voice plug-in) |
| 21,089 ELF (/usr/bin, /usr/sbin, /usr/lib, Steam runtimes) | 0 | 0 |

Read these honestly:

- EMBER's files are from 2018. Malware has changed since; expect a lower detection rate on today's samples, and the model is a second opinion beside hashes, YARA and behaviour rules, not a verdict.
- 0.1% of benign files is still one in a thousand: on a developer machine full of unusual binaries, expect some `malicious` scores on good software. Start with `detect`, review a week of alerts, add exclusions, then turn on `block` where it fits.
- The ELF heuristics are not trained (there is no public labelled ELF dataset like EMBER) and have no measured rate; they are tuned to fire on miners, botnet droppers and packed payloads, which are most Linux malware.

## Rebuilding the model

```sh
python -m venv .venv && .venv/bin/pip install -r ml/requirements.txt
# EMBER 2018 v2 features (1.7 GB): https://ember.elastic.co/ember_dataset_2018_2.tar.bz2
.venv/bin/python ml/train.py ember2018/ agent/internal/mlscore/model.json.gz
cd agent && go test ./internal/mlscore    # Go scores match LightGBM's
```

`ml/vectorize.py` and `agent/internal/mlscore/vector.go` turn EMBER's raw feature JSON into the same 2381 numbers (FNV-1a feature hashing, our own; not EMBER's code). The agent extracts the raw features with Go's `debug/pe`; `ml/compare.py` checks them against LIEF on real files (section names, sizes and entropy, entry section, data directories, imports, exports) and that both vectorisers agree exactly. Training needs about 16 GB of RAM (`ML_LOAD_WORKERS`, default 3, files vectorised at once) and under an hour on 14 cores.

The EMBER 2018 dataset (Anderson & Roth, 2018) is listed under the MIT license; check `LICENSE.txt` in [elastic/ember](https://github.com/elastic/ember) before redistributing a model trained on it.
