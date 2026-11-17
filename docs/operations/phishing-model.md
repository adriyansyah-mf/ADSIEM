# Phishing domain model

The worker scores host names with a lexical model and alerts on the ones that look like phishing. It looks at the name only: no page is fetched and no lookup leaves the server.

## Where it runs

`worker/worker/consumer.py` `_detect` calls `phishing.enrich()` on every event before the Sigma rules run. The first of `dns.question.name`, `url.domain` or `destination.domain` that is a dotted host name (not an address, `.arpa`, `.local`, `.internal`, `.lan` or a single label) is scored. The event gets:

| Field | Value |
|---|---|
| `phishing.score` | model probability, 0 to 1 |
| `phishing.domain` | the name scored |
| `phishing.registered_domain` | its registered domain (Public Suffix List, private section included, so `user.github.io` is its own domain) |
| `phishing.verdict` | `medium` or `high`, only above the thresholds below and only when the registered domain is not on the popular list |

The fields are indexed with the event, so `phishing.score >= 0.9` works as a hunt. Scores are cached per name (50,000 names), so a busy DNS stream costs little.

Rules: `rules/phishing_domain_ml_medium.yaml` (level medium) and `rules/phishing_domain_ml_high.yaml` (level high), on `phishing.verdict`. Disable or tune them like any rule; add a suppression for a domain your company owns.

## Features

`worker/worker/phishing/features.py`, used both by training and by the worker (`FEATURE_VERSION` in the model must match):

- length of the name, the registered label and the subdomain; label counts; longest label
- digits, hyphens, entropy, vowel ratio, longest consonant and digit runs
- the public suffix as a category (`com`, `co.id`, `xyz`, `top`, ...)
- punycode (`xn--`)
- brand names (global brands and Indonesian banks, e-wallets, marketplaces, tax and BPJS) in the subdomain or the registered label, and whether the registered domain is not the brand's own (`login-bca.example.xyz` yes, `www.klikbca.com` no); short brands such as `bca`, `bri`, `ovo` only as whole tokens or with a 3 to 6 letter affix (`klikbca`), never inside a word
- login, verify, account, wallet, bonus, hadiah, verifikasi and similar words
- edit distance of the registered label to a brand (`paypa1`)
- free hosting and dynamic DNS parents (`000webhostapp.com`, `github.io`, `pages.dev`, `workers.dev`, `r2.dev`, `web.app`, `ngrok`, ...)
- hex-looking labels, repeated characters, underscores, numeric labels, a TLD used as a subdomain label

## Data and training

`ml/phish/train.py`, all public and without keys:

| Side | Source | Names |
|---|---|---|
| phishing | [Phishing.Database](https://github.com/mitchellkrogza/Phishing.Database) `phishing-domains-ACTIVE.txt`, [OpenPhish](https://github.com/openphish/public_feed) feed | 378,666 |
| benign | [Cisco Umbrella top 1M](http://s3-us-west-1.amazonaws.com/umbrella-static/top-1m.csv.zip) (real DNS names, subdomains included), [Tranco](https://tranco-list.eu/) top 300,000 | 1,036,089 |

A name on both sides is dropped (319), and so is a phishing name under one of Tranco's top 1,000 registered domains (7,886): a page on a big platform cannot be judged from its host. One fifth of the registered domains (hash of the name) is held out, so no domain is in both train and test. LightGBM, 63 leaves, early stopping on the held-out fold; the shipped model is then trained on everything with the same number of rounds. Thresholds are set on the held-out benign scores.

```
python ml/phish/train.py --phish phishing-domains-ACTIVE.txt --phish feed.txt \
    --umbrella top-1m.csv --tranco tranco-top-1m.csv \
    --out worker/worker/phishing/assets/model.json.gz --report report.json
```

The model file is LightGBM's `dump_model()` as gzip JSON; `worker/worker/phishing/model.py` walks the trees, so the worker needs no LightGBM. `model.parity.json.gz` holds 200 names with LightGBM's scores, and `tests/worker/test_phishing_domain_model.py` checks the worker gives the same.

`assets/popular_domains.txt.gz` is the first 20,000 registered domains of Tranco: never given a verdict.

## Results (17 Nov 2026)

Held-out: 70,541 phishing, 224,931 benign. AUC 0.936.

| Threshold | False positives (benign) | Phishing caught |
|---|---|---|
| 1 in 1,000 | 224 | 42.8% |
| 1 in 10,000 (`medium`) | 22 | 21.0% |
| 1 in 100,000 (`high`) | 2 | 9.9% |

By kind of phishing name (60,000 sampled phishing names):

| Kind | 1 in 1,000 | `medium` | `high` |
|---|---|---|---|
| brand outside its own domain | 70.7% | 43.6% | 23.1% |
| login/verify/prize words | 64.3% | 42.8% | 26.7% |
| free hosting subdomain | 89.9% | 48.9% | 22.3% |
| none of these (hacked sites, random names) | 22.6% | 8.4% | 4.6% |

The highest-scoring "benign" names are mostly random subdomains of `r2.dev`, `workers.dev`, `pages.dev` and `appspot.com` (for example `bpjs138-assets.pages.dev`): on the Umbrella list because they are queried a lot, and several are likely abuse themselves, so the real false-positive rate is probably lower than measured.

## Limits

- A name alone does not reveal phishing hosted on a hacked site with an ordinary name; feeds (URLhaus, PhishTank in Web Protection), the web block and YARA on downloaded pages cover more of that.
- Your own domains and those of your vendors can look like the patterns (`login-portal.company.co.id`): add a rule suppression for them.
- The benign side is global top lists. A fleet with many local Indonesian sites may see a different false-positive rate; check `phishing.score` on your own DNS data before raising the rule levels.
- Phishing names change; retrain with fresh feeds every few months.
