"""Lexical features of a domain name for the phishing domain model.

One module for both sides: ml/phish/train.py builds the training matrix with
it and worker/worker/phishing/model.py scores live DNS and URL domains with
it, so a feature can never differ between training and production. Change a
feature and FEATURE_VERSION must change too (the model file records it and
the worker refuses a model built from other features).
"""
from __future__ import annotations

import math
import re
from collections import Counter
from functools import lru_cache
from pathlib import Path

FEATURE_VERSION = 1

_DATA = Path(__file__).parent / "assets"

# Brands phishing imitates, by the label they show; each with its own
# registered domains (a brand in its own domain is not phishing).
BRANDS: dict[str, tuple[str, ...]] = {
    "paypal": ("paypal.com", "paypal.me"),
    "apple": ("apple.com", "icloud.com"),
    "icloud": ("icloud.com", "apple.com"),
    "microsoft": ("microsoft.com", "live.com", "office.com", "microsoftonline.com", "azure.com", "windows.net"),
    "office365": ("office.com", "microsoft.com"),
    "outlook": ("outlook.com", "live.com", "office.com"),
    "onedrive": ("live.com", "microsoft.com"),
    "sharepoint": ("sharepoint.com",),
    "google": ("google.com", "google.co.id", "googleapis.com", "gstatic.com", "youtube.com"),
    "gmail": ("google.com", "gmail.com"),
    "amazon": ("amazon.com", "amazonaws.com", "amazon.co.jp", "amazon.de"),
    "netflix": ("netflix.com", "nflxvideo.net"),
    "facebook": ("facebook.com", "fb.com", "fbcdn.net"),
    "instagram": ("instagram.com", "cdninstagram.com"),
    "whatsapp": ("whatsapp.com", "whatsapp.net"),
    "telegram": ("telegram.org", "t.me"),
    "linkedin": ("linkedin.com",),
    "dropbox": ("dropbox.com", "dropboxusercontent.com"),
    "docusign": ("docusign.com", "docusign.net"),
    "adobe": ("adobe.com", "adobelogin.com"),
    "steam": ("steampowered.com", "steamcommunity.com", "steamstatic.com"),
    "binance": ("binance.com",),
    "coinbase": ("coinbase.com",),
    "metamask": ("metamask.io",),
    "blockchain": ("blockchain.com",),
    "dhl": ("dhl.com", "dhl.de"),
    "fedex": ("fedex.com",),
    "usps": ("usps.com",),
    "wellsfargo": ("wellsfargo.com",),
    "chase": ("chase.com",),
    "citibank": ("citi.com", "citibank.com"),
    "hsbc": ("hsbc.com", "hsbc.co.id"),
    # Indonesia
    "bca": ("bca.co.id", "klikbca.com"),
    "klikbca": ("klikbca.com", "bca.co.id"),
    "mandiri": ("bankmandiri.co.id", "mandiri.co.id"),
    "livin": ("bankmandiri.co.id",),
    "bri": ("bri.co.id",),
    "brimo": ("bri.co.id",),
    "bni": ("bni.co.id",),
    "btn": ("btn.co.id",),
    "cimb": ("cimbniaga.co.id", "cimb.com"),
    "jenius": ("jenius.com", "btpn.com"),
    "dana": ("dana.id",),
    "ovo": ("ovo.id",),
    "gopay": ("gojek.com", "gopay.co.id"),
    "shopee": ("shopee.co.id", "shopee.com"),
    "tokopedia": ("tokopedia.com",),
    "lazada": ("lazada.co.id", "lazada.com"),
    "pajak": ("pajak.go.id",),
    "djponline": ("pajak.go.id",),
    "bpjs": ("bpjs-kesehatan.go.id", "bpjsketenagakerjaan.go.id"),
}

KEYWORDS = ("login", "signin", "logon", "verify", "verification", "secure", "security", "account", "update",
            "confirm", "billing", "invoice", "payment", "wallet", "auth", "recover", "recovery", "unlock",
            "support", "webscr", "suspend", "validate", "password", "reset", "bonus", "claim", "airdrop",
            "gift", "reward", "hadiah", "undian", "promo", "masuk", "akun", "verifikasi", "blokir")

# Free hosting and dynamic DNS where anyone gets a subdomain: the subdomain
# label is what a phisher chooses.
SHARED_HOSTS = ("000webhostapp.com", "github.io", "web.app", "firebaseapp.com", "pages.dev", "workers.dev",
                "netlify.app", "vercel.app", "weebly.com", "wixsite.com", "blogspot.com", "glitch.me",
                "repl.co", "replit.app", "herokuapp.com", "azurewebsites.net", "ngrok.io", "ngrok-free.app",
                "duckdns.org", "no-ip.org", "ddns.net", "web.core.windows.net", "r2.dev", "surge.sh",
                "webflow.io", "framer.app", "godaddysites.com", "square.site", "mybluehost.me", "sites.google.com",
                "ipfs.io", "dweb.link", "trycloudflare.com", "onrender.com", "fly.dev", "vercel.app",
                "translate.goog", "appspot.com", "cloudfront.net", "blob.core.windows.net", "s3.amazonaws.com")

# Top-level domains, each its own category (others share 0): which TLD a
# name sits under is one of the strongest signals.
TLDS = ("com", "net", "org", "io", "co", "id", "co.id", "go.id", "ac.id", "or.id", "web.id", "my.id", "biz.id",
        "info", "xyz", "top", "online", "site", "shop", "store", "club", "live", "app", "dev", "me", "tk",
        "ml", "ga", "cf", "gq", "ru", "cn", "su", "icu", "vip", "buzz", "cyou", "sbs", "cfd", "bond", "click",
        "link", "work", "rest", "fun", "monster", "lol", "pw", "cc", "ws", "uk", "co.uk", "de", "fr", "jp",
        "br", "in", "us", "ca", "au", "nl", "it", "es", "pl", "edu", "gov", "mil", "tv", "ai", "cloud", "page",
        "digital", "today", "world", "email", "support", "services", "network", "pro", "asia", "sg", "my",
        "ph", "vn", "th", "kr", "tw", "hk")
_TLD_ID = {t: i + 1 for i, t in enumerate(TLDS)}

FEATURES = (
    "len_fqdn", "len_reg_label", "len_sub", "n_labels", "n_sub_labels", "max_label_len",
    "digit_ratio_fqdn", "digit_ratio_reg", "hyphens_fqdn", "hyphens_reg", "entropy_reg", "entropy_sub",
    "vowel_ratio_reg", "max_consonant_run", "max_digit_run", "tld_id", "tld_len", "punycode",
    "brand_in_sub", "brand_in_reg", "brand_foreign", "keyword_count", "keyword_in_reg", "typo_dist",
    "shared_host", "hex_like_sub", "repeat_char_ratio", "underscore", "www_prefix", "num_like_labels",
    "sub_has_reg_tld", "dash_label_count", "longest_word_like",
)

_VOWELS = set("aeiou")
_LETTERS = set("abcdefghijklmnopqrstuvwxyz")


class PSL:
    """Public Suffix List (both sections): the registered domain of a name."""

    def __init__(self, text: str):
        self.rules: set[str] = set()
        self.wild: set[str] = set()
        self.exc: set[str] = set()
        for line in text.splitlines():
            line = line.strip().lower()
            if not line or line.startswith("//"):
                continue
            line = line.split()[0]
            if line.startswith("!"):
                self.exc.add(line[1:])
            elif line.startswith("*."):
                self.wild.add(line[2:])
            else:
                self.rules.add(line)

    def suffix_len(self, labels: list[str]) -> int:
        """Number of labels in the public suffix of labels."""
        n = len(labels)
        best = 1
        for i in range(n):
            cand = ".".join(labels[i:])
            if cand in self.exc:
                return n - i - 1
            if cand in self.rules:
                best = max(best, n - i)
            if i + 1 < n and ".".join(labels[i + 1:]) in self.wild:
                best = max(best, n - i)
        return best

    def split(self, name: str) -> tuple[str, str, str]:
        """(subdomain, registrable label, public suffix); registrable label is ''
        when the name is a public suffix itself."""
        labels = name.split(".")
        k = self.suffix_len(labels)
        if k >= len(labels):
            return "", "", name
        suffix = ".".join(labels[len(labels) - k:])
        reg = labels[len(labels) - k - 1]
        sub = ".".join(labels[:len(labels) - k - 1])
        return sub, reg, suffix


@lru_cache(maxsize=1)
def default_psl() -> PSL:
    return PSL((_DATA / "public_suffix_list.dat").read_text(encoding="utf-8"))


def entropy(s: str) -> float:
    if not s:
        return 0.0
    c = Counter(s)
    n = len(s)
    return -sum(v / n * math.log2(v / n) for v in c.values())


def _max_run(s: str, chars) -> int:
    best = cur = 0
    for ch in s:
        if ch in chars:
            cur += 1
            best = max(best, cur)
        else:
            cur = 0
    return best


def _levenshtein(a: str, b: str, cap: int = 3) -> int:
    if abs(len(a) - len(b)) > cap:
        return cap + 1
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        lo = i
        for j, cb in enumerate(b, 1):
            v = min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb))
            cur.append(v)
            lo = min(lo, v)
        if lo > cap:
            return cap + 1
        prev = cur
    return min(prev[-1], cap + 1)


_TYPO_TARGETS = tuple(b for b in BRANDS if len(b) >= 5)
_HEX = re.compile(r"^[0-9a-f]{12,}$")
_NUMLIKE = re.compile(r"^\d+$")
_WORDISH = re.compile(r"[a-z]{4,}")
_DIGITS = set("0123456789")
_CONSONANTS = _LETTERS - _VOWELS


_SPLIT = re.compile(r"[-._]")


def _brand_in(brand: str, text: str, tokens: list[str]) -> int:
    """A long brand anywhere in text; a short one (under 5 letters: bca, bri,
    ovo, dana) only as a whole token, or a token's start or end with 3 to 6
    more letters (klikbca, bcamobile), never inside a word (fabric, novo)."""
    if len(brand) >= 5:
        return int(brand in text)
    return int(any(t == brand or (len(brand) + 3 <= len(t) <= len(brand) + 6
                                   and (t.startswith(brand) or t.endswith(brand)))
                   for t in tokens))


def normalize(name: str) -> str:
    return (name or "").strip().strip(".").lower()


def scorable(name: str) -> bool:
    """Names the model judges: a dotted host name, not an address, not a
    reverse lookup, not a single label."""
    if not name or "." not in name or len(name) > 253:
        return False
    if name.endswith(".arpa") or name.endswith(".local") or name.endswith(".internal") or name.endswith(".lan"):
        return False
    if all(p.isdigit() for p in name.split(".")) or ":" in name:
        return False
    return all(ch.isalnum() or ch in "-._" for ch in name)


def registered_domain(name: str, psl: PSL | None = None) -> str:
    sub, reg, suffix = (psl or default_psl()).split(normalize(name))
    return f"{reg}.{suffix}" if reg else suffix


def features(name: str, psl: PSL | None = None) -> list[float]:
    """The FEATURES vector of one host name (normalize()d)."""
    psl = psl or default_psl()
    name = normalize(name)
    sub, reg, suffix = psl.split(name)
    regdom = f"{reg}.{suffix}" if reg else suffix
    labels = name.split(".")
    sub_labels = sub.split(".") if sub else []
    letters_reg = [c for c in reg if c in _LETTERS]
    n_fqdn = max(len(name), 1)
    tokens = name.replace("-", ".").replace("_", ".").split(".")

    brand_in_sub = brand_in_reg = brand_foreign = 0
    sub_tokens = _SPLIT.split(sub) if sub else []
    reg_tokens = reg.split("-")
    for brand, owned in BRANDS.items():
        in_sub = _brand_in(brand, sub, sub_tokens)
        in_reg = _brand_in(brand, reg, reg_tokens)
        brand_in_sub |= in_sub
        brand_in_reg |= in_reg
        if (in_sub or in_reg) and not any(regdom == o or regdom.endswith("." + o) for o in owned):
            brand_foreign = 1
    kw = sum(1 for k in KEYWORDS if k in name)
    kw_reg = int(any(k in reg for k in KEYWORDS))
    typo = 4
    if reg and reg not in BRANDS:
        for b in _TYPO_TARGETS:
            typo = min(typo, _levenshtein(reg, b))
    shared = int(any(name == h or name.endswith("." + h) for h in SHARED_HOSTS))
    repeat = 0.0
    if name:
        repeat = max(Counter(name.replace(".", "")).values() or [0]) / n_fqdn

    return [
        float(len(name)),
        float(len(reg)),
        float(len(sub)),
        float(len(labels)),
        float(len(sub_labels)),
        float(max(len(x) for x in labels)),
        sum(c in _DIGITS for c in name) / n_fqdn,
        sum(c in _DIGITS for c in reg) / max(len(reg), 1),
        float(name.count("-")),
        float(reg.count("-")),
        entropy(reg),
        entropy(sub.replace(".", "")),
        sum(c in _VOWELS for c in letters_reg) / max(len(letters_reg), 1),
        float(_max_run(reg, _CONSONANTS)),
        float(_max_run(name, _DIGITS)),
        float(_TLD_ID.get(suffix, 0)),
        float(len(suffix)),
        float("xn--" in name),
        float(brand_in_sub),
        float(brand_in_reg),
        float(brand_foreign),
        float(kw),
        float(kw_reg),
        float(typo),
        float(shared),
        float(any(_HEX.match(x) for x in sub_labels)),
        repeat,
        float("_" in name),
        float(bool(sub_labels) and sub_labels[0] == "www"),
        float(sum(1 for x in labels if _NUMLIKE.match(x))),
        float(any(x in _TLD_ID and x not in ("id", "co", "me", "io") for x in sub_labels)),
        float(sum(1 for x in labels if "-" in x)),
        float(max((len(m) for t in tokens for m in _WORDISH.findall(t)), default=0)),
    ]
