# tests/worker/test_phishing_domain_model.py
"""The phishing domain model (worker/worker/phishing): the shipped model
scores like LightGBM did, names get phishing.* fields, popular domains never
get a verdict, and an agent DNS line for a phishing-looking host raises the
ML rule through the shipped decoder and rules."""
import asyncio
import glob
import gzip
import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../../worker"))

import pytest  # noqa: E402
import yaml  # noqa: E402

from worker import phishing  # noqa: E402
from worker.decoder_engine import DecoderEngine  # noqa: E402
from worker.phishing import features as F  # noqa: E402
from worker.phishing import model as M  # noqa: E402
from worker.sigma_engine import SigmaEngine  # noqa: E402

ROOT = os.path.join(os.path.dirname(__file__), "../..")
DATA = os.path.join(ROOT, "worker/worker/phishing/assets")
_LOOP = asyncio.new_event_loop()


def test_model_loads_and_matches_lightgbm():
    m = M.default()
    assert m is not None
    assert {"fpr_0.0001", "fpr_1e-05"} <= set(m.thresholds)
    with gzip.open(os.path.join(DATA, "model.parity.json.gz"), "rt") as f:
        parity = json.load(f)
    assert len(parity) >= 100
    for p in parity:
        assert abs(m.score_features(F.features(p["name"])) - p["score"]) < 1e-9, p["name"]


def test_feature_vector_shape_and_psl():
    assert len(F.features("a.b.example.co.id")) == len(F.FEATURES)
    assert F.default_psl().split("login.user1.github.io") == ("login", "user1", "github.io")
    assert F.registered_domain("x.y.tokopedia.com") == "tokopedia.com"


def test_short_brands_match_tokens_not_words():
    fx = lambda n: dict(zip(F.FEATURES, F.features(n)))  # noqa: E731
    assert fx("login-bca.verify.xyz")["brand_foreign"] == 1
    assert fx("www.klikbca.com")["brand_foreign"] == 0      # the brand's own domain
    assert fx("fabric.example.com")["brand_in_sub"] == 0    # "bri" inside a word
    assert fx("novo.example.com")["brand_in_sub"] == 0      # "ovo" inside a word


@pytest.mark.parametrize("name", ["login-bca-verifikasi.xyz", "microsoft-office365-login.web.app",
                                  "paypal-account-update.info"])
def test_phishing_looking_names_get_a_verdict(name):
    ev = {"dns.question.name": name}
    assert phishing.enrich(ev) in ("medium", "high")
    assert ev["phishing.domain"] == name and ev["phishing.score"] > 0.99


@pytest.mark.parametrize("name", ["www.google.com", "api.tokopedia.com", "cdn.jsdelivr.net", "github.com",
                                  "d1a2b3c4d5.cloudfront.net"])
def test_ordinary_names_get_none(name):
    ev = {"url.domain": name}
    assert phishing.enrich(ev) is None
    assert "phishing.verdict" not in ev


def test_popular_domains_never_get_a_verdict():
    assert "google.com" in phishing.popular() and "#" not in "".join(list(phishing.popular())[:50])
    m = M.default()

    class Always(M.Model):
        def __init__(self):
            self.trees, self.thresholds, self.report = m.trees, m.thresholds, {}

        def score(self, name):
            return 1.0

    ev = {"dns.question.name": "secure-login.google.com"}
    assert phishing.enrich(ev, Always()) is None and "phishing.verdict" not in ev
    ev = {"dns.question.name": "secure-login.example-unknown-site.xyz"}
    assert phishing.enrich(ev, Always()) == "high"


def test_unscorable_names_are_left_alone():
    for name in ["10.0.0.1", "1.0.168.192.in-addr.arpa", "printer.local", "localhost", ""]:
        ev = {"dns.question.name": name}
        assert phishing.enrich(ev) is None and "phishing.score" not in ev


def test_agent_dns_line_raises_the_ml_rule():
    load = lambda p: [open(f).read() for f in sorted(glob.glob(os.path.join(ROOT, p)))]  # noqa: E731
    dec = DecoderEngine()
    dec.load_from_yaml_list(sorted(load("decoders/*.yaml"), key=lambda c: yaml.safe_load(c).get("priority", 100)))
    sig = SigmaEngine()
    sig.load_from_yaml_list(load("rules/*.yaml"))
    assert not sig.load_errors, sig.load_errors

    def titles(host):
        raw = f"host={host} dst=1.1.1.1 dport=53 proto=udp pid=4242 comm=firefox uid=1000"
        decoded, _ = dec.decode_named("linux_dns_query", raw)
        phishing.enrich(decoded)
        ev = dict(decoded, raw_message=raw, log_type="linux_dns_query")
        return {m["title"] for m in _LOOP.run_until_complete(sig.evaluate(ev))}

    assert any(t.startswith("Likely Phishing Domain (ML") for t in titles("login-bca-verifikasi.xyz"))
    assert not any(t.startswith("Likely Phishing Domain (ML") for t in titles("api.tokopedia.com"))
