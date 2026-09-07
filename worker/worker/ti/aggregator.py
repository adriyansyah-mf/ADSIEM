"""Concurrent TI enrichment aggregator. Adapted from soc-agent (no memory/Settings deps)."""
from __future__ import annotations
import asyncio
import ipaddress
from typing import Any

import httpx

from worker.ti.cache import get_or_fetch
from worker.ti.config import TIConfig
from worker.ti.extractor import extract_iocs
from worker.ti.iocs import IOC, IOCType
from worker.ti.models import EnrichmentSummary
from worker.ti.providers import (
    AbuseIPDBProvider, GeoIPProvider, GreyNoiseProvider,
    OTXProvider, ShodanProvider, URLhausProvider, VirusTotalProvider, WhoisLookupProvider,
)

# Ports whose mere exposure to the internet is itself a finding — remote
# admin protocols and databases/caches that are routinely left unauthenticated.
_RISKY_PORTS: dict[int, str] = {
    21: "ftp", 23: "telnet", 445: "smb", 1433: "mssql", 1521: "oracle-listener",
    3306: "mysql", 3389: "rdp", 5432: "postgres", 5900: "vnc", 5984: "couchdb",
    6379: "redis", 9042: "cassandra", 9200: "elasticsearch", 11211: "memcached",
    27017: "mongodb",
}


def _bullet(name: str, text: str) -> str:
    return f"{name}: {text}"


def _vals(iocs: list[IOC], t: IOCType) -> list[str]:
    return [i.value for i in iocs if i.type == t]


def _abuseipdb_summary(d: dict[str, Any]) -> str | None:
    if d.get("skipped"):
        return None
    sc = d.get("data", {}).get("abuseConfidenceScore")
    return f"abuseConfidenceScore={sc}" if sc is not None else None


def _vt_summary(d: dict[str, Any], label: str) -> str | None:
    if d.get("skipped") or d.get("not_found"):
        return None
    stats = d.get("data", {}).get("attributes", {}).get("last_analysis_stats") or {}
    mal, sus = stats.get("malicious"), stats.get("suspicious")
    if mal is None and sus is None:
        return None
    return _bullet(label, f"malicious={mal} suspicious={sus}")


def _otx_pulse(d: dict[str, Any], label: str) -> str | None:
    if d.get("skipped") or d.get("not_found"):
        return None
    pc = d.get("pulse_info", {}).get("count")
    return _bullet(label, f"pulse_count={pc}") if pc is not None else None


def _urlhaus_host(d: dict[str, Any]) -> str | None:
    if d.get("query_status") and d["query_status"] != "ok":
        return None
    if d.get("urlhaus_reference"):
        return f"references={d['urlhaus_reference']}"
    return "listed_sample" if d.get("urlhaus_status") else None


def _urlhaus_payload(d: dict[str, Any]) -> str | None:
    if d.get("skipped") or (d.get("query_status") and d["query_status"] != "ok"):
        return None
    parts = []
    if sig := (d.get("signature") or d.get("malware_printable")):
        parts.append(f"sig={str(sig)[:160]}")
    if d.get("md5_hash"):
        parts.append("md5_match")
    if st := d.get("urlhaus_status"):
        parts.append(f"urlhaus={st}")
    return ", ".join(parts) if parts else "payload_listed"


def _greynoise_bullet(d: dict[str, Any]) -> str | None:
    if d.get("skipped") or d.get("not_found"):
        return None
    if isinstance(d.get("message"), str) and "not found" in d["message"].lower():
        return None
    bits = []
    if "noise" in d:
        bits.append(f"noise={d['noise']}")
    if "riot" in d:
        bits.append(f"riot={d['riot']}")
    if cls := (d.get("classification") or d.get("grey_type")):
        bits.append(f"class={str(cls)[:100]}")
    if name := (d.get("name") or d.get("actor")):
        bits.append(f"name={str(name)[:100]}")
    if bits:
        return _bullet("greynoise", " ".join(bits))
    seen = d.get("seen")
    return _bullet("greynoise", f"seen={seen}") if seen is not None else None


def _ripe_bullet(d: dict[str, Any]) -> str | None:
    if d.get("skipped"):
        return None
    s = d.get("summary")
    return _bullet("whois(ip)", s.strip()[:420]) if isinstance(s, str) and s.strip() else None


def _shodan_bullet(d: dict[str, Any]) -> tuple[str | None, float]:
    """Returns (bullet text, risk contribution 0.0-1.0)."""
    if d.get("skipped") or d.get("not_found"):
        return None, 0.0
    ports = d.get("ports") or []
    vulns = d.get("vulns") or []
    org = d.get("org") or ""
    risky = sorted({_RISKY_PORTS[p] for p in ports if p in _RISKY_PORTS})
    parts = []
    if ports:
        parts.append(f"open_ports={','.join(str(p) for p in sorted(ports)[:15])}")
    if risky:
        parts.append(f"exposed_services={','.join(risky)}")
    if vulns:
        parts.append(f"known_vulns={','.join(sorted(vulns)[:8])}")
    if org:
        parts.append(f"org={org}")
    if not parts:
        return None, 0.0
    risk = 0.0
    if vulns:
        risk = 0.85
    elif risky:
        risk = 0.55
    return _bullet("shodan", " ".join(parts)), risk


def _geoip_bullet(d: dict[str, Any]) -> str | None:
    if d.get("status") != "success":
        return None
    country = str(d.get("country") or "").strip()
    city = str(d.get("city") or "").strip()
    isp = str(d.get("isp") or "").strip()
    return _bullet("geoip", f"{country} {city} isp={isp}".strip())


class EnrichmentAggregator:
    def __init__(self, cfg: TIConfig, redis: Any = None, tenant: str = "default") -> None:
        self._cfg = cfg
        self._redis = redis
        self._tenant = tenant
        self._vt = VirusTotalProvider(cfg)
        self._abuse = AbuseIPDBProvider(cfg)
        self._otx = OTXProvider(cfg)
        self._urlhaus = URLhausProvider(cfg)
        self._whois = WhoisLookupProvider(cfg)
        self._geo = GeoIPProvider(cfg)
        self._gn = GreyNoiseProvider(cfg)
        self._shodan = ShodanProvider(cfg)

    async def _cached(self, provider: str, lookup_type: str, indicator: str, fetch) -> dict[str, Any]:
        """Route a provider call through the Redis cache when a redis client
        was supplied; otherwise call the provider directly (e.g. soar_engine's
        simpler call site, which has no tenant/redis context readily
        available -- caching there is a fast-follow, not a regression)."""
        if self._redis is None:
            return await fetch()
        return await get_or_fetch(
            self._redis, tenant=self._tenant, provider=provider,
            lookup_type=lookup_type, indicator=indicator, fetch=fetch,
        )

    async def enrich(self, text: str, alert_title: str = "") -> EnrichmentSummary:
        iocs = extract_iocs(text)
        bullets: list[str] = []
        risk_samples: list[float] = []
        triage_hints: list[str] = []
        sem = asyncio.Semaphore(8)

        async def gate(coro):
            async with sem:
                await coro

        async def ingest_ip(ip: str) -> None:
            try:
                ipaddress.ip_address(ip.strip())
            except ValueError:
                return
            abuse, vt, otx, uh, geo, who, gn, shodan = await asyncio.gather(
                self._cached("abuseipdb", "ip", ip, lambda: self._abuse.lookup_ip(ip)),
                self._cached("virustotal", "ip", ip, lambda: self._vt.lookup_ip(ip)),
                self._cached("otx", "ip", ip, lambda: self._otx.lookup_ip(ip)),
                self._cached("urlhaus", "ip", ip, lambda: self._urlhaus.lookup_ip(ip)),
                self._cached("geoip", "ip", ip, lambda: self._geo.lookup_ip(ip)),
                self._cached("whois", "ip", ip, lambda: self._whois.lookup_ip(ip)),
                self._cached("greynoise", "ip", ip, lambda: self._gn.lookup_ip(ip)),
                self._cached("shodan", "ip", ip, lambda: self._shodan.lookup_ip(ip)),
            )
            if s := _abuseipdb_summary(abuse):
                bullets.append(_bullet("abuseipdb", s))
                ac = abuse.get("data", {}).get("abuseConfidenceScore")
                if isinstance(ac, (int, float)):
                    risk_samples.append(min(1.0, float(ac) / 100.0))
            if s := _vt_summary(vt, "virustotal(ip)"):
                bullets.append(s)
                stats = vt.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                mal = int(stats.get("malicious") or 0)
                tot = sum(int(stats.get(k) or 0) for k in ("harmless", "malicious", "suspicious"))
                if tot:
                    risk_samples.append(min(1.0, mal / tot + 0.1))
            if s := _otx_pulse(otx, "otx(ip)"):
                bullets.append(s)
                pc = otx.get("pulse_info", {}).get("count")
                if isinstance(pc, int) and pc > 0:
                    risk_samples.append(min(1.0, 0.2 + min(pc, 10) / 50.0))
            if s := _urlhaus_host(uh):
                bullets.append(_bullet("urlhaus(ip)", s))
                risk_samples.append(0.75)
            if s := _ripe_bullet(who):
                bullets.append(s)
            if s := _greynoise_bullet(gn):
                bullets.append(s)
                if isinstance(gn.get("noise"), bool) and gn["noise"]:
                    risk_samples.append(0.35)
                if str(gn.get("classification") or "").lower().find("malicious") >= 0:
                    risk_samples.append(0.82)
            if s := _geoip_bullet(geo):
                bullets.append(s)
            shodan_bullet, shodan_risk = _shodan_bullet(shodan)
            if shodan_bullet:
                bullets.append(shodan_bullet)
            if shodan_risk:
                risk_samples.append(shodan_risk)

        async def ingest_domain(dom: str) -> None:
            vt, otx, uh, who = await asyncio.gather(
                self._cached("virustotal", "domain", dom, lambda: self._vt.lookup_domain(dom)),
                self._cached("otx", "domain", dom, lambda: self._otx.lookup_domain(dom)),
                self._cached("urlhaus", "domain", dom, lambda: self._urlhaus.lookup_domain(dom)),
                self._cached("whois", "domain", dom, lambda: self._whois.lookup_domain(dom)),
            )
            if s := _vt_summary(vt, "virustotal(domain)"):
                bullets.append(s)
            if s := _otx_pulse(otx, "otx(domain)"):
                bullets.append(s)
            if s := _urlhaus_host(uh):
                bullets.append(_bullet("urlhaus(domain)", s))
                risk_samples.append(0.65)
            if who.get("rdap"):
                bullets.append(_bullet("rdap(domain)", "registration queried"))

        async def ingest_hash(h: str) -> None:
            vt, otx, uh = await asyncio.gather(
                self._cached("virustotal", "hash", h, lambda: self._vt.lookup_hash(h)),
                self._cached("otx", "hash", h, lambda: self._otx.lookup_hash(h)),
                self._cached("urlhaus", "hash", h, lambda: self._urlhaus.lookup_hash(h)),
            )
            if s := _vt_summary(vt, "virustotal(hash)"):
                bullets.append(s)
                stats = vt.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                mal = int(stats.get("malicious") or 0)
                if mal:
                    risk_samples.append(min(1.0, 0.5 + mal / 40.0))
            if s := _otx_pulse(otx, "otx(hash)"):
                bullets.append(s)
            if s := _urlhaus_payload(uh):
                bullets.append(_bullet("urlhaus(hash)", s))
                risk_samples.append(0.78)

        async def ingest_url(url: str) -> None:
            uh, vt, otx = await asyncio.gather(
                self._cached("urlhaus", "url", url, lambda: self._urlhaus.lookup_url(url)),
                self._cached("virustotal", "url", url, lambda: self._vt.lookup_url(url)),
                self._cached("otx", "url", url, lambda: self._otx.lookup_url(url)),
            )
            if s := _urlhaus_host(uh):
                bullets.append(_bullet("urlhaus(url)", s))
                risk_samples.append(0.85)
            if s := _vt_summary(vt, "virustotal(url)"):
                bullets.append(s)
            if s := _otx_pulse(otx, "otx(url)"):
                bullets.append(s)

        # SearXNG search
        if self._cfg.searxng_url:
            q_parts = [i.value for i in iocs if i.type in (IOCType.ipv4, IOCType.hash_sha256, IOCType.domain)][:3]
            if not q_parts and alert_title:
                q_parts = [alert_title]
            if q_parts:
                q = " ".join(q_parts)[:300]
                try:
                    async with httpx.AsyncClient(timeout=15.0) as c:
                        r = await c.get(f"{self._cfg.searxng_url}/search", params={"q": q, "format": "json"})
                        if r.status_code == 200:
                            results = r.json().get("results", [])[:self._cfg.searxng_max_results]
                            if results:
                                lines = [f"{x.get('title','')} — {x.get('content','')[:200]}" for x in results]
                                bullets.append(_bullet("searxng", "\n".join(lines)[:self._cfg.searxng_max_answer_chars]))
                                triage_hints.append(f"Web search returned {len(results)} results for {q!r}; corroborate with IOC/TI.")
                            else:
                                triage_hints.append("Web search returned no results; rely on IOC/TI bullets.")
                except Exception:
                    triage_hints.append("Web search unavailable; rely on IOC/TI bullets.")

        tasks: list[asyncio.Task] = []
        for ip in _vals(iocs, IOCType.ipv4) + _vals(iocs, IOCType.ipv6):
            tasks.append(asyncio.create_task(gate(ingest_ip(ip))))
        for dom in _vals(iocs, IOCType.domain):
            tasks.append(asyncio.create_task(gate(ingest_domain(dom))))
        for h in _vals(iocs, IOCType.hash_md5) + _vals(iocs, IOCType.hash_sha1) + _vals(iocs, IOCType.hash_sha256):
            tasks.append(asyncio.create_task(gate(ingest_hash(h))))
        for url in _vals(iocs, IOCType.url):
            tasks.append(asyncio.create_task(gate(ingest_url(url))))

        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)

        overall = max(risk_samples) if risk_samples else 0.0
        return EnrichmentSummary(
            iocs=iocs,
            provider_bullets=sorted(set(bullets))[:40],
            reputation=[],
            overall_risk=round(overall, 3),
            triage_hints=triage_hints[:20],
        )
