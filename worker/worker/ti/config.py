from dataclasses import dataclass, field


@dataclass
class TIConfig:
    virustotal_api_key: str = ""
    abuseipdb_api_key: str = ""
    otx_api_key: str = ""
    greynoise_api_key: str = ""
    searxng_url: str = ""
    http_verify_tls: bool = True
    greynoise_enrich_ips: bool = True
    greynoise_timeout_seconds: float = 30.0
    whois_rdap_timeout_seconds: float = 10.0
    searxng_max_results: int = 5
    searxng_max_answer_chars: int = 2000
