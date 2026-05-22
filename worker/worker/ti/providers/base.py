from abc import ABC, abstractmethod
from typing import Any


class ThreatIntelProvider(ABC):
    name: str = "base"

    @abstractmethod
    async def lookup_ip(self, ip: str) -> dict[str, Any]: ...
    @abstractmethod
    async def lookup_domain(self, domain: str) -> dict[str, Any]: ...
    @abstractmethod
    async def lookup_url(self, url: str) -> dict[str, Any]: ...
    @abstractmethod
    async def lookup_hash(self, h: str) -> dict[str, Any]: ...
