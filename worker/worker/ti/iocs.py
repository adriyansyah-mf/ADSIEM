from __future__ import annotations
from enum import Enum
from pydantic import BaseModel, Field


class IOCType(str, Enum):
    ipv4 = "ipv4"
    ipv6 = "ipv6"
    domain = "domain"
    url = "url"
    hash_md5 = "hash_md5"
    hash_sha1 = "hash_sha1"
    hash_sha256 = "hash_sha256"
    command = "command"
    powershell = "powershell"


class IOC(BaseModel):
    type: IOCType
    value: str = Field(..., min_length=1, max_length=4096)
    context: str | None = None
