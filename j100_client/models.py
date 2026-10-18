"""Public configuration and result types."""

from dataclasses import dataclass
from typing import Union
from urllib.parse import urlsplit


def normalize_base_url(host: str) -> str:
    """Return a normalized HTTPS base URL for a phone host or URL."""
    value = host.strip()
    if not value:
        raise ValueError("phone address must not be empty")
    if "://" not in value:
        value = "https://" + value
    parsed = urlsplit(value)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise ValueError("phone address must be a host or HTTP(S) URL")
    return "{}://{}{}".format(
        parsed.scheme, parsed.netloc, parsed.path.rstrip("/")
    )


@dataclass(frozen=True)
class J100Config:
    host: str
    password: str = ""
    verify: Union[bool, str] = True
    timeout: float = 10.0

    @property
    def base_url(self) -> str:
        return normalize_base_url(self.host)


@dataclass(frozen=True)
class RestartResult:
    accepted: bool
    completed: bool
    observed_unavailable: bool


@dataclass(frozen=True)
class PhoneReport:
    content: bytes
    filename: str


@dataclass(frozen=True)
class PacketCapture:
    path: str


@dataclass(frozen=True)
class SipAccountStatus:
    registration_status: str
    sip_user_id: str
    sip_domain: str
    sip_proxy_server: str
