"""Small HTTP adapters with optional native async backends."""

import asyncio
import importlib
from dataclasses import dataclass
from typing import Any, Dict, Optional

from .exceptions import TransportError


@dataclass
class Response:
    status_code: int
    text: str
    headers: Dict[str, str]


def select_backend() -> str:
    """Select the first compatible optional backend, then requests."""
    for name in ("httpx2", "httpx"):
        try:
            module = importlib.import_module(name)
        except ImportError:
            continue
        if hasattr(module, "Client") and hasattr(module, "AsyncClient"):
            return name
    return "requests"


class SyncTransport:
    def __init__(self, base_url: str, verify: Any, timeout: float, backend: Optional[str] = None):
        self.base_url = base_url
        self.backend = backend or select_backend()
        self._timeout = timeout
        self._module = importlib.import_module(self.backend)
        if self.backend == "requests":
            self._client = self._module.Session()
            self._verify = verify
            if verify is False:
                self._module.packages.urllib3.disable_warnings(self._module.packages.urllib3.exceptions.InsecureRequestWarning)
        else:
            self._client = self._module.Client(verify=verify, timeout=timeout)

    def request(self, method: str, path: str, **kwargs: Any) -> Response:
        url = self.base_url + path
        try:
            if self.backend == "requests":
                response = self._client.request(method, url, verify=self._verify, timeout=self._timeout, **kwargs)
            else:
                response = self._client.request(method, url, **kwargs)
        except Exception as error:
            raise TransportError("unable to communicate with phone; check address and TLS settings") from error
        return Response(response.status_code, response.text, dict(response.headers))

    def cookie(self, name: str) -> Optional[str]:
        return self._client.cookies.get(name)

    def close(self) -> None:
        self._client.close()


class AsyncTransport:
    def __init__(self, base_url: str, verify: Any, timeout: float, backend: Optional[str] = None):
        self.base_url = base_url
        self.backend = backend or select_backend()
        self._timeout = timeout
        self._verify = verify
        self._module = importlib.import_module(self.backend)
        self._lock = asyncio.Lock()
        if self.backend == "requests":
            self._client = self._module.Session()
            if verify is False:
                self._module.packages.urllib3.disable_warnings(self._module.packages.urllib3.exceptions.InsecureRequestWarning)
        else:
            self._client = self._module.AsyncClient(verify=verify, timeout=timeout)

    async def request(self, method: str, path: str, **kwargs: Any) -> Response:
        url = self.base_url + path
        try:
            if self.backend == "requests":
                async with self._lock:
                    response = await asyncio.to_thread(
                        self._client.request, method, url, verify=self._verify, timeout=self._timeout, **kwargs
                    )
            else:
                response = await self._client.request(method, url, **kwargs)
        except Exception as error:
            raise TransportError("unable to communicate with phone; check address and TLS settings") from error
        return Response(response.status_code, response.text, dict(response.headers))

    async def cookie(self, name: str) -> Optional[str]:
        if self.backend == "requests":
            return self._client.cookies.get(name)
        return self._client.cookies.get(name)

    async def close(self) -> None:
        if self.backend == "requests":
            await asyncio.to_thread(self._client.close)
        else:
            await self._client.aclose()
