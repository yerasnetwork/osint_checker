from __future__ import annotations

import asyncio
import ipaddress
import socket
import time
from dataclasses import dataclass, field
from typing import Any, Callable
from urllib.parse import urlsplit, urljoin

import httpx

from .models import ScanConfig, Target

USER_AGENT = "CyberCheck/0.1 (infrastructure inventory)"


def error_text(exc: BaseException) -> str:
    text = str(exc).strip() or type(exc).__name__
    return f"{type(exc).__name__}: {text}"[:350]


class RateLimiter:
    def __init__(self, rate: int):
        self.interval = 1 / rate
        self.lock = asyncio.Lock()
        self.next_at = 0.0

    async def wait(self):
        async with self.lock:
            now = time.monotonic()
            delay = max(0, self.next_at - now)
            if delay:
                await asyncio.sleep(delay)
            self.next_at = time.monotonic() + self.interval


async def resolve(host: str, timeout: float = 5) -> list[str]:
    records = await asyncio.wait_for(
        asyncio.get_running_loop().getaddrinfo(host, None, type=socket.SOCK_STREAM), timeout)
    addresses = list(dict.fromkeys(record[4][0] for record in records))
    return sorted(addresses, key=lambda address: ipaddress.ip_address(address).version)


@dataclass
class ScanContext:
    config: ScanConfig
    target: Target
    client: httpx.AsyncClient
    progress: Callable[[str, int, int], None]
    publish: Callable[[str, dict], None] = field(default=lambda module, data: None)
    limiter: RateLimiter = field(init=False)
    dns_cache: dict[tuple[str, str], dict[str, Any]] = field(default_factory=dict)

    def __post_init__(self):
        self.limiter = RateLimiter(self.config.rate)

    async def fetch(self, url: str, *, scoped: bool = False, limit: int = 524288,
                    params: dict | None = None, headers: dict | None = None) -> dict:
        """Bounded requests, explicit redirects; target redirects never leave scope."""
        chain = []
        for hop in range(6):
            parsed = urlsplit(url)
            if parsed.scheme not in {"http", "https"} or parsed.username or parsed.password:
                raise ValueError("Некорректный URL редиректа")
            if scoped and not self.target.in_scope(parsed.hostname):
                raise ValueError("Редирект за пределы выбранной цели")
            await self.limiter.wait()
            async with self.client.stream("GET", url, params=params, headers=headers) as response:
                chain.append({"url": str(response.url), "status": response.status_code})
                location = response.headers.get("location")
                if response.is_redirect and location:
                    destination = urljoin(str(response.url), location)
                    if scoped and not self.target.in_scope(urlsplit(destination).hostname):
                        return {"url": str(response.url), "status": response.status_code,
                                "headers": dict(response.headers), "cookies": [], "body": "",
                                "redirects": chain, "blocked_redirect": destination, "truncated": False}
                    if hop == 5:
                        raise ValueError("Слишком много редиректов (больше 5)")
                    url, params = destination, None
                    continue
                body = bytearray()
                truncated = False
                async for chunk in response.aiter_bytes():
                    remaining = limit - len(body)
                    body.extend(chunk[:remaining])
                    if len(chunk) > remaining:
                        truncated = True
                        break
                return {"url": str(response.url), "status": response.status_code,
                        "headers": dict(response.headers),
                        "cookies": response.headers.get_list("set-cookie"),
                        "body": body.decode(response.encoding or "utf-8", errors="replace"),
                        "redirects": chain, "truncated": truncated}
        raise ValueError("Слишком много редиректов")

    async def dns_query(self, name: str, kind: str) -> dict:
        import json

        key = (name, kind)
        if key in self.dns_cache:
            return self.dns_cache[key]
        errors = []
        for endpoint in ("https://cloudflare-dns.com/dns-query", "https://dns.google/resolve"):
            try:
                result = await self.fetch(endpoint, params={"name": name, "type": kind},
                                          headers={"Accept": "application/dns-json"}, limit=131072)
                if result["status"] != 200 or result["truncated"]:
                    raise ValueError(f"DNS-источник вернул HTTP {result['status']} или слишком большой ответ")
                payload = json.loads(result["body"])
                status = payload.get("Status")
                if status not in (0, 3):
                    raise ValueError(f"DNS-ошибка {status}")
                result = {"name": name, "type": kind, "status": "nxdomain" if status == 3 else "ok",
                          "records": payload.get("Answer", []), "source": result["url"]}
                self.dns_cache[key] = result
                return result
            except (httpx.HTTPError, ValueError) as exc:
                errors.append(error_text(exc))
        raise ValueError("; ".join(errors))
