from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from typing import Literal
from urllib.parse import urlsplit, urlunsplit

from pydantic import BaseModel, Field, field_validator, model_validator

MODULES = ("ports", "dns", "subdomains", "web", "tls", "osint")
QUICK_PORTS = (21, 22, 25, 53, 80, 110, 135, 139, 143, 443, 445, 465, 587,
               993, 995, 1433, 3306, 3389, 5432, 6379, 8000, 8080, 8443, 9200, 27017)
STANDARD_PORTS = tuple(sorted(set(QUICK_PORTS) | {
    20, 23, 26, 49, 79, 81, 88, 111, 113, 119, 123, 161, 389, 427, 515,
    548, 554, 631, 636, 873, 902, 990, 1080, 1194, 1521, 1723, 1883,
    2049, 2375, 2376, 3000, 3128, 4444, 5000, 5001, 5060, 5601, 5672,
    5900, 5985, 5986, 6443, 7001, 8001, 8081, 8088, 8888, 9000, 9090,
    9100, 9300, 9418, 11211, 15672, 27018,
}))


@dataclass(frozen=True)
class Target:
    host: str
    url: str
    port: int | None
    explicit_url: bool
    is_ip: bool

    def in_scope(self, hostname: str | None) -> bool:
        if not hostname:
            return False
        candidate = hostname.rstrip(".").lower()
        return candidate == self.host or (not self.is_ip and candidate.endswith("." + self.host))


def normalize_target(value: str) -> Target:
    value = value.strip()
    if not value or len(value) > 2048 or any(c.isspace() for c in value):
        raise ValueError("Введите домен, IP или HTTP(S)-адрес без пробелов")
    explicit = "://" in value
    if not explicit and "/" in value:
        try:
            ipaddress.ip_network(value, strict=False)
        except ValueError:
            pass
        else:
            raise ValueError("Укажите один IP или домен; диапазоны CIDR не поддерживаются")
    # A bare IPv6 address must not be parsed as host:port.
    if not explicit:
        try:
            parsed_ip = ipaddress.ip_address(value)
            if parsed_ip.version == 6:
                value = f"[{value}]"
        except ValueError:
            pass
    parsed = urlsplit(value if explicit else "https://" + value)
    if parsed.scheme not in {"http", "https"} or parsed.username or parsed.password:
        raise ValueError("Поддерживаются HTTP(S)-адреса без логина и пароля")
    if parsed.path.endswith(".git"):
        raise ValueError("Это адрес Git-репозитория. Укажите домен или URL сайта для проверки")
    host = (parsed.hostname or "").rstrip(".").lower()
    if not host or "%" in host:
        raise ValueError("Некорректный адрес цели")
    try:
        host = str(ipaddress.ip_address(host))
        is_ip = True
    except ValueError:
        host = host.encode("idna").decode("ascii")
        is_ip = False
        labels = host.split(".")
        if len(host) > 253 or any(not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label) for label in labels):
            raise ValueError("Некорректное доменное имя")
    try:
        port = parsed.port
    except ValueError as exc:
        raise ValueError("Порт должен быть в диапазоне 1–65535") from exc
    if port == 0:
        raise ValueError("Порт должен быть в диапазоне 1–65535")
    netloc = f"[{host}]" if ":" in host else host
    if port is not None:
        netloc += f":{port}"
    url = urlunsplit((parsed.scheme, netloc, parsed.path or "/", parsed.query, ""))
    return Target(host, url, port, explicit, is_ip)


def parse_ports(value: str) -> list[int]:
    ports: set[int] = set()
    if not value.strip() or len(value) > 4096:
        raise ValueError("Укажите порты, например 22,80,443,8000-8100")
    for part in value.split(","):
        part = part.strip()
        match = re.fullmatch(r"(\d{1,5})(?:\s*-\s*(\d{1,5}))?", part)
        if not match:
            raise ValueError(f"Некорректный порт или диапазон: {part[:40]}")
        start = int(match[1])
        end = int(match[2] or start)
        if not 1 <= start <= end <= 65535:
            raise ValueError("Порты должны быть в диапазоне 1–65535; начало не больше конца")
        ports.update(range(start, end + 1))
    return sorted(ports)


class ScanConfig(BaseModel):
    target: str = Field(min_length=1, max_length=2048)
    profile: Literal["quick", "standard", "full", "custom"] = "quick"
    ports: str = Field(default="", max_length=4096)
    modules: list[Literal["ports", "dns", "subdomains", "web", "tls", "osint"]] = Field(default_factory=lambda: list(MODULES))
    concurrency: int = Field(default=32, ge=1, le=128)
    rate: int = Field(default=40, ge=1, le=200)
    timeout: float = Field(default=2.0, ge=0.2, le=15)
    max_addresses: int = Field(default=1, ge=1, le=4)
    max_subdomains: int = Field(default=100, ge=1, le=500)
    public_sources: bool = True
    probe_subdomains: bool = False
    service_detection: bool = False

    @field_validator("target")
    @classmethod
    def validate_target(cls, value: str) -> str:
        normalize_target(value)
        return value.strip()

    @field_validator("modules")
    @classmethod
    def validate_modules(cls, value: list[str]) -> list[str]:
        if not value:
            raise ValueError("Выберите хотя бы один модуль")
        return list(dict.fromkeys(value))

    @model_validator(mode="after")
    def validate_custom_ports(self):
        if self.profile == "custom" and "ports" in self.modules:
            parse_ports(self.ports)
        return self

    def selected_ports(self) -> list[int]:
        ports = (parse_ports(self.ports) if self.profile == "custom" else
                 list(range(1, 65536)) if self.profile == "full" else
                 list(STANDARD_PORTS if self.profile == "standard" else QUICK_PORTS))
        target = normalize_target(self.target)
        if target.port:
            ports = sorted(set(ports) | {target.port})
        return ports
