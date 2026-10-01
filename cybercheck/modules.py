from __future__ import annotations

import asyncio
import errno
import ipaddress
import json
import re
import shutil
import socket
import ssl
import time
import uuid
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from http.cookies import SimpleCookie
from urllib.parse import quote, urlsplit, urlunsplit

import httpx
from cryptography import x509
from cryptography.hazmat.primitives import hashes

from .network import ScanContext, error_text, resolve

DNS_TYPES = ("A", "AAAA", "CNAME", "MX", "NS", "TXT", "SOA", "CAA")
SUBDOMAIN_WORDS = ("www", "mail", "api", "app", "admin", "dev", "test", "staging", "beta",
                   "cdn", "static", "assets", "blog", "docs", "status", "support", "portal",
                   "vpn", "ftp", "smtp", "imap", "webmail", "ns1", "ns2", "m")


def outcome(data: dict, errors: list[str] | None = None, status: str | None = None) -> dict:
    errors = errors or []
    return {"status": status or ("partial" if errors else "ok"), "data": data, "errors": errors}


async def scan_ports(ctx: ScanContext, addresses: list[str]) -> dict:
    ports = ctx.config.selected_ports()
    selected = addresses[:ctx.config.max_addresses]
    if not selected:
        return outcome({"rows": [], "counts": {}, "addresses": []}, ["Не удалось определить IP цели"], "error")
    rows = []
    counts = {state: 0 for state in ("open", "closed", "no_response", "error")}
    ctx.publish("ports", {"rows": rows, "counts": counts, "addresses": selected,
                          "resolved_addresses": addresses, "ports_per_address": len(ports)})
    total = len(selected) * len(ports)
    completed = 0
    work = iter((address, port) for address in selected for port in ports)
    last_update = 0.0

    async def worker():
        nonlocal completed, last_update
        for address, port in work:
            await ctx.limiter.wait()
            start = time.monotonic()
            writer = None
            detail = ""
            banner = ""
            state = "error"
            latency_ms = None
            try:
                reader, writer = await asyncio.wait_for(asyncio.open_connection(address, port), ctx.config.timeout)
                state = "open"
                latency_ms = round((time.monotonic() - start) * 1000, 1)
                # Read only banners that servers volunteer. Service names by port remain guesses.
                try:
                    raw = await asyncio.wait_for(reader.read(256), min(0.35, ctx.config.timeout))
                    banner = raw.decode("utf-8", "replace").strip()
                except (TimeoutError, OSError):
                    pass
            except TimeoutError:
                state, detail = "no_response", "Таймаут: фильтрация или отсутствие ответа"
            except OSError as exc:
                if exc.errno in {errno.ECONNREFUSED, 10061} or getattr(exc, "winerror", None) == 10061:
                    state, detail = "closed", "Соединение отклонено"
                elif exc.errno in {errno.ETIMEDOUT, 10060} or getattr(exc, "winerror", None) == 10060:
                    state, detail = "no_response", "Системный таймаут соединения"
                else:
                    state, detail = "error", error_text(exc)
            finally:
                if writer:
                    writer.close()
                    try:
                        await asyncio.wait_for(writer.wait_closed(), 0.5)
                    except (OSError, TimeoutError):
                        pass
            try:
                service = socket.getservbyport(port, "tcp")
            except OSError:
                service = "unknown"
            rows.append({"ip": address, "port": port, "protocol": "tcp", "state": state,
                         "service": service, "service_source": "port_number_hint", "banner": banner,
                         "latency_ms": latency_ms if latency_ms is not None else round((time.monotonic() - start) * 1000, 1), "detail": detail})
            counts[state] += 1
            completed += 1
            if time.monotonic() - last_update > 0.35 or completed == total:
                ctx.progress("ports", completed, total)
                last_update = time.monotonic()

    workers = [asyncio.create_task(worker()) for _ in range(min(ctx.config.concurrency, total))]
    try:
        await asyncio.gather(*workers)
    finally:
        for task in workers:
            if not task.done():
                task.cancel()
        await asyncio.gather(*workers, return_exceptions=True)
    order = {"open": 0, "closed": 1, "no_response": 2, "error": 3}
    rows.sort(key=lambda row: (order[row["state"]], row["ip"], row["port"]))
    errors = []
    if ctx.config.service_detection:
        try:
            await nmap_services(ctx, rows)
        except (OSError, ValueError, TimeoutError) as exc:
            errors.append(error_text(exc))
    if counts["error"]:
        errors.append(f"Сетевые ошибки для {counts['error']} портов; подробности в строках отчёта")
    return outcome({"rows": rows, "counts": counts, "addresses": selected,
                    "resolved_addresses": addresses, "ports_per_address": len(ports),
                    "note": "Проверка TCP connect. Название по номеру порта — предположение. IP за CDN может принадлежать CDN."}, errors)


async def nmap_services(ctx: ScanContext, rows: list[dict]):
    executable = shutil.which("nmap")
    if not executable:
        raise ValueError("Nmap не установлен; результаты TCP-проверки сохранены")
    for address in dict.fromkeys(row["ip"] for row in rows if row["state"] == "open"):
        open_rows = [row for row in rows if row["ip"] == address and row["state"] == "open"]
        args = [executable, "-sT", "-sV", "--version-light", "-Pn", "-n", "--max-retries", "1",
                "--max-rate", str(ctx.config.rate), "--host-timeout", "60s", "-p",
                ",".join(str(row["port"]) for row in open_rows), "-oX", "-"]
        if ":" in address:
            args.append("-6")
        args.append(address)
        process = await asyncio.create_subprocess_exec(*args, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
        try:
            stdout, stderr = await asyncio.wait_for(process.communicate(), 70)
        except BaseException:
            if process.returncode is None:
                process.kill()
                await process.communicate()
            raise
        if process.returncode:
            raise ValueError("Nmap: " + stderr.decode("utf-8", "replace")[:300])
        try:
            root = ET.fromstring(stdout)
        except ET.ParseError as exc:
            raise ValueError("Nmap вернул некорректный XML") from exc
        for port_node in root.findall(".//port"):
            node = port_node.find("service")
            if node is None:
                continue
            for row in open_rows:
                if row["port"] == int(port_node.attrib["portid"]):
                    row.update(service=node.get("name", row["service"]), service_source="nmap",
                               product=node.get("product", ""), version=node.get("version", ""))


async def scan_dns(ctx: ScanContext, addresses: list[str]) -> dict:
    data = {"host": ctx.target.host, "addresses": addresses, "records": []}
    if ctx.target.is_ip or ctx.target.host == "localhost":
        return outcome(data | {"note": "IP или локальное имя: публичные DNS-запросы пропущены"})
    if not ctx.config.public_sources:
        return outcome(data | {"note": "Публичные источники отключены; IP определены системным DNS"})
    errors = []

    async def query(kind):
        try:
            response = await ctx.dns_query(ctx.target.host, kind)
            return [{"query_type": kind, "name": record.get("name"), "type": record.get("type"),
                     "ttl": record.get("TTL"), "value": record.get("data"), "source": response["source"]}
                    for record in response["records"]]
        except (httpx.HTTPError, ValueError) as exc:
            errors.append(f"{kind}: {error_text(exc)}")
            return []
    for batch in await asyncio.gather(*(query(kind) for kind in DNS_TYPES)):
        data["records"].extend(batch)
    return outcome(data, errors)


async def scan_subdomains(ctx: ScanContext) -> dict:
    if ctx.target.is_ip or ctx.target.host == "localhost" or "." not in ctx.target.host:
        return outcome({"rows": [], "note": "Поиск поддоменов доступен для доменного имени"}, status="skipped")
    candidates: dict[str, set[str]] = {f"{word}.{ctx.target.host}": {"dns_wordlist"} for word in SUBDOMAIN_WORDS}
    errors = []
    capped = False
    ct_source = ""
    if ctx.config.public_sources:
        try:
            response = await ctx.fetch("https://crt.sh/", params={"q": "%." + ctx.target.host,
                                        "output": "json"}, limit=3 * 1024 * 1024)
            # Avoid ever treating a partially downloaded certificate list as complete.
            if response["status"] != 200 or response["truncated"]:
                raise ValueError(f"Certificate Transparency: HTTP {response['status']} / ответ превышает лимит")
            payload = json.loads(response["body"])
            if not isinstance(payload, list):
                raise ValueError("Неверный формат Certificate Transparency")
            ct_source = response["url"]
            for record in payload:
                for name in str(record.get("name_value", "")).lower().splitlines():
                    name = name.strip().rstrip(".")
                    if name.startswith("*.") or name == ctx.target.host or not name.endswith("." + ctx.target.host):
                        continue
                    if len(name) > 253 or not re.fullmatch(r"[a-z0-9.-]+", name):
                        continue
                    candidates.setdefault(name, set()).add("certificate_transparency")
                    if len(candidates) >= ctx.config.max_subdomains + len(SUBDOMAIN_WORDS):
                        capped = True
                        break
                if capped:
                    break
        except (httpx.HTTPError, ValueError) as exc:
            errors.append(error_text(exc))
    # Compare two independent wildcard probes; CT-backed names remain in the inventory.
    wildcard_addresses = set()
    wildcard_checks = []
    for _ in range(2):
        try:
            await ctx.limiter.wait()
            wildcard_checks.append(set(await resolve(f"cc-{uuid.uuid4().hex[:16]}.{ctx.target.host}", ctx.config.timeout)))
        except (OSError, TimeoutError):
            wildcard_checks.append(set())
    if all(wildcard_checks):
        wildcard_addresses = set.union(*wildcard_checks)
    names = sorted(candidates, key=lambda name: ("certificate_transparency" not in candidates[name], name))
    capped = capped or len(names) > ctx.config.max_subdomains
    names = names[:ctx.config.max_subdomains]
    rows = []
    semaphore = asyncio.Semaphore(min(12, ctx.config.concurrency))
    ctx.publish("subdomains", {"rows": rows, "wildcard_addresses": sorted(wildcard_addresses), "limited": capped})
    completed = 0

    async def check(name):
        nonlocal completed
        async with semaphore:
            await ctx.limiter.wait()
            row = {"host": name, "sources": sorted(candidates[name]), "addresses": [], "status": "unresolved"}
            try:
                row["addresses"] = await resolve(name, ctx.config.timeout)
                row["status"] = "resolved"
                row["wildcard_possible"] = bool(wildcard_addresses.intersection(row["addresses"]))
                if row["wildcard_possible"] and candidates[name] == {"dns_wordlist"}:
                    row["status"] = "wildcard"
                if ctx.config.probe_subdomains and row["status"] == "resolved":
                    try:
                        web = await ctx.fetch(f"https://{name}/", scoped=True, limit=16384)
                        row["http_status"] = web["status"]
                        row["http_url"] = web["url"]
                    except (httpx.HTTPError, ValueError) as exc:
                        row["http_error"] = error_text(exc)
            except socket.gaierror as exc:
                row["status"] = "unresolved" if exc.errno in {socket.EAI_NONAME, socket.EAI_NODATA} else "error"
                row["detail"] = error_text(exc)
            except (OSError, TimeoutError) as exc:
                row["status"], row["detail"] = "error", error_text(exc)
            rows.append(row)
            completed += 1
            ctx.progress("subdomains", completed, len(names))

    await asyncio.gather(*(check(name) for name in names))
    rows.sort(key=lambda row: (row["status"] != "resolved", row["host"]))
    dns_errors = sum(row["status"] == "error" for row in rows)
    if dns_errors:
        errors.append(f"Ошибки разрешения DNS для {dns_errors} имён")
    return outcome({"rows": rows, "wildcard_addresses": sorted(wildcard_addresses),
                    "limited": capped, "ct_source": ct_source,
                    "resolved_count": sum(row["status"] == "resolved" for row in rows),
                    "note": "Имена из сертификатов могут быть историческими. Wildcard-ответы не считаются подтверждёнными поддоменами."}, errors)


def analyze_web(response: dict) -> dict:
    body, headers = response["body"], response["headers"]
    title_match = re.search(r"<title\b[^>]*>(.*?)</title>", body, re.I | re.S)
    import html
    title = html.unescape(re.sub(r"\s+", " ", title_match[1]).strip())[:300] if title_match else ""
    technologies = []
    for header in ("server", "x-powered-by", "x-generator"):
        if headers.get(header):
            technologies.append({"name": headers[header], "evidence": f"HTTP {header}", "confidence": "hint"})
    for name, pattern in (("WordPress", r"wp-content/|wp-includes/"), ("Next.js", r"/_next/"),
                          ("Drupal", r"Drupal\.settings|sites/default/files"), ("Nuxt", r"/_nuxt/")):
        if re.search(pattern, body, re.I):
            technologies.append({"name": name, "evidence": "Маркер в HTML", "confidence": "hint"})
    cookies = []
    for value in response["cookies"]:
        parsed = SimpleCookie()
        try:
            parsed.load(value)
            for name, morsel in parsed.items():
                cookies.append({"name": name, "secure": bool(morsel["secure"]),
                                "httponly": bool(morsel["httponly"]), "samesite": morsel["samesite"]})
        except Exception:
            pass
    findings = []
    successful = 200 <= response["status"] < 400 and not response.get("blocked_redirect")
    if successful:
        checks = [("content-security-policy", "Не задан Content-Security-Policy", "info"),
                  ("x-content-type-options", "Не задан X-Content-Type-Options", "info")]
        if response["url"].startswith("https://"):
            checks.append(("strict-transport-security", "Не задан Strict-Transport-Security", "info"))
        for header, message, severity in checks:
            if not headers.get(header):
                findings.append({"severity": severity, "title": message,
                                 "evidence": "Заголовок отсутствует в ответе", "source": response["url"]})
        if not headers.get("x-frame-options") and "frame-ancestors" not in headers.get("content-security-policy", "").lower():
            findings.append({"severity": "info", "title": "Не обнаружена политика ограничения встраивания",
                             "evidence": "Нет X-Frame-Options и CSP frame-ancestors", "source": response["url"]})
        if response["url"].startswith("http://"):
            findings.append({"severity": "warning", "title": "Ответ получен по HTTP",
                             "evidence": response["url"], "source": response["url"]})
    return {"url": response["url"], "status_code": response["status"], "title": title,
            "headers": {key: value for key, value in headers.items() if key != "set-cookie"},
            "cookies": cookies, "technologies": technologies,
            "redirects": response["redirects"], "blocked_redirect": response.get("blocked_redirect"),
            "body_truncated": response["truncated"], "findings": findings}


async def scan_web(ctx: ScanContext) -> dict:
    urls = [ctx.target.url]
    if not ctx.target.explicit_url:
        parsed = urlsplit(ctx.target.url)
        urls.append(urlunsplit(("http", parsed.netloc, parsed.path, parsed.query, "")))
    attempts = []
    response = None
    for url in urls:
        try:
            response = await ctx.fetch(url, scoped=True)
            break
        except (httpx.HTTPError, ValueError) as exc:
            attempts.append({"url": url, "error": error_text(exc)})
    if response is None:
        return outcome({"attempts": attempts}, [attempt["error"] for attempt in attempts], "error")
    data = analyze_web(response)
    data["attempts"] = attempts
    data["resources"] = []
    errors = []
    if response.get("blocked_redirect"):
        errors.append("Редирект на другой домен записан; переход за пределы цели остановлен")
    else:
        parsed = urlsplit(response["url"])
        for path in ("/robots.txt", "/sitemap.xml"):
            url = urlunsplit((parsed.scheme, parsed.netloc, path, "", ""))
            try:
                resource = await ctx.fetch(url, scoped=True, limit=65536)
                data["resources"].append({"url": resource["url"], "status_code": resource["status"],
                                          "preview": resource["body"][:1000], "truncated": resource["truncated"],
                                          "blocked_redirect": resource.get("blocked_redirect")})
            except (httpx.HTTPError, ValueError) as exc:
                errors.append(f"{path}: {error_text(exc)}")
    return outcome(data, errors)


async def scan_tls(ctx: ScanContext) -> dict:
    port = ctx.target.port if ctx.target.url.startswith("https://") and ctx.target.port else 443
    if ctx.target.explicit_url and ctx.target.url.startswith("http://"):
        return outcome({"note": "Для явного HTTP-адреса TLS-проверка пропущена"}, status="skipped")
    verified = True
    verify_error = ""
    certificate = None
    details = {}
    for verify in (True, False):
        context = ssl.create_default_context()
        if not verify:
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
        writer = None
        try:
            await ctx.limiter.wait()
            _, writer = await asyncio.wait_for(
                asyncio.open_connection(ctx.target.host, port, ssl=context, server_hostname=ctx.target.host,
                                        ssl_handshake_timeout=ctx.config.timeout), ctx.config.timeout + 1)
            tls = writer.get_extra_info("ssl_object")
            certificate = x509.load_der_x509_certificate(tls.getpeercert(binary_form=True))
            details = {"tls_version": tls.version(), "cipher": tls.cipher()[0]}
            break
        except ssl.SSLCertVerificationError as exc:
            verified, verify_error = False, error_text(exc)
        except (OSError, TimeoutError, ValueError) as exc:
            return outcome({"host": ctx.target.host, "port": port, "verified": False}, [error_text(exc)], "error")
        finally:
            if writer:
                writer.close()
                try:
                    await asyncio.wait_for(writer.wait_closed(), 0.5)
                except (OSError, TimeoutError):
                    pass
    if certificate is None:
        return outcome({"verified": False}, [verify_error or "Сертификат не получен"], "error")
    try:
        sans = certificate.extensions.get_extension_for_class(x509.SubjectAlternativeName).value.get_values_for_type(x509.DNSName)
    except x509.ExtensionNotFound:
        sans = []
    now = datetime.now(timezone.utc)
    expires = certificate.not_valid_after_utc
    findings = []
    if not verified:
        findings.append({"severity": "warning", "title": "Сертификат не прошёл проверку",
                         "evidence": verify_error, "source": f"{ctx.target.host}:{port}"})
    if expires <= now:
        findings.append({"severity": "warning", "title": "Срок сертификата истёк",
                         "evidence": expires.isoformat(), "source": f"{ctx.target.host}:{port}"})
    elif (expires - now).days < 30:
        findings.append({"severity": "info", "title": "Сертификат истекает менее чем через 30 дней",
                         "evidence": expires.isoformat(), "source": f"{ctx.target.host}:{port}"})
    return outcome(details | {"host": ctx.target.host, "port": port, "verified": verified,
                              "verification_error": verify_error, "subject": certificate.subject.rfc4514_string(),
                              "issuer": certificate.issuer.rfc4514_string(), "valid_from": certificate.not_valid_before_utc.isoformat(),
                              "valid_until": expires.isoformat(), "days_remaining": (expires - now).days,
                              "dns_names": sans, "sha256": certificate.fingerprint(hashes.SHA256()).hex(),
                              "findings": findings}, [verify_error] if verify_error else [])


def rdap_summary(payload: dict, source: str) -> dict:
    entities = []
    for entity in payload.get("entities", []):
        name = ""
        vcard = entity.get("vcardArray", [])
        if len(vcard) == 2:
            for item in vcard[1]:
                if len(item) >= 4 and item[0] == "fn":
                    name = item[3]
        entities.append({"handle": entity.get("handle"), "roles": entity.get("roles", []), "name": name})
    return {"source": source, "name": payload.get("ldhName") or payload.get("name"),
            "handle": payload.get("handle"), "status": payload.get("status", []),
            "country": payload.get("country"), "start_address": payload.get("startAddress"),
            "end_address": payload.get("endAddress"), "entities": entities,
            "events": [{"action": event.get("eventAction"), "date": event.get("eventDate")}
                       for event in payload.get("events", [])],
            "nameservers": [item.get("ldhName") for item in payload.get("nameservers", [])]}


async def scan_osint(ctx: ScanContext, addresses: list[str]) -> dict:
    if not ctx.config.public_sources:
        return outcome({"note": "Публичные источники отключены"}, status="skipped")
    data = {"domain": None, "networks": [], "asn": []}
    errors = []
    if not ctx.target.is_ip and ctx.target.host != "localhost" and "." in ctx.target.host:
        # RDAP is the authority for the registered name, including multi-label suffixes.
        labels = ctx.target.host.split(".")
        for index in range(min(len(labels) - 1, 6)):
            name = ".".join(labels[index:])
            try:
                response = await ctx.fetch("https://rdap.org/domain/" + quote(name, safe=""), limit=1048576)
                if response["status"] == 404:
                    continue
                if response["status"] != 200 or response["truncated"]:
                    raise ValueError(f"RDAP: HTTP {response['status']} / ответ превышает лимит")
                data["domain"] = rdap_summary(json.loads(response["body"]), response["url"])
                break
            except (httpx.HTTPError, ValueError) as exc:
                errors.append(error_text(exc))
                break
        if data["domain"] is None and not errors:
            errors.append("RDAP не вернул регистрационные сведения для домена")
    for address in addresses[:ctx.config.max_addresses]:
        ip = ipaddress.ip_address(address)
        if not ip.is_global:
            data["networks"].append({"ip": address, "note": "Локальный или специальный IP: публичные запросы пропущены"})
            continue
        try:
            response = await ctx.fetch("https://rdap.org/ip/" + quote(address, safe=""), limit=1048576)
            if response["status"] != 200 or response["truncated"]:
                raise ValueError(f"IP RDAP: HTTP {response['status']} / ответ превышает лимит")
            data["networks"].append(rdap_summary(json.loads(response["body"]), response["url"]) | {"ip": address})
        except (httpx.HTTPError, ValueError) as exc:
            errors.append(f"{address}: {error_text(exc)}")
        origin_name = (".".join(reversed(address.split("."))) + ".origin.asn.cymru.com" if ip.version == 4
                       else ".".join(reversed(ip.exploded.replace(":", ""))) + ".origin6.asn.cymru.com")
        try:
            response = await ctx.dns_query(origin_name, "TXT")
            for record in response["records"]:
                if record.get("type") == 16:
                    value = str(record.get("data", "")).strip('"')
                    parts = [part.strip() for part in value.split("|")]
                    if len(parts) >= 5:
                        data["asn"].append({"ip": address, "asn": parts[0], "prefix": parts[1],
                                            "country": parts[2], "registry": parts[3], "allocated": parts[4],
                                            "source": response["source"]})
        except (httpx.HTTPError, ValueError) as exc:
            errors.append(f"ASN {address}: {error_text(exc)}")
    return outcome(data, errors)
