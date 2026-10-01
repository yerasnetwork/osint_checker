import asyncio
import csv
import errno
import io
import json
import socket
import ssl
import uuid
from contextlib import contextmanager
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import AsyncMock, patch

import httpx
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from pydantic import ValidationError

from cybercheck.models import ScanConfig, normalize_target, parse_ports
from cybercheck.modules import analyze_web, scan_dns, scan_osint, scan_ports, scan_subdomains, scan_tls
from cybercheck.network import ScanContext
from cybercheck.reports import compact_scan, export_csv, export_html
from cybercheck.runner import ScanManager
from cybercheck.server import create_app
from cybercheck.storage import ScanStore

TEST_DATA = Path(__file__).resolve().parent.parent / "data" / "test-temp"
TEST_DATA.mkdir(parents=True, exist_ok=True)


@contextmanager
def test_directory():
    # Python 3.14's owner-only temporary ACL excludes the managed Windows token.
    directory = TEST_DATA / uuid.uuid4().hex
    directory.mkdir(mode=0o777)
    try:
        yield directory
    finally:
        for child in directory.iterdir():
            if child.is_file():
                child.unlink()
        directory.rmdir()


class TargetTests(unittest.TestCase):
    def test_url_idna_ipv6(self):
        self.assertEqual(normalize_target("https://Example.COM:8443/path#fragment").url,"https://example.com:8443/path")
        self.assertEqual(normalize_target("пример.рф").host,"xn--e1afmkfd.xn--p1ai")
        self.assertEqual(normalize_target("::1").url,"https://[::1]/")
        self.assertEqual(normalize_target("http://[::1]:8080/").port,8080)

    def test_bad_targets(self):
        for target in ("", "foo bar", "ftp://example.com", "https://user:pass@example.com", "https://example.com:70000", "https://example.com:0", "-evil.com", "*.example.com", "https://github.com/user/project.git", "http://[fe80::1%eth0]/", "10.0.0.0/24"):
            with self.subTest(target=target), self.assertRaises(ValueError):
                normalize_target(target)

    def test_scope_boundaries(self):
        target = normalize_target("example.com")
        self.assertTrue(target.in_scope("api.example.com"))
        self.assertFalse(target.in_scope("evil-example.com"))
        self.assertFalse(target.in_scope("example.com.evil.test"))
        self.assertFalse(normalize_target("127.0.0.1").in_scope("evil.127.0.0.1"))

    def test_port_ranges_and_explicit_port(self):
        self.assertEqual(parse_ports("22,80-82,80"),[22,80,81,82])
        self.assertIn(8765,ScanConfig(target="http://127.0.0.1:8765").selected_ports())
        self.assertEqual(len(ScanConfig(target="example.com",profile="full").selected_ports()),65535)
        for ports in ("", "0", "65536", "82-80", "80,", "22;whoami"):
            with self.subTest(ports=ports), self.assertRaises(ValueError):
                parse_ports(ports)

    def test_invalid_config(self):
        with self.assertRaises(ValidationError):
            ScanConfig(target="example.com",modules=[])
        with self.assertRaises(ValidationError):
            ScanConfig(target="example.com",profile="custom",ports="bad")


class NetworkTests(unittest.IsolatedAsyncioTestCase):
    async def test_open_closed_ports(self):
        async def banner(reader,writer):
            writer.write(b"SSH-2.0-LocalFixture\r\n")
            await writer.drain()
            writer.close()
            await writer.wait_closed()
        server = await asyncio.start_server(banner,"127.0.0.1",0)
        port = server.sockets[0].getsockname()[1]
        with socket.socket() as sock:
            sock.bind(("127.0.0.1",0))
            closed = sock.getsockname()[1]
        async with server, httpx.AsyncClient() as client:
            config = ScanConfig(target="127.0.0.1",profile="custom",ports=f"{port},{closed}",modules=["ports"],rate=200,timeout=2)
            ctx = ScanContext(config,normalize_target(config.target),client,lambda *args: None)
            result = await scan_ports(ctx,["127.0.0.1"])
        by_port = {row["port"]:row for row in result["data"]["rows"]}
        self.assertEqual(by_port[port]["state"],"open")
        self.assertIn(by_port[closed]["state"],{"closed","no_response"})
        self.assertIn("SSH-2.0",by_port[port]["banner"])
        self.assertEqual(result["data"]["counts"]["open"],1)

    async def test_timeout_not_closed(self):
        async with httpx.AsyncClient() as client:
            config = ScanConfig(target="127.0.0.1",profile="custom",ports="12345",modules=["ports"],timeout=.2)
            ctx = ScanContext(config,normalize_target(config.target),client,lambda *args: None)
            with patch("cybercheck.modules.asyncio.open_connection",new=AsyncMock(side_effect=TimeoutError())):
                result = await scan_ports(ctx,["127.0.0.1"])
        self.assertEqual(result["data"]["rows"][0]["state"],"no_response")

    async def test_refused_connection_is_closed(self):
        async with httpx.AsyncClient(transport=httpx.MockTransport(lambda request: httpx.Response(200))) as client:
            config = ScanConfig(target="127.0.0.1",profile="custom",ports="12345",modules=["ports"])
            ctx = ScanContext(config,normalize_target(config.target),client,lambda *args: None)
            with patch("cybercheck.modules.asyncio.open_connection",new=AsyncMock(side_effect=ConnectionRefusedError(errno.ECONNREFUSED,"refused"))):
                result = await scan_ports(ctx,["127.0.0.1"])
        self.assertEqual(result["data"]["rows"][0]["state"],"closed")

    async def test_scoped_redirect_and_body_limit(self):
        requested = []
        def handler(request):
            requested.append(str(request.url))
            if request.url.path == "/outside":
                return httpx.Response(302,headers={"location":"https://other.test/"})
            if request.url.path == "/redirect":
                return httpx.Response(302,headers={"location":"/done"})
            return httpx.Response(200,content=b"A" * 1000)
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            config = ScanConfig(target="https://example.com",rate=200)
            ctx = ScanContext(config,normalize_target(config.target),client,lambda *args: None)
            blocked = await ctx.fetch("https://example.com/outside",scoped=True)
            response = await ctx.fetch("https://example.com/redirect",scoped=True,limit=100)
        self.assertEqual(blocked["blocked_redirect"],"https://other.test/")
        self.assertFalse(any("other.test" in url for url in requested))
        self.assertEqual(response["url"],"https://example.com/done")
        self.assertEqual(len(response["body"]),100)
        self.assertTrue(response["truncated"])

    async def test_dns_fallback_and_partial(self):
        def handler(request):
            if request.url.host == "cloudflare-dns.com":
                return httpx.Response(503)
            return httpx.Response(200,json={"Status":0,"Answer":[{"name":"example.com.","type":1,"TTL":300,"data":"192.0.2.1"}]})
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            config = ScanConfig(target="example.com",rate=200)
            ctx = ScanContext(config,normalize_target(config.target),client,lambda *args: None)
            result = await scan_dns(ctx,["192.0.2.1"])
        self.assertEqual(result["status"],"ok")
        self.assertEqual(len(result["data"]["records"]),8)
        self.assertIn("dns.google",result["data"]["records"][0]["source"])

    async def test_dns_failure_is_visible(self):
        def handler(request):
            return httpx.Response(500)
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            config = ScanConfig(target="example.com",rate=200)
            ctx = ScanContext(config,normalize_target(config.target),client,lambda *args: None)
            result = await scan_dns(ctx,["192.0.2.1"])
        self.assertEqual(result["status"],"partial")
        self.assertEqual(len(result["errors"]),8)

    async def test_subdomain_ct_scope_and_wildcard(self):
        def handler(request):
            return httpx.Response(200,json=[{"name_value":"real.example.com\n*.example.com\nother.test\nexample.com.evil.test"}])
        async def resolver(name,timeout):
            return ["192.0.2.42"]
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            config = ScanConfig(target="example.com",rate=200,max_subdomains=5)
            ctx = ScanContext(config,normalize_target(config.target),client,lambda *args: None)
            with patch("cybercheck.modules.resolve",resolver):
                result = await scan_subdomains(ctx)
        rows = result["data"]["rows"]
        self.assertTrue(all(row["host"].endswith(".example.com") for row in rows))
        real = next(row for row in rows if row["host"] == "real.example.com")
        self.assertEqual(real["status"],"resolved")
        self.assertTrue(real["wildcard_possible"])
        self.assertTrue(any(row["status"] == "wildcard" for row in rows))
        self.assertTrue(result["data"]["limited"])

    async def test_rdap_registered_domain_and_local_ip(self):
        requested = []
        def handler(request):
            requested.append(str(request.url))
            if request.url.path.endswith("api.example.co.uk"):
                return httpx.Response(404)
            return httpx.Response(200,json={"ldhName":"example.co.uk","events":[{"eventAction":"registration","eventDate":"2020-01-01"}],"entities":[]})
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            config = ScanConfig(target="api.example.co.uk",rate=200)
            ctx = ScanContext(config,normalize_target(config.target),client,lambda *args: None)
            result = await scan_osint(ctx,["127.0.0.1"])
        self.assertEqual(result["data"]["domain"]["name"],"example.co.uk")
        self.assertEqual(len(requested),2)
        self.assertIn("Локальный",result["data"]["networks"][0]["note"])

    async def test_invalid_tls_certificate_is_reported(self):
        key = rsa.generate_private_key(public_exponent=65537,key_size=2048)
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,"localhost")])
        certificate = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(x509.random_serial_number()).not_valid_before(datetime.now(timezone.utc)-timedelta(days=1))
            .not_valid_after(datetime.now(timezone.utc)+timedelta(days=10))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName("localhost")]),critical=False).sign(key,hashes.SHA256()))
        with test_directory() as directory:
            cert_path, key_path = Path(directory)/"cert.pem", Path(directory)/"key.pem"
            cert_path.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
            key_path.write_bytes(key.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption()))
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.load_cert_chain(cert_path,key_path)
            async def handle(reader,writer):
                writer.close()
                try:
                    await writer.wait_closed()
                except OSError:
                    pass
            server = await asyncio.start_server(handle,"127.0.0.1",0,ssl=context)
            port = server.sockets[0].getsockname()[1]
            async with server, httpx.AsyncClient() as client:
                config = ScanConfig(target=f"https://127.0.0.1:{port}",timeout=1,rate=200)
                ctx = ScanContext(config,normalize_target(config.target),client,lambda *args: None)
                result = await scan_tls(ctx)
        self.assertEqual(result["status"],"partial")
        self.assertFalse(result["data"]["verified"])
        self.assertEqual(result["data"]["dns_names"],["localhost"])
        self.assertTrue(result["data"]["verification_error"])

    async def test_missing_nmap_retains_ports(self):
        async def handle(reader,writer):
            writer.close()
            await writer.wait_closed()
        server = await asyncio.start_server(handle,"127.0.0.1",0)
        port = server.sockets[0].getsockname()[1]
        async with server, httpx.AsyncClient() as client:
            config = ScanConfig(target="127.0.0.1",profile="custom",ports=str(port),modules=["ports"],service_detection=True)
            ctx = ScanContext(config,normalize_target(config.target),client,lambda *args: None)
            with patch("cybercheck.modules.shutil.which",return_value=None):
                result = await scan_ports(ctx,["127.0.0.1"])
        self.assertEqual(result["status"],"partial")
        self.assertEqual(result["data"]["counts"]["open"],1)


class APITests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.directory = test_directory()
        self.test_path = self.directory.__enter__()
        self.store = ScanStore(self.test_path/"history.sqlite3")
        self.app = create_app(self.store.path)
        self.client = httpx.AsyncClient(transport=httpx.ASGITransport(app=self.app),base_url="http://127.0.0.1")

    async def asyncTearDown(self):
        await self.app.state.manager.close()
        await self.client.aclose()
        self.directory.__exit__(None,None,None)

    async def test_full_api_scan_and_exports(self):
        response = await self.client.post("/api/scans",json={"target":"127.0.0.1","profile":"custom","ports":"1","modules":["ports","dns","osint"],"public_sources":False,"timeout":.2})
        self.assertEqual(response.status_code,202)
        scan_id = response.json()["id"]
        await self.app.state.manager.tasks[scan_id]
        report = (await self.client.get(f"/api/scans/{scan_id}")).json()
        self.assertEqual(report["status"],"completed")
        self.assertEqual(report["progress"],100)
        self.assertEqual((await self.client.get("/api/scans")).json()[0]["id"],scan_id)
        for format in ("json","csv","html"):
            export = await self.client.get(f"/api/scans/{scan_id}/export?format={format}")
            self.assertEqual(export.status_code,200)
            self.assertIn("attachment",export.headers["content-disposition"])
        page = (await self.client.get(f"/api/scans/{scan_id}/ports?state=all")).json()
        self.assertEqual(page["total"],1)

    async def test_cancel_keeps_partial_results(self):
        response = await self.client.post("/api/scans",json={"target":"127.0.0.1","profile":"custom","ports":"1-100","modules":["ports"],"rate":10,"timeout":.2})
        scan_id = response.json()["id"]
        for _ in range(50):
            if self.app.state.manager.get(scan_id)["sections"]["ports"]["data"].get("rows"):
                break
            await asyncio.sleep(.02)
        await self.client.post(f"/api/scans/{scan_id}/cancel")
        await self.app.state.manager.tasks[scan_id]
        report = (await self.client.get(f"/api/scans/{scan_id}")).json()
        self.assertEqual(report["status"],"cancelled")
        self.assertGreater(len(report["sections"]["ports"]["data"]["rows"]),0)
        self.assertLess(len(report["sections"]["ports"]["data"]["rows"]),100)
        self.assertEqual(self.store.get(scan_id)["status"],"cancelled")

    async def test_cancel_queued(self):
        manager = self.app.state.manager
        scan = manager.create(ScanConfig(target="127.0.0.1",modules=["ports"]))
        manager.cancel(scan["id"])
        await asyncio.gather(manager.tasks[scan["id"]],return_exceptions=True)
        self.assertEqual(self.store.get(scan["id"])["status"],"cancelled")

    async def test_validation_and_unknown_scan(self):
        response = await self.client.post("/api/scans",json={"target":"https://github.com/user/repo.git"})
        self.assertEqual(response.status_code,422)
        self.assertEqual((await self.client.get("/api/scans/missing")).status_code,404)

    async def test_cross_origin_and_host_protection(self):
        response = await self.client.post("/api/scans",json={"target":"127.0.0.1"},headers={"origin":"https://evil.test"})
        self.assertEqual(response.status_code,403)
        response = await self.client.get("/api/health",headers={"host":"evil.test"})
        self.assertEqual(response.status_code,400)
        page = await self.client.get("/")
        self.assertEqual(page.status_code,200)
        self.assertIn("frame-ancestors 'none'",page.headers["content-security-policy"])
        for path in ("/assets/app.js","/assets/style.css"):
            self.assertEqual((await self.client.get(path)).status_code,200)

    async def test_two_jobs_limit(self):
        manager = self.app.state.manager
        config = ScanConfig(target="127.0.0.1",modules=["ports"],profile="full",rate=1)
        manager.create(config)
        manager.create(config)
        response = await self.client.post("/api/scans",json=config.model_dump())
        self.assertEqual(response.status_code,429)

    async def test_restart_marks_interrupted(self):
        manager = self.app.state.manager
        scan = manager.create(ScanConfig(target="127.0.0.1",modules=["ports"]))
        self.store.interrupt_unfinished()
        self.assertEqual(self.store.get(scan["id"])["status"],"interrupted")


class ReportTests(unittest.TestCase):
    def make_scan(self):
        scan = {"id":"test","host":"example.com","target":"<script>alert(1)</script>","status":"completed","created_at":"now","events":[],"sections":{key:{"status":"ok","data":{},"errors":[]} for key in ("ports","dns","subdomains","web","tls","osint")}}
        scan["sections"]["ports"]["data"] = {"rows":[{"ip":"192.0.2.1","port":22,"state":"open","service":"ssh","banner":"=CMD()","detail":""},{"ip":"192.0.2.1","port":80,"state":"closed","service":"http","detail":""}]}
        return scan

    def test_export_escaping_and_csv_formula(self):
        scan = self.make_scan()
        report = export_html(scan)
        self.assertNotIn("<script>",report)
        self.assertIn("&lt;script&gt;",report)
        parsed = list(csv.reader(io.StringIO(export_csv(scan))))
        self.assertEqual(parsed[1][0],"scan")
        from cybercheck.reports import csv_safe
        self.assertTrue(csv_safe(" =HYPERLINK(1)").startswith("'"))

    def test_compact_report_does_not_mutate_full_data(self):
        scan = self.make_scan()
        compact = compact_scan(scan)
        self.assertEqual(len(compact["sections"]["ports"]["data"]["rows"]),1)
        self.assertEqual(len(scan["sections"]["ports"]["data"]["rows"]),2)

    def test_web_observations_and_cookie_redaction(self):
        data = analyze_web({"body":"<title>A &amp; B</title><link href='/_next/app.js'>","headers":{"server":"fixture","set-cookie":"session=secret; Secure; HttpOnly; SameSite=Lax"},"cookies":["session=secret; Secure; HttpOnly; SameSite=Lax"],"url":"https://example.com/","status":200,"redirects":[],"truncated":False})
        self.assertEqual(data["title"],"A & B")
        self.assertNotIn("set-cookie",data["headers"])
        self.assertNotIn("secret",json.dumps(data))
        self.assertTrue(data["cookies"][0]["secure"])
        self.assertTrue(any(item["name"] == "Next.js" for item in data["technologies"]))


if __name__ == "__main__":
    unittest.main()
