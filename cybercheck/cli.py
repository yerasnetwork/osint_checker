import argparse
import asyncio
import json
from pathlib import Path

from pydantic import ValidationError

from .models import MODULES, ScanConfig
from .reports import export_csv, export_html
from .runner import ScanManager
from .storage import ScanStore


async def run_scan(args):
    config = ScanConfig(target=args.target, profile="custom" if args.ports else args.profile,
                        ports=args.ports or "", modules=args.modules.split(","), rate=args.rate,
                        concurrency=args.concurrency, timeout=args.timeout, public_sources=not args.offline,
                        max_addresses=args.max_addresses, probe_subdomains=args.probe_subdomains,
                        service_detection=args.nmap)
    manager = ScanManager(ScanStore())
    scan = manager.create(config)
    try:
        await manager.tasks[scan["id"]]
    finally:
        await manager.close()
    print(f"CyberCheck / {scan['host']} / {scan['status']}")
    for row in scan["sections"]["ports"]["data"].get("rows", []):
        if row["state"] == "open":
            print(f"  OPEN {row['ip']}:{row['port']} tcp {row['service']} {row.get('banner', '')}")
    for row in scan["sections"]["subdomains"]["data"].get("rows", []):
        if row["status"] == "resolved":
            print(f"  DOMAIN {row['host']} -> {', '.join(row['addresses'])}")
    for module, section in scan["sections"].items():
        if section["status"] != "disabled":
            print(f"  {module}: {section['status']}")
        for error in section["errors"]:
            print(f"    {error}")
    output = Path(args.output or f"reports/{scan['id']}")
    output.mkdir(parents=True, exist_ok=True)
    (output / "report.json").write_text(json.dumps(scan, ensure_ascii=False, indent=2), encoding="utf-8")
    (output / "report.html").write_text(export_html(scan), encoding="utf-8")
    (output / "report.csv").write_text(export_csv(scan), encoding="utf-8", newline="")
    print(f"Reports: {output.resolve()}")
    return 1 if scan["status"] == "failed" else 0


def main():
    parser = argparse.ArgumentParser(description="CyberCheck — unified infrastructure scanner")
    commands = parser.add_subparsers(dest="command", required=True)
    serve = commands.add_parser("serve", help="Start the local web dashboard")
    serve.add_argument("--port", type=int, default=8765)
    scan = commands.add_parser("scan", help="Scan a domain, URL or IP")
    scan.add_argument("target")
    scan.add_argument("--profile", choices=["quick", "standard", "full"], default="quick")
    scan.add_argument("--ports", help="Comma-separated ports/ranges; selects custom profile")
    scan.add_argument("--modules", default=",".join(MODULES))
    scan.add_argument("--rate", type=int, default=40)
    scan.add_argument("--concurrency", type=int, default=32)
    scan.add_argument("--timeout", type=float, default=2)
    scan.add_argument("--max-addresses", type=int, default=1)
    scan.add_argument("--offline", action="store_true", help="Disable external OSINT/DoH/CT sources; target probes still run")
    scan.add_argument("--probe-subdomains", action="store_true")
    scan.add_argument("--nmap", action="store_true", help="Identify open services with installed Nmap")
    scan.add_argument("--output", help="Directory for JSON, CSV and HTML reports")
    args = parser.parse_args()
    if args.command == "serve":
        import uvicorn
        from .server import create_app
        if not 1 <= args.port <= 65535:
            parser.error("Port must be between 1 and 65535")
        print(f"CyberCheck: http://127.0.0.1:{args.port}", flush=True)
        uvicorn.run(create_app(), host="127.0.0.1", port=args.port, log_level="info")
    else:
        try:
            raise SystemExit(asyncio.run(run_scan(args)))
        except (ValidationError, ValueError) as exc:
            parser.error(str(exc))
        except KeyboardInterrupt:
            print("Scan cancelled. Partial results are available in dashboard history.")


if __name__ == "__main__":
    main()
