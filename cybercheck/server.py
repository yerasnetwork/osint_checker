import shutil
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.responses import FileResponse, Response
from fastapi.staticfiles import StaticFiles
from starlette.middleware.trustedhost import TrustedHostMiddleware

from . import __version__
from .models import ScanConfig, QUICK_PORTS, STANDARD_PORTS
from .reports import compact_scan, export_csv, export_html
from .runner import ScanManager
from .storage import ScanStore, DEFAULT_DATABASE

STATIC = Path(__file__).resolve().parent / "static"


def create_app(database: Path = DEFAULT_DATABASE) -> FastAPI:
    store = ScanStore(database)
    manager = ScanManager(store)

    @asynccontextmanager
    async def lifespan(app):
        store.interrupt_unfinished()
        yield
        await manager.close()

    app = FastAPI(title="CyberCheck", version=__version__, lifespan=lifespan)
    app.state.manager = manager
    app.add_middleware(TrustedHostMiddleware, allowed_hosts=["127.0.0.1", "localhost", "[::1]", "testserver"])

    @app.middleware("http")
    async def local_access(request: Request, call_next):
        origin = request.headers.get("origin")
        if request.method not in {"GET", "HEAD", "OPTIONS"}:
            expected = f"{request.url.scheme}://{request.headers.get('host')}"
            if request.headers.get("sec-fetch-site") == "cross-site" or (origin and origin != expected):
                return Response("Cross-origin mutations are not allowed", status_code=403)
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["X-Frame-Options"] = "DENY"
        if request.url.path == "/":
            response.headers["Content-Security-Policy"] = "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'"
        return response

    @app.get("/")
    async def index():
        return FileResponse(STATIC / "index.html")

    @app.get("/api/health")
    async def health():
        return {"status": "ok", "version": __version__}

    @app.get("/api/info")
    async def info():
        return {"nmap_available": bool(shutil.which("nmap")),
                "profiles": {"quick": len(QUICK_PORTS), "standard": len(STANDARD_PORTS), "full": 65535}}

    @app.get("/api/scans")
    async def list_scans():
        return store.list()

    @app.post("/api/scans", status_code=202)
    async def start_scan(config: ScanConfig):
        try:
            return compact_scan(manager.create(config))
        except ValueError as exc:
            raise HTTPException(429, str(exc)) from exc

    def require_scan(scan_id: str):
        scan = manager.get(scan_id)
        if not scan:
            raise HTTPException(404, "Проверка не найдена")
        return scan

    @app.get("/api/scans/{scan_id}")
    async def get_scan(scan_id: str, compact: bool = False):
        scan = require_scan(scan_id)
        return compact_scan(scan) if compact else scan

    @app.post("/api/scans/{scan_id}/cancel", status_code=202)
    async def cancel_scan(scan_id: str):
        require_scan(scan_id)
        return compact_scan(manager.cancel(scan_id))

    @app.get("/api/scans/{scan_id}/ports")
    async def port_rows(scan_id: str, state: str = "all", search: str = Query("", max_length=100),
                        offset: int = Query(0, ge=0), limit: int = Query(100, ge=1, le=500)):
        rows = require_scan(scan_id)["sections"]["ports"]["data"].get("rows", [])
        needle = search.casefold()
        filtered = [row for row in rows if (state == "all" or row["state"] == state) and
                    (not needle or needle in f"{row['ip']} {row['port']} {row['service']} {row.get('banner','')}".casefold())]
        order = {"open": 0, "closed": 1, "no_response": 2, "error": 3}
        filtered.sort(key=lambda row: (order[row["state"]], row["ip"], row["port"]))
        return {"rows": filtered[offset:offset + limit], "total": len(filtered), "offset": offset, "limit": limit}

    @app.get("/api/scans/{scan_id}/export")
    async def export(scan_id: str, format: str = "json"):
        import json
        scan = require_scan(scan_id)
        if format == "json":
            content, media = json.dumps(scan, ensure_ascii=False, indent=2), "application/json"
        elif format == "csv":
            content, media = export_csv(scan), "text/csv"
        elif format == "html":
            content, media = export_html(scan), "text/html"
        else:
            raise HTTPException(400, "Формат: json, csv или html")
        return Response(content, media_type=media,
                        headers={"Content-Disposition": f'attachment; filename="cybercheck-{scan_id[:8]}.{format}"'})

    app.mount("/assets", StaticFiles(directory=STATIC), name="assets")
    return app
