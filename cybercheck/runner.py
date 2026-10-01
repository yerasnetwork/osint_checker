import asyncio
import time
import uuid
from datetime import datetime, timezone

import httpx

from .models import MODULES, ScanConfig, normalize_target
from .modules import scan_ports, scan_dns, scan_subdomains, scan_web, scan_tls, scan_osint
from .network import ScanContext, USER_AGENT, error_text, resolve
from .storage import ScanStore


def now() -> str:
    return datetime.now(timezone.utc).isoformat()


class ScanManager:
    def __init__(self, store: ScanStore):
        self.store = store
        self.scans: dict[str, dict] = {}
        self.tasks: dict[str, asyncio.Task] = {}

    def get(self, scan_id: str) -> dict | None:
        return self.scans.get(scan_id) or self.store.get(scan_id)

    def create(self, config: ScanConfig) -> dict:
        if sum(not task.done() for task in self.tasks.values()) >= 2:
            raise ValueError("Уже выполняются две проверки. Дождитесь завершения или остановите одну")
        scan_id, stamp = uuid.uuid4().hex, now()
        target = normalize_target(config.target)
        scan = {"id": scan_id, "target": config.target, "host": target.host, "status": "queued",
                "created_at": stamp, "updated_at": stamp, "finished_at": None,
                "config": config.model_dump(), "addresses": [], "progress": 0,
                "sections": {module: {"status": "pending" if module in config.modules else "disabled",
                                      "data": {}, "errors": []} for module in MODULES},
                "events": [{"time": stamp, "message": "Проверка поставлена в очередь"}]}
        self.scans[scan_id] = scan
        self.store.save(scan)
        self.tasks[scan_id] = asyncio.create_task(self._run(scan, config), name=f"scan-{scan_id}")
        if len(self.scans) > 20:
            for old_id in list(self.scans):
                if old_id != scan_id and self.scans[old_id]["status"] not in {"queued", "running"}:
                    self.scans.pop(old_id)
                    self.tasks.pop(old_id, None)
                    break
        return scan

    def cancel(self, scan_id: str) -> dict | None:
        scan, task = self.get(scan_id), self.tasks.get(scan_id)
        if scan and task and not task.done():
            if scan["status"] == "queued":
                scan["status"] = "cancelled"
                scan["finished_at"] = scan["updated_at"] = now()
                for section in scan["sections"].values():
                    if section["status"] == "pending":
                        section["status"] = "cancelled"
                self.store.save(scan)
            task.cancel()
        return scan

    async def close(self):
        tasks = [task for task in self.tasks.values() if not task.done()]
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)

    async def _run(self, scan: dict, config: ScanConfig):
        target = normalize_target(config.target)
        scan["status"] = "running"
        fractions = {module: 0.0 for module in config.modules}
        last_save = 0.0

        def save(force=False):
            nonlocal last_save
            scan["updated_at"] = now()
            scan["progress"] = round(sum(fractions.values()) / len(fractions) * 100)
            if force or time.monotonic() - last_save > 1:
                self.store.save(scan)
                last_save = time.monotonic()

        def event(message):
            scan["events"].append({"time": now(), "message": message})
            scan["events"] = scan["events"][-100:]

        def progress(module: str, completed: int, total: int):
            fractions[module] = min(0.98, completed / max(total, 1))
            scan["sections"][module]["progress"] = {"completed": completed, "total": total}
            save()

        def publish(module: str, data: dict):
            scan["sections"][module]["data"] = data

        async def execute(module: str, operation, deadline: float | None = None):
            section = scan["sections"][module]
            section["status"] = "running"
            event(f"Запущен модуль: {module}")
            save(True)
            try:
                result = await asyncio.wait_for(operation, deadline) if deadline else await operation
                section.update(result)
            except asyncio.CancelledError:
                section["status"] = "cancelled"
                raise
            except Exception as exc:
                section.update(status="error", errors=[error_text(exc)])
            fractions[module] = 1
            event(f"Модуль {module}: {section['status']}")
            save(True)

        try:
            event("Определение IP цели")
            save(True)
            try:
                scan["addresses"] = await resolve(target.host, max(3, config.timeout))
            except (OSError, TimeoutError) as exc:
                event("Системный DNS: " + error_text(exc))
            async with httpx.AsyncClient(timeout=httpx.Timeout(max(3, min(15, config.timeout * 2))),
                    follow_redirects=False, headers={"User-Agent": USER_AGENT},
                    limits=httpx.Limits(max_connections=32, max_keepalive_connections=12)) as client:
                ctx = ScanContext(config, target, client, progress, publish=publish)
                operations = {
                    "ports": (lambda: scan_ports(ctx, scan["addresses"]), None),
                    "dns": (lambda: scan_dns(ctx, scan["addresses"]), 60),
                    "subdomains": (lambda: scan_subdomains(ctx), 120),
                    "web": (lambda: scan_web(ctx), 45),
                    "tls": (lambda: scan_tls(ctx), 30),
                    "osint": (lambda: scan_osint(ctx, scan["addresses"]), 60),
                }
                await asyncio.gather(*(execute(module, operations[module][0](), operations[module][1])
                                       for module in config.modules))
            scan["status"] = "partial" if any(scan["sections"][module]["status"] in {"partial", "error"}
                                             for module in config.modules) else "completed"
            event("Проверка завершена" if scan["status"] == "completed" else "Проверка завершена с неполными данными")
        except asyncio.CancelledError:
            scan["status"] = "cancelled"
            for section in scan["sections"].values():
                if section["status"] in {"pending", "running"}:
                    section["status"] = "cancelled"
            event("Проверка остановлена; полученные результаты сохранены")
        except Exception as exc:
            scan["status"] = "failed"
            event("Ошибка: " + error_text(exc))
            for section in scan["sections"].values():
                if section["status"] in {"pending", "running"}:
                    section["status"] = "error"
                    section["errors"].append(error_text(exc))
        finally:
            scan["finished_at"] = now()
            save(True)
