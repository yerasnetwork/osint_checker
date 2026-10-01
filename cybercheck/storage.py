import json
import sqlite3
from contextlib import contextmanager
from pathlib import Path

DEFAULT_DATABASE = Path.cwd() / "data" / "cybercheck.sqlite3"


class ScanStore:
    def __init__(self, path: Path = DEFAULT_DATABASE):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.connect() as connection:
            connection.execute("""CREATE TABLE IF NOT EXISTS scans (
                id TEXT PRIMARY KEY, target TEXT NOT NULL, status TEXT NOT NULL,
                created_at TEXT NOT NULL, payload TEXT NOT NULL)""")

    @contextmanager
    def connect(self):
        connection = sqlite3.connect(self.path, timeout=10)
        connection.row_factory = sqlite3.Row
        try:
            with connection:
                yield connection
        finally:
            connection.close()

    def save(self, scan: dict):
        with self.connect() as connection:
            connection.execute("""INSERT INTO scans VALUES (?, ?, ?, ?, ?)
                ON CONFLICT(id) DO UPDATE SET status=excluded.status, payload=excluded.payload""",
                (scan["id"], scan["target"], scan["status"], scan["created_at"], json.dumps(scan, ensure_ascii=False)))

    def get(self, scan_id: str) -> dict | None:
        with self.connect() as connection:
            row = connection.execute("SELECT payload FROM scans WHERE id=?", (scan_id,)).fetchone()
        return json.loads(row["payload"]) if row else None

    def list(self, limit: int = 100) -> list[dict]:
        with self.connect() as connection:
            rows = connection.execute("SELECT id,target,status,created_at FROM scans ORDER BY created_at DESC LIMIT ?", (limit,)).fetchall()
        return [dict(row) for row in rows]

    def interrupt_unfinished(self):
        with self.connect() as connection:
            rows = connection.execute("SELECT payload FROM scans WHERE status IN ('queued','running')").fetchall()
        for row in rows:
            scan = json.loads(row["payload"])
            scan["status"] = "interrupted"
            scan["events"].append({"time": scan["updated_at"], "message": "Процесс завершился до окончания проверки"})
            for section in scan["sections"].values():
                if section["status"] in {"pending", "running"}:
                    section["status"] = "interrupted"
            self.save(scan)
