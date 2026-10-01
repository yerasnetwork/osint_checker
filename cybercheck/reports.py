import csv
import html
import io
import json

LABELS = {"ports": "Порты", "subdomains": "Домены и поддомены", "dns": "IP и DNS",
          "web": "Веб-сайт", "tls": "TLS и сертификат", "osint": "OSINT"}
ORDER = ("ports", "subdomains", "dns", "web", "tls", "osint")


def findings(scan: dict) -> list[dict]:
    return [item for module in ("web", "tls") for item in scan["sections"][module]["data"].get("findings", [])]


def csv_safe(value) -> str:
    if isinstance(value, (list, dict)):
        value = json.dumps(value, ensure_ascii=False)
    result = str(value if value is not None else "")
    if result.lstrip().startswith(("=", "+", "-", "@")) or result.startswith(("\t", "\r", "\n")):
        result = "'" + result
    return result


def export_csv(scan: dict) -> str:
    stream = io.StringIO(newline="")
    writer = csv.writer(stream)
    writer.writerow(["section", "host", "name", "status", "value", "source"])

    def row(*values):
        writer.writerow([csv_safe(value) for value in values])

    row("scan", scan["host"], scan["id"], scan["status"], scan["created_at"], "CyberCheck")
    sections = scan["sections"]
    for item in sections["ports"]["data"].get("rows", []):
        row("ports", item["ip"], item["port"], item["state"], {key: item[key] for key in item if key not in {"ip", "port", "state"}}, "tcp_connect")
    for item in sections["subdomains"]["data"].get("rows", []):
        row("subdomains", item["host"], "DNS", item["status"], item, item["sources"])
    for item in sections["dns"]["data"].get("records", []):
        row("dns", item["name"], item["query_type"], "observed", item["value"], item["source"])
    for module in ("web", "tls", "osint"):
        row(module, scan["host"], LABELS[module], sections[module]["status"], sections[module]["data"], "")
    for item in findings(scan):
        row("finding", scan["host"], item["title"], item["severity"], item["evidence"], item["source"])
    for module, section in sections.items():
        for error in section["errors"]:
            row("error", scan["host"], module, section["status"], error, "")
    return "\ufeff" + stream.getvalue()


def export_html(scan: dict) -> str:
    esc = lambda value: html.escape(str(value), quote=True)
    blocks = []
    for module in ORDER:
        section = scan["sections"][module]
        if section["status"] == "disabled":
            continue
        errors = "".join(f"<p class='error'>{esc(error)}</p>" for error in section["errors"])
        data = section["data"]
        if module == "ports":
            parts = ["<table><thead><tr><th>IP</th><th>Порт</th><th>Состояние</th><th>Служба</th><th>Данные</th></tr></thead><tbody>"]
            for item in data.get("rows", []):
                parts.append("<tr>" + "".join(f"<td>{esc(value)}</td>" for value in (item["ip"], item["port"], item["state"], item["service"], item.get("banner") or item.get("detail", ""))) + "</tr>")
            parts.append("</tbody></table>")
            body = "".join(parts)
        else:
            body = f"<pre>{esc(json.dumps(data, ensure_ascii=False, indent=2))}</pre>"
        blocks.append(f"<section><h2>{esc(LABELS[module])} <small>{esc(section['status'])}</small></h2>{errors}{body}</section>")
    return f"""<!doctype html><html lang="ru"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>CyberCheck — {esc(scan['host'])}</title><style>
body{{font:15px system-ui;color:#152436;background:#f3f6fa;margin:0;padding:32px;max-width:1200px;margin:auto}}
h1{{font-size:32px}}h2{{font-size:21px}}small{{font-size:12px;color:#65768a}}section{{background:white;border:1px solid #dde5ee;padding:22px;margin:20px 0;border-radius:12px}}
pre{{white-space:pre-wrap;overflow-wrap:anywhere;font:13px monospace}}table{{width:100%;border-collapse:collapse}}th,td{{text-align:left;padding:10px;border-bottom:1px solid #e3e9ef;overflow-wrap:anywhere}}.error{{color:#a13e23}}
</style><h1>CyberCheck / {esc(scan['host'])}</h1><p>{esc(scan['target'])} · {esc(scan['status'])} · {esc(scan['created_at'])}</p>
<p>Наблюдения относятся к моменту проверки. Название службы по номеру порта — предположение. Исторические имена и wildcard DNS отмечены отдельно.</p>
{''.join(blocks)}<section><h2>Журнал</h2><pre>{esc(json.dumps(scan['events'], ensure_ascii=False, indent=2))}</pre></section></html>"""


def compact_scan(scan: dict) -> dict:
    result = {**scan, "sections": {key: {**value, "data": dict(value["data"])} for key, value in scan["sections"].items()}}
    ports = result["sections"]["ports"]["data"]
    rows = ports.get("rows", [])
    ports["row_count"] = len(rows)
    ports["rows"] = sorted((row for row in rows if row["state"] == "open"), key=lambda row: (row["ip"], row["port"]))[:200]
    ports["preview_only"] = True
    return result
