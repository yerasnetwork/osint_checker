"use strict";
const $ = (selector) => document.querySelector(selector);
const labels = {ports:"Порты",dns:"DNS",subdomains:"Поддомены",web:"Веб",tls:"TLS",osint:"OSINT"};
const statuses = {queued:"В очереди",running:"Выполняется",completed:"Завершена",partial:"Неполные данные",cancelled:"Остановлена",failed:"Ошибка",interrupted:"Прервана",ok:"Готово",error:"Ошибка",skipped:"Пропущено",disabled:"Отключено",pending:"Ожидает",open:"Открыт",closed:"Закрыт",no_response:"Нет ответа",resolved:"Подтверждён",unresolved:"Не разрешается",wildcard:"Wildcard DNS",info:"Информация",warning:"Замечание"};
const headings = {overview:"Открытые порты и обнаруженные имена",ports:"TCP-порты выбранной цели",subdomains:"Найденные имена и DNS-подтверждение",dns:"DNS-записи и IP-адреса",web:"Сведения о веб-сайте",tls:"Сертификат и параметры TLS",osint:"Сведения из публичных источников",findings:"Наблюдения по конфигурации",events:"Журнал проверки"};
let current = null, tab = "overview", pollTimer = null, searchTimer = null, portOffset = 0, portTotal = 0, selection = 0, resultVersion = 0;
function el(tag, text, className) { const node = document.createElement(tag); if (text !== undefined) node.textContent = String(text); if (className) node.className = className; return node; }
function badge(value) { return el("span", statuses[value] || value, `badge ${value}`); }
function text(value) { return typeof value === "object" && value !== null ? JSON.stringify(value) : String(value ?? "—"); }
function formatDate(value) { return new Date(value).toLocaleString("ru-RU", {day:"2-digit",month:"2-digit",hour:"2-digit",minute:"2-digit"}); }
function showError(message) { $("#form-error").textContent = message; $("#form-error").hidden = false; }
function toast(message) { $("#toast").textContent = message; $("#toast").hidden = false; setTimeout(() => { $("#toast").hidden = true; }, 5000); }
async function api(path, options = {}) {
  const response = await fetch(path, {...options, headers:{"Content-Type":"application/json", ...options.headers}});
  const payload = await response.json().catch(() => null);
  if (!response.ok) { const detail = payload?.detail; throw new Error(Array.isArray(detail) ? detail.map(x => x.msg.replace(/^Value error, /, "")).join("; ") : detail || `HTTP ${response.status}`); }
  return payload;
}
function table(headers, rows) {
  const node = el("table", undefined, "table"), head = el("thead"), tr = el("tr"), body = el("tbody");
  headers.forEach(h => tr.append(el("th", h))); head.append(tr); node.append(head);
  rows.forEach(values => { const row = el("tr"); values.forEach(value => { const cell = el("td"); cell.append(value instanceof Node ? value : document.createTextNode(text(value))); row.append(cell); }); body.append(row); });
  node.append(body); return node;
}
function portTable(rows) {
  return table(["IP / ПОРТ", "СОСТОЯНИЕ", "СЛУЖБА", "ДАННЫЕ", "ВРЕМЯ"], rows.map(row => {
    const service = el("div", row.service);
    service.append(el("span", row.service_source === "nmap" ? [row.product,row.version].filter(Boolean).join(" ") || "Nmap" : "По номеру порта · предположение", "service-hint"));
    return [`${row.ip}:${row.port}`,badge(row.state),service,el("code",row.banner || row.detail || "—"),`${row.latency_ms} ms`];
  }));
}
function domainTable(rows) { return table(["ДОМЕН", "СОСТОЯНИЕ", "IP-АДРЕСА", "ИСТОЧНИК"], rows.map(row => [row.host,badge(row.status),row.addresses.join(", ") || "—",row.sources.map(x => x === "dns_wordlist" ? "DNS / список имён" : "Сертификаты CT").join(", ")])); }
function empty(container, message) { container.append(el("p", message, "result-empty")); }
function note(container, message) { if (message) container.append(el("p", message, "note")); }
function jsonBlock(container, value) { container.append(el("pre", JSON.stringify(value, null, 2), "json-block")); }
function card(title, values) {
  const node = el("article", undefined, "data-card"); node.append(el("h3", title)); const list = el("dl");
  Object.entries(values).forEach(([key,value]) => { list.append(el("dt",key),el("dd",text(value))); }); node.append(list); return node;
}
function getFindings() { return ["web","tls"].flatMap(key => current.sections[key].data.findings || []); }
function matches(row) { return JSON.stringify(row).toLocaleLowerCase().includes($("#result-search").value.toLocaleLowerCase()); }
function renderErrors(container, keys) {
  keys.forEach(key => { const errors = current.sections[key].errors; if (errors.length) container.append(el("div",`${labels[key]}: ${errors.join(" · ")}`,"module-errors")); });
}
async function history() {
  const rows = await api("/api/scans"); $("#history-count").textContent = rows.length;
  const node = $("#history"); node.replaceChildren();
  if (!rows.length) node.append(el("p","Здесь появятся ваши проверки","side-empty"));
  rows.forEach(row => {
    const button = el("button",undefined,`history-item ${current?.id === row.id ? "selected" : ""}`);
    button.append(el("strong",row.target)); const meta = el("small"); meta.append(el("span",formatDate(row.created_at)),el("span",statuses[row.status] || row.status)); button.append(meta);
    button.addEventListener("click", () => selectScan(row.id)); node.append(button);
  });
}
async function selectScan(id) {
  clearTimeout(pollTimer); const token = ++selection;
  try { const data = await api(`/api/scans/${encodeURIComponent(id)}?compact=true`); if (token !== selection) return; current = data; portOffset = 0; location.hash = id; render(); await history(); schedulePoll(); }
  catch (error) { toast(error.message); }
}
function schedulePoll() {
  clearTimeout(pollTimer);
  if (!current || !["queued","running"].includes(current.status)) return;
  const id = current.id, token = selection;
  pollTimer = setTimeout(async () => {
    try { const data = await api(`/api/scans/${id}?compact=true`); if (token !== selection || current?.id !== id) return; current = data; render(); if (!["queued","running"].includes(data.status)) await history(); schedulePoll(); }
    catch (error) { if (token === selection) { toast(`Не удалось обновить отчёт: ${error.message}`); pollTimer = setTimeout(schedulePoll, 2000); } }
  }, 1300);
}
function render() {
  if (!current) return;
  $("#report").hidden = false; $("#empty-state").hidden = true;
  $("#report-target").textContent = current.host;
  $("#report-meta").textContent = `${formatDate(current.created_at)} · ${current.addresses.join(", ") || "Определение IP…"} · #${current.id.slice(0,8)}`;
  const active = ["queued","running"].includes(current.status); $("#cancel").hidden = !active;
  const statusNode = $("#scan-status"); statusNode.textContent = statuses[current.status]; statusNode.className = `badge ${current.status}`;
  $("#scan-progress").value = current.progress;
  $("#scan-progress-label").textContent = `${current.progress}% · ${active ? "Сбор данных" : "Результаты сохранены"}`;
  const modules = $("#module-statuses"); modules.replaceChildren();
  Object.entries(current.sections).forEach(([key,section]) => {
    if (section.status === "disabled") return;
    const node = el("span",undefined,section.status); node.append(el("i"),document.createTextNode(`${labels[key]} / ${statuses[section.status] || section.status}`)); modules.append(node);
  });
  const ports = current.sections.ports.data, domains = current.sections.subdomains.data, dns = current.sections.dns.data;
  $("#metric-ports").textContent = ports.counts?.open ?? "—";
  $("#metric-ports-detail").textContent = ports.counts ? `${ports.row_count ?? 0} проверено · ${ports.counts.no_response} без ответа` : "TCP-соединения";
  $("#metric-domains").textContent = domains.rows ? domains.rows.filter(row => row.status === "resolved").length : "—";
  $("#metric-dns").textContent = dns.records?.length ?? "—";
  $("#metric-findings").textContent = [current.sections.web.status,current.sections.tls.status].every(x => ["disabled","pending","running"].includes(x)) ? "—" : getFindings().length;
  ["html","json","csv"].forEach(format => { $(`#export-${format}`).href = `/api/scans/${current.id}/export?format=${format}`; });
  renderResults();
}
async function renderResults() {
  const version = ++resultVersion;
  const container = $("#result-body"), id = current?.id, requestedTab = tab;
  if (!current) return;
  container.replaceChildren(); $("#result-heading").textContent = headings[tab]; $("#port-state").hidden = tab !== "ports"; $("#pagination").hidden = true;
  if (tab === "overview") {
    const ports = (current.sections.ports.data.rows || []).filter(matches), domains = (current.sections.subdomains.data.rows || []).filter(row => row.status === "resolved" && matches(row));
    container.append(el("h3","Открытые порты","section-title"));
    if (ports.length) container.append(portTable(ports)); else note(container,"Открытых портов пока нет в результатах. Состояние проверки указано выше.");
    container.append(el("h3","Подтверждённые поддомены","section-title"));
    if (domains.length) container.append(domainTable(domains)); else note(container,"Подтверждённые поддомены пока не найдены.");
    const web = current.sections.web.data; if (web.url) container.append(card("Веб-сайт",{"Адрес":web.url,"HTTP":web.status_code,"Заголовок":web.title || "—"}));
    note(container,"Порты относятся к проверенным IP. Если используется CDN, это может быть инфраструктура CDN. Названия служб по номеру порта являются предположениями.");
    renderErrors(container,Object.keys(labels));
  } else if (tab === "ports") {
    const query = new URLSearchParams({state:$("#port-state").value,search:$("#result-search").value,offset:portOffset,limit:100});
    try {
      const page = await api(`/api/scans/${id}/ports?${query}`);
      if (current?.id !== id || tab !== requestedTab || version !== resultVersion) return;
      container.replaceChildren(); portTotal = page.total;
      if (page.rows.length) container.append(portTable(page.rows)); else empty(container,"Нет портов, соответствующих фильтру.");
      $("#pagination").hidden = false; $("#page-label").textContent = `${page.total ? page.offset + 1 : 0}–${Math.min(page.offset + 100,page.total)} / ${page.total}`;
      $("#page-prev").disabled = portOffset === 0; $("#page-next").disabled = portOffset + 100 >= portTotal;
      renderErrors(container,["ports"]); note(container,current.sections.ports.data.note);
    } catch (error) { if (current?.id === id && tab === requestedTab && version === resultVersion) empty(container,error.message); }
  } else if (tab === "subdomains") {
    const data = current.sections.subdomains.data, rows = (data.rows || []).filter(matches);
    if (rows.length) container.append(domainTable(rows)); else empty(container,data.note || "Найденных имён пока нет.");
    note(container,data.note); if (data.limited) note(container,"Список ограничен выбранным лимитом поддоменов.");
    if (data.wildcard_addresses?.length) note(container,`Wildcard DNS: ${data.wildcard_addresses.join(", ")}`); renderErrors(container,[tab]);
  } else if (tab === "dns") {
    const data = current.sections.dns.data, records = (data.records || []).filter(matches);
    note(container,`Системный DNS: ${(data.addresses || current.addresses).join(", ") || "IP не определены"}`);
    if (records.length) container.append(table(["ТИП ЗАПРОСА","ИМЯ","ЗНАЧЕНИЕ","TTL"],records.map(row => [row.query_type,row.name,el("code",row.value),row.ttl]))); else empty(container,"DNS-записей пока нет.");
    note(container,data.note); renderErrors(container,[tab]);
  } else if (tab === "web") {
    const data = current.sections.web.data;
    if (data.url) {
      const grid = el("div",undefined,"data-grid"); grid.append(card("HTTP",{"Адрес":data.url,"Статус":data.status_code,"Заголовок страницы":data.title || "—"}),card("Технологии · признаки",Object.fromEntries((data.technologies || []).map((item,index) => [`${index+1}. ${item.name}`,item.evidence])))); container.append(grid);
      container.append(el("h3","HTTP-заголовки","section-title")); const entries = Object.entries(data.headers || {}).filter(matches); container.append(table(["ЗАГОЛОВОК","ЗНАЧЕНИЕ"],entries));
      if (data.cookies?.length) { container.append(el("h3","Cookies · только имена и атрибуты","section-title")); container.append(table(["ИМЯ","SECURE","HTTPONLY","SAMESITE"],data.cookies.filter(matches).map(row => [row.name,row.secure,row.httponly,row.samesite]))); }
      container.append(el("h3","Редиректы","section-title")); container.append(table(["АДРЕС","HTTP"],(data.redirects || []).filter(matches).map(row => [row.url,row.status])));
      if (data.blocked_redirect) note(container,`Переход за пределы цели остановлен: ${data.blocked_redirect}`);
      if (data.resources?.length) { container.append(el("h3","robots.txt / sitemap.xml","section-title")); container.append(table(["АДРЕС","HTTP","ФРАГМЕНТ"],data.resources.filter(matches).map(row => [row.url,row.status_code,el("code",row.preview)]))); }
    } else empty(container,"Сведения о веб-сайте пока не получены."); renderErrors(container,[tab]);
  } else if (tab === "tls") {
    const data = current.sections.tls.data;
    if (data.issuer) {
      const grid = el("div",undefined,"data-grid"); grid.append(card("Сертификат",{"Проверен":data.verified ? "Да" : "Нет","Выдан":data.subject,"Издатель":data.issuer,"Действует до":data.valid_until,"Осталось дней":data.days_remaining}),card("Соединение",{"Цель":`${data.host}:${data.port}`,"TLS":data.tls_version,"Шифр":data.cipher,"SHA-256":data.sha256})); container.append(grid);
      container.append(el("h3","Имена в сертификате","section-title")); jsonBlock(container,(data.dns_names || []).filter(matches));
    } else empty(container,data.note || "TLS-сведения пока не получены."); renderErrors(container,[tab]);
  } else if (tab === "osint") {
    const data = current.sections.osint.data;
    if (data.domain) { container.append(el("h3","Регистрация домена / RDAP","section-title")); jsonBlock(container,data.domain); }
    if (data.networks?.length) { container.append(el("h3","Сети и провайдеры / RDAP","section-title")); jsonBlock(container,data.networks.filter(matches)); }
    if (data.asn?.length) { container.append(el("h3","Автономные системы / ASN","section-title")); container.append(table(["IP","ASN","ПРЕФИКС","СТРАНА","РЕЕСТР"],data.asn.filter(matches).map(row => [row.ip,row.asn,row.prefix,row.country,row.registry]))); }
    if (!data.domain && !data.networks?.length && !data.asn?.length) empty(container,data.note || "Публичные сведения пока не получены."); renderErrors(container,[tab]);
  } else if (tab === "findings") {
    const rows = getFindings().filter(matches), list = el("div",undefined,"findings-list");
    rows.forEach(row => { const item = el("article",undefined,"finding"), heading = el("h3"); heading.append(badge(row.severity),document.createTextNode(row.title)); item.append(heading,el("p",`${row.evidence}\nИсточник: ${row.source}`)); list.append(item); });
    if (rows.length) container.append(list); else empty(container,"Замечаний по выполненным проверкам нет.");
    note(container,"Это наблюдения по конфигурации. Они сами по себе не подтверждают возможность эксплуатации.");
  } else if (tab === "events") {
    container.append(table(["ВРЕМЯ","СОБЫТИЕ"],current.events.filter(matches).map(row => [new Date(row.time).toLocaleTimeString("ru-RU"),row.message])));
  }
}
$("#scan-form").addEventListener("submit",async event => {
  event.preventDefault(); $("#form-error").hidden = true;
  const modules = Array.from(document.querySelectorAll('input[name="module"]:checked')).map(node => node.value);
  if (!modules.length) { showError("Выберите хотя бы один модуль"); return; }
  const config = {target:$("#target").value.trim(),profile:$("#profile").value,ports:$("#ports").value,modules,
    concurrency:Number($("#concurrency").value),rate:Number($("#rate").value),timeout:Number($("#timeout").value),
    max_addresses:Number($("#max-addresses").value),max_subdomains:Number($("#max-subdomains").value),
    public_sources:$("#public-sources").checked,probe_subdomains:$("#probe-subdomains").checked,service_detection:$("#nmap").checked};
  $("#start").disabled = true;
  try { const scan = await api("/api/scans",{method:"POST",body:JSON.stringify(config)}); clearTimeout(pollTimer); ++selection; current = scan; portOffset = 0; tab = "overview"; updateTabs(); location.hash = scan.id; render(); await history(); schedulePoll(); }
  catch (error) { showError(error.message); }
  finally { $("#start").disabled = false; }
});
function updateTabs() { document.querySelectorAll("[data-tab]").forEach(node => node.setAttribute("aria-selected",String(node.dataset.tab === tab))); }
document.querySelectorAll("[data-tab]").forEach(node => node.addEventListener("click",() => { tab = node.dataset.tab; portOffset = 0; updateTabs(); renderResults(); }));
$("#profile").addEventListener("change",() => { $("#custom-ports").hidden = $("#profile").value !== "custom"; $("#ports").required = $("#profile").value === "custom"; });
$("#result-search").addEventListener("input",() => { clearTimeout(searchTimer); portOffset = 0; searchTimer = setTimeout(renderResults,200); });
$("#port-state").addEventListener("change",() => { portOffset = 0; renderResults(); });
$("#page-prev").addEventListener("click",() => { portOffset = Math.max(0,portOffset-100); renderResults(); });
$("#page-next").addEventListener("click",() => { if (portOffset+100<portTotal) portOffset += 100; renderResults(); });
$("#cancel").addEventListener("click",async () => { if (!current) return; try { await api(`/api/scans/${current.id}/cancel`,{method:"POST"}); toast("Остановка проверки…"); schedulePoll(); } catch(error) { toast(error.message); } });
$("#new-scan").addEventListener("click",() => { clearTimeout(pollTimer); ++selection; current = null; location.hash = ""; $("#report").hidden = true; $("#empty-state").hidden = false; $("#target").focus(); history().catch(error => toast(error.message)); });
async function initialize() {
  try {
    const [health,info] = await Promise.all([api("/api/health"),api("/api/info")]);
    $("#connection").textContent = `Система готова · ${health.version}`;
    $("#profile").options[1].textContent = `Стандартный · ${info.profiles.standard} портов`;
    $("#nmap").disabled = !info.nmap_available; $("#nmap-note").textContent = info.nmap_available ? "· доступен" : "· не установлен";
    await history(); if (/^#[a-f0-9]{32}$/.test(location.hash)) await selectScan(location.hash.slice(1));
  } catch (error) { $("#connection").textContent = "Сервер недоступен"; showError(error.message); }
}
initialize();
