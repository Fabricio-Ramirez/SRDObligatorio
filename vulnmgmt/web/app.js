/* Dashboard for the vulnerability management engine.
 * All text from the data files is inserted with textContent (never innerHTML),
 * so CVE references, host names or AI output cannot inject markup. */
"use strict";

const SEV = [
  ["Critical", "Crítica", "--crit"], ["High", "Alta", "--high"], ["Medium", "Media", "--med"],
  ["Low", "Baja", "--low"], ["Unknown", "Sin dato", "--unk"],
];
const PRIOS = ["P1", "P2", "P3", "P4"];
const ACTION_LABEL = { actualizar: "Actualizar", mitigar: "Mitigar", revisar: "Revisar" };
const state = { report: null, prios: new Set(PRIOS), open: new Set() };

function el(tag, attrs, ...children) {
  const node = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (v === undefined || v === null || v === false) continue;
    if (k === "class") node.className = v;
    else if (k === "text") node.textContent = v;
    else if (k.startsWith("on")) node.addEventListener(k.slice(2), v);
    else node.setAttribute(k, v === true ? "" : String(v));
  }
  for (const c of children.flat()) {
    if (c === null || c === undefined) continue;
    node.append(c instanceof Node ? c : document.createTextNode(String(c)));
  }
  return node;
}

const cssVar = (name) => getComputedStyle(document.documentElement).getPropertyValue(name).trim();
const fmtDate = (iso) => (iso ? new Date(iso).toLocaleString("es-UY") : "—");
const pct = (x) => (x === null || x === undefined ? "—" : (x * 100).toFixed(1) + " %");
const safeCve = (id) => /^CVE-\d{4}-\d{4,}$/.test(id || "");

async function getJSON(url) {
  const res = await fetch(url, { cache: "no-store" });
  if (!res.ok) throw new Error(`${url}: HTTP ${res.status}`);
  return res.json();
}

function renderMeta(r) {
  const meta = document.getElementById("meta");
  meta.replaceChildren(
    el("div", { text: "Último informe: " + fmtDate(r.generated_at) }),
    el("div", { text: `Motor v${r.engine_version} · KEV ${r.intel.kev ? r.intel.kev.version : "no disponible"}` +
      ` · EPSS ${r.intel.epss ? r.intel.epss.scored + " CVE con puntaje" : "no disponible"}` }),
  );
  document.getElementById("demo-banner").hidden = r.source !== "demo";
  const warn = document.getElementById("warnings");
  warn.replaceChildren(...(r.warnings || []).map((w) => el("li", { text: w })));
  warn.hidden = !(r.warnings || []).length;
  document.getElementById("foot").textContent =
    "Fuentes: detector de vulnerabilidades de Wazuh, catálogo KEV de CISA y EPSS de FIRST. " +
    "Las prioridades se calculan con reglas; la IA sólo redacta texto de apoyo.";
}

function renderKpis(k) {
  const items = [
    ["Vulnerabilidades únicas", k.unique_cves],
    ["Servidores afectados", `${k.hosts_affected} / ${k.hosts_total}`],
    ["En catálogo KEV", k.kev, k.kev > 0],
    ["Acciones P1", k.actions.P1, k.actions.P1 > 0],
    ["Acciones P2", k.actions.P2],
    ["Vencidas (SLA)", k.overdue, k.overdue > 0],
    ["Sin parche (mitigar)", k.no_fix],
    ["Resueltas en 30 días", k.resolved_30d],
  ];
  document.getElementById("kpis").replaceChildren(...items.map(([label, value, alert]) =>
    el("div", { class: "kpi" + (alert ? " alert" : "") }, el("div", { class: "v", text: value }),
      el("div", { class: "l", text: label }))));
  const total = SEV.reduce((s, [key]) => s + (k.severity[key] || 0), 0) || 1;
  const bar = document.getElementById("sevbar");
  bar.replaceChildren(...SEV.filter(([key]) => k.severity[key]).map(([key, label, color]) => {
    const seg = el("span", { title: `${label}: ${k.severity[key]}` });
    seg.style.width = (100 * k.severity[key] / total) + "%";
    seg.style.background = cssVar(color);
    return seg;
  }));
  document.getElementById("sevlegend").replaceChildren(...SEV.map(([key, label, color]) => {
    const dot = el("i");
    dot.style.background = cssVar(color);
    return el("span", {}, dot, `${label}: ${k.severity[key] || 0}`);
  }));
}

function renderAI(ai) {
  const badge = document.getElementById("ai-badge");
  if (ai.source === "ia-local") {
    badge.textContent = `IA local · ${ai.model} · ${ai.duration_s} s`;
    badge.className = "badge ai";
  } else {
    badge.textContent = "Resumen por reglas (IA no disponible)";
    badge.className = "badge";
  }
  document.getElementById("ai-summary").textContent = ai.summary || "";
  document.getElementById("ai-risks").replaceChildren(...(ai.risks || []).map((r) => el("li", { text: r })));
  document.getElementById("ai-window").textContent = ai.maintenance_window || "";
  document.getElementById("ai-note").textContent = ai.source === "ia-local"
    ? "Texto generado por un modelo de lenguaje local en el propio servidor (sin enviar datos fuera). " +
      "Es una ayuda: revisarlo antes de actuar. Las prioridades no dependen de la IA."
    : "";
}

function renderFilters() {
  const box = document.getElementById("prio-filter");
  box.replaceChildren(el("legend", { text: "Prioridad" }), ...PRIOS.map((p) => el("button", {
    type: "button", class: "chip", "aria-pressed": "true", text: p,
    onclick: (ev) => {
      if (state.prios.has(p)) state.prios.delete(p); else state.prios.add(p);
      ev.currentTarget.setAttribute("aria-pressed", String(state.prios.has(p)));
      renderActions();
    },
  })));
  for (const id of ["f-action", "f-text", "f-overdue"]) {
    document.getElementById(id).addEventListener("input", renderActions);
  }
  document.getElementById("filters").addEventListener("submit", (ev) => ev.preventDefault());
}

function matches(a) {
  const action = document.getElementById("f-action").value;
  const text = document.getElementById("f-text").value.trim().toLowerCase();
  const overdue = document.getElementById("f-overdue").checked;
  if (!state.prios.has(a.priority)) return false;
  if (action && a.action !== action) return false;
  if (overdue && !a.overdue) return false;
  if (text) {
    const hay = [a.package, ...a.hosts.map((h) => h.name), ...a.cves.map((c) => c.id)].join(" ").toLowerCase();
    if (!hay.includes(text)) return false;
  }
  return true;
}

function copyButton(text) {
  return el("button", {
    type: "button", class: "copy", text: "Copiar",
    onclick: async (ev) => {
      try { await navigator.clipboard.writeText(text); ev.target.textContent = "Copiado"; }
      catch { ev.target.textContent = "No disponible"; }
    },
  });
}

function detailRow(a) {
  const notes = (state.report.ai.notes || {})[a.id];
  const cveRows = a.cves.map((c) => el("tr", {},
    el("td", {}, safeCve(c.id)
      ? el("a", { href: `https://nvd.nist.gov/vuln/detail/${c.id}`, target: "_blank", rel: "noopener noreferrer", text: c.id })
      : c.id),
    el("td", { text: (SEV.find(([k]) => k === c.severity) || [, c.severity])[1] }),
    el("td", { class: "num", text: c.cvss + (c.cvss_from_severity ? "*" : "") }),
    el("td", { class: "num", text: pct(c.epss) }),
    el("td", { text: c.kev ? (c.kev_ransomware ? "Sí (ransomware)" : "Sí") : "No" }),
    el("td", { class: "num", text: c.risk }),
  ));
  return el("tr", { class: "detail" }, el("td", { colspan: 8 },
    el("div", { class: "detail-grid" },
      el("div", {},
        el("h3", { text: "Por qué tiene esta prioridad" }),
        el("ul", {}, a.reasons.map((r) => el("li", { text: r }))),
        el("h3", { text: "Versiones" }),
        el("p", { text: `Instalada(s): ${a.installed_versions.join(", ") || "—"} · Corregida en: ${a.fixed_version || "sin versión corregida conocida"}` }),
        el("h3", { text: "Servidores" }),
        el("p", { text: a.hosts.map((h) => `${h.name} (criticidad ${h.criticality})`).join(", ") }),
        a.reboot_required ? el("p", { class: "overdue", text: "Requiere reinicio del servidor." }) : null,
        notes ? el("div", {}, el("h3", { text: "Nota de la IA local" }), el("p", { text: notes })) : null,
      ),
      el("div", {},
        el("h3", { text: "Remediación" }), el("pre", { text: a.commands.remediation }), copyButton(a.commands.remediation),
        el("h3", { text: "Verificación" }), el("pre", { text: a.commands.verification }), copyButton(a.commands.verification),
        el("h3", { text: `Detectada desde ${a.first_seen} · vence ${a.due_date}` }),
      ),
    ),
    el("div", { class: "table-wrap" }, el("table", {},
      el("thead", {}, el("tr", {}, ["CVE", "Severidad", "CVSS", "EPSS", "KEV", "Riesgo"].map((h) => el("th", { text: h })))),
      el("tbody", {}, cveRows))),
    a.cves.some((c) => c.cvss_from_severity) ? el("p", { class: "note", text: "* CVSS estimado a partir de la severidad (Wazuh no informó puntaje)." }) : null,
  ));
}

function renderActions() {
  const body = document.querySelector("#actions tbody");
  const rows = [];
  const list = state.report.actionables.filter(matches);
  for (const a of list) {
    const toggle = () => { if (state.open.has(a.id)) state.open.delete(a.id); else state.open.add(a.id); renderActions(); };
    rows.push(el("tr", {
      class: "act", tabindex: "0", "aria-expanded": String(state.open.has(a.id)),
      onclick: toggle, onkeydown: (ev) => { if (ev.key === "Enter" || ev.key === " ") { ev.preventDefault(); toggle(); } },
    },
      el("td", {}, el("span", { class: "prio " + a.priority, text: a.priority })),
      el("td", { class: "num", text: a.risk }),
      el("td", { text: ACTION_LABEL[a.action] || a.action }),
      el("td", {}, el("strong", { text: a.package }), a.reboot_required ? el("span", { class: "tag", text: "reinicio" }) : null),
      el("td", { text: a.hosts.length > 3 ? `${a.hosts.slice(0, 3).map((h) => h.name).join(", ")} +${a.hosts.length - 3}` : a.hosts.map((h) => h.name).join(", ") }),
      el("td", { class: "num", text: a.cve_count }),
      el("td", { text: a.kev_count ? "Sí" : "—" }),
      el("td", { class: a.overdue ? "overdue" : "", text: a.due_date + (a.overdue ? " (vencida)" : "") }),
    ));
    if (state.open.has(a.id)) rows.push(detailRow(a));
  }
  body.replaceChildren(...rows);
  document.getElementById("actions-empty").hidden = list.length > 0;
}

function renderHosts(hosts) {
  const statusLabel = { active: "Activo", disconnected: "Desconectado", never_connected: "Nunca conectado", pending: "Pendiente" };
  document.querySelector("#hosts tbody").replaceChildren(...hosts.map((h) => el("tr", {},
    el("td", {}, el("strong", { text: h.name })),
    el("td", { text: h.os || "—" }),
    el("td", { text: h.criticality }),
    el("td", { class: h.status === "disconnected" ? "overdue" : "", text: statusLabel[h.status] || h.status || "—" }),
    el("td", { class: "num", text: h.severity.Critical }),
    el("td", { class: "num", text: h.severity.High }),
    el("td", { class: "num", text: h.severity.Medium }),
    el("td", { class: "num", text: h.severity.Low }),
    el("td", { class: "num", text: h.kev }),
    el("td", { class: "num", text: h.max_risk }),
    el("td", { class: "num", text: h.actions }),
  )));
}

function renderTrend(history) {
  const box = document.getElementById("trend");
  if (!history.length) { box.textContent = "Sin historial todavía."; return; }
  const series = [
    ["Vulnerabilidades únicas", (h) => h.unique_cves, "--accent"],
    ["Acciones P1", (h) => h.actions.P1, "--p1"],
    ["Acciones P2", (h) => h.actions.P2, "--p2"],
    ["En KEV", (h) => h.kev, "--crit"],
  ];
  const W = 800, H = 220, L = 40, B = 24, T = 10;
  const max = Math.max(1, ...history.flatMap((h) => series.map(([, f]) => f(h))));
  const x = (i) => L + (history.length === 1 ? (W - L) / 2 : i * (W - L - 10) / (history.length - 1));
  const y = (v) => T + (H - T - B) * (1 - v / max);
  const NS = "http://www.w3.org/2000/svg";
  const svg = document.createElementNS(NS, "svg");
  svg.setAttribute("viewBox", `0 0 ${W} ${H}`);
  svg.setAttribute("role", "img");
  svg.setAttribute("aria-label", "Evolución diaria de vulnerabilidades y acciones");
  const add = (tag, attrs, text) => {
    const n = document.createElementNS(NS, tag);
    for (const [k, v] of Object.entries(attrs)) n.setAttribute(k, v);
    if (text !== undefined) n.textContent = text;
    svg.append(n);
    return n;
  };
  for (const v of [0, max / 2, max]) {
    add("line", { x1: L, x2: W, y1: y(v), y2: y(v), class: "axis" });
    add("text", { x: 4, y: y(v) + 4 }, String(Math.round(v)));
  }
  const step = Math.max(1, Math.ceil(history.length / 8));
  history.forEach((h, i) => { if (i % step === 0) add("text", { x: x(i) - 20, y: H - 6 }, h.date.slice(5)); });
  for (const [, f, color] of series) {
    const pts = history.map((h, i) => `${x(i)},${y(f(h))}`).join(" ");
    add("polyline", { points: pts, fill: "none", stroke: cssVar(color), "stroke-width": 2 });
    history.forEach((h, i) => add("circle", { cx: x(i), cy: y(f(h)), r: 3, fill: cssVar(color) }));
  }
  box.replaceChildren(svg);
  document.getElementById("trend-legend").replaceChildren(...series.map(([label, , color]) => {
    const dot = el("i");
    dot.style.background = cssVar(color);
    return el("span", {}, dot, label);
  }));
}

function renderMethod(s) {
  const w = s.weights, t = s.thresholds, d = s.sla_days;
  document.getElementById("method").replaceChildren(
    el("p", {}, "Riesgo (0-100) = ", el("code", { text: `(CVSS × ${w.cvss} + EPSS × ${w.epss} + KEV × ${w.kev}) × criticidad del servidor` }),
      `, con criticidad ${Object.entries(s.criticality.factors).map(([k, v]) => `${k} ×${v}`).join(", ")}.`),
    el("p", { text: `Prioridad: P1 si la CVE está en KEV o el riesgo es ≥ ${t.P1}; P2 si ≥ ${t.P2}; P3 si ≥ ${t.P3}; P4 en otro caso.` }),
    el("p", { text: `Plazo (SLA) desde la primera detección: P1 ${d.P1} días, P2 ${d.P2}, P3 ${d.P3}, P4 ${d.P4}. ` +
      "Si CISA fijó una fecha posterior a la detección y más cercana, se usa esa." }),
    el("p", { text: "Las acciones agrupan por paquete todas las CVE y servidores afectados. " +
      "\"Actualizar\": Wazuh conoce la versión corregida. \"Mitigar\": no hay versión corregida conocida." }),
  );
}

async function main() {
  try {
    state.report = await getJSON("data/latest.json");
  } catch (err) {
    document.getElementById("meta").textContent = "Todavía no hay informes: ejecutar el motor (vulnmgmt run).";
    return;
  }
  const history = await getJSON("data/history.json").catch(() => []);
  const r = state.report;
  renderMeta(r);
  renderKpis(r.kpis);
  renderAI(r.ai);
  renderFilters();
  renderActions();
  renderHosts(r.hosts);
  renderTrend(history);
  renderMethod(r.scoring);
}

main();
