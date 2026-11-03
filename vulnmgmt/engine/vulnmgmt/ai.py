"""Local AI assistant (Ollama) tuned for a small VM.

Design choices for scarce resources:
- small quantised models (default qwen2.5:1.5b, ~1 GB; qwen2.5:0.5b as a lighter
  fallback), chosen at run time from the RAM that is actually free;
- one request per run, compact prompt (only the top-N tasks, no free text from
  feeds), bounded context (num_ctx) and output (num_predict);
- keep_alive=0 so the model is unloaded from RAM as soon as it answers;
- structured output (JSON schema) so a small model cannot break the format.

The AI only writes explanatory text. Priorities come from prioritize.py, and
if the AI is disabled, out of memory or fails, a rule-based summary is used.
Everything runs on the server: no data leaves the infrastructure.
"""

import json
import logging
import os
import time

from .httpclient import Client, HTTPError

log = logging.getLogger(__name__)

SCHEMA = {
    "type": "object",
    "properties": {
        "resumen_ejecutivo": {"type": "string"},
        "riesgos_clave": {"type": "array", "items": {"type": "string"}},
        "acciones": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {"id": {"type": "string"}, "nota": {"type": "string"}},
                "required": ["id", "nota"],
            },
        },
        "ventana_mantenimiento": {"type": "string"},
    },
    "required": ["resumen_ejecutivo", "riesgos_clave", "acciones", "ventana_mantenimiento"],
}

SYSTEM = (
    "Eres un analista de gestión de vulnerabilidades. Respondes en español, en tono "
    "profesional y conciso, sólo con JSON válido según el esquema. Usas únicamente los "
    "datos recibidos: no inventes CVE, versiones, servidores ni fechas. No cambies las "
    "prioridades: ya fueron calculadas."
)


def mem_available_mb(path="/proc/meminfo"):
    try:
        with open(path, encoding="ascii") as fh:
            for line in fh:
                if line.startswith("MemAvailable:"):
                    return int(line.split()[1]) // 1024
    except (OSError, ValueError, IndexError):
        pass
    return None


def choose_model(models, installed, free_mb):
    """First configured model that is installed and fits in the free RAM."""
    for model in models:
        if model["name"] in installed and (free_mb is None or free_mb >= model.get("min_free_mb", 0)):
            return model["name"]
    return None


def build_prompt(actionables, kpis, max_actions):
    tasks = []
    for a in actionables[:max_actions]:
        tasks.append({
            "id": a["id"], "prioridad": a["priority"], "riesgo": a["risk"], "accion": a["action"],
            "paquete": a["package"], "version_corregida": a["fixed_version"],
            "servidores": [h["name"] for h in a["hosts"]][:10],
            "cves": [c["id"] for c in a["cves"]][:5], "kev": a["kev_count"],
            "cvss_max": a["max_cvss"], "vence": a["due_date"], "reinicio": a["reboot_required"],
        })
    data = {"indicadores": {k: kpis[k] for k in ("unique_cves", "hosts_affected", "kev", "actions", "overdue")},
            "tareas": tasks}
    return (
        "Con estos datos del escaneo de vulnerabilidades de los servidores, redacta:\n"
        "1) resumen_ejecutivo: 3 a 5 oraciones para la gerencia.\n"
        "2) riesgos_clave: hasta 4 riesgos concretos.\n"
        "3) acciones: para cada tarea (mismo id) una nota breve para el equipo de "
        "infraestructura: orden sugerido, impacto operativo (reinicio, servicio afectado) y cómo verificar.\n"
        "4) ventana_mantenimiento: cómo agrupar las tareas en ventanas de mantenimiento.\n"
        "DATOS:\n" + json.dumps(data, ensure_ascii=False, separators=(",", ":"))
    )


def _clean(text, limit):
    text = " ".join(str(text or "").split())
    return text[:limit]


def validate(answer, ids):
    """Keep only well-formed, bounded fields and notes for known task ids."""
    if not isinstance(answer, dict):
        raise ValueError("answer is not an object")
    summary = _clean(answer.get("resumen_ejecutivo"), 1500)
    if not summary:
        raise ValueError("empty summary")
    notes = {}
    for item in answer.get("acciones") or []:
        if isinstance(item, dict) and item.get("id") in ids and item.get("nota"):
            notes[item["id"]] = _clean(item["nota"], 600)
    return {
        "summary": summary,
        "risks": [_clean(r, 300) for r in (answer.get("riesgos_clave") or [])[:5] if r],
        "notes": notes,
        "maintenance_window": _clean(answer.get("ventana_mantenimiento"), 800),
    }


def rule_based(actionables, kpis):
    """Deterministic summary used when the AI is not available."""
    a = kpis["actions"]
    parts = [f"Se detectaron {kpis['unique_cves']} vulnerabilidades únicas en "
             f"{kpis['hosts_affected']} servidores, agrupadas en {sum(a.values())} acciones."]
    if a["P1"]:
        parts.append(f"Hay {a['P1']} acciones P1 de atención inmediata.")
    if kpis["kev"]:
        parts.append(f"{kpis['kev']} vulnerabilidades figuran en el catálogo KEV de CISA (explotación activa).")
    if kpis["overdue"]:
        parts.append(f"{kpis['overdue']} acciones están vencidas respecto de su SLA.")
    risks = [f"{x['priority']} {x['package']}: {', '.join(x['reasons'][:2])}" for x in actionables[:4]]
    reboot = [x["package"] for x in actionables[:10] if x["reboot_required"]]
    window = ("Aplicar primero las P1 en una ventana de emergencia; agrupar P2 en la ventana semanal"
              + (f"; requieren reinicio: {', '.join(reboot)}" if reboot else "") + ".")
    return {"summary": " ".join(parts), "risks": risks, "notes": {}, "maintenance_window": window}


def analyse(cfg, actionables, kpis, status):
    """Return the AI section of the report (always returns something usable)."""
    result = {"source": "reglas", "model": None, "duration_s": None, "generated_at": None}
    result.update(rule_based(actionables, kpis))
    if not cfg.get("enabled", True) or not actionables:
        return result
    client = Client(cfg.get("url", "http://127.0.0.1:11434"), timeout=cfg.get("timeout", 600), local=True)
    try:
        installed = {m.get("name") for m in client.request("GET", "/api/tags").get("models", [])}
    except HTTPError as exc:
        status["warnings"].append(f"IA: Ollama no responde ({exc}); se usa el resumen por reglas.")
        return result
    free_mb = mem_available_mb()
    model = choose_model(cfg.get("models", []), installed, free_mb)
    if model is None:
        status["warnings"].append(
            f"IA: ningún modelo instalado entra en la RAM libre ({free_mb} MB); se usa el resumen por reglas.")
        return result
    threads = int(cfg.get("threads") or 0) or max(1, min(4, (os.cpu_count() or 2) - 1))
    body = {
        "model": model,
        "system": SYSTEM,
        "prompt": build_prompt(actionables, kpis, int(cfg.get("max_actions", 8))),
        "format": SCHEMA,
        "stream": False,
        "keep_alive": 0,
        "options": {"num_ctx": int(cfg.get("num_ctx", 4096)), "num_predict": int(cfg.get("num_predict", 900)),
                    "num_thread": threads, "temperature": float(cfg.get("temperature", 0.2)), "seed": 42},
    }
    started = time.monotonic()
    try:
        answer = client.request("POST", "/api/generate", body)
        parsed = validate(json.loads(answer.get("response") or "{}"), {a["id"] for a in actionables})
    except (HTTPError, ValueError) as exc:
        status["warnings"].append(f"IA: respuesta no válida de {model} ({exc}); se usa el resumen por reglas.")
        return result
    result.update(parsed)
    result.update({"source": "ia-local", "model": model,
                   "duration_s": round(time.monotonic() - started, 1),
                   "generated_at": time.strftime("%Y-%m-%dT%H:%M:%S%z")})
    log.info("AI summary generated with %s in %ss", model, result["duration_s"])
    return result
