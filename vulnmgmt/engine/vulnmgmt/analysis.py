"""Deterministic summary of the report, written for the dashboard.

This replaces the local LLM (Ollama) that earlier versions used for this text.
The reasons are the ones that matter on a small VM shared with Wazuh:

- no model to load, so no 1-2 GB of RAM and no minutes of CPU inference per run;
- the same input always produces the same text, which can be reviewed and
  defended line by line;
- nothing can be invented: every number and every package name printed here
  comes from prioritize.py.

The prioritised work plan with the proposed solution for each action is built
by the n8n workflow (vulnmgmt/n8n/priorizar-soluciones.js), which reads this
same report. This module only writes the short summary shown in the panel.
"""


def _phrase(count, one, many):
    """Pick the singular or plural wording and fill in the number.

    Both templates take {n}, so Spanish agreement stays readable:
        _phrase(1, "{n} acción está vencida", "{n} acciones están vencidas")
    """
    return (one if count == 1 else many).format(n=count)


def summarise(actionables, kpis):
    """Return the "analysis" section of the report.

    Pure function of the prioritised results: no I/O, no configuration, and it
    never changes a priority or a deadline.
    """
    counts = kpis["actions"]
    total = sum(counts.values())
    parts = [
        "Se detectaron "
        + _phrase(kpis["unique_cves"], "{n} vulnerabilidad única", "{n} vulnerabilidades únicas")
        + " en " + _phrase(kpis["hosts_affected"], "{n} servidor", "{n} servidores")
        + ", agrupadas en " + _phrase(total, "{n} acción", "{n} acciones") + "."
    ]
    if counts["P1"]:
        parts.append(_phrase(counts["P1"],
                             "Hay {n} acción P1 de atención inmediata.",
                             "Hay {n} acciones P1 de atención inmediata."))
    if kpis["kev"]:
        parts.append(_phrase(kpis["kev"],
                             "{n} vulnerabilidad figura en el catálogo KEV de CISA (explotación activa).",
                             "{n} vulnerabilidades figuran en el catálogo KEV de CISA (explotación activa)."))
    if kpis["overdue"]:
        parts.append(_phrase(kpis["overdue"],
                             "{n} acción está vencida respecto de su SLA.",
                             "{n} acciones están vencidas respecto de su SLA."))
    if kpis["no_fix"]:
        parts.append(_phrase(kpis["no_fix"],
                             "{n} acción no tiene versión corregida y requiere mitigación.",
                             "{n} acciones no tienen versión corregida y requieren mitigación."))
    if not total:
        parts.append("No hay acciones de remediación pendientes.")

    risks = [f"{a['priority']} {a['package']}: {', '.join(a['reasons'][:2])}" for a in actionables[:4]]
    reboot = [a["package"] for a in actionables[:10] if a["reboot_required"]]
    window = ("Aplicar primero las P1 en una ventana de emergencia; agrupar P2 en la ventana semanal"
              + (f"; requieren reinicio: {', '.join(reboot)}" if reboot else "") + ".")
    return {
        "source": "reglas",
        "summary": " ".join(parts),
        "risks": risks,
        "maintenance_window": window,
    }
