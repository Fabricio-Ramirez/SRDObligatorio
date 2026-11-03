"""Risk scoring and grouping of findings into actionable remediation tasks.

The scoring is deterministic and explainable (every task carries the reasons
behind its priority). The local AI never changes priorities: it only writes
text on top of these results.

risk (0-100) = min(100, (CVSS * w_cvss + EPSS * w_epss + KEV * w_kev) * criticality)
with the default weights CVSS 6 (max 60), EPSS 25 (probability 0-1) and KEV 15.
Priority: P1 if the CVE is in CISA KEV or risk >= 75, P2 >= 55, P3 >= 35, else P4.
"""

import datetime as dt
import hashlib
import re

SEVERITY_ORDER = ["Critical", "High", "Medium", "Low", "Unknown"]
# Lower bound of each CVSS v3 severity range, used when Wazuh has no score.
SEVERITY_FALLBACK_SCORE = {"Critical": 9.0, "High": 7.0, "Medium": 4.0, "Low": 0.1}
PRIORITIES = ["P1", "P2", "P3", "P4"]
REBOOT_PACKAGES = re.compile(
    r"^(kernel|kernel-core|kernel-modules.*|linux-image.*|glibc|systemd|openssl-libs|libc6|dbus)$")
DEFAULT_SCORING = {
    "weights": {"cvss": 6, "epss": 25, "kev": 15},
    "thresholds": {"P1": 75, "P2": 55, "P3": 35},
    "sla_days": {"P1": 7, "P2": 30, "P3": 90, "P4": 180},
    "criticality": {"default": "media", "factors": {"alta": 1.2, "media": 1.0, "baja": 0.8},
                    "hosts": {}, "groups": {}},
}


def merge_scoring(cfg):
    merged = {k: (dict(v) if isinstance(v, dict) else v) for k, v in DEFAULT_SCORING.items()}
    for key, value in (cfg or {}).items():
        if isinstance(value, dict) and isinstance(merged.get(key), dict):
            merged[key].update(value)
        else:
            merged[key] = value
    return merged


def normalise_severity(value):
    value = (value or "").strip().capitalize()
    return value if value in SEVERITY_FALLBACK_SCORE else "Unknown"


def parse_condition(condition):
    """Interpret Wazuh's vulnerability.scanner.condition.

    Returns (fix_status, version): "fixed" with the first fixed version when
    the condition is "Package less than X"; "no_fix" for "Package default
    status" (no patched version known); "unknown" otherwise.
    """
    condition = (condition or "").strip()
    match = re.match(r"^Package less than (\S+)$", condition)
    if match:
        return "fixed", match.group(1)
    if condition == "Package default status":
        return "no_fix", None
    return "unknown", None


def _version_key(version):
    """Rough version ordering (good enough to pick the highest fixed version)."""
    return [int(p) if p.isdigit() else p for p in re.split(r"[.\-+:~_]", version or "") if p != ""]


def _max_version(versions):
    best = None
    for version in versions:
        if version and (best is None or _cmp_versions(version, best) > 0):
            best = version
    return best


def _cmp_versions(a, b):
    for x, y in zip(_version_key(a), _version_key(b)):
        if x == y:
            continue
        if isinstance(x, int) and isinstance(y, int):
            return 1 if x > y else -1
        return 1 if str(x) > str(y) else -1
    return (len(_version_key(a)) > len(_version_key(b))) - (len(_version_key(a)) < len(_version_key(b)))


def host_criticality(agent_name, groups, crit_cfg):
    if agent_name in crit_cfg.get("hosts", {}):
        return crit_cfg["hosts"][agent_name]
    levels = list(crit_cfg.get("factors", {}))
    found = [crit_cfg["groups"][g] for g in groups or [] if g in crit_cfg.get("groups", {})]
    if found:  # the most critical group wins
        return min(found, key=lambda lvl: levels.index(lvl) if lvl in levels else len(levels))
    return crit_cfg.get("default", "media")


def score(cvss, epss, kev, factor, scoring):
    w = scoring["weights"]
    raw = (cvss or 0.0) * w["cvss"] + (epss or 0.0) * w["epss"] + (w["kev"] if kev else 0)
    return round(min(100.0, raw * factor), 1)


def priority_for(risk, kev, scoring):
    t = scoring["thresholds"]
    if kev or risk >= t["P1"]:
        return "P1"
    if risk >= t["P2"]:
        return "P2"
    if risk >= t["P3"]:
        return "P3"
    return "P4"


def commands_for(package, pkg_type, fixed_version):
    """Remediation and verification commands for the package manager in use."""
    if pkg_type == "rpm":
        return {"remediation": f"sudo dnf upgrade -y {package}",
                "verification": f"rpm -q {package}" + (f"  # esperado >= {fixed_version}" if fixed_version else "")}
    if pkg_type == "deb":
        return {"remediation": f"sudo apt-get update && sudo apt-get install --only-upgrade -y {package}",
                "verification": f"dpkg -l {package}" + (f"  # esperado >= {fixed_version}" if fixed_version else "")}
    if pkg_type == "pypi":
        return {"remediation": f"pip install --upgrade '{package}" + (f">={fixed_version}'" if fixed_version else "'"),
                "verification": f"pip show {package}"}
    if pkg_type == "npm":
        return {"remediation": f"npm install {package}@" + (fixed_version or "latest"),
                "verification": f"npm ls {package}"}
    if pkg_type == "win":
        return {"remediation": "Instalar la actualización del proveedor (Windows Update / WSUS / instalador oficial)",
                "verification": "Revisar la versión instalada en 'Aplicaciones y características'"}
    return {"remediation": f"Actualizar {package} con el gestor de paquetes del sistema",
            "verification": f"Comprobar la versión instalada de {package}"}


def analyse(findings, kev, epss, agents, scoring_cfg, state, today=None):
    """Score findings and build actionables, hosts and KPIs.

    state = {"actionables": {id: {"first_seen": "YYYY-MM-DD"}}} is updated in place
    so SLA due dates survive between runs.
    """
    scoring = merge_scoring(scoring_cfg)
    crit_cfg = scoring["criticality"]
    factors = crit_cfg.get("factors", {})
    today = today or dt.date.today()
    agents = agents or {}

    groups = {}
    hosts = {}
    for f in findings:
        cve = f.get("vulnerability.id") or "-"
        agent_id = f.get("agent.id") or "?"
        agent_name = f.get("agent.name") or agent_id
        agent_info = agents.get(agent_id, {})
        crit = host_criticality(agent_name, agent_info.get("groups"), crit_cfg)
        severity = normalise_severity(f.get("vulnerability.severity"))
        base = f.get("vulnerability.score.base")
        cvss = float(base) if isinstance(base, (int, float)) and base > 0 else \
            SEVERITY_FALLBACK_SCORE.get(severity, 0.0)
        e = epss.get(cve, {})
        in_kev = cve in kev
        risk = score(cvss, e.get("epss"), in_kev, factors.get(crit, 1.0), scoring)
        prio = priority_for(risk, in_kev, scoring)
        fix_status, fixed_version = parse_condition(f.get("vulnerability.scanner.condition"))
        package = f.get("package.name") or "?"
        pkg_type = (f.get("package.type") or "").lower()

        key = (package, pkg_type, "no_fix" if fix_status == "no_fix" else "update")
        g = groups.setdefault(key, {"package": package, "type": pkg_type, "fix_status": set(),
                                    "fixed_versions": set(), "versions": set(), "hosts": {},
                                    "cves": {}, "risk": 0.0, "priority": "P4"})
        g["fix_status"].add(fix_status)
        if fixed_version:
            g["fixed_versions"].add(fixed_version)
        if f.get("package.version"):
            g["versions"].add(f["package.version"])
        g["hosts"][agent_id] = {"id": agent_id, "name": agent_name, "criticality": crit,
                                "os": f.get("host.os.full") or f.get("host.os.name") or ""}
        cve_entry = g["cves"].get(cve)
        if cve_entry is None or risk > cve_entry["risk"]:
            k = kev.get(cve, {})
            g["cves"][cve] = {
                "id": cve, "severity": severity, "cvss": round(cvss, 1),
                "cvss_from_severity": not (isinstance(base, (int, float)) and base > 0),
                "epss": e.get("epss"), "epss_percentile": e.get("percentile"),
                "kev": in_kev, "kev_due": k.get("dueDate"),
                "kev_ransomware": k.get("knownRansomwareCampaignUse") == "Known",
                "risk": risk, "priority": prio,
                "under_evaluation": bool(f.get("vulnerability.under_evaluation")),
                "reference": f.get("vulnerability.reference"),
            }
        g["risk"] = max(g["risk"], risk)
        if PRIORITIES.index(prio) < PRIORITIES.index(g["priority"]):
            g["priority"] = prio

        h = hosts.setdefault(agent_id, {"id": agent_id, "name": agent_name, "criticality": crit,
                                        "os": f.get("host.os.full") or f.get("host.os.name") or "",
                                        "severity": {s: 0 for s in SEVERITY_ORDER},
                                        "vulnerabilities": 0, "kev": 0, "max_risk": 0.0,
                                        "status": agent_info.get("status"), "_cves": set()})
        if cve not in h["_cves"]:
            h["_cves"].add(cve)
            h["vulnerabilities"] += 1
            h["severity"][severity] += 1
            h["kev"] += int(in_kev)
        h["max_risk"] = max(h["max_risk"], risk)

    known = state.setdefault("actionables", {})
    actionables = []
    for (package, pkg_type, kind), g in groups.items():
        ident = "VM-" + hashlib.sha1(f"{package}|{pkg_type}|{kind}".encode()).hexdigest()[:8]
        record = known.setdefault(ident, {"first_seen": today.isoformat()})
        first_seen = record["first_seen"]
        previous_priority = record.get("priority")
        record["priority"] = g["priority"]
        cves = sorted(g["cves"].values(), key=lambda c: (-c["risk"], c["id"]))
        sla = scoring["sla_days"][g["priority"]]
        due = dt.date.fromisoformat(first_seen) + dt.timedelta(days=sla)
        # CISA's dueDate (set for US federal agencies) only tightens the SLA when
        # it is still ahead of our first detection; past dates are informative.
        kev_dues = [dt.date.fromisoformat(c["kev_due"]) for c in cves if c["kev"] and c["kev_due"]]
        kev_dues = [d for d in kev_dues if d >= dt.date.fromisoformat(first_seen)]
        if kev_dues and min(kev_dues) < due:
            due = min(kev_dues)
        fixed_version = _max_version(g["fixed_versions"])
        if kind == "no_fix":
            action = "mitigar"
        elif "fixed" in g["fix_status"]:
            action = "actualizar"
        else:
            action = "revisar"
        reasons = []
        top = cves[0]
        reasons.append(f"CVSS {top['cvss']}" + (" (estimado por severidad)" if top["cvss_from_severity"] else ""))
        if top["epss"] is not None:
            reasons.append(f"EPSS {top['epss'] * 100:.1f}% de probabilidad de explotación en 30 días")
        kev_count = sum(1 for c in cves if c["kev"])
        if kev_count:
            reasons.append(f"{kev_count} CVE en el catálogo KEV de CISA (explotación activa)")
        if any(c["kev_ransomware"] for c in cves):
            reasons.append("usado en campañas de ransomware")
        high_crit = [h["name"] for h in g["hosts"].values() if h["criticality"] == "alta"]
        if high_crit:
            reasons.append("servidores de criticidad alta: " + ", ".join(sorted(high_crit)))
        actionables.append({
            "id": ident,
            "priority": g["priority"],
            "risk": g["risk"],
            "action": action,
            "package": package,
            "package_type": pkg_type or "desconocido",
            "installed_versions": sorted(g["versions"]),
            "fixed_version": fixed_version,
            "hosts": sorted(g["hosts"].values(), key=lambda h: h["name"]),
            "cves": cves,
            "cve_count": len(cves),
            "kev_count": kev_count,
            "max_cvss": max(c["cvss"] for c in cves),
            "max_epss": max((c["epss"] for c in cves if c["epss"] is not None), default=None),
            "reboot_required": bool(REBOOT_PACKAGES.match(package)),
            "commands": commands_for(package, pkg_type, fixed_version) if action != "mitigar" else {
                "remediation": "Sin versión corregida conocida: aplicar mitigaciones (deshabilitar el "
                               "servicio o módulo afectado, restringir acceso con firewall, monitorear) "
                               "y revisar el aviso del proveedor.",
                "verification": f"dnf updateinfo list --cve {top['id']}" if pkg_type == "rpm" else
                                f"Revisar periódicamente el aviso de {top['id']}"},
            "first_seen": first_seen,
            "previous_priority": previous_priority,
            "due_date": due.isoformat(),
            "overdue": due < today,
            "reasons": reasons,
        })
    actionables.sort(key=lambda a: (PRIORITIES.index(a["priority"]), -a["risk"], a["package"]))

    current = {a["id"] for a in actionables}
    resolved = state.setdefault("resolved", [])
    for ident in [i for i in known if i not in current]:
        resolved.append({"id": ident, "first_seen": known[ident]["first_seen"],
                         "resolved": today.isoformat()})
        del known[ident]
    state["resolved"] = resolved[-500:]

    for agent_id, info in agents.items():  # coverage: agents without findings
        if agent_id not in hosts:
            hosts[agent_id] = {"id": agent_id, "name": info.get("name"),
                               "criticality": host_criticality(info.get("name"), info.get("groups"), crit_cfg),
                               "os": info.get("os", ""), "severity": {s: 0 for s in SEVERITY_ORDER},
                               "vulnerabilities": 0, "kev": 0, "max_risk": 0.0,
                               "status": info.get("status"), "_cves": set()}
    host_list = []
    for h in hosts.values():
        h.pop("_cves", None)
        h["actions"] = sum(1 for a in actionables if any(x["id"] == h["id"] for x in a["hosts"]))
        host_list.append(h)
    host_list.sort(key=lambda h: (-h["max_risk"], h["name"] or ""))

    unique_cves = {}
    for a in actionables:
        for c in a["cves"]:
            unique_cves[c["id"]] = c
    kpis = {
        "findings": len(findings),
        "unique_cves": len(unique_cves),
        "hosts_affected": sum(1 for h in host_list if h["vulnerabilities"]),
        "hosts_total": len(host_list),
        "severity": {s: sum(1 for c in unique_cves.values() if c["severity"] == s) for s in SEVERITY_ORDER},
        "kev": sum(1 for c in unique_cves.values() if c["kev"]),
        "actions": {p: sum(1 for a in actionables if a["priority"] == p) for p in PRIORITIES},
        "overdue": sum(1 for a in actionables if a["overdue"]),
        "no_fix": sum(1 for a in actionables if a["action"] == "mitigar"),
        "resolved_30d": sum(1 for r in state["resolved"]
                            if dt.date.fromisoformat(r["resolved"]) >= today - dt.timedelta(days=30)),
    }
    return actionables, host_list, kpis
