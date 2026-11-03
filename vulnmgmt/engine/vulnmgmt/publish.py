"""Write the dashboard data, CSV export, history, SLA state and SIEM events."""

import csv
import io
import json
import os
import time

CSV_FIELDS = ["id", "priority", "risk", "action", "package", "package_type", "fixed_version",
              "hosts", "cves", "kev_count", "max_cvss", "max_epss", "reboot_required",
              "first_seen", "due_date", "overdue", "remediation", "verification", "ai_note"]


def atomic_write(path, text, mode=0o644):
    tmp = f"{path}.tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        fh.write(text)
    os.chmod(tmp, mode)
    os.replace(tmp, path)


def read_json(path, default):
    try:
        with open(path, encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, ValueError):
        return default


def _cell(value):
    """Neutralise spreadsheet formulas (CSV injection)."""
    text = "" if value is None else str(value)
    return "'" + text if text[:1] in ("=", "+", "-", "@", "\t", "\r") else text


def actionables_csv(actionables, notes):
    buf = io.StringIO()
    writer = csv.writer(buf, delimiter=";")
    writer.writerow(CSV_FIELDS)
    for a in actionables:
        row = {
            **a,
            "hosts": ", ".join(h["name"] for h in a["hosts"]),
            "cves": ", ".join(c["id"] for c in a["cves"]),
            "remediation": a["commands"]["remediation"],
            "verification": a["commands"]["verification"],
            "ai_note": notes.get(a["id"], ""),
        }
        writer.writerow([_cell(row.get(f)) for f in CSV_FIELDS])
    return "﻿" + buf.getvalue()  # BOM so Excel opens the accents correctly


def write_outputs(cfg, report, state, state_name="state.json"):
    out = cfg["web_data_dir"]
    state_dir = cfg["state_dir"]
    os.makedirs(os.path.join(out, "reports"), exist_ok=True)
    os.makedirs(state_dir, exist_ok=True)

    day = report["generated_at"][:10]
    payload = json.dumps(report, ensure_ascii=False, indent=1)
    atomic_write(os.path.join(out, "latest.json"), payload)
    atomic_write(os.path.join(out, "reports", f"{day}.json"), payload)
    atomic_write(os.path.join(out, "actionables.csv"),
                 actionables_csv(report["actionables"], report["ai"].get("notes", {})))

    reports = sorted(f for f in os.listdir(os.path.join(out, "reports")) if f.endswith(".json"))
    keep = int(cfg.get("history_runs", 90))
    for old in reports[:-keep] if keep > 0 else []:
        os.remove(os.path.join(out, "reports", old))

    history = [h for h in read_json(os.path.join(out, "history.json"), []) if h.get("date") != day]
    k = report["kpis"]
    history.append({"date": day, "unique_cves": k["unique_cves"], "kev": k["kev"],
                    "hosts_affected": k["hosts_affected"], "severity": k["severity"],
                    "actions": k["actions"], "overdue": k["overdue"], "resolved_30d": k["resolved_30d"]})
    atomic_write(os.path.join(out, "history.json"), json.dumps(history[-keep:], ensure_ascii=False))
    atomic_write(os.path.join(state_dir, state_name), json.dumps(state, ensure_ascii=False), 0o600)


def siem_events(cfg, report, previous_ids):
    """Append JSON lines read by the Wazuh manager (localfile, log_format json).

    One summary per run, plus one event per high-priority task that is new,
    escalated (its priority went up) or overdue, so the SIEM alerts without
    repeating itself every day.
    """
    path = cfg.get("wazuh_events_log")
    if not path:
        return 0
    wanted = set(cfg.get("wazuh_event_priorities", ["P1", "P2"]))
    now = time.strftime("%Y-%m-%dT%H:%M:%S%z")
    k = report["kpis"]
    lines = [{"vulnmgmt": {"event": "summary", "timestamp": now, "unique_cves": k["unique_cves"],
                           "kev": k["kev"], "p1": k["actions"]["P1"], "p2": k["actions"]["P2"],
                           "overdue": k["overdue"], "ai_source": report["ai"]["source"]}}]
    for a in report["actionables"]:
        if a["priority"] not in wanted:
            continue
        prev = a.get("previous_priority")
        if a["id"] not in previous_ids:
            status = "new"
        elif a["overdue"]:
            status = "overdue"
        elif prev and prev > a["priority"]:  # "P3" > "P1": the priority went up
            status = "escalated"
        else:
            status = None
        if status is None:
            continue
        lines.append({"vulnmgmt": {
            "event": "actionable", "status": status, "timestamp": now, "id": a["id"],
            "priority": a["priority"], "risk": a["risk"], "action": a["action"],
            "package": a["package"], "fixed_version": a["fixed_version"] or "",
            "kev": a["kev_count"] > 0, "cves": ",".join(c["id"] for c in a["cves"][:10]),
            "hosts": ",".join(h["name"] for h in a["hosts"][:20]), "due_date": a["due_date"]}})
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "a", encoding="utf-8") as fh:
        for line in lines:
            fh.write(json.dumps(line, ensure_ascii=False, separators=(",", ":")) + "\n")
    return len(lines)
