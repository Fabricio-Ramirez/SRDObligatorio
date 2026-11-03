"""Command line: python3 -m vulnmgmt {run,demo} --config /etc/vulnmgmt/config.json"""

import argparse
import json
import logging
import os
import sys
import time

from . import __version__, ai, demo, intel, prioritize, publish, wazuh
from .httpclient import HTTPError

log = logging.getLogger("vulnmgmt")


def load_config(path):
    with open(path, encoding="utf-8") as fh:
        cfg = json.load(fh)
    cfg.setdefault("intel", {}).setdefault("cache_dir", os.path.join(cfg["output"]["state_dir"], "intel"))
    return cfg


def run(cfg, use_demo=False):
    status = {"warnings": [], "kev": None, "epss": None}
    out = cfg["output"]
    os.makedirs(cfg["intel"]["cache_dir"], exist_ok=True)
    # The demo keeps its own SLA state so it never marks real tasks as resolved.
    state_name = "demo-state.json" if use_demo else "state.json"
    state = publish.read_json(os.path.join(out["state_dir"], state_name), {})
    previous_ids = set(state.get("actionables", {}))

    if use_demo:
        findings, agents = demo.findings(), dict(demo.DEMO_AGENTS)
        kev, epss = dict(demo.DEMO_KEV), dict(demo.DEMO_EPSS)
        status["kev"] = {"version": "demo", "count": len(kev)}
        status["epss"] = {"scored": len(epss), "requested": len(epss)}
    else:
        # A failed collection must stop the run: publishing an empty result
        # would mark every open task as resolved.
        findings = wazuh.fetch_vulnerabilities(cfg["indexer"])
        agents = {}
        if cfg.get("api", {}).get("enabled") and cfg["api"].get("password"):
            try:
                agents = wazuh.fetch_agents(cfg["api"])
            except (HTTPError, KeyError) as exc:
                status["warnings"].append(f"API de Wazuh no disponible ({exc}); sin datos de cobertura de agentes.")
        kev, epss = {}, {}
        if cfg["intel"].get("enabled", True):
            kev = intel.load_kev(cfg["intel"], status)
            epss = intel.load_epss(cfg["intel"], {f["vulnerability.id"] for f in findings
                                                  if f.get("vulnerability.id")}, status)

    actionables, hosts, kpis = prioritize.analyse(findings, kev, epss, agents, cfg.get("scoring"), state)
    ai_section = ai.analyse(cfg.get("ai", {}), actionables, kpis, status)
    report = {
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "engine_version": __version__,
        "source": "demo" if use_demo else "wazuh",
        "kpis": kpis,
        "actionables": actionables,
        "hosts": hosts,
        "ai": ai_section,
        "intel": {"kev": status["kev"], "epss": status["epss"]},
        "scoring": prioritize.merge_scoring(cfg.get("scoring")),
        "warnings": status["warnings"],
    }
    publish.write_outputs(out, report, state, state_name)
    sent = publish.siem_events(out, report, previous_ids) if not use_demo else 0
    log.info("Report: %d findings, %d actions (P1=%d P2=%d), AI=%s, SIEM events=%d",
             kpis["findings"], len(actionables), kpis["actions"]["P1"], kpis["actions"]["P2"],
             ai_section["source"], sent)
    for warning in status["warnings"]:
        log.warning(warning)
    return report


def main(argv=None):
    parser = argparse.ArgumentParser(prog="vulnmgmt", description="Gestión de vulnerabilidades para Wazuh")
    parser.add_argument("command", choices=["run", "demo"],
                        help="run: datos reales de Wazuh; demo: datos sintéticos de demostración")
    parser.add_argument("--config", default="/etc/vulnmgmt/config.json")
    parser.add_argument("-v", "--verbose", action="store_true")
    args = parser.parse_args(argv)
    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO,
                        format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    try:
        run(load_config(args.config), use_demo=args.command == "demo")
    except (HTTPError, OSError, KeyError, ValueError) as exc:
        log.error("Run failed: %s", exc)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
