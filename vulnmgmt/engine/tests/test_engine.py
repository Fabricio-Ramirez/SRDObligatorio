"""Unit tests (standard library only): python3 -m unittest discover -s tests"""

import datetime as dt
import json
import os
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer

from vulnmgmt import ai, demo, intel, prioritize, publish, wazuh


class FakeServer:
    """Tiny HTTP server answering from a routing function (method, path, body) -> (code, obj)."""

    def __init__(self, route):
        outer = self
        self.requests = []

        class Handler(BaseHTTPRequestHandler):
            def _do(self):
                length = int(self.headers.get("Content-Length") or 0)
                body = json.loads(self.rfile.read(length) or b"null") if length else None
                outer.requests.append((self.command, self.path, body, dict(self.headers)))
                code, obj = route(self.command, self.path, body)
                data = json.dumps(obj).encode()
                self.send_response(code)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            do_GET = do_POST = do_DELETE = _do

            def log_message(self, *args):
                pass

        self.httpd = HTTPServer(("127.0.0.1", 0), Handler)
        self.url = f"http://127.0.0.1:{self.httpd.server_address[1]}"
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()

    def close(self):
        self.httpd.shutdown()


def finding(cve="CVE-2024-0001", sev="High", cvss=7.5, pkg="openssl", agent=("001", "srv-a"),
            cond="Package less than 3.0.7", ptype="rpm"):
    return {"agent.id": agent[0], "agent.name": agent[1], "host.os.full": "Rocky Linux 9.6",
            "package.name": pkg, "package.version": "3.0.1", "package.type": ptype,
            "vulnerability.id": cve, "vulnerability.severity": sev, "vulnerability.score.base": cvss,
            "vulnerability.scanner.condition": cond, "vulnerability.under_evaluation": False}


class ScoringTests(unittest.TestCase):
    def test_condition_parsing(self):
        self.assertEqual(prioritize.parse_condition("Package less than 1.2.3-4.el9"), ("fixed", "1.2.3-4.el9"))
        self.assertEqual(prioritize.parse_condition("Package default status"), ("no_fix", None))
        self.assertEqual(prioritize.parse_condition("Package less than or equal to 2.0"), ("unknown", None))
        self.assertEqual(prioritize.parse_condition(None), ("unknown", None))

    def test_priorities(self):
        s = prioritize.merge_scoring({})
        self.assertEqual(prioritize.priority_for(10, True, s), "P1")      # KEV always P1
        self.assertEqual(prioritize.priority_for(80, False, s), "P1")
        self.assertEqual(prioritize.priority_for(60, False, s), "P2")
        self.assertEqual(prioritize.priority_for(40, False, s), "P3")
        self.assertEqual(prioritize.priority_for(10, False, s), "P4")
        self.assertEqual(prioritize.score(10, 1, True, 1.2, s), 100.0)    # capped
        self.assertEqual(prioritize.score(9.8, 0.0, False, 1.0, s), 58.8)

    def test_grouping_sla_and_resolution(self):
        state = {}
        day1 = dt.date(2026, 1, 1)
        findings = [finding(), finding(cve="CVE-2024-0002", cvss=9.8, agent=("002", "srv-b")),
                    finding(pkg="less", cond="Package default status", cvss=5.0, sev="Medium")]
        acts, hosts, kpis = prioritize.analyse(findings, {}, {}, {}, None, state, today=day1)
        self.assertEqual(len(acts), 2)
        ssl = next(a for a in acts if a["package"] == "openssl")
        self.assertEqual(ssl["fixed_version"], "3.0.7")
        self.assertEqual(ssl["priority"], "P2")                            # 9.8 * 6 = 58.8
        self.assertEqual(ssl["due_date"], "2026-01-31")                    # 30-day SLA
        self.assertEqual({h["name"] for h in ssl["hosts"]}, {"srv-a", "srv-b"})
        self.assertEqual(next(a for a in acts if a["package"] == "less")["action"], "mitigar")
        self.assertEqual(kpis["unique_cves"], 2)
        # Later run: first_seen is kept, openssl disappears -> resolved
        day2 = dt.date(2026, 2, 15)
        acts2, _, kpis2 = prioritize.analyse(findings[2:], {}, {}, {}, None, state, today=day2)
        self.assertEqual(acts2[0]["first_seen"], "2026-01-01")
        self.assertEqual(acts2[0]["previous_priority"], "P4")
        self.assertEqual(kpis2["resolved_30d"], 1)
        self.assertEqual(state["resolved"][0]["id"], ssl["id"])

    def test_kev_due_date_only_when_in_future(self):
        kev = {"CVE-2024-0001": {"cveID": "CVE-2024-0001", "dueDate": "2020-01-01"}}
        acts, _, _ = prioritize.analyse([finding()], kev, {}, {}, None, {}, today=dt.date(2026, 1, 1))
        self.assertEqual(acts[0]["priority"], "P1")
        self.assertEqual(acts[0]["due_date"], "2026-01-08")               # 7-day SLA, not 2020
        self.assertFalse(acts[0]["overdue"])

    def test_criticality(self):
        cfg = {"criticality": {"hosts": {"srv-a": "alta"}, "groups": {"dmz": "baja"}}}
        agents = {"002": {"name": "srv-b", "groups": ["dmz"]}}
        acts, hosts, _ = prioritize.analyse([finding(), finding(agent=("002", "srv-b"))], {}, {}, agents, cfg, {})
        crit = {h["name"]: h["criticality"] for h in hosts}
        self.assertEqual(crit, {"srv-a": "alta", "srv-b": "baja"})

    def test_demo_dataset(self):
        acts, hosts, kpis = prioritize.analyse(demo.findings(), demo.DEMO_KEV, demo.DEMO_EPSS,
                                               demo.DEMO_AGENTS, None, {})
        self.assertEqual(kpis["kev"], 4)
        self.assertTrue(all(a["priority"] == "P1" for a in acts if a["kev_count"]))
        self.assertIn("srv-backup", [h["name"] for h in hosts])            # agent without findings


class PublishTests(unittest.TestCase):
    def test_csv_injection_is_neutralised(self):
        acts, _, _ = prioritize.analyse([finding(pkg="=cmd|calc")], {}, {}, {}, None, {})
        text = publish.actionables_csv(acts, {})
        self.assertIn(";'=cmd|calc;", text)

    def test_outputs_and_siem_events(self):
        with tempfile.TemporaryDirectory() as tmp:
            cfg = {"web_data_dir": os.path.join(tmp, "www"), "state_dir": os.path.join(tmp, "st"),
                   "wazuh_events_log": os.path.join(tmp, "log", "events.json")}
            state = {}
            acts, hosts, kpis = prioritize.analyse(demo.findings(), demo.DEMO_KEV, demo.DEMO_EPSS,
                                                   {}, None, state)
            report = {"generated_at": "2026-01-01T00:00:00", "kpis": kpis, "actionables": acts,
                      "hosts": hosts, "ai": {"source": "reglas", "notes": {}}}
            publish.write_outputs(cfg, report, state)
            for name in ("latest.json", "history.json", "actionables.csv", "reports/2026-01-01.json"):
                self.assertTrue(os.path.exists(os.path.join(cfg["web_data_dir"], name)), name)
            sent = publish.siem_events(cfg, report, previous_ids=set())
            self.assertEqual(sent, 1 + kpis["actions"]["P1"] + kpis["actions"]["P2"])
            sent_again = publish.siem_events(cfg, report, previous_ids={a["id"] for a in acts})
            self.assertEqual(sent_again, 1)                                  # only the summary
            acts[0]["previous_priority"] = "P3"                              # escalated P3 -> P1
            self.assertEqual(publish.siem_events(cfg, report, previous_ids={a["id"] for a in acts}), 2)
            with open(cfg["wazuh_events_log"], encoding="utf-8") as fh:
                first = json.loads(fh.readline())
            self.assertEqual(first["vulnmgmt"]["event"], "summary")


class AITests(unittest.TestCase):
    def setUp(self):
        self.acts, _, self.kpis = prioritize.analyse(demo.findings(), demo.DEMO_KEV, demo.DEMO_EPSS,
                                                     {}, None, {})

    def test_choose_model_by_memory(self):
        models = [{"name": "big", "min_free_mb": 1800}, {"name": "small", "min_free_mb": 900}]
        self.assertEqual(ai.choose_model(models, {"big", "small"}, 4000), "big")
        self.assertEqual(ai.choose_model(models, {"big", "small"}, 1000), "small")
        self.assertIsNone(ai.choose_model(models, {"big", "small"}, 500))
        self.assertEqual(ai.choose_model(models, {"small"}, 4000), "small")

    def test_validate_drops_unknown_ids_and_bounds_text(self):
        out = ai.validate({"resumen_ejecutivo": "x" * 5000, "riesgos_clave": ["a"],
                           "acciones": [{"id": "VM-1", "nota": "ok"}, {"id": "BAD", "nota": "no"}],
                           "ventana_mantenimiento": "w"}, {"VM-1"})
        self.assertEqual(len(out["summary"]), 1500)
        self.assertEqual(out["notes"], {"VM-1": "ok"})
        with self.assertRaises(ValueError):
            ai.validate({"resumen_ejecutivo": ""}, set())

    def test_ollama_round_trip(self):
        first_id = self.acts[0]["id"]
        answer = {"resumen_ejecutivo": "Resumen.", "riesgos_clave": ["r1"],
                  "acciones": [{"id": first_id, "nota": "Actualizar primero."}],
                  "ventana_mantenimiento": "Domingo 02:00."}

        def route(method, path, body):
            if path == "/api/tags":
                return 200, {"models": [{"name": "qwen2.5:1.5b"}, {"name": "qwen2.5:0.5b"}]}
            if path == "/api/generate":
                return 200, {"model": body["model"], "response": json.dumps(answer), "done": True}
            return 404, {}

        srv = FakeServer(route)
        try:
            status = {"warnings": []}
            cfg = {"url": srv.url, "models": [{"name": "qwen2.5:1.5b", "min_free_mb": 0}]}
            out = ai.analyse(cfg, self.acts, self.kpis, status)
        finally:
            srv.close()
        self.assertEqual(out["source"], "ia-local")
        self.assertEqual(out["notes"], {first_id: "Actualizar primero."})
        body = srv.requests[-1][2]
        self.assertEqual(body["keep_alive"], 0)                              # unloads the model
        self.assertFalse(body["stream"])
        self.assertEqual(body["format"]["required"], ai.SCHEMA["required"])
        self.assertNotIn("srv-backup", body["prompt"])                       # only task data is sent

    def test_fallback_on_bad_answer(self):
        def route(method, path, body):
            if path == "/api/tags":
                return 200, {"models": [{"name": "m"}]}
            return 200, {"response": "not json"}

        srv = FakeServer(route)
        try:
            status = {"warnings": []}
            out = ai.analyse({"url": srv.url, "models": [{"name": "m"}]}, self.acts, self.kpis, status)
        finally:
            srv.close()
        self.assertEqual(out["source"], "reglas")
        self.assertTrue(out["summary"])
        self.assertTrue(status["warnings"])


class SourceTests(unittest.TestCase):
    def test_indexer_scroll_and_api(self):
        doc = {"agent": {"id": "001", "name": "srv-a"}, "package": {"name": "curl", "type": "rpm"},
               "vulnerability": {"id": "CVE-1", "severity": "High", "score": {"base": 7.5}}}
        pages = [[{"_source": doc}, {"_source": doc}], [{"_source": doc}], []]

        def route(method, path, body):
            if path.startswith("/wazuh-states-vulnerabilities-*/_search"):
                return 200, {"_scroll_id": "s1", "hits": {"hits": pages[0]}}
            if path == "/_search/scroll" and method == "POST":
                pages.pop(0)
                return 200, {"_scroll_id": "s1", "hits": {"hits": pages[0]}}
            if path == "/_search/scroll" and method == "DELETE":
                return 200, {"succeeded": True}
            if path == "/security/user/authenticate":
                return 200, {"data": {"token": "T"}}
            if path.startswith("/agents"):
                return 200, {"data": {"affected_items": [{"id": "001", "name": "srv-a", "status": "active",
                                                          "os": {"name": "Rocky Linux", "version": "9.6"},
                                                          "group": ["default"]}],
                                      "total_affected_items": 1}}
            return 404, {}

        srv = FakeServer(route)
        try:
            found = wazuh.fetch_vulnerabilities({"url": srv.url, "username": "u", "password": "p"})
            agents = wazuh.fetch_agents({"url": srv.url, "username": "u", "password": "p"})
        finally:
            srv.close()
        self.assertEqual(len(found), 3)
        self.assertEqual(found[0]["vulnerability.score.base"], 7.5)
        self.assertEqual(agents["001"]["os"], "Rocky Linux 9.6")
        methods = [(m, p.split("?")[0]) for m, p, _, _ in srv.requests]
        self.assertIn(("DELETE", "/_search/scroll"), methods)
        self.assertEqual(srv.requests[-1][3].get("Authorization"), "Bearer T")

    def test_epss_cache_and_offline_fallback(self):
        def route(method, path, body):
            return 200, {"status": "OK", "data": [{"cve": "CVE-1", "epss": "0.5", "percentile": "0.9"}]}

        with tempfile.TemporaryDirectory() as tmp:
            srv = FakeServer(route)
            try:
                status = {"warnings": []}
                cfg = {"cache_dir": tmp, "epss_url": srv.url + "/epss"}
                scores = intel.load_epss(cfg, {"CVE-1", "CVE-2"}, status)
                self.assertEqual(scores, {"CVE-1": {"epss": 0.5, "percentile": 0.9}})
                n = len(srv.requests)
                intel.load_epss(cfg, {"CVE-1", "CVE-2"}, status)             # same day: cached
                self.assertEqual(len(srv.requests), n)
            finally:
                srv.close()
            with open(os.path.join(tmp, "epss.json"), encoding="utf-8") as fh:
                cached = json.load(fh)
            cached["day"] = "2000-01-01"                                     # stale cache
            with open(os.path.join(tmp, "epss.json"), "w", encoding="utf-8") as fh:
                json.dump(cached, fh)
            status = {"warnings": []}
            offline = {"cache_dir": tmp, "epss_url": "http://127.0.0.1:9/epss", "timeout": 2}
            self.assertEqual(intel.load_epss(offline, {"CVE-1"}, status)["CVE-1"]["epss"], 0.5)
            self.assertTrue(status["warnings"])


if __name__ == "__main__":
    unittest.main()
