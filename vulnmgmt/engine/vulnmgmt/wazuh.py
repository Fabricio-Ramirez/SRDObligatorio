"""Data sources: Wazuh indexer (vulnerability states) and Wazuh server API (agents).

Index and field names follow the Wazuh 4.8+ vulnerability detector template
(src/wazuh_modules/vulnerability_scanner/indexer/template/index-template.json):
index pattern "wazuh-states-vulnerabilities-*".
"""

from .httpclient import Client, HTTPError

FIELDS = [
    "agent.id", "agent.name",
    "host.os.full", "host.os.name", "host.os.platform", "host.os.version",
    "package.name", "package.version", "package.type", "package.architecture",
    "vulnerability.id", "vulnerability.severity", "vulnerability.score.base",
    "vulnerability.score.version", "vulnerability.scanner.condition",
    "vulnerability.under_evaluation", "vulnerability.detected_at",
    "vulnerability.published_at", "vulnerability.reference", "vulnerability.category",
]


def _get(doc, dotted, default=None):
    cur = doc
    for part in dotted.split("."):
        if not isinstance(cur, dict) or part not in cur:
            return default
        cur = cur[part]
    return cur


def flatten(source):
    """Turn an indexer _source document into a flat finding dict."""
    return {name: _get(source, name) for name in FIELDS}


def fetch_vulnerabilities(cfg):
    """Return every vulnerability document (flattened) using the scroll API."""
    client = Client(cfg["url"], verify=cfg.get("verify_tls", True),
                    ca_file=cfg.get("ca_file") or None, timeout=cfg.get("timeout", 60),
                    username=cfg["username"], password=cfg["password"], local=True)
    index = cfg.get("index", "wazuh-states-vulnerabilities-*")
    body = {"size": int(cfg.get("page_size", 1000)), "_source": FIELDS,
            "query": {"match_all": {}}, "sort": ["_doc"]}
    page = client.request("POST", f"/{index}/_search?scroll=2m", body)
    findings, scroll_id = [], page.get("_scroll_id")
    try:
        while True:
            hits = page.get("hits", {}).get("hits", [])
            if not hits:
                break
            findings.extend(flatten(h.get("_source", {})) for h in hits)
            page = client.request("POST", "/_search/scroll",
                                  {"scroll": "2m", "scroll_id": scroll_id})
            scroll_id = page.get("_scroll_id", scroll_id)
    finally:
        if scroll_id:
            try:  # the scroll also expires by itself after 2 minutes
                client.request("DELETE", "/_search/scroll", {"scroll_id": scroll_id})
            except HTTPError:
                pass
    return findings


def fetch_agents(cfg):
    """Return the agents known by the Wazuh server API (id -> info).

    Used to report coverage: agents never scanned or disconnected.
    """
    client = Client(cfg["url"], verify=cfg.get("verify_tls", False),
                    ca_file=cfg.get("ca_file") or None, timeout=cfg.get("timeout", 30),
                    username=cfg["username"], password=cfg["password"], local=True)
    token = client.request("POST", "/security/user/authenticate")["data"]["token"]
    client.headers["Authorization"] = f"Bearer {token}"
    agents, offset, limit = {}, 0, 500
    select = "id,name,ip,status,os.name,os.version,os.platform,lastKeepAlive,group,version"
    while True:
        data = client.request("GET", f"/agents?limit={limit}&offset={offset}&select={select}")["data"]
        items = data.get("affected_items", [])
        for item in items:
            agents[item.get("id")] = {
                "id": item.get("id"),
                "name": item.get("name"),
                "ip": item.get("ip"),
                "status": item.get("status"),
                "os": " ".join(x for x in [_get(item, "os.name"), _get(item, "os.version")] if x),
                "groups": item.get("group") or [],
                "last_keepalive": item.get("lastKeepAlive"),
                "version": item.get("version"),
            }
        offset += len(items)
        if not items or offset >= int(data.get("total_affected_items", 0)):
            break
    return agents
