"""External threat intelligence: CISA KEV catalog and FIRST EPSS scores.

Both feeds are cached on disk so the engine keeps working (with the last known
data) when the server has no Internet access. Nothing about the
infrastructure is sent out: KEV is a full download and EPSS is queried by CVE
identifier only.
"""

import json
import logging
import os
import time
import urllib.parse

from .httpclient import Client, HTTPError

log = logging.getLogger(__name__)

DEFAULT_KEV_URLS = [
    "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
    "https://raw.githubusercontent.com/cisagov/kev-data/main/known_exploited_vulnerabilities.json",
]
DEFAULT_EPSS_URL = "https://api.first.org/data/v1/epss"
EPSS_BATCH = 50  # CVE ids per request, keeps the URL short


def _read_json(path):
    try:
        with open(path, encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, ValueError):
        return None


def _write_json(path, data):
    tmp = f"{path}.tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(data, fh)
    os.replace(tmp, path)


def _fresh(path, max_age_hours):
    try:
        return time.time() - os.path.getmtime(path) < max_age_hours * 3600
    except OSError:
        return False


def load_kev(cfg, status):
    """Return {cve_id: kev_entry} from CISA's Known Exploited Vulnerabilities catalog."""
    cache = os.path.join(cfg["cache_dir"], "kev.json")
    catalog = _read_json(cache) if _fresh(cache, cfg.get("cache_hours", 24)) else None
    if catalog is None:
        for url in cfg.get("kev_urls") or DEFAULT_KEV_URLS:
            try:
                catalog = Client(url, timeout=cfg.get("timeout", 30)).request("GET", url)
                if isinstance(catalog, dict) and "vulnerabilities" in catalog:
                    _write_json(cache, catalog)
                    break
                catalog = None
            except (HTTPError, OSError) as exc:
                log.warning("KEV download failed from %s: %s", url, exc)
        if catalog is None:
            catalog = _read_json(cache)  # stale cache is better than nothing
            if catalog is not None:
                status["warnings"].append("KEV: no se pudo actualizar, se usa la copia en caché.")
    if not catalog:
        status["warnings"].append("KEV: catálogo no disponible.")
        status["kev"] = None
        return {}
    status["kev"] = {"version": catalog.get("catalogVersion"), "count": catalog.get("count")}
    return {v["cveID"]: v for v in catalog.get("vulnerabilities", []) if v.get("cveID")}


def _float(value):
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def load_epss(cfg, cves, status):
    """Return {cve_id: {"epss": float, "percentile": float}} from FIRST's EPSS API."""
    cache_path = os.path.join(cfg["cache_dir"], "epss.json")
    cache = _read_json(cache_path) or {}
    today = time.strftime("%Y-%m-%d")
    scores = {c: v for c, v in cache.get("scores", {}).items()} if cache.get("day") == today else {}
    missing = sorted({c for c in cves if c.startswith("CVE-")} - set(scores))
    url = cfg.get("epss_url", DEFAULT_EPSS_URL)
    client = Client(url, timeout=cfg.get("timeout", 30))
    failed = False
    for i in range(0, len(missing), EPSS_BATCH):
        batch = missing[i:i + EPSS_BATCH]
        query = urllib.parse.urlencode({"cve": ",".join(batch)})
        try:
            answer = client.request("GET", f"{url}?{query}")
        except HTTPError as exc:
            log.warning("EPSS query failed: %s", exc)
            failed = True
            break
        for row in (answer or {}).get("data", []):
            epss, pct = _float(row.get("epss")), _float(row.get("percentile"))
            if row.get("cve") and epss is not None:
                scores[row["cve"]] = {"epss": epss, "percentile": pct}
        for cve in batch:  # remember CVEs without score so they are not asked again today
            scores.setdefault(cve, None)
    if failed and cache.get("scores"):
        for cve, value in cache["scores"].items():  # fall back to the last known scores
            scores.setdefault(cve, value)
        status["warnings"].append("EPSS: no se pudo actualizar, se usan los últimos valores conocidos.")
    elif failed:
        status["warnings"].append("EPSS: servicio no disponible, la prioridad no incluye EPSS.")
    try:
        _write_json(cache_path, {"day": today, "scores": scores})
    except OSError as exc:
        log.warning("Cannot write EPSS cache: %s", exc)
    status["epss"] = {"scored": sum(1 for v in scores.values() if v), "requested": len(cves)}
    return {c: v for c, v in scores.items() if v}
