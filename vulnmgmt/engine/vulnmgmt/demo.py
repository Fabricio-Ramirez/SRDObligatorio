"""Synthetic dataset for demonstrations and tests (no Wazuh needed).

The documents have the shape of the Wazuh vulnerability index. Hosts, package
versions and EPSS values are invented; the dashboard labels every demo report
as "DATOS DE DEMOSTRACIÓN". The KEV entries are copied from the real CISA
catalog (cveID, dueDate, knownRansomwareCampaignUse).
"""

DEMO_KEV = {
    "CVE-2023-4911": {"cveID": "CVE-2023-4911", "dueDate": "2023-12-12", "knownRansomwareCampaignUse": "Unknown"},
    "CVE-2024-1086": {"cveID": "CVE-2024-1086", "dueDate": "2024-06-20", "knownRansomwareCampaignUse": "Known"},
    "CVE-2021-4034": {"cveID": "CVE-2021-4034", "dueDate": "2022-07-18", "knownRansomwareCampaignUse": "Known"},
    "CVE-2021-3156": {"cveID": "CVE-2021-3156", "dueDate": "2022-04-27", "knownRansomwareCampaignUse": "Unknown"},
}

DEMO_EPSS = {  # invented values, for demonstration only
    "CVE-2023-4911": {"epss": 0.71, "percentile": 0.98},
    "CVE-2024-1086": {"epss": 0.83, "percentile": 0.99},
    "CVE-2024-6387": {"epss": 0.38, "percentile": 0.97},
    "CVE-2023-38545": {"epss": 0.04, "percentile": 0.88},
    "CVE-2023-48795": {"epss": 0.55, "percentile": 0.97},
    "CVE-2021-3156": {"epss": 0.92, "percentile": 0.99},
    "CVE-2021-4034": {"epss": 0.85, "percentile": 0.99},
    "CVE-2025-00001": {"epss": 0.001, "percentile": 0.20},
}

DEMO_AGENTS = {
    "000": {"id": "000", "name": "wazuh-server", "status": "active", "os": "Rocky Linux 9.6", "groups": []},
    "001": {"id": "001", "name": "srv-idp", "status": "active", "os": "Rocky Linux 9.6", "groups": ["criticos"]},
    "002": {"id": "002", "name": "srv-bastion", "status": "active", "os": "Rocky Linux 9.6", "groups": ["criticos"]},
    "003": {"id": "003", "name": "srv-web", "status": "active", "os": "Rocky Linux 10.0", "groups": ["default"]},
    "004": {"id": "004", "name": "srv-backup", "status": "disconnected", "os": "Rocky Linux 9.6", "groups": ["default"]},
}

# (cve, severity, cvss, package, installed, condition, agents)
_ROWS = [
    ("CVE-2023-4911", "High", 7.8, "glibc", "2.34-60.el9", "Package less than 2.34-83.el9_3.7", ["000", "001", "002"]),
    ("CVE-2024-1086", "High", 7.8, "kernel", "5.14.0-362.8.1.el9_3", "Package less than 5.14.0-427.13.1.el9_4", ["001", "002", "003"]),
    ("CVE-2024-6387", "High", 8.1, "openssh-server", "8.7p1-34.el9", "Package less than 8.7p1-38.el9_4.1", ["000", "001", "002", "003"]),
    ("CVE-2023-48795", "Medium", 5.9, "openssh-server", "8.7p1-34.el9", "Package less than 8.7p1-38.el9", ["000", "001", "002", "003"]),
    ("CVE-2023-38545", "Critical", 9.8, "curl", "7.76.1-26.el9", "Package less than 7.76.1-26.el9_3.2", ["003"]),
    ("CVE-2021-3156", "High", 7.8, "sudo", "1.9.5p2-7.el9", "Package less than 1.9.5p2-10.el9_3", ["003"]),
    ("CVE-2021-4034", "High", 7.8, "polkit", "0.117-10.el9", "Package less than 0.117-11.el9", ["000"]),
    ("CVE-2025-00001", "Medium", 5.3, "less", "590-2.el9", "Package default status", ["000", "001"]),
]


def findings():
    docs = []
    for cve, sev, cvss, pkg, ver, cond, agent_ids in _ROWS:
        for agent_id in agent_ids:
            agent = DEMO_AGENTS[agent_id]
            docs.append({
                "agent.id": agent_id, "agent.name": agent["name"],
                "host.os.full": agent["os"], "host.os.name": "Rocky Linux", "host.os.platform": "rocky",
                "host.os.version": agent["os"].split()[-1],
                "package.name": pkg, "package.version": ver, "package.type": "rpm",
                "package.architecture": "x86_64",
                "vulnerability.id": cve, "vulnerability.severity": sev, "vulnerability.score.base": cvss,
                "vulnerability.score.version": "3.1", "vulnerability.scanner.condition": cond,
                "vulnerability.under_evaluation": False, "vulnerability.detected_at": "2026-10-01T03:00:00Z",
                "vulnerability.published_at": None,
                "vulnerability.reference": f"https://nvd.nist.gov/vuln/detail/{cve}",
                "vulnerability.category": "Packages",
            })
    return docs
