"""Vulnerability management engine for the Wazuh server (SRD assignment, item 5).

Collects the vulnerabilities detected by Wazuh, enriches them with threat
intelligence (CISA KEV, FIRST EPSS), prioritises them into actionable tasks,
and publishes a static dashboard plus events for the SIEM.

The prioritised work plan with the proposed solution for each action is built
from this report by the n8n workflow (vulnmgmt/n8n/priorizar-soluciones.js).

Only the Python standard library is used (Python >= 3.9).
"""

__version__ = "1.0.0"
