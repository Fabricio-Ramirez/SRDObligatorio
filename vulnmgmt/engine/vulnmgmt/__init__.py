"""Vulnerability management engine for the Wazuh server (SRD assignment, item 5).

Collects the vulnerabilities detected by Wazuh, enriches them with threat
intelligence (CISA KEV, FIRST EPSS), prioritises them into actionable tasks,
optionally asks a small local LLM (Ollama) for an executive summary, and
publishes a static dashboard plus events for the SIEM.

Only the Python standard library is used (Python >= 3.9).
"""

__version__ = "1.0.0"
