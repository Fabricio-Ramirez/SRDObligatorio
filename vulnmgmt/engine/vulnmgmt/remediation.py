"""Remediation plan: per-server one-liners and an Ansible playbook (standard library only).

The engine NEVER runs anything on the servers. It only prepares:
  * per-server shell commands to copy and paste, and
  * data/remediation.yml, an Ansible playbook (one play per Wazuh agent name) that the
    infrastructure team runs from the bastion / control node, which already holds the
    SSH keys. Running it from the SIEM would require a root-capable key for every server
    on the most sensitive host, so that path is deliberately not offered.

Only updates are automated: findings with a known fixed version ("actualizar") on rpm or deb
packages. Everything else (no patch, unparsed condition, other package managers, Wazuh's own
packages) is listed as manual work with the reason.
"""

import json
import re

from .prioritize import PROTECTED_PACKAGES, SAFE_PACKAGE

PRIORITIES = ("P1", "P2", "P3", "P4")
PACKAGE_TYPES = ("rpm", "deb")
# Names end up in shell commands and in YAML: accept only what real package and host names use.
SAFE_HOST = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")
PLAYBOOK_NAME = "remediation.yml"


def manual_reason(action):
    """Why an action cannot be automated, or None when it can."""
    if action["action"] == "mitigar":
        return "Sin versión corregida conocida: aplicar las mitigaciones indicadas en la acción."
    if action["action"] != "actualizar":
        return "La condición de versión no permite deducir el parche: revisar el aviso del proveedor."
    if action["package_type"] not in PACKAGE_TYPES:
        return f"Gestor de paquetes no soportado ({action['package_type']}): actualizar manualmente."
    if PROTECTED_PACKAGES.match(action["package"] or ""):
        return "Componente de Wazuh: actualizar siguiendo la guía oficial (el agente no puede superar al manager)."
    if not SAFE_PACKAGE.match(action["package"] or ""):
        return "Nombre de paquete no estándar: no se genera comando automático."
    return None


def command(pkg_type, packages):
    names = " ".join(sorted(packages))
    if pkg_type == "deb":
        return f"sudo apt-get update && sudo apt-get install --only-upgrade -y {names}"
    return f"sudo dnf upgrade -y --disablerepo='wazuh*' {names}"


def ansible_commands(host_name, is_local, tag):
    """Simulation and apply commands for one server. host_name already passed SAFE_HOST."""
    if is_local:   # the Wazuh server itself: ad-hoc inventory with a local connection
        base = f"ansible-playbook -i '{host_name},' -c local {PLAYBOOK_NAME} --tags {tag} -K"
    else:
        base = f"ansible-playbook -i inventory/hosts.ini {PLAYBOOK_NAME} --limit {host_name} --tags {tag} -K"
    return {"simular": base + " --check --diff", "aplicar": base}


def _commands(pkg_type, packages):
    """P1 / up to P2 / all, skipping scopes that add nothing to the previous one."""
    sets, acc = {}, set()
    for prio in PRIORITIES:
        acc = acc | set(packages[prio])
        sets[prio] = set(acc)
    out, previous = {}, None
    for key, scope in (("P1", "P1"), ("hasta-P2", "P2"), ("todas", "P4")):
        if sets[scope] and sets[scope] != previous:
            out[key] = command(pkg_type, sets[scope])
        previous = sets[scope] if sets[scope] else previous
    return out


def build(actionables):
    hosts, manual = {}, []
    for a in actionables:
        reason = manual_reason(a)
        if reason:
            manual.append({"id": a["id"], "package": a["package"], "priority": a["priority"],
                           "action": a["action"], "reason": reason})
            continue
        for h in a["hosts"]:
            if not SAFE_HOST.match(h.get("name") or ""):
                manual.append({"id": a["id"], "package": a["package"], "priority": a["priority"],
                               "action": a["action"],
                               "reason": f"Nombre de servidor no válido para Ansible: {h.get('name')!r}."})
                continue
            entry = hosts.setdefault((h["name"], a["package_type"]), {
                "name": h["name"], "id": h.get("id"), "os": h.get("os", ""), "package_type": a["package_type"],
                "packages": {p: set() for p in PRIORITIES}})
            entry["packages"][a["priority"]].add(a["package"])

    out = []
    for entry in hosts.values():
        packages = entry["packages"]
        out.append({
            "name": entry["name"], "id": entry["id"], "os": entry["os"], "package_type": entry["package_type"],
            "local": entry["id"] == "000",   # agent 000 is the Wazuh server itself
            "packages": {p: sorted(packages[p]) for p in PRIORITIES},
            "total": len(set().union(*packages.values())),
            "commands": _commands(entry["package_type"], packages),
            "ansible": ansible_commands(entry["name"], entry["id"] == "000",
                                        next(p for p in PRIORITIES if packages[p])),
        })
    out.sort(key=lambda h: (next((i for i, p in enumerate(PRIORITIES) if h["packages"][p]), 9), h["name"]))
    manual.sort(key=lambda m: (m["priority"], m["package"]))
    return {"playbook": PLAYBOOK_NAME, "hosts": out, "manual": manual}


def _q(value):
    """Quote any value for YAML: a JSON string is a valid YAML double-quoted scalar."""
    return json.dumps(value, ensure_ascii=False)


# Folded (">-") blocks keep every generated line short, which the YAML linters require.
_NEED = "'REINICIO NECESARIO: programar una ventana de mantenimiento (este playbook no reinicia el servidor)'"
# "dnf needs-restarting -r" exits 1 both when a reboot is needed (and prints "Reboot is required ...",
# see dnf-plugins-core plugins/needs_restarting.py) and when dnf does not know the command, so the exit
# code alone would raise a false alarm on a server without dnf-plugins-core.
_REBOOT_MSG = [
    "{{ " + _NEED,
    "   if (vulnmgmt_reboot.rc == 1 and 'Reboot is required' in (vulnmgmt_reboot.stdout | default('')))",
    "   else ('No hace falta reiniciar' if vulnmgmt_reboot.rc == 0 else",
    "   'No se pudo determinar si hace falta reiniciar: instalar dnf-plugins-core') }}",
]
_REBOOT_MSG_DEB = [
    "{{ " + _NEED,
    "   if vulnmgmt_reboot.stat.exists else 'No hace falta reiniciar' }}",
]


def _msg_block(parts):
    return ["      ansible.builtin.debug:", "        msg: >-"] + ["          " + part for part in parts]


def playbook(plan, generated_at, source):
    lines = [
        "---",
        "# vulnmgmt - plan de remediación (generado automáticamente, no editar a mano).",
        f"# Generado: {generated_at}  |  fuente: {source}",
    ]
    if source == "demo":
        lines.append("# DATOS DE DEMOSTRACIÓN: NO aplicar a servidores reales.")
    lines += [
        "#",
        "# El motor no ejecuta nada. Revisar y aplicar desde el bastión / nodo de control (el que tiene las claves SSH):",
        "#   1) Simulación, no cambia nada:",
        f"#      ansible-playbook -i inventory/hosts.ini {PLAYBOOK_NAME} --limit <servidor> --tags P1 -K --check --diff",
        "#   2) Aplicar:",
        f"#      ansible-playbook -i inventory/hosts.ini {PLAYBOOK_NAME} --limit <servidor> --tags P1 -K",
        "#   --tags P1 | P2 | P3 | P4 limita por prioridad; sin --tags se aplican todas.",
        "# Los nombres de 'hosts:' son los nombres de agente de Wazuh y deben existir en el inventario",
        "# (o usar un alias en el inventario). El servidor Wazuh (agente 000) se parchea en local:",
        f"#   ansible-playbook -i '<nombre-del-agente>,' -c local {PLAYBOOK_NAME} -K",
        "# Los componentes de Wazuh (wazuh-*) se excluyen a propósito. Ningún paso reinicia el servidor.",
        "",
    ]
    if not plan["hosts"]:
        lines += [
            "- name: Sin acciones de actualización pendientes",
            "  hosts: localhost",
            "  connection: local",
            "  gather_facts: false",
            "  tasks:",
            "    - name: Informar que no hay nada que aplicar",
            "      ansible.builtin.debug:",
            f"        msg: {_q('No hay actualizaciones automatizables en el último informe.')}",
            "",
        ]
        return "\n".join(lines)

    for host in plan["hosts"]:
        title = f"Remediación - {host['name']}" + (f" ({host['os']})" if host["os"] else "")
        lines += [f"- name: {_q(title)}", f"  hosts: {_q(host['name'])}", "  become: true",
                  "  gather_facts: false", "  tasks:"]
        for prio in PRIORITIES:
            names = host["packages"][prio]
            if not names:
                continue
            label = f"{prio} | Actualizar {len(names)} paquete(s)"
            if host["package_type"] == "deb":
                lines += [f"    - name: {_q(label)}", "      ansible.builtin.apt:", f"        name: {_q(names)}",
                          "        state: latest", "        only_upgrade: true", "        update_cache: true"]
            else:
                lines += [f"    - name: {_q(label)}", "      ansible.builtin.dnf:", f"        name: {_q(names)}",
                          "        state: latest", "        update_only: true", '        disablerepo: ["wazuh*"]']
            lines.append(f"      tags: [{prio}]")
        if host["package_type"] == "deb":
            lines += [
                "    - name: Comprobar si hace falta reiniciar", "      ansible.builtin.stat:",
                "        path: /var/run/reboot-required", "      register: vulnmgmt_reboot", "      tags: [always]",
                "    - name: Informar si hace falta reiniciar", *_msg_block(_REBOOT_MSG_DEB), "      tags: [always]",
            ]
        else:
            lines += [
                "    - name: Comprobar si hace falta reiniciar", "      ansible.builtin.command: dnf needs-restarting -r",
                "      register: vulnmgmt_reboot", "      changed_when: false", "      failed_when: false",
                "      check_mode: false", "      tags: [always]",
                "    - name: Informar si hace falta reiniciar", *_msg_block(_REBOOT_MSG), "      tags: [always]",
            ]
        lines.append("")
    return "\n".join(lines)
