#!/usr/bin/env bash
# =============================================================================
# bootstrap.sh - installs and runs one component of this repository on THIS server:
#
#   --component hardening (default)  CIS Benchmark Level 1 hardening. Rocky Linux 9 / 10 only.
#   --component vulnmgmt             Vulnerability management platform. Runs on the Wazuh
#                                    server: Rocky Linux 9 / 10 or Amazon Linux 2023
#                                    (the operating system of the official Wazuh image).
#
# Each component checks the operating system it needs; one never blocks the other.
#
# 1. Installs git and Ansible (ansible-core from the distribution repositories; where
#    the distribution does not package it, a Python virtual environment in /opt/srd-ansible).
# 2. Downloads (or updates) this repository.
# 3. Installs the required Ansible collection.
# 4. Runs the playbook of the component: site.yml (Rocky 9, CIS v2.0.0),
#    site-rocky10.yml (Rocky 10, CIS RHEL 10 v1.0.1) or vulnmgmt.yml.
#
# Usage (as root, on the freshly installed server):
#   ./bootstrap.sh --siem-host 10.0.10.12            # inside a clone
#   curl -fsSL https://raw.githubusercontent.com/Fabricio-Ramirez/SRDObligatorio/HEAD/bootstrap.sh \
#     | sudo bash -s -- --siem-host 10.0.10.12        # without a clone
#
# Run "./bootstrap.sh --help" for every option.
# =============================================================================
set -Eeuo pipefail

REPO_URL="${REPO_URL:-https://github.com/Fabricio-Ramirez/SRDObligatorio.git}"
REPO_BRANCH="${REPO_BRANCH:-}"            # empty = repository default branch
INSTALL_DIR="${INSTALL_DIR:-/opt/srd-hardening}"
LOG_DIR="/var/log/srd-hardening"
SIEM_TYPE="${SIEM_TYPE:-}"
SIEM_HOST="${SIEM_HOST:-}"
COMPONENT="${COMPONENT:-hardening}"   # hardening | vulnmgmt
OS_RELEASE_FILE="${OS_RELEASE_FILE:-/etc/os-release}"   # overridable only to test the detection
VENV_DIR="${VENV_DIR:-/opt/srd-ansible}"                # ansible-core fallback (outside the repository)
CHECK_MODE=0
TAGS=""
EXTRA_ARGS=()

log()  { printf '\033[1;34m[bootstrap]\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[bootstrap] WARNING:\033[0m %s\n' "$*" >&2; }
die()  { printf '\033[1;31m[bootstrap] ERROR:\033[0m %s\n' "$*" >&2; exit 1; }

usage() {
  cat <<EOF
Usage: $0 [options] [-- extra ansible-playbook arguments]

Options:
  --component NAME     hardening (default; Rocky Linux 9/10 only) or vulnmgmt (vulnerability
                       management platform, only on the Wazuh server: Rocky Linux 9/10
                       or Amazon Linux 2023)
  --siem-host HOST     Wazuh manager / syslog collector address (required unless --siem-type none)
  --siem-type TYPE     wazuh (default), syslog or none
  --branch NAME        Git branch to use (default: repository default branch)
  --repo URL           Git repository URL (default: ${REPO_URL})
  --dir PATH           Where to clone the repository (default: ${INSTALL_DIR})
  --check              Dry run: show what would change (ansible --check --diff)
  --tags LIST          Run only some sections, e.g. --tags ssh,firewall
  -h, --help           Show this help

Environment variables with the same meaning: COMPONENT, SIEM_HOST, SIEM_TYPE,
REPO_URL, REPO_BRANCH, INSTALL_DIR. For --component vulnmgmt the passwords can
also come from VULNMGMT_INDEXER_ADMIN_PASSWORD, VULNMGMT_API_USER and
VULNMGMT_API_PASSWORD; otherwise they are asked interactively.
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --component) COMPONENT="${2:?--component needs a value}"; shift 2 ;;
    --siem-host) SIEM_HOST="${2:?--siem-host needs a value}"; shift 2 ;;
    --siem-type) SIEM_TYPE="${2:?--siem-type needs a value}"; shift 2 ;;
    --branch)    REPO_BRANCH="${2:?--branch needs a value}"; shift 2 ;;
    --repo)      REPO_URL="${2:?--repo needs a value}"; shift 2 ;;
    --dir)       INSTALL_DIR="${2:?--dir needs a value}"; shift 2 ;;
    --check)     CHECK_MODE=1; shift ;;
    --tags)      TAGS="${2:?--tags needs a value}"; shift 2 ;;
    -h|--help)   usage; exit 0 ;;
    --)          shift; EXTRA_ARGS=("$@"); break ;;
    *)           usage; die "Unknown option: $1" ;;
  esac
done

# --- 1. Pre-checks ----------------------------------------------------------
[[ ${EUID} -eq 0 ]] || die "Run as root (sudo $0 ...)."

# shellcheck disable=SC1090
. "${OS_RELEASE_FILE}"
OS_ID="${ID:-unknown}"
OS_MAJOR="${VERSION_ID:-}"; OS_MAJOR="${OS_MAJOR%%.*}"
OS_NAME="${PRETTY_NAME:-${OS_ID} ${OS_MAJOR}}"

# The operating system is validated by the component that needs it, so that the
# hardening (CIS Rocky benchmarks) never blocks the vulnerability platform, which
# runs on the Wazuh server.
case "${COMPONENT}" in
  hardening)
    [[ "${OS_ID}" == "rocky" ]] || die "The hardening targets Rocky Linux 9 or 10 (found: ${OS_NAME}). It follows the CIS Rocky Linux benchmarks and does not apply to other distributions."
    case "${OS_MAJOR}" in
      9)  PLAYBOOK="site.yml" ;;
      10) PLAYBOOK="site-rocky10.yml" ;;
      *)  die "The hardening targets Rocky Linux 9 or 10 (found: ${OS_NAME})." ;;
    esac ;;
  vulnmgmt)
    PLAYBOOK="vulnmgmt.yml"
    case "${OS_ID}:${OS_MAJOR}" in
      rocky:9|rocky:10|amzn:2023) ;;
      amzn:*) die "Amazon Linux ${OS_MAJOR} is not supported (found: ${OS_NAME}): the platform needs dnf and Python 3.9 or newer, i.e. Amazon Linux 2023." ;;
      *)      die "The vulnerability platform targets Rocky Linux 9/10 or Amazon Linux 2023 (found: ${OS_NAME})." ;;
    esac ;;
  *) die "Unknown component: ${COMPONENT} (use hardening or vulnmgmt)." ;;
esac

# The playbook stops early if no SIEM address is configured anywhere
# (--siem-host or group_vars/all.yml).
if [[ "${COMPONENT}" == "hardening" && "${SIEM_TYPE:-wazuh}" != "none" && -z "${SIEM_HOST}" ]]; then
  warn "No --siem-host given: it must be set in group_vars/all.yml, or use --siem-type none."
fi

# --- 2. Install git and Ansible ---------------------------------------------
# ansible-core < 2.16 so that it also runs on Python 3.9 (Amazon Linux 2023, Rocky 9).
install_ansible_in_venv() {
  log "Installing ansible-core in a Python virtual environment (${VENV_DIR})..."
  python3 -m venv "${VENV_DIR}" \
    || die "python3 -m venv failed: install the python3 virtual environment support and run again."
  "${VENV_DIR}/bin/pip" install -q --upgrade pip
  "${VENV_DIR}/bin/pip" install -q "ansible-core>=2.14,<2.16" \
    || die "pip could not install ansible-core (is pypi.org reachable?)."
}

if [[ "${OS_ID}" == "rocky" ]]; then
  log "Installing git and ansible-core from the Rocky Linux repositories..."
  dnf -y -q install git ansible-core
else
  log "Installing git..."
  dnf -y -q install git
  if command -v ansible-playbook >/dev/null 2>&1; then
    log "Ansible is already installed: $(command -v ansible-playbook)"
  elif dnf -y -q install ansible-core 2>/dev/null; then
    log "ansible-core installed from the distribution repositories."
  else
    install_ansible_in_venv
  fi
fi
# The virtual environment (if any) goes first in the PATH for the rest of the script.
[[ -x "${VENV_DIR}/bin/ansible-playbook" ]] && export PATH="${VENV_DIR}/bin:${PATH}"

# --- 3. Download / update the repository ------------------------------------
# If this script is run from inside a clone, that clone is used as-is.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" 2>/dev/null && pwd || true)"
if [[ -n "${SCRIPT_DIR}" && -f "${SCRIPT_DIR}/site.yml" && -d "${SCRIPT_DIR}/roles/hardening" ]]; then
  INSTALL_DIR="${SCRIPT_DIR}"
  log "Using the local repository at ${INSTALL_DIR}"
elif [[ -d "${INSTALL_DIR}/.git" ]]; then
  log "Updating ${INSTALL_DIR}..."
  git -C "${INSTALL_DIR}" fetch --prune origin
  if [[ -n "${REPO_BRANCH}" ]]; then
    git -C "${INSTALL_DIR}" checkout "${REPO_BRANCH}"
  fi
  git -C "${INSTALL_DIR}" pull --ff-only
else
  log "Cloning ${REPO_URL} into ${INSTALL_DIR}..."
  clone_args=(--depth 1)
  [[ -n "${REPO_BRANCH}" ]] && clone_args+=(--branch "${REPO_BRANCH}")
  git clone "${clone_args[@]}" "${REPO_URL}" "${INSTALL_DIR}" \
    || die "git clone failed. If the repository is private, use a deploy key or a read-only token (see README)."
fi
cd "${INSTALL_DIR}"

# --- 4. Ansible collection ----------------------------------------------------
if ansible-galaxy collection list ansible.posix 2>/dev/null | grep -q '^ansible\.posix '; then
  log "Collection ansible.posix already installed."
else
  log "Installing the ansible.posix collection..."
  if ! ansible-galaxy collection install -r requirements.yml -p ./collections; then
    [[ "${OS_ID}" == "rocky" ]] \
      || die "Could not install ansible.posix from Ansible Galaxy (is galaxy.ansible.com reachable?)."
    warn "Ansible Galaxy is not reachable; trying the EPEL package instead."
    dnf -y -q install epel-release
    dnf -y -q install ansible-collection-ansible-posix \
      || die "Could not install ansible.posix (Galaxy and EPEL both failed)."
  fi
fi

# --- 5. Run the hardening playbook -------------------------------------------
mkdir -p "${LOG_DIR}"
chmod 0700 "${LOG_DIR}"
ANSIBLE_LOG_PATH="${LOG_DIR}/ansible-$(date +%Y%m%d-%H%M%S).log"
export ANSIBLE_LOG_PATH

playbook_args=(-i inventory/localhost.ini "${PLAYBOOK}")

# Secrets for vulnmgmt go through a private temporary vars file, never on the
# command line (where any user could read them in the process list).
if [[ "${COMPONENT}" == "vulnmgmt" ]]; then
  if [[ -z "${VULNMGMT_INDEXER_ADMIN_PASSWORD:-}" && ! -f /etc/vulnmgmt/indexer.secret ]]; then
    read -rsp "Wazuh indexer 'admin' password (wazuh-passwords.txt): " VULNMGMT_INDEXER_ADMIN_PASSWORD </dev/tty; echo
  fi
  # The API user (not its password) is remembered so repeat runs are unattended.
  API_USER_FILE=/etc/vulnmgmt/api.user
  if [[ -z "${VULNMGMT_API_USER:-}" && -r "${API_USER_FILE}" ]]; then
    VULNMGMT_API_USER="$(tr -d '\r\n' < "${API_USER_FILE}")"
    [[ -n "${VULNMGMT_API_USER}" ]] && log "Reusing the Wazuh API user from ${API_USER_FILE}: ${VULNMGMT_API_USER}"
  fi
  if [[ -z "${VULNMGMT_API_USER:-}" ]]; then
    read -rp "Wazuh API user for agent inventory (optional, Enter to skip): " VULNMGMT_API_USER </dev/tty
    if [[ -n "${VULNMGMT_API_USER}" ]]; then
      mkdir -p /etc/vulnmgmt && chmod 0750 /etc/vulnmgmt
      printf '%s\n' "${VULNMGMT_API_USER}" > "${API_USER_FILE}"
      chmod 0640 "${API_USER_FILE}"
    fi
  fi
  if [[ -n "${VULNMGMT_API_USER:-}" && -z "${VULNMGMT_API_PASSWORD:-}" ]]; then
    read -rsp "Wazuh API password for ${VULNMGMT_API_USER}: " VULNMGMT_API_PASSWORD </dev/tty; echo
  fi
  export VULNMGMT_INDEXER_ADMIN_PASSWORD VULNMGMT_API_USER VULNMGMT_API_PASSWORD
  SECRETS_FILE="$(mktemp)"
  chmod 0600 "${SECRETS_FILE}"
  trap 'rm -f "${SECRETS_FILE}"' EXIT
  python3 -c 'import json, os, sys
json.dump({"vulnmgmt_indexer_admin_password": os.environ.get("VULNMGMT_INDEXER_ADMIN_PASSWORD", ""),
           "vulnmgmt_api_user": os.environ.get("VULNMGMT_API_USER", ""),
           "vulnmgmt_api_password": os.environ.get("VULNMGMT_API_PASSWORD", "")}, open(sys.argv[1], "w"))' \
    "${SECRETS_FILE}"
  playbook_args+=(-e "@${SECRETS_FILE}")
fi
if [[ "${COMPONENT}" == "hardening" ]]; then
  [[ -n "${SIEM_TYPE}" ]] && playbook_args+=(-e "hardening_siem_type=${SIEM_TYPE}")
  [[ -n "${SIEM_HOST}" ]] && playbook_args+=(-e "hardening_siem_host=${SIEM_HOST}")
fi
[[ -n "${TAGS}" ]] && playbook_args+=(--tags "${TAGS}")
[[ ${CHECK_MODE} -eq 1 ]] && playbook_args+=(--check --diff)
playbook_args+=("${EXTRA_ARGS[@]}")

log "Running: ansible-playbook ${playbook_args[*]}"
log "Log file: ${ANSIBLE_LOG_PATH}"
ansible-playbook "${playbook_args[@]}"

if [[ "${COMPONENT}" == "vulnmgmt" ]]; then
  log "Done. The dashboard URL and how to reach n8n are shown in the summary above."
else
  log "Done. Report saved in /var/log/hardening-report.txt"
  log "Reboot if the summary above says 'REBOOT REQUIRED', then verify with: ${INSTALL_DIR}/scripts/verify.sh"
fi
