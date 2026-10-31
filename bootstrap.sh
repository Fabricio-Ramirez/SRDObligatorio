#!/usr/bin/env bash
# =============================================================================
# bootstrap.sh - Rocky Linux 9 / 10 hardening (CIS Benchmark Level 1 Server)
#
# 1. Installs git and ansible-core from the Rocky Linux repositories.
# 2. Downloads (or updates) this repository.
# 3. Installs the required Ansible collection.
# 4. Runs the hardening playbook for the detected version against the local
#    server: site.yml (Rocky 9, CIS v2.0.0) or site-rocky10.yml (Rocky 10,
#    CIS RHEL 10 v1.0.1).
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
  --siem-host HOST     Wazuh manager / syslog collector address (required unless --siem-type none)
  --siem-type TYPE     wazuh (default), syslog or none
  --branch NAME        Git branch to use (default: repository default branch)
  --repo URL           Git repository URL (default: ${REPO_URL})
  --dir PATH           Where to clone the repository (default: ${INSTALL_DIR})
  --check              Dry run: show what would change (ansible --check --diff)
  --tags LIST          Run only some sections, e.g. --tags ssh,firewall
  -h, --help           Show this help

Environment variables with the same meaning: SIEM_HOST, SIEM_TYPE, REPO_URL,
REPO_BRANCH, INSTALL_DIR.
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
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

# shellcheck disable=SC1091
. /etc/os-release
[[ "${ID:-}" == "rocky" ]] || die "This hardening targets Rocky Linux 9 or 10 (found: ${PRETTY_NAME:-unknown})."
case "${VERSION_ID%%.*}" in
  9)  PLAYBOOK="site.yml" ;;
  10) PLAYBOOK="site-rocky10.yml" ;;
  *)  die "This hardening targets Rocky Linux 9 or 10 (found: ${PRETTY_NAME:-unknown})." ;;
esac

# The playbook stops early if no SIEM address is configured anywhere
# (--siem-host or group_vars/all.yml).
if [[ "${SIEM_TYPE:-wazuh}" != "none" && -z "${SIEM_HOST}" ]]; then
  warn "No --siem-host given: it must be set in group_vars/all.yml, or use --siem-type none."
fi

# --- 2. Install git and Ansible ---------------------------------------------
log "Installing git and ansible-core from the Rocky Linux repositories..."
dnf -y -q install git ansible-core

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
[[ -n "${SIEM_TYPE}" ]] && playbook_args+=(-e "hardening_siem_type=${SIEM_TYPE}")
[[ -n "${SIEM_HOST}" ]] && playbook_args+=(-e "hardening_siem_host=${SIEM_HOST}")
[[ -n "${TAGS}" ]] && playbook_args+=(--tags "${TAGS}")
[[ ${CHECK_MODE} -eq 1 ]] && playbook_args+=(--check --diff)
playbook_args+=("${EXTRA_ARGS[@]}")

log "Running: ansible-playbook ${playbook_args[*]}"
log "Log file: ${ANSIBLE_LOG_PATH}"
ansible-playbook "${playbook_args[@]}"

log "Done. Report saved in /var/log/hardening-report.txt"
log "Reboot if the summary above says 'REBOOT REQUIRED', then verify with: ${INSTALL_DIR}/scripts/verify.sh"
