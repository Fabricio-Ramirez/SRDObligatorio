#!/usr/bin/env bash
# =============================================================================
# verify.sh - Collect evidence that the hardening is in place.
#
#   sudo ./scripts/verify.sh            # quick checks (a few seconds)
#   sudo ./scripts/verify.sh --oscap    # + OpenSCAP scan, CIS Level 1 Server profile
#
# The output can be attached to the project documentation.
# =============================================================================
set -uo pipefail

[[ ${EUID} -eq 0 ]] || { echo "Run as root." >&2; exit 1; }

PASS=0; FAIL=0
section() { printf '\n\033[1m== %s ==\033[0m\n' "$*"; }
check() {   # check "<description>" <command...>
  local desc="$1"; shift
  if "$@" >/dev/null 2>&1; then
    printf '  [\033[32mPASS\033[0m] %s\n' "$desc"; PASS=$((PASS + 1))
  else
    printf '  [\033[31mFAIL\033[0m] %s\n' "$desc"; FAIL=$((FAIL + 1))
  fi
}
sshd_has() { sshd -T 2>/dev/null | grep -qix "$1"; }
sysctl_is() { [[ "$(sysctl -n "$1" 2>/dev/null)" == "$2" ]]; }
mount_has() { findmnt -kn -o OPTIONS "$1" 2>/dev/null | tr ',' '\n' | grep -qx "$2"; }

section "1.1 Filesystem"
check "cramfs module not loadable"         sh -c "modprobe -n -v cramfs 2>&1 | grep -q '/bin/false'"
if grep -q '^VERSION_ID="10' /etc/os-release; then
  check "sctp module not loadable (Rocky 10)" sh -c "modprobe -n -v sctp 2>&1 | grep -q '/bin/false'"
fi
check "usb-storage module not loadable"    sh -c "modprobe -n -v usb-storage 2>&1 | grep -q '/bin/false'"
check "/tmp is a separate mount"           findmnt -kn /tmp
check "/tmp mounted noexec"                mount_has /tmp noexec
check "/dev/shm mounted noexec"            mount_has /dev/shm noexec

section "1.3 SELinux / 1.6 crypto policy"
check "SELinux enforcing"                  sh -c "[ \"\$(getenforce)\" = Enforcing ]"
check "Crypto policy is not LEGACY"        sh -c "! update-crypto-policies --show | grep -qi legacy"
echo "  crypto policy: $(update-crypto-policies --show)"

section "1.5 / 3.3 Kernel parameters"
check "ASLR enabled (randomize_va_space=2)" sysctl_is kernel.randomize_va_space 2
check "ptrace_scope restricted"             sysctl_is kernel.yama.ptrace_scope 1
check "IP forwarding disabled"              sysctl_is net.ipv4.ip_forward 0
check "ICMP redirects not accepted"         sysctl_is net.ipv4.conf.all.accept_redirects 0
check "Reverse path filtering"              sysctl_is net.ipv4.conf.all.rp_filter 1
check "Martian packets logged"              sysctl_is net.ipv4.conf.all.log_martians 1
check "TCP SYN cookies"                     sysctl_is net.ipv4.tcp_syncookies 1

section "4 Firewall"
check "firewalld active"                   systemctl is-active firewalld
check "nftables service not enabled"       sh -c "! systemctl is-enabled nftables"
check "loopback in trusted zone"           sh -c "firewall-cmd --zone=trusted --list-interfaces | grep -qw lo"
echo "  default zone: $(firewall-cmd --get-default-zone 2>/dev/null)"
firewall-cmd --list-all 2>/dev/null | sed 's/^/    /'

section "5.1 SSH"
check "PermitRootLogin no"                 sshd_has "permitrootlogin no"
check "PermitEmptyPasswords no"            sshd_has "permitemptypasswords no"
check "MaxAuthTries 4"                     sshd_has "maxauthtries 4"
check "X11Forwarding no"                   sshd_has "x11forwarding no"
check "LogLevel VERBOSE or INFO"           sh -c "sshd -T | grep -qiE '^loglevel (verbose|info)$'"
check "Banner configured"                  sshd_has "banner /etc/issue.net"
check "No CBC ciphers"                     sh -c "! sshd -T | grep -i '^ciphers' | grep -qi cbc"
# chacha20-poly1305 is disabled only by the Rocky 9 baseline (CIS RHEL 9 1.6.6).
if grep -q '^VERSION_ID="9' /etc/os-release; then
  check "No chacha20 cipher (Rocky 9)"      sh -c "! sshd -T | grep -i '^ciphers' | grep -qi chacha20"
fi
echo "  $(sshd -T | grep -iE '^(ciphers|macs|allowgroups|passwordauthentication) ' | tr '\n' ';')"

section "5.2 / 5.3 sudo and PAM"
check "sudo use_pty"                       sh -c "grep -rqE '^\s*Defaults\s+.*use_pty' /etc/sudoers /etc/sudoers.d"
check "sudo logfile"                       sh -c "grep -rqE '^\s*Defaults\s+.*logfile=' /etc/sudoers /etc/sudoers.d"
check "su restricted with pam_wheel"       grep -qE '^\s*auth\s+required\s+pam_wheel\.so.*group=' /etc/pam.d/su
check "pam_faillock enabled"               grep -q pam_faillock.so /etc/pam.d/system-auth
check "pam_pwhistory enabled"              grep -q pam_pwhistory.so /etc/pam.d/system-auth
check "pam_unix without nullok"            sh -c "! grep -E 'pam_unix\.so.*nullok' /etc/pam.d/system-auth /etc/pam.d/password-auth"
check "Password minlen >= 14"              sh -c "grep -rhE '^\s*minlen' /etc/security/pwquality.conf /etc/security/pwquality.conf.d/ | awk -F= '{gsub(/ /,\"\",\$2); exit !(\$2>=14)}'"
echo "  authselect: $(authselect current --raw 2>/dev/null)"

section "6 Logging, auditing and integrity"
check "rsyslog active"                     systemctl is-active rsyslog
check "auditd active"                      systemctl is-active auditd
check "audit=1 on the running kernel"      grep -qw 'audit=1' /proc/cmdline
check "audit rules loaded"                 sh -c "[ \$(auditctl -l | grep -vc 'No rules') -gt 50 ]"
check "audit rules immutable (enabled 2)"  sh -c "auditctl -s | grep -qx 'enabled 2'"
check "AIDE database present"              test -f /var/lib/aide/aide.db.gz
check "AIDE daily check scheduled"         grep -qs 'aide --check' /etc/cron.d/aide-check

section "SIEM integration"
if systemctl list-unit-files wazuh-agent.service >/dev/null 2>&1; then
  check "wazuh-agent active"               systemctl is-active wazuh-agent
  check "wazuh-agent connected to manager" sh -c "grep -q \"^status='connected'\" /var/ossec/var/run/wazuh-agentd.state"
else
  check "rsyslog forwards to the SIEM"     grep -qs 'omfwd' /etc/rsyslog.d/90-siem-forward.conf
fi

printf '\n\033[1mResult: %d passed, %d failed\033[0m\n' "${PASS}" "${FAIL}"
[[ -f /var/log/hardening-report.txt ]] && printf 'Last playbook report: /var/log/hardening-report.txt\n'

# --- Optional OpenSCAP scan -----------------------------------------------------
if [[ "${1:-}" == "--oscap" ]]; then
  section "OpenSCAP - CIS Level 1 Server"
  dnf -y -q install openscap-scanner scap-security-guide || exit 1
  DS=""
  for f in /usr/share/xml/scap/ssg/content/ssg-rl{9,10}-ds.xml /usr/share/xml/scap/ssg/content/ssg-rhel{9,10}-ds.xml; do
    [[ -f "$f" ]] && { DS="$f"; break; }
  done
  [[ -n "${DS}" ]] || { echo "No RHEL 9/10 compatible SCAP datastream found." >&2; exit 1; }
  REPORT="/root/oscap-cis-l1-$(date +%Y%m%d-%H%M%S).html"
  oscap xccdf eval --profile xccdf_org.ssgproject.content_profile_cis_server_l1 \
    --report "${REPORT}" "${DS}" >/dev/null 2>&1
  echo "  Datastream: ${DS}"
  echo "  HTML report: ${REPORT}"
  echo "  Note: if most rules are 'notapplicable', the SCAP content does not recognise this OS as RHEL."
fi

[[ ${FAIL} -eq 0 ]]
