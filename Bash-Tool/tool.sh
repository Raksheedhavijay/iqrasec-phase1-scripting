#!/usr/bin/env bash
# =============================================================================
#  LinuxSec Audit  -  Linux Security Checker
#  IqraSec Academy | Cybersecurity Scripting & Automation Internship | Phase 1
# -----------------------------------------------------------------------------
#  Audits a Linux host against common hardening best practices (loosely based on
#  CIS Benchmark ideas) and prints a colour-coded report with a security score.
#
#  Checks : system info, user accounts, file permissions, SSH configuration,
#           network exposure + firewall, risky filesystem entries (SUID / world-
#           writable), pending updates, failed-login activity, kernel hardening
#           and risky/protective services.
#
#  The tool is READ-ONLY. It never changes the system it audits.
#  Only run it on machines you own or are authorised to assess.
# =============================================================================

set -u   # Treat unset variables as errors (catches typos early)

# ----------------------------- Constants ------------------------------------
readonly VERSION="1.0.0"
readonly SCRIPT_NAME="${0##*/}"
readonly ALL_SECTIONS=(system accounts permissions ssh network filesystem updates logs kernel services)

# ----------------------------- Global state ---------------------------------
REPORT_FILE=""        # -o : optional plain-text report path
SECTIONS="all"        # -s : comma separated list of sections to run
DEEP=0                # -d : deeper (slower) filesystem scan
QUIET=0               # -q : only show WARN / FAIL lines
USE_COLOR=1           # --no-color turns this off
FORCE_COLOR=0         # --color forces colour even when piped
PASS=0; WARN=0; FAIL=0; INFO=0
IS_ROOT=0
[[ ${EUID:-$(id -u)} -eq 0 ]] && IS_ROOT=1

# ----------------------------- Helpers --------------------------------------

# usage: print help text
usage() {
cat <<EOF
LinuxSec Audit v${VERSION} - Linux Security Checker

USAGE
  ${SCRIPT_NAME} [options]

OPTIONS
  -h, --help              Show this help message and exit
  -V, --version           Show version and exit
  -l, --list              List the available check sections
  -s, --section LIST      Run only these sections (comma separated)
                          e.g. -s ssh,network      (default: all)
  -o, --output FILE       Also save a plain-text report to FILE
  -d, --deep              Deep scan: search the whole filesystem for SUID /
                          world-writable files (slower)
  -q, --quiet             Only print WARN and FAIL results
      --no-color          Disable coloured output
      --color             Force colour even when output is piped

SECTIONS
  ${ALL_SECTIONS[*]}

EXAMPLES
  ${SCRIPT_NAME}                         # full audit
  sudo ${SCRIPT_NAME}                    # full audit with root-only checks
  ${SCRIPT_NAME} -s ssh,accounts -q      # just SSH + accounts, warnings only
  sudo ${SCRIPT_NAME} -d -o report.txt   # deep scan and save a report

EXIT CODES
  0  audit finished, no FAIL findings
  1  audit finished, at least one FAIL finding
  2  usage or runtime error
EOF
}

# die: print an error to stderr and exit with code 2
die() { printf 'Error: %s\n' "$1" >&2; printf "Try '%s --help' for usage.\n" "$SCRIPT_NAME" >&2; exit 2; }

# have: true if a command exists
have() { command -v "$1" >/dev/null 2>&1; }

# setup_colors: define ANSI colour variables (empty strings when disabled)
setup_colors() {
    if [[ $FORCE_COLOR -eq 1 || ( $USE_COLOR -eq 1 && -t 1 ) ]]; then
        RED=$'\033[31m'; GREEN=$'\033[32m'; YELLOW=$'\033[33m'; BLUE=$'\033[34m'
        CYAN=$'\033[36m'; BOLD=$'\033[1m'; DIM=$'\033[2m'; RESET=$'\033[0m'
    else
        RED=""; GREEN=""; YELLOW=""; BLUE=""; CYAN=""; BOLD=""; DIM=""; RESET=""
    fi
}

# emit: print a line to the terminal and (colour-stripped) to the report file
emit() {
    printf '%s\n' "$1"
    if [[ -n "$REPORT_FILE" ]]; then
        printf '%s\n' "$1" | sed 's/\x1b\[[0-9;]*m//g' >> "$REPORT_FILE"
    fi
}

# section_header <title>
section_header() {
    emit ""
    emit "${BOLD}${CYAN}>> $1${RESET}"
    emit "${DIM}------------------------------------------------------------${RESET}"
}

# result <PASS|WARN|FAIL|INFO> <message> [remediation hint]
result() {
    local status="$1" msg="$2" hint="${3:-}" tag
    case "$status" in
        PASS) PASS=$((PASS + 1)); tag="${GREEN}[ PASS ]${RESET}" ;;
        WARN) WARN=$((WARN + 1)); tag="${YELLOW}[ WARN ]${RESET}" ;;
        FAIL) FAIL=$((FAIL + 1)); tag="${RED}[ FAIL ]${RESET}" ;;
        *)    INFO=$((INFO + 1)); tag="${BLUE}[ INFO ]${RESET}" ;;
    esac
    # In quiet mode skip PASS/INFO output (they are still counted)
    if [[ $QUIET -eq 1 && ( "$status" == "PASS" || "$status" == "INFO" ) ]]; then return; fi
    emit "  ${tag} ${msg}"
    if [[ -n "$hint" && ( "$status" == "WARN" || "$status" == "FAIL" ) ]]; then
        emit "           ${DIM}-> Fix: ${hint}${RESET}"
    fi
}

# detail <text> : indented supporting line under a finding
detail() { emit "           ${DIM}$1${RESET}"; }

# find_limited: run find with a time limit so huge filesystems cannot hang us
find_limited() {
    if have timeout; then timeout 90 find "$@" 2>/dev/null; else find "$@" 2>/dev/null; fi
}

# ----------------------------- Check sections -------------------------------

check_system() {
    section_header "SYSTEM INFORMATION"
    local os kernel up
    # Parse (do NOT source) os-release: sourcing would overwrite our readonly VERSION
    os=$(grep -m1 '^PRETTY_NAME=' /etc/os-release 2>/dev/null | cut -d= -f2- | tr -d '"')
    os=${os:-unknown}
    kernel=$(uname -r)
    up=$(uptime -p 2>/dev/null || echo "n/a")
    result INFO "Hostname : $(hostname 2>/dev/null || echo unknown)"
    result INFO "OS       : ${os}"
    result INFO "Kernel   : ${kernel} ($(uname -m))"
    result INFO "Uptime   : ${up}"
    result INFO "Run as   : $(id -un) (uid $(id -u))"
    if [[ $IS_ROOT -eq 0 ]]; then
        result WARN "Not running as root - some checks will be limited" "re-run with sudo for a complete audit"
    fi
}

check_accounts() {
    section_header "USER ACCOUNTS & AUTHENTICATION"
    local out

    # 1. Only root should have UID 0
    out=$(awk -F: '($3==0 && $1!="root"){print $1}' /etc/passwd 2>/dev/null | paste -sd, -)
    if [[ -n "$out" ]]; then
        result FAIL "Extra accounts with UID 0 (root privileges): ${out}" "remove or change the UID of these accounts"
    else
        result PASS "Only 'root' has UID 0"
    fi

    # 2. Duplicate UIDs
    out=$(cut -d: -f3 /etc/passwd 2>/dev/null | sort | uniq -d | paste -sd, -)
    if [[ -n "$out" ]]; then
        result WARN "Duplicate UIDs found: ${out}" "give each account a unique UID"
    else
        result PASS "No duplicate UIDs"
    fi

    # 3. Empty passwords (needs read access to /etc/shadow)
    if [[ -r /etc/shadow ]]; then
        out=$(awk -F: '($2==""){print $1}' /etc/shadow | paste -sd, -)
        if [[ -n "$out" ]]; then
            result FAIL "Accounts with EMPTY passwords: ${out}" "set a password or lock: passwd -l <user>"
        else
            result PASS "No accounts with empty passwords"
        fi
    else
        result INFO "Skipped empty-password check (/etc/shadow not readable - use sudo)"
    fi

    # 4. Password ageing policy
    if [[ -r /etc/login.defs ]]; then
        local maxdays
        maxdays=$(awk '$1=="PASS_MAX_DAYS"{print $2}' /etc/login.defs)
        if [[ "$maxdays" =~ ^[0-9]+$ && "$maxdays" -le 365 ]]; then
            result PASS "Password maximum age is ${maxdays} days"
        else
            result WARN "Password expiry not enforced (PASS_MAX_DAYS=${maxdays:-unset})" "set PASS_MAX_DAYS in /etc/login.defs"
        fi
    fi

    # 5. Passwordless sudo
    if [[ -r /etc/sudoers ]]; then
        out=$(grep -rEsh '^[^#]*NOPASSWD' /etc/sudoers /etc/sudoers.d 2>/dev/null | head -n 3)
        if [[ -n "$out" ]]; then
            result WARN "Passwordless sudo (NOPASSWD) rules present" "review with: visudo"
            while IFS= read -r line; do detail "$line"; done <<< "$out"
        else
            result PASS "No NOPASSWD sudo rules"
        fi
    else
        result INFO "Skipped sudoers check (not readable - use sudo)"
    fi

    # 6. Interactive login accounts (informational)
    out=$(awk -F: '($7 !~ /(nologin|false)$/ && $7 != ""){print $1}' /etc/passwd 2>/dev/null | paste -sd, -)
    result INFO "Accounts with an interactive shell: ${out:-none}"
}

# check_file_mode <file> <max-octal-mode> : mode must not be MORE permissive than max
check_file_mode() {
    local f="$1" max="$2" mode owner
    [[ -e "$f" ]] || return 0
    mode=$(stat -c '%a' "$f" 2>/dev/null) || return 0
    owner=$(stat -c '%U' "$f" 2>/dev/null)
    if (( (8#$mode & ~8#$max) != 0 )); then
        result FAIL "${f} is too permissive (mode ${mode}, expected <= ${max})" "chmod ${max} ${f}"
    elif [[ "$owner" != "root" ]]; then
        result FAIL "${f} is owned by '${owner}' instead of root" "chown root ${f}"
    else
        result PASS "${f} permissions OK (${mode}, owner ${owner})"
    fi
}

check_permissions() {
    section_header "CRITICAL FILE PERMISSIONS"
    check_file_mode /etc/passwd 644
    check_file_mode /etc/group 644
    check_file_mode /etc/shadow 640
    check_file_mode /etc/gshadow 640
    check_file_mode /etc/sudoers 440
    check_file_mode /etc/ssh/sshd_config 644
    check_file_mode /etc/crontab 644
}

# ssh_val <keyword> : effective value of an sshd option (lower-case), or empty
ssh_val() {
    local key="$1" v=""
    if [[ $IS_ROOT -eq 1 ]] && have sshd; then
        v=$(sshd -T 2>/dev/null | awk -v k="${key,,}" '$1==k{print $2; exit}')
    fi
    if [[ -z "$v" ]]; then
        v=$(grep -hiE "^[[:space:]]*${key}[[:space:]]+" /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*.conf 2>/dev/null \
            | head -n1 | awk '{print tolower($2)}')
    fi
    printf '%s' "$v"
}

check_ssh() {
    section_header "SSH SERVER CONFIGURATION"
    if [[ ! -f /etc/ssh/sshd_config ]]; then
        result INFO "OpenSSH server is not installed (no /etc/ssh/sshd_config) - nothing to check"
        return
    fi
    local v

    v=$(ssh_val PermitRootLogin)
    case "$v" in
        no|prohibit-password|without-password|forced-commands-only) result PASS "Root login over SSH is restricted (${v})" ;;
        yes) result FAIL "Root login over SSH is ENABLED" "set 'PermitRootLogin no' in sshd_config" ;;
        *)   result WARN "PermitRootLogin not set explicitly (default varies by version)" "set 'PermitRootLogin no'" ;;
    esac

    v=$(ssh_val PasswordAuthentication)
    if [[ "$v" == "no" ]]; then
        result PASS "Password authentication disabled (key-based only)"
    else
        result WARN "Password authentication is enabled (${v:-default yes})" "use keys and set 'PasswordAuthentication no'"
    fi

    v=$(ssh_val PermitEmptyPasswords)
    if [[ "$v" == "yes" ]]; then
        result FAIL "Empty passwords are permitted over SSH" "set 'PermitEmptyPasswords no'"
    else
        result PASS "Empty SSH passwords not permitted"
    fi

    v=$(ssh_val MaxAuthTries)
    if [[ "$v" =~ ^[0-9]+$ && "$v" -le 4 ]]; then
        result PASS "MaxAuthTries is ${v}"
    else
        result WARN "MaxAuthTries is ${v:-default (6)} (recommended <= 4)" "set 'MaxAuthTries 3'"
    fi

    v=$(ssh_val X11Forwarding)
    if [[ "$v" == "yes" ]]; then
        result WARN "X11 forwarding enabled" "set 'X11Forwarding no' unless needed"
    else
        result PASS "X11 forwarding disabled"
    fi

    v=$(ssh_val Port)
    result INFO "SSH listens on port ${v:-22}"
}

check_network() {
    section_header "NETWORK EXPOSURE & FIREWALL"
    local listeners
    if have ss; then
        listeners=$(ss -tuln 2>/dev/null | awk 'NR>1{print $1, $5}')
    elif have netstat; then
        listeners=$(netstat -tuln 2>/dev/null | awk 'NR>2{print $1, $4}')
    else
        result INFO "Neither 'ss' nor 'netstat' found - skipping port check"
        listeners=""
    fi

    if [[ -n "$listeners" ]]; then
        local exposed=() risky=() proto addr host port name
        while read -r proto addr; do
            [[ -z "${addr:-}" ]] && continue
            port="${addr##*:}"; host="${addr%:*}"
            case "$host" in
                127.*|"[::1]"|"::1") continue ;;      # loopback only: not exposed
            esac
            exposed+=("${proto%%[0-9]*}/${port}")
            case "$port" in
                21) name="FTP (cleartext)" ;;   23) name="Telnet (cleartext)" ;;
                69) name="TFTP" ;;              111) name="rpcbind" ;;
                512|513|514) name="r-services" ;; 2049) name="NFS" ;;
                3306) name="MySQL" ;;           3389) name="RDP" ;;
                5900) name="VNC" ;;             6379) name="Redis" ;;
                11211) name="Memcached" ;;      27017) name="MongoDB" ;;
                *) name="" ;;
            esac
            [[ -n "$name" ]] && risky+=("${port}=${name}")
        done <<< "$listeners"

        local uniq_exposed
        uniq_exposed=$(printf '%s\n' "${exposed[@]:-}" | sort -u | paste -sd' ' -)
        result INFO "Ports reachable from the network: ${uniq_exposed:-none}"
        if [[ ${#risky[@]} -gt 0 ]]; then
            result FAIL "Risky services exposed: $(printf '%s\n' "${risky[@]}" | sort -u | paste -sd, -)" \
                "disable the service or bind it to 127.0.0.1 / firewall it"
        else
            result PASS "No commonly-abused services exposed on all interfaces"
        fi
    fi

    # Firewall detection
    local fw=""
    if have ufw && [[ $IS_ROOT -eq 1 ]]; then
        fw=$(ufw status 2>/dev/null | head -n1)
        [[ "$fw" == *"active"* && "$fw" != *"inactive"* ]] && result PASS "UFW firewall is active" \
            || result FAIL "UFW firewall is inactive" "sudo ufw enable"
    elif have firewall-cmd; then
        if firewall-cmd --state >/dev/null 2>&1; then result PASS "firewalld is running"
        else result FAIL "firewalld is not running" "sudo systemctl enable --now firewalld"; fi
    elif have nft && [[ $IS_ROOT -eq 1 ]]; then
        local n; n=$(nft list ruleset 2>/dev/null | grep -c 'rule\|accept\|drop' || true)
        [[ "${n:-0}" -gt 0 ]] && result PASS "nftables ruleset present" \
            || result WARN "No nftables rules loaded" "configure a firewall (ufw / nftables)"
    elif have iptables && [[ $IS_ROOT -eq 1 ]]; then
        local n; n=$(iptables -S 2>/dev/null | grep -vc '^-P' || true)
        [[ "${n:-0}" -gt 0 ]] && result PASS "iptables has ${n} rule(s)" \
            || result WARN "iptables has no rules" "configure a firewall (ufw / nftables)"
    else
        result INFO "Could not determine firewall status (need root or no firewall tool installed)"
    fi
}

check_filesystem() {
    section_header "FILESYSTEM RISKS"
    local roots_ww=(/etc /usr/bin /usr/sbin /bin /sbin /usr/lib)
    local roots_suid=(/usr /bin /sbin)
    if [[ $DEEP -eq 1 ]]; then
        roots_ww=(/etc /usr /bin /sbin /var /opt /home /root)
        roots_suid=(/)
        result INFO "Deep scan enabled - this may take a while"
    fi

    # /tmp sticky bit
    if [[ -k /tmp ]]; then result PASS "/tmp has the sticky bit set"
    else result FAIL "/tmp is missing the sticky bit" "chmod +t /tmp"; fi

    # World-writable files in system directories
    local ww
    ww=$(find_limited "${roots_ww[@]}" -xdev -type f -perm -0002 | head -n 10)
    if [[ -n "$ww" ]]; then
        result FAIL "World-writable files found in system directories" "chmod o-w <file>"
        while IFS= read -r f; do detail "$f"; done <<< "$ww"
    else
        result PASS "No world-writable files in system directories"
    fi

    # SUID binaries not on the well-known list
    local known=" sudo su passwd chsh chfn gpasswd newgrp mount umount ping ping6 pkexec fusermount fusermount3 \
ssh-keysign chage expiry unix_chkpwd crontab at dbus-daemon-launch-helper polkit-agent-helper-1 \
Xorg.wrap mount.nfs traceroute6.iputils sudoedit ksu vmware-user-suid-wrapper snap-confine newuidmap newgidmap dumpcap chrome-sandbox pppd auth_pam_tool "
    local suid_all suid_odd="" f b count
    suid_all=$(find_limited "${roots_suid[@]}" -xdev -type f -perm -4000)
    count=$(printf '%s\n' "$suid_all" | grep -c . || true)
    while IFS= read -r f; do
        [[ -z "$f" ]] && continue
        b="${f##*/}"
        [[ "$known" == *" $b "* ]] || suid_odd+="${f}"$'\n'
    done <<< "$suid_all"
    result INFO "SUID binaries found: ${count}"
    if [[ -n "$suid_odd" ]]; then
        result WARN "Uncommon SUID binaries (review for privilege escalation)" "remove with: chmod u-s <file>"
        printf '%s' "$suid_odd" | head -n 8 | while IFS= read -r f; do detail "$f"; done
    else
        result PASS "All SUID binaries are on the common/expected list"
    fi

    # Orphaned files (deep only)
    if [[ $DEEP -eq 1 ]]; then
        local orphans
        orphans=$(find_limited /etc /usr /var /home -xdev \( -nouser -o -nogroup \) | head -n 5)
        if [[ -n "$orphans" ]]; then
            result WARN "Files without a valid owner/group"
            while IFS= read -r f; do detail "$f"; done <<< "$orphans"
        else
            result PASS "No orphaned files"
        fi
    fi
}

check_updates() {
    section_header "PATCH STATUS"
    local n sec
    if have apt-get; then
        n=$(apt-get -s upgrade 2>/dev/null | grep -c '^Inst' || true)
        sec=$(apt-get -s upgrade 2>/dev/null | grep '^Inst' | grep -ci 'security' || true)
        if [[ "${n:-0}" -eq 0 ]]; then result PASS "No pending package updates (per local apt cache)"
        elif [[ "${sec:-0}" -gt 0 ]]; then result FAIL "${n} pending updates, ${sec} security-related" "sudo apt update && sudo apt upgrade"
        else result WARN "${n} pending package updates" "sudo apt update && sudo apt upgrade"; fi
    elif have dnf; then
        n=$(dnf -q check-update 2>/dev/null | grep -cE '^[A-Za-z0-9_.+-]+\.[a-z0-9_]+ ' || true)
        [[ "${n:-0}" -eq 0 ]] && result PASS "No pending updates" \
            || result WARN "${n} pending updates" "sudo dnf upgrade"
    else
        result INFO "No supported package manager (apt/dnf) detected"
    fi
    if [[ -f /var/run/reboot-required ]]; then
        result WARN "A reboot is required to finish applying updates" "schedule a reboot"
    fi
}

check_logs() {
    section_header "AUTHENTICATION LOG ANALYSIS"
    local logfile="" data=""
    for f in /var/log/auth.log /var/log/secure; do
        [[ -r "$f" ]] && { logfile="$f"; break; }
    done
    if [[ -n "$logfile" ]]; then
        data=$(cat "$logfile" 2>/dev/null)
    elif have journalctl; then
        data=$(journalctl -q --no-pager -t sshd -t sshd-session -n 20000 2>/dev/null)
        logfile="journalctl"
    fi
    if [[ -z "$data" ]]; then
        result INFO "No readable authentication log (try sudo)"
        return
    fi
    local failed invalid
    failed=$(grep -c 'Failed password' <<< "$data" || true)
    invalid=$(grep -c 'Invalid user' <<< "$data" || true)
    result INFO "Source: ${logfile}"
    if   [[ "${failed:-0}" -gt 100 ]]; then result FAIL "${failed} failed SSH password attempts (possible brute force)" "install fail2ban, disable password auth"
    elif [[ "${failed:-0}" -gt 10  ]]; then result WARN "${failed} failed SSH password attempts" "monitor and consider fail2ban"
    else result PASS "Failed SSH logins are low (${failed:-0})"; fi
    result INFO "Attempts against non-existent users: ${invalid:-0}"

    local top
    top=$(grep -E 'Failed password|Invalid user' <<< "$data" \
          | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' | sort | uniq -c | sort -rn | head -n 5)
    if [[ -n "$top" && $QUIET -eq 0 ]]; then
        detail "Top offending source IPs (count IP):"
        while IFS= read -r line; do detail "  $line"; done <<< "$top"
    fi
}

# check_sysctl <key> <expected|alt> <description> [note] : compare /proc/sys value
# "expected" may list several acceptable values separated by | (e.g. "1|2")
check_sysctl() {
    local key="$1" expected="$2" desc="$3" note="${4:-}" path val
    path="/proc/sys/${key//.//}"
    [[ -r "$path" ]] || return 0
    val=$(tr -s '[:space:]' ' ' < "$path" | sed 's/ $//')
    if [[ "|${expected}|" == *"|${val}|"* ]]; then
        result PASS "${desc} (${key}=${val})"
    else
        result WARN "${desc}: NOT met (${key}=${val}, expected ${expected//|/ or })" \
            "sysctl -w ${key}=${expected%%|*}${note:+  ($note)}"
    fi
}

check_kernel() {
    section_header "KERNEL HARDENING"
    check_sysctl kernel.randomize_va_space 2 "ASLR fully enabled"
    check_sysctl net.ipv4.tcp_syncookies 1 "SYN-flood protection"
    check_sysctl net.ipv4.ip_forward 0 "IP forwarding disabled" "expected =1 on Docker/VM/VPN/router hosts"
    check_sysctl net.ipv4.conf.all.accept_redirects 0 "ICMP redirects ignored"
    check_sysctl net.ipv4.conf.all.rp_filter "1|2" "Reverse-path filtering (strict or loose)"
    check_sysctl fs.suid_dumpable 0 "No core dumps from SUID programs"
    check_sysctl kernel.dmesg_restrict 1 "dmesg restricted to root"
}

check_services() {
    section_header "SERVICES & SECURITY CONTROLS"
    if ! have systemctl; then result INFO "systemd not available - skipping"; return; fi

    # Legacy / insecure services that should not be running
    local svc found=()
    for svc in telnet telnetd telnet.socket rsh.socket rlogin.socket vsftpd tftpd-hpa xinetd rpcbind nfs-server avahi-daemon; do
        systemctl is-active --quiet "$svc" 2>/dev/null && found+=("$svc")
    done
    if [[ ${#found[@]} -gt 0 ]]; then
        result WARN "Legacy/risky services running: ${found[*]}" "systemctl disable --now <service>"
    else
        result PASS "No legacy/insecure services running"
    fi

    # Protective controls
    if systemctl is-active --quiet fail2ban 2>/dev/null; then result PASS "fail2ban is running"
    else result INFO "fail2ban is not running (optional brute-force protection)"; fi

    if have getenforce; then
        local se; se=$(getenforce 2>/dev/null)
        [[ "$se" == "Enforcing" ]] && result PASS "SELinux is Enforcing" || result WARN "SELinux mode: ${se}" "setenforce 1"
    elif have aa-status && [[ $IS_ROOT -eq 1 ]]; then
        aa-status --enabled 2>/dev/null && result PASS "AppArmor is enabled" || result WARN "AppArmor is not enabled"
    elif [[ -d /sys/kernel/security/apparmor ]]; then
        result PASS "AppArmor is present"
    else
        result INFO "No mandatory access control (SELinux/AppArmor) detected"
    fi
}

# ----------------------------- Summary --------------------------------------
print_summary() {
    local total=$((PASS + WARN + FAIL)) score=0 grade colour
    if [[ $total -gt 0 ]]; then score=$(( (PASS * 100 + WARN * 50) / total )); fi
    if   [[ $score -ge 90 ]]; then grade="A"; colour="$GREEN"
    elif [[ $score -ge 75 ]]; then grade="B"; colour="$GREEN"
    elif [[ $score -ge 60 ]]; then grade="C"; colour="$YELLOW"
    elif [[ $score -ge 40 ]]; then grade="D"; colour="$YELLOW"
    else grade="F"; colour="$RED"; fi

    local filled=$((score / 5)) bar="" i
    for ((i = 0; i < 20; i++)); do [[ $i -lt $filled ]] && bar+="#" || bar+="."; done

    emit ""
    emit "${BOLD}============================================================${RESET}"
    emit "${BOLD} AUDIT SUMMARY${RESET}"
    emit "${BOLD}============================================================${RESET}"
    emit "  ${GREEN}PASS: ${PASS}${RESET}   ${YELLOW}WARN: ${WARN}${RESET}   ${RED}FAIL: ${FAIL}${RESET}   ${BLUE}INFO: ${INFO}${RESET}"
    emit "  Security score : ${colour}${BOLD}${score}/100  (grade ${grade})${RESET}  [${bar}]"
    if [[ $FAIL -gt 0 ]]; then
        emit "  ${RED}Action needed:${RESET} fix the FAIL items first, then the WARN items."
    else
        emit "  ${GREEN}No critical failures detected.${RESET} Review WARN items to harden further."
    fi
    [[ -n "$REPORT_FILE" ]] && emit "  Report saved to: ${REPORT_FILE}"
    emit ""
}

# ----------------------------- Argument parsing -----------------------------
parse_args() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            -h|--help)    usage; exit 0 ;;
            -V|--version) echo "LinuxSec Audit v${VERSION}"; exit 0 ;;
            -l|--list)    printf '%s\n' "${ALL_SECTIONS[@]}"; exit 0 ;;
            -s|--section) [[ $# -ge 2 ]] || die "option $1 needs a value"; SECTIONS="$2"; shift 2 ;;
            -o|--output)  [[ $# -ge 2 ]] || die "option $1 needs a file name"; REPORT_FILE="$2"; shift 2 ;;
            -d|--deep)    DEEP=1; shift ;;
            -q|--quiet)   QUIET=1; shift ;;
            --no-color)   USE_COLOR=0; shift ;;
            --color)      FORCE_COLOR=1; shift ;;
            *)            die "unknown option: $1" ;;
        esac
    done

    # Validate requested sections
    if [[ "$SECTIONS" != "all" ]]; then
        local s ok x
        IFS=',' read -ra req <<< "$SECTIONS"
        for s in "${req[@]}"; do
            ok=0
            for x in "${ALL_SECTIONS[@]}"; do [[ "$s" == "$x" ]] && ok=1; done
            [[ $ok -eq 1 ]] || die "unknown section '${s}' (use --list to see valid names)"
        done
    fi

    # Validate the report file location before doing any work
    if [[ -n "$REPORT_FILE" ]]; then
        { : > "$REPORT_FILE"; } 2>/dev/null || die "cannot write report file: ${REPORT_FILE}"
    fi
}

# want <section> : should this section run?
want() { [[ "$SECTIONS" == "all" || ",${SECTIONS}," == *",$1,"* ]]; }

# ----------------------------- Main -----------------------------------------
main() {
    parse_args "$@"
    [[ "$(uname -s)" == "Linux" ]] || die "this tool supports Linux only"
    setup_colors

    emit "${BOLD}${CYAN}"
    emit "  _     _                  ____            "
    emit " | |   (_)_ __  _   ___  _/ ___|  ___  ___ "
    emit " | |   | | '_ \\| | | \\ \\/ /\\___ \\ / _ \\/ __|"
    emit " | |___| | | | | |_| |>  <  ___) |  __/ (__ "
    emit " |_____|_|_| |_|\\__,_/_/\\_\\|____/ \\___|\\___|  Audit v${VERSION}"
    emit "${RESET}${DIM} IqraSec Academy | read-only Linux security checker${RESET}"
    emit " Started : $(date '+%Y-%m-%d %H:%M:%S %Z')"

    local s
    for s in "${ALL_SECTIONS[@]}"; do
        want "$s" && "check_${s}"
    done

    print_summary
    [[ $FAIL -gt 0 ]] && exit 1
    exit 0
}

main "$@"
