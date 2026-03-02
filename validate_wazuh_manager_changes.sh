#!/usr/bin/env bash
# =============================================================================
# Wazuh Manager Package Changes Validation Script
# =============================================================================
# Validates all changes described in tareas.md:
#   1. Installation directory (/var/ossec -> /var/wazuh-manager)
#   2. Manager daemon binary names (wazuh-* -> wazuh-manager-*)
#   3. Python script names (API/Framework)
#   4. Configuration file names
#   5. XML root tag (<ossec_config> -> <wazuh_config>)
#   6. Certificate file names (server.* -> manager.*)
#   7. Log file names (ossec.* -> wazuh-manager.*)
#   8. System user and group (wazuh -> wazuh-manager)
#   9. File/directory permissions and ownership
#  10. Terminology: "server" -> "manager" in config and templates
#  11. Residual "ossec" references (names, content, system, processes)
# =============================================================================

set -euo pipefail

# ---------------------------------------------------------------------------
# Color codes
# ---------------------------------------------------------------------------
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[1;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
RESET='\033[0m'

# ---------------------------------------------------------------------------
# Counters
# ---------------------------------------------------------------------------
PASS=0
FAIL=0
WARN=0
SKIP=0

# ---------------------------------------------------------------------------
# Files
# ---------------------------------------------------------------------------
REPORT_FILE="/tmp/wazuh_validation_report_$(date +%Y%m%d_%H%M%S).md"
ROWS_TSV=$(mktemp /tmp/wazuh_rows_XXXXXX.tsv)
trap 'rm -f "$ROWS_TSV"' EXIT
WAZUH_HOME="/var/wazuh-manager"

# ---------------------------------------------------------------------------
# Section tracking
# ---------------------------------------------------------------------------
CURRENT_SECTION="General"
CURRENT_SUBSECTION=""

# ---------------------------------------------------------------------------
# Internal: write one TSV row
# Columns: section | subsection | test | expected | got | result
# ---------------------------------------------------------------------------
_row() {
    local result="$1"
    local test="${2//$'\t'/ }"
    local expected="${3//$'\t'/ }"
    local got="${4//$'\t'/ }"
    printf '%s\t%s\t%s\t%s\t%s\t%s\n' \
        "$CURRENT_SECTION" "$CURRENT_SUBSECTION" \
        "$test" "$expected" "$got" "$result" >> "$ROWS_TSV"
}

# ---------------------------------------------------------------------------
# Section / subsection headers  (console only — no direct file writes)
# ---------------------------------------------------------------------------
log_section() {
    local msg="$1"
    CURRENT_SECTION="$msg"
    CURRENT_SUBSECTION=""
    echo ""
    echo -e "${BLUE}${BOLD}════════════════════════════════════════════════════════${RESET}"
    echo -e "${BLUE}${BOLD}  $msg${RESET}"
    echo -e "${BLUE}${BOLD}════════════════════════════════════════════════════════${RESET}"
}

log_subsection() {
    local msg="$1"
    CURRENT_SUBSECTION="$msg"
    echo -e "\n${CYAN}${BOLD}--- $msg ---${RESET}"
}

# ---------------------------------------------------------------------------
# Result reporters  (accept optional expected / got for richer tables)
# ---------------------------------------------------------------------------
pass() {
    local msg="$1"; local expected="${2:--}"; local got="${3:--}"
    echo -e "  ${GREEN}[PASS]${RESET} $msg"
    _row "PASS" "$msg" "$expected" "$got"
    PASS=$((PASS + 1))
}

fail() {
    local msg="$1"; local expected="${2:--}"; local got="${3:--}"
    echo -e "  ${RED}[FAIL]${RESET} $msg"
    _row "FAIL" "$msg" "$expected" "$got"
    FAIL=$((FAIL + 1))
}

warn() {
    local msg="$1"; local expected="${2:--}"; local got="${3:--}"
    echo -e "  ${YELLOW}[WARN]${RESET} $msg"
    _row "WARN" "$msg" "$expected" "$got"
    WARN=$((WARN + 1))
}

skip() {
    local msg="$1"; local expected="${2:--}"; local got="${3:--}"
    echo -e "  ${YELLOW}[SKIP]${RESET} $msg"
    _row "SKIP" "$msg" "$expected" "$got"
    SKIP=$((SKIP + 1))
}

info() {
    local msg="$1"
    echo -e "  ${BOLD}[INFO]${RESET} $msg"
    # console-only; not a check result
}

# ---------------------------------------------------------------------------
# check_exists / check_not_exists
# ---------------------------------------------------------------------------
check_exists() {
    local path="$1"; local label="${2:-$path}"
    if [[ -e "$path" ]]; then
        echo -e "  ${GREEN}[PASS]${RESET} Exists:  $label"
        _row "PASS" "$label" "exists" "exists"
        PASS=$((PASS + 1))
    else
        echo -e "  ${RED}[FAIL]${RESET} Missing: $label"
        _row "FAIL" "$label" "exists" "missing"
        FAIL=$((FAIL + 1))
    fi
}

check_not_exists() {
    local path="$1"; local label="${2:-$path}"
    if [[ ! -e "$path" ]]; then
        echo -e "  ${GREEN}[PASS]${RESET} Absent (expected): $label"
        _row "PASS" "$label" "absent" "absent"
        PASS=$((PASS + 1))
    else
        echo -e "  ${RED}[FAIL]${RESET} Still present (should be gone): $label"
        _row "FAIL" "$label" "absent" "present"
        FAIL=$((FAIL + 1))
    fi
}

# ---------------------------------------------------------------------------
# check_entry: combined ownership + permissions
# ---------------------------------------------------------------------------
check_entry() {
    local path="$1"; local owner="$2"; local group="$3"; local mode="$4"
    if [[ ! -e "$path" ]]; then
        echo -e "  ${YELLOW}[SKIP]${RESET} Not found: $path"
        _row "SKIP" "$path" "$owner:$group $mode" "not found"
        SKIP=$((SKIP + 1)); return
    fi
    local ao ag am
    ao=$(stat -c '%U' "$path")
    ag=$(stat -c '%G' "$path")
    am=$(stat -c '%a' "$path")
    local exp="$owner:$group $mode"
    local got="$ao:$ag $am"
    if [[ "$ao" == "$owner" && "$ag" == "$group" && "$am" == "$mode" ]]; then
        echo -e "  ${GREEN}[PASS]${RESET} $exp  →  $path"
        _row "PASS" "$path" "$exp" "$got"
        PASS=$((PASS + 1))
    else
        echo -e "  ${RED}[FAIL]${RESET} Mismatch: $path"
        echo -e "  ${BOLD}[INFO]${RESET}   Expected: $exp"
        echo -e "  ${BOLD}[INFO]${RESET}   Got:      $got"
        _row "FAIL" "$path" "$exp" "$got"
        FAIL=$((FAIL + 1))
    fi
}

# ---------------------------------------------------------------------------
# check_ownership (standalone)
# ---------------------------------------------------------------------------
check_ownership() {
    local path="$1"; local exp_owner="$2"; local exp_group="$3"
    if [[ ! -e "$path" ]]; then
        echo -e "  ${YELLOW}[SKIP]${RESET} Not found: $path"
        _row "SKIP" "$path" "$exp_owner:$exp_group" "not found"
        SKIP=$((SKIP + 1)); return
    fi
    local ao ag
    ao=$(stat -c '%U' "$path"); ag=$(stat -c '%G' "$path")
    if [[ "$ao" == "$exp_owner" && "$ag" == "$exp_group" ]]; then
        echo -e "  ${GREEN}[PASS]${RESET} Ownership $exp_owner:$exp_group  →  $path"
        _row "PASS" "$path" "$exp_owner:$exp_group" "$ao:$ag"
        PASS=$((PASS + 1))
    else
        echo -e "  ${RED}[FAIL]${RESET} Ownership mismatch: $path (expected: $exp_owner:$exp_group  got: $ao:$ag)"
        _row "FAIL" "$path" "$exp_owner:$exp_group" "$ao:$ag"
        FAIL=$((FAIL + 1))
    fi
}

# ---------------------------------------------------------------------------
# check_perms (standalone)
# ---------------------------------------------------------------------------
check_perms() {
    local path="$1"; local exp_mode="$2"
    if [[ ! -e "$path" ]]; then
        echo -e "  ${YELLOW}[SKIP]${RESET} Not found: $path"
        _row "SKIP" "$path" "mode=$exp_mode" "not found"
        SKIP=$((SKIP + 1)); return
    fi
    local am; am=$(stat -c '%a' "$path")
    if [[ "$am" == "$exp_mode" ]]; then
        echo -e "  ${GREEN}[PASS]${RESET} Mode $exp_mode  →  $path"
        _row "PASS" "$path" "mode=$exp_mode" "mode=$am"
        PASS=$((PASS + 1))
    else
        echo -e "  ${RED}[FAIL]${RESET} Mode mismatch: $path (expected: $exp_mode  got: $am)"
        _row "FAIL" "$path" "mode=$exp_mode" "mode=$am"
        FAIL=$((FAIL + 1))
    fi
}

# ---------------------------------------------------------------------------
# check_contains / check_not_contains
# ---------------------------------------------------------------------------
check_contains() {
    local path="$1"; local pattern="$2"; local label="${3:-$pattern}"
    if [[ ! -f "$path" ]]; then
        echo -e "  ${YELLOW}[SKIP]${RESET} File not found: $path"
        _row "SKIP" "$label in $(basename "$path")" "pattern present" "file not found"
        SKIP=$((SKIP + 1)); return
    fi
    if grep -qE "$pattern" "$path" 2>/dev/null; then
        echo -e "  ${GREEN}[PASS]${RESET} Pattern found '$label'  in $path"
        _row "PASS" "$label in $(basename "$path")" "pattern present" "present"
        PASS=$((PASS + 1))
    else
        echo -e "  ${RED}[FAIL]${RESET} Pattern NOT found '$label'  in $path"
        _row "FAIL" "$label in $(basename "$path")" "pattern present" "absent"
        FAIL=$((FAIL + 1))
    fi
}

check_not_contains() {
    local path="$1"; local pattern="$2"; local label="${3:-$pattern}"
    if [[ ! -f "$path" ]]; then
        echo -e "  ${YELLOW}[SKIP]${RESET} File not found: $path"
        _row "SKIP" "$label in $(basename "$path")" "pattern absent" "file not found"
        SKIP=$((SKIP + 1)); return
    fi
    if ! grep -qE "$pattern" "$path" 2>/dev/null; then
        echo -e "  ${GREEN}[PASS]${RESET} Pattern absent '$label'  in $path"
        _row "PASS" "$label in $(basename "$path")" "pattern absent" "absent"
        PASS=$((PASS + 1))
    else
        echo -e "  ${RED}[FAIL]${RESET} Pattern still present '$label'  in $path"
        _row "FAIL" "$label in $(basename "$path")" "pattern absent" "present"
        FAIL=$((FAIL + 1))
    fi
}

# ---------------------------------------------------------------------------
# check_glob_exists / check_glob_entries
# ---------------------------------------------------------------------------
check_glob_exists() {
    local pattern="$1"; local label="${2:-$pattern}"
    if compgen -G "$pattern" &>/dev/null; then
        echo -e "  ${GREEN}[PASS]${RESET} Glob match found: $label"
        _row "PASS" "glob: $label" "match exists" "match found"
        PASS=$((PASS + 1))
    else
        echo -e "  ${RED}[FAIL]${RESET} No files matching: $label"
        _row "FAIL" "glob: $label" "match exists" "no match"
        FAIL=$((FAIL + 1))
    fi
}

check_glob_entries() {
    local glob_pattern="$1"; local owner="$2"; local group="$3"; local mode="$4"
    local files
    files=$(compgen -G "$glob_pattern" 2>/dev/null || true)
    if [[ -z "$files" ]]; then
        echo -e "  ${YELLOW}[SKIP]${RESET} No files matched: $glob_pattern"
        _row "SKIP" "glob: $glob_pattern" "$owner:$group $mode" "no files matched"
        SKIP=$((SKIP + 1)); return
    fi
    while IFS= read -r f; do
        check_entry "$f" "$owner" "$group" "$mode"
    done <<< "$files"
}

# ---------------------------------------------------------------------------
# Markdown report generator (called at the very end)
# ---------------------------------------------------------------------------
generate_markdown_report() {
    python3 - "$ROWS_TSV" "$REPORT_FILE" \
        "$(hostname)" "$(uname -r)" "$(date)" \
        "$PASS" "$FAIL" "$WARN" "$SKIP" << 'PYEOF'
import sys
from collections import OrderedDict

tsv_file, report_file, host, kernel, gen_date, \
    pass_c, fail_c, warn_c, skip_c = sys.argv[1:]
pass_c, fail_c, warn_c, skip_c = int(pass_c), int(fail_c), int(warn_c), int(skip_c)
total = pass_c + fail_c + warn_c + skip_c

rows = []
with open(tsv_file, encoding='utf-8', errors='replace') as f:
    for line in f:
        parts = line.rstrip('\n').split('\t')
        if len(parts) == 6:
            rows.append({
                'section':    parts[0],
                'subsection': parts[1],
                'test':       parts[2],
                'expected':   parts[3],
                'got':        parts[4],
                'result':     parts[5],
            })

ICONS = {'PASS': '✅', 'FAIL': '❌', 'WARN': '⚠️', 'SKIP': '⏭️'}

def esc(s):
    return s.replace('|', '\\|').replace('\n', ' ')

# Build structure: section -> subsection -> [rows]  (insertion-ordered)
sections = OrderedDict()
for row in rows:
    sec = row['section']
    sub = row['subsection']
    if sec not in sections:
        sections[sec] = OrderedDict()
    if sub not in sections[sec]:
        sections[sec][sub] = []
    sections[sec][sub].append(row)

with open(report_file, 'w', encoding='utf-8') as f:

    # ── Header ───────────────────────────────────────────────────────────────
    f.write('# Wazuh Manager Package Changes – Validation Report\n\n')
    f.write('| | |\n|---|---|\n')
    f.write(f'| **Generated** | {gen_date} |\n')
    f.write(f'| **Host**      | {host} |\n')
    f.write(f'| **Kernel**    | {kernel} |\n\n')
    f.write('---\n\n')

    # ── Full report: one table per subsection ─────────────────────────────────
    for section, subsections in sections.items():
        f.write(f'## {section}\n\n')
        for subsection, sub_rows in subsections.items():
            if subsection:
                f.write(f'### {subsection}\n\n')
            f.write('| Test | Expected | Got | Result |\n')
            f.write('|------|----------|-----|--------|\n')
            for row in sub_rows:
                icon = ICONS.get(row['result'], '❓')
                f.write(
                    f"| {esc(row['test'])} "
                    f"| {esc(row['expected'])} "
                    f"| {esc(row['got'])} "
                    f"| {icon} {row['result']} |\n"
                )
            f.write('\n')

    # ── Summary ───────────────────────────────────────────────────────────────
    f.write('---\n\n')
    f.write('## Validation Summary\n\n')
    f.write('| Result | Count |\n')
    f.write('|--------|-------|\n')
    f.write(f'| ✅ PASS | {pass_c} |\n')
    f.write(f'| ❌ FAIL | {fail_c} |\n')
    f.write(f'| ⚠️ WARN | {warn_c} |\n')
    f.write(f'| ⏭️ SKIP | {skip_c} |\n')
    f.write(f'| **Total** | **{total}** |\n\n')

    # ── Failures by section ───────────────────────────────────────────────────
    if fail_c > 0:
        f.write('---\n\n')
        f.write('## ❌ Failures by Section\n\n')
        for section, subsections in sections.items():
            section_has_fails = any(
                r['result'] == 'FAIL'
                for sub_rows in subsections.values()
                for r in sub_rows
            )
            if not section_has_fails:
                continue
            f.write(f'### {section}\n\n')
            for subsection, sub_rows in subsections.items():
                fail_rows = [r for r in sub_rows if r['result'] == 'FAIL']
                if not fail_rows:
                    continue
                if subsection:
                    f.write(f'#### {subsection}\n\n')
                f.write('| Test | Expected | Got |\n')
                f.write('|------|----------|-----|\n')
                for row in fail_rows:
                    f.write(
                        f"| {esc(row['test'])} "
                        f"| {esc(row['expected'])} "
                        f"| {esc(row['got'])} |\n"
                    )
                f.write('\n')
PYEOF
}

# =============================================================================
# Start
# =============================================================================
echo ""
echo -e "${BOLD}Wazuh Manager Package Changes – Validation Script${RESET}"
echo -e "Report will be saved to: ${CYAN}$REPORT_FILE${RESET}"

# =============================================================================
# Section 1 – Installation Directory
# =============================================================================
log_section "1. Installation Directory"

log_subsection "New directory must exist"
check_exists "$WAZUH_HOME" "/var/wazuh-manager"

log_subsection "Old directory must NOT exist"
check_not_exists "/var/ossec" "/var/ossec (legacy path)"

# =============================================================================
# Section 2 – Manager Daemon Binaries
# =============================================================================
log_section "2. Manager Daemon Binaries"

log_subsection "New wazuh-manager-* binaries must exist"
for binary in \
    wazuh-manager-analysisd \
    wazuh-manager-apid \
    wazuh-manager-authd \
    wazuh-manager-clusterd \
    wazuh-manager-db \
    wazuh-manager-modulesd \
    wazuh-manager-monitord \
    wazuh-manager-remoted \
    wazuh-manager-control \
    wazuh-manager-keystore; do
    check_exists "$WAZUH_HOME/bin/$binary" "bin/$binary"
done

log_subsection "Old wazuh-* binaries must NOT exist in manager directory"
for old_binary in \
    wazuh-analysisd \
    wazuh-apid \
    wazuh-authd \
    wazuh-clusterd \
    wazuh-db \
    wazuh-modulesd \
    wazuh-monitord \
    wazuh-remoted \
    wazuh-control \
    wazuh-keystore; do
    check_not_exists "$WAZUH_HOME/bin/$old_binary" "bin/$old_binary (legacy name)"
done

log_subsection "Agent-only binaries must NOT be present in manager"
for agent_binary in \
    wazuh-logcollector \
    wazuh-syscheckd \
    wazuh-execd; do
    check_not_exists "$WAZUH_HOME/bin/$agent_binary" "bin/$agent_binary (agent-only)"
done

# =============================================================================
# Section 3 – Python Scripts (Framework / API)
# =============================================================================
log_section "3. Python Scripts (Framework / API)"

log_subsection "New Python scripts must exist"
check_exists "$WAZUH_HOME/api/scripts/wazuh_manager_apid.py"     "api/scripts/wazuh_manager_apid.py"
check_exists "$WAZUH_HOME/framework/scripts/wazuh_manager_clusterd.py" "framework/scripts/wazuh_manager_clusterd.py"

log_subsection "Old Python scripts must NOT exist"
check_not_exists "$WAZUH_HOME/api/scripts/wazuh_apid.py"          "api/scripts/wazuh_apid.py (legacy)"
check_not_exists "$WAZUH_HOME/framework/scripts/wazuh_clusterd.py" "framework/scripts/wazuh_clusterd.py (legacy)"

# =============================================================================
# Section 4 – Configuration Files
# =============================================================================
log_section "4. Configuration Files"

log_subsection "New config files must exist"
check_exists "$WAZUH_HOME/etc/wazuh-manager.conf" "etc/wazuh-manager.conf"
check_exists "$WAZUH_HOME/etc/ossec-server.conf"  "etc/ossec-server.conf (updated internally)"
check_exists "$WAZUH_HOME/api/tools/env/wazuh-manager/xml/master_wazuh-manager_conf.xml" \
    "api/tools/env/.../master_wazuh-manager_conf.xml"
check_exists "$WAZUH_HOME/api/tools/env/wazuh-manager/xml/worker_wazuh-manager_conf.xml" \
    "api/tools/env/.../worker_wazuh-manager_conf.xml"
check_exists "$WAZUH_HOME/framework/wazuh/core/tests/data/configuration/wazuh-manager.conf" \
    "framework/.../data/configuration/wazuh-manager.conf"

log_subsection "Old config files must NOT exist"
check_not_exists "$WAZUH_HOME/etc/ossec.conf" "etc/ossec.conf (legacy)"
check_not_exists "$WAZUH_HOME/api/tools/env/wazuh-manager/xml/master_ossec_conf.xml" \
    "api/tools/env/.../master_ossec_conf.xml (legacy)"
check_not_exists "$WAZUH_HOME/api/tools/env/wazuh-manager/xml/worker_ossec_conf.xml" \
    "api/tools/env/.../worker_ossec_conf.xml (legacy)"
check_not_exists "$WAZUH_HOME/framework/wazuh/core/tests/data/configuration/ossec.conf" \
    "framework/.../data/configuration/ossec.conf (legacy)"

# =============================================================================
# Section 5 – XML Configuration Root Tag
# =============================================================================
log_section "5. XML Configuration Root Tag"

log_subsection "Manager config must use <wazuh_config> root tag"
check_contains "$WAZUH_HOME/etc/wazuh-manager.conf" '<wazuh_config>' '<wazuh_config> root tag'

log_subsection "Manager config must NOT use old <ossec_config> root tag"
check_not_contains "$WAZUH_HOME/etc/wazuh-manager.conf" '<ossec_config>' '<ossec_config> (old tag)'

log_subsection "Agent config: <client><manager> tag (not <client><server>)"
if [[ -f "$WAZUH_HOME/etc/ossec-server.conf" ]]; then
    check_contains     "$WAZUH_HOME/etc/ossec-server.conf" '<manager>'       '<manager> tag present'
    check_not_contains "$WAZUH_HOME/etc/ossec-server.conf" '<client><server>' '<client><server> (old tag)'
fi

# =============================================================================
# Section 6 – Certificate Files
# =============================================================================
log_section "6. Certificate Files"

log_subsection "New certificate files must exist"
check_exists "$WAZUH_HOME/etc/certs/manager.pem"     "etc/certs/manager.pem"
check_exists "$WAZUH_HOME/etc/certs/manager-key.pem" "etc/certs/manager-key.pem"

log_subsection "Old certificate files must NOT exist"
check_not_exists "$WAZUH_HOME/etc/certs/server.pem"     "etc/certs/server.pem (legacy)"
check_not_exists "$WAZUH_HOME/etc/certs/server-key.pem" "etc/certs/server-key.pem (legacy)"

# =============================================================================
# Section 7 – Log Files
# =============================================================================
log_section "7. Log Files"

log_subsection "New log files must exist"
check_exists "$WAZUH_HOME/logs/wazuh-manager.log"  "logs/wazuh-manager.log"
check_exists "$WAZUH_HOME/logs/wazuh-manager.json" "logs/wazuh-manager.json"

log_subsection "Old log files must NOT exist"
check_not_exists "$WAZUH_HOME/logs/ossec.log"  "logs/ossec.log (legacy)"
check_not_exists "$WAZUH_HOME/logs/ossec.json" "logs/ossec.json (legacy)"

# =============================================================================
# Section 8 – System User and Group
# =============================================================================
log_section "8. System User and Group"

log_subsection "New user 'wazuh-manager' must exist"
if id "wazuh-manager" &>/dev/null; then
    pass "User 'wazuh-manager' exists" "user exists" "exists"
else
    fail "User 'wazuh-manager' does NOT exist" "user exists" "not found"
fi

log_subsection "New group 'wazuh-manager' must exist"
if getent group "wazuh-manager" &>/dev/null; then
    pass "Group 'wazuh-manager' exists" "group exists" "exists"
else
    fail "Group 'wazuh-manager' does NOT exist" "group exists" "not found"
fi

log_subsection "Old user 'wazuh' must NOT exist as primary manager user"
if id "wazuh" &>/dev/null; then
    warn "User 'wazuh' still exists (verify it is not the manager service user)" \
        "user absent" "present"
else
    pass "User 'wazuh' does not exist (expected)" "user absent" "absent"
fi

log_subsection "Old group 'wazuh' must NOT exist as primary manager group"
if getent group "wazuh" &>/dev/null; then
    warn "Group 'wazuh' still exists (verify it is not the manager service group)" \
        "group absent" "present"
else
    pass "Group 'wazuh' does not exist (expected)" "group absent" "absent"
fi

# =============================================================================
# Section 9 – Files and Directory Permissions
# =============================================================================
log_section "9. Files and Directory Permissions"

B="$WAZUH_HOME"

log_subsection "9a. Root-launched daemon binaries (root:root 750)"
for bin in \
    bin/wazuh-manager-analysisd \
    bin/wazuh-manager-authd \
    bin/wazuh-manager-remoted \
    bin/wazuh-manager-db \
    bin/wazuh-manager-modulesd \
    bin/wazuh-manager-monitord \
    bin/wazuh-manager-control \
    bin/wazuh-manager-keystore; do
    check_entry "$B/$bin" root root 750
done

log_subsection "9b. API/Cluster daemon binaries (root:wazuh-manager 750)"
check_entry "$B/bin/wazuh-manager-apid"     root wazuh-manager 750
check_entry "$B/bin/wazuh-manager-clusterd" root wazuh-manager 750

log_subsection "9c. Framework/API wrapper binaries (root:wazuh-manager 750)"
for bin in \
    bin/agent_groups \
    bin/agent_upgrade \
    bin/cluster_control \
    bin/rbac_control \
    bin/verify-agent-conf; do
    check_entry "$B/$bin" root wazuh-manager 750
done

log_subsection "9d. Active response scripts (root:wazuh-manager 750)"
check_entry "$B/active-response/bin/restart.sh"   root wazuh-manager 750
check_entry "$B/active-response/bin/kaspersky.py" root wazuh-manager 750

log_subsection "9e. Shared libraries (root:wazuh-manager 750)"
if compgen -G "$B/lib/*.so" &>/dev/null; then
    check_glob_entries "$B/lib/*.so"   root wazuh-manager 750
    check_glob_entries "$B/lib/*.so.*" root wazuh-manager 750
else
    skip "No .so files found in $B/lib/" "root:wazuh-manager 750" "no files"
fi

log_subsection "9f. Framework Python scripts (root:wazuh-manager 640)"
if [[ -d "$B/framework" ]]; then
    while IFS= read -r -d '' f; do
        check_entry "$f" root wazuh-manager 640
    done < <(find "$B/framework" -name "*.py" -type f -print0 2>/dev/null)
else
    skip "Directory $B/framework not found" "root:wazuh-manager 640" "not found"
fi

log_subsection "9g. API Python scripts (root:wazuh-manager 640)"
if compgen -G "$B/api/scripts/*.py" &>/dev/null; then
    check_glob_entries "$B/api/scripts/*.py" root wazuh-manager 640
else
    skip "No .py files found in $B/api/scripts/" "root:wazuh-manager 640" "no files"
fi

log_subsection "9h. Static config files"
check_entry "$B/etc/internal_options.conf"       root wazuh-manager 640
check_entry "$B/etc/local_internal_options.conf" root wazuh-manager 640
check_entry "$B/etc/sslmanager.cert"             root root           640
check_entry "$B/etc/sslmanager.key"              root root           640
check_entry "$B/etc/localtime"                   root root           640
check_entry "$B/VERSION.json"                    root wazuh-manager  440

log_subsection "9i. Runtime-writable config/data files"
check_entry "$B/etc/wazuh-manager.conf"         root          wazuh-manager 660
check_entry "$B/etc/client.keys"                wazuh-manager wazuh-manager 660
check_entry "$B/etc/shared/agent-template.conf" wazuh-manager wazuh-manager 660
check_entry "$B/etc/shared/default/agent.conf"  wazuh-manager wazuh-manager 660
check_entry "$B/api/configuration/api.yaml"     root          wazuh-manager 660
check_entry "$B/var/db/mitre.db"                root          wazuh-manager 660

log_subsection "9j. Engine base directories"
check_entry "$B/engine/"          root          root          755
check_entry "$B/engine/kvdb/"     wazuh-manager wazuh-manager 770
check_entry "$B/engine/mmdb/"     root          wazuh-manager 770
check_entry "$B/engine/outputs/"  wazuh-manager wazuh-manager 770
check_entry "$B/engine/store/"    wazuh-manager wazuh-manager 770
if compgen -G "$B/engine/mmdb/*.mmdb" &>/dev/null; then
    check_glob_entries "$B/engine/mmdb/*.mmdb" wazuh-manager wazuh-manager 660
else
    skip "No .mmdb files in $B/engine/mmdb/ (may not yet be populated)" \
        "wazuh-manager:wazuh-manager 660" "no files"
fi
if compgen -G "$B/engine/outputs/*.yml" &>/dev/null; then
    check_glob_entries "$B/engine/outputs/*.yml" wazuh-manager wazuh-manager 660
else
    info "No .yml files yet in $B/engine/outputs/ (runtime-generated)"
fi

log_subsection "9j-i. engine/store subdirectories (wazuh-manager:wazuh-manager 770)"
if [[ -d "$B/engine/store" ]]; then
    while IFS= read -r -d '' d; do
        [[ "$d" == "$B/engine/store/geo"      ]] && continue
        [[ "$d" == "$B/engine/store/geo/mmdb" ]] && continue
        check_entry "$d" wazuh-manager wazuh-manager 770
    done < <(find "$B/engine/store" -mindepth 1 -type d -print0 2>/dev/null)
fi

log_subsection "9j-ii. engine/store files (wazuh-manager:wazuh-manager 660)"
if [[ -d "$B/engine/store" ]]; then
    while IFS= read -r -d '' f; do
        check_entry "$f" wazuh-manager wazuh-manager 660
    done < <(find "$B/engine/store" -type f -print0 2>/dev/null)
fi

log_subsection "9j-iii. engine/store/geo exceptions"
check_entry "$B/engine/store/geo/"      root root          755
check_entry "$B/engine/store/geo/mmdb/" root wazuh-manager 770

log_subsection "9k. Queue directories 770 (wazuh-manager:wazuh-manager)"
for qdir in queue queue/alerts queue/sockets queue/rids queue/cluster \
            queue/tasks queue/vd queue/indexer queue/router; do
    check_entry "$B/$qdir/" wazuh-manager wazuh-manager 770
done

log_subsection "9k-i. Queue directories 750 (wazuh-manager:wazuh-manager)"
for qdir in queue/db queue/keystore queue/tzdb; do
    check_entry "$B/$qdir/" wazuh-manager wazuh-manager 750
done

log_subsection "9k-ii. queue/agents-timestamp file"
check_entry "$B/queue/agents-timestamp" wazuh-manager wazuh-manager 660

log_subsection "9l. Log directories and files"
check_entry "$B/logs/" wazuh-manager wazuh-manager 770
if compgen -G "$B/logs/*.log"  &>/dev/null; then
    check_glob_entries "$B/logs/*.log"  wazuh-manager wazuh-manager 660
fi
if compgen -G "$B/logs/*.json" &>/dev/null; then
    check_glob_entries "$B/logs/*.json" wazuh-manager wazuh-manager 660
fi
for logdir in logs/api logs/alerts logs/archives logs/cluster logs/firewall logs/wazuh; do
    check_entry "$B/$logdir/" wazuh-manager wazuh-manager 750
done

log_subsection "9m. Temporary and variable data"
check_entry "$B/tmp/"             root          wazuh-manager 1770
check_entry "$B/var/run/"         root          wazuh-manager 770
check_entry "$B/var/multigroups/" wazuh-manager wazuh-manager 770
check_entry "$B/var/upgrade/"     root          wazuh-manager 770
check_entry "$B/var/db/"          root          wazuh-manager 770
check_entry "$B/var/download/"    root          wazuh-manager 770
check_entry "$B/var/selinux/"     root          wazuh-manager 770
check_entry "$B/var/selinux/wazuh.pp" root      wazuh-manager 640

log_subsection "9n. Backup directories"
check_entry "$B/backup/db/"     wazuh-manager wazuh-manager 750
check_entry "$B/backup/agents/" wazuh-manager wazuh-manager 750
check_entry "$B/backup/shared/" root          wazuh-manager 750

# =============================================================================
# Section 10 – Terminology: "server" → "manager"
# =============================================================================
log_section "10. Terminology: 'server' -> 'manager'"

log_subsection "10a. wazuh-manager.conf: no leftover <server> tag"
if [[ -f "$B/etc/wazuh-manager.conf" ]]; then
    check_not_contains "$B/etc/wazuh-manager.conf" '<server>' \
        '<server> (old agent-facing tag)'
    check_contains "$B/etc/wazuh-manager.conf" 'manager' \
        "'manager' keyword present in config"
fi

log_subsection "10b. preloaded-vars.conf: USER_AGENT_MANAGER_IP"
if [[ -f "$B/etc/preloaded-vars.conf" ]]; then
    check_not_contains "$B/etc/preloaded-vars.conf" 'USER_AGENT_SERVER_IP' \
        'USER_AGENT_SERVER_IP (legacy key)'
    check_contains "$B/etc/preloaded-vars.conf" 'USER_AGENT_MANAGER_IP' \
        'USER_AGENT_MANAGER_IP (new key)'
fi

log_subsection "10c. Installation templates: all languages updated"
TEMPLATE_BASE="$B/etc/templates"
if [[ -d "$TEMPLATE_BASE" ]]; then
    for lang in br cn de el en es fr hu it jp nl pl ru sr tr; do
        msg_file="$TEMPLATE_BASE/$lang/messages.txt"
        if [[ -f "$msg_file" ]]; then
            check_contains "$msg_file" 'manager' "'manager' in $lang/messages.txt"
        else
            skip "Template not found: $lang/messages.txt" "manager keyword" "file absent"
        fi
    done
else
    skip "Templates directory not found: $TEMPLATE_BASE" "dir exists" "not found"
fi

log_subsection "10d. Build output: 'manager' in Makefile"
if [[ -f "$B/src/Makefile" ]]; then
    if grep -q 'TARGET=server' "$B/src/Makefile"; then
        warn "src/Makefile still has TARGET=server (verify it is remapped)" \
            "TARGET=manager" "TARGET=server"
    fi
    check_contains "$B/src/Makefile" 'manager' "'manager' referenced in Makefile"
fi

log_subsection "10e. Engine config keys: no leftover 'server' references"
if [[ -d "$B/engine" ]]; then
    found_server_keys=false
    while IFS= read -r -d '' f; do
        if grep -qlE '\bserver\b' "$f" 2>/dev/null; then
            found_server_keys=true
            warn "Possible leftover 'server' key in engine config: $f" \
                "no 'server' keys" "found in $(basename "$f")"
        fi
    done < <(find "$B/engine" -maxdepth 3 \
        \( -name "*.yaml" -o -name "*.yml" -o -name "*.conf" \) -print0 2>/dev/null)
    if ! $found_server_keys; then
        pass "No leftover 'server' keys in engine config files" \
            "no 'server' keys" "none found"
    fi
fi

# =============================================================================
# Section 11 – Residual 'ossec' References
# =============================================================================
log_section "11. Residual 'ossec' References"

log_subsection "11a. Legacy /var/ossec directory"
check_not_exists "/var/ossec" "/var/ossec (legacy install directory)"

log_subsection "11b. File/directory names containing 'ossec' under $WAZUH_HOME"
OSSEC_NAMES_EXCEPTION="ossec-server.conf"
if [[ -d "$WAZUH_HOME" ]]; then
    ossec_names_found=false
    while IFS= read -r -d '' entry; do
        base=$(basename "$entry")
        if [[ "$base" == "$OSSEC_NAMES_EXCEPTION" ]]; then
            info "  Skipping known exception: $entry"; continue
        fi
        ossec_names_found=true
        fail "Path name contains 'ossec': $entry" \
            "no 'ossec' in path name" "found: $base"
    done < <(find "$WAZUH_HOME" -name "*ossec*" -print0 2>/dev/null)
    if ! $ossec_names_found; then
        pass "No 'ossec' path names found (except known exceptions)" \
            "no 'ossec' in path names" "none found"
    fi
else
    skip "$WAZUH_HOME not found" "no 'ossec' paths" "dir absent"
fi

log_subsection "11c. Config file content: no 'ossec' in .conf/.yaml/.yml/.xml"
if [[ -d "$WAZUH_HOME" ]]; then
    ossec_conf_found=false
    for ext in "*.conf" "*.yaml" "*.yml" "*.xml"; do
        while IFS= read -r -d '' f; do
            [[ "$(basename "$f")" == "ossec-server.conf" ]] && continue
            if grep -qiE '\bossec\b' "$f" 2>/dev/null; then
                ossec_conf_found=true
                mc=$(grep -icE '\bossec\b' "$f" 2>/dev/null || echo "?")
                fail "Found 'ossec' in: $(basename "$f")" \
                    "no 'ossec' references" "$mc occurrence(s)"
                grep -inE '\bossec\b' "$f" 2>/dev/null | head -5 | \
                    while IFS= read -r line; do info "    $line"; done
            fi
        done < <(find "$WAZUH_HOME" -name "$ext" -type f -print0 2>/dev/null)
    done
    if ! $ossec_conf_found; then
        pass "No 'ossec' references in config/yaml/yml/xml files" \
            "no 'ossec' references" "none found"
    fi
else
    skip "$WAZUH_HOME not found" "no 'ossec' in configs" "dir absent"
fi

log_subsection "11d. Python script content: no legacy 'ossec_' references"
if [[ -d "$WAZUH_HOME" ]]; then
    ossec_py_found=false
    while IFS= read -r -d '' f; do
        if grep -qiE '(ossec_|from ossec|import ossec|/var/ossec|ossec\.conf)' "$f" 2>/dev/null; then
            ossec_py_found=true
            mc=$(grep -icE '(ossec_|from ossec|import ossec|/var/ossec|ossec\.conf)' "$f" 2>/dev/null || echo "?")
            fail "Found 'ossec' identifiers in: $f" \
                "no 'ossec' identifiers" "$mc occurrence(s)"
            grep -inE '(ossec_|from ossec|import ossec|/var/ossec|ossec\.conf)' "$f" 2>/dev/null | head -5 | \
                while IFS= read -r line; do info "    $line"; done
        fi
    done < <(find "$WAZUH_HOME" -name "*.py" -type f -print0 2>/dev/null)
    if ! $ossec_py_found; then
        pass "No legacy 'ossec' references in Python files" \
            "no 'ossec' identifiers" "none found"
    fi
else
    skip "$WAZUH_HOME not found" "no 'ossec' in Python" "dir absent"
fi

log_subsection "11e. Shell script content: no legacy '/var/ossec' paths"
if [[ -d "$WAZUH_HOME" ]]; then
    ossec_sh_found=false
    while IFS= read -r -d '' f; do
        if grep -qE '/var/ossec' "$f" 2>/dev/null; then
            ossec_sh_found=true
            mc=$(grep -cE '/var/ossec' "$f" 2>/dev/null || echo "?")
            fail "Found '/var/ossec' in: $f" \
                "no /var/ossec paths" "$mc occurrence(s)"
            grep -nE '/var/ossec' "$f" 2>/dev/null | head -5 | \
                while IFS= read -r line; do info "    $line"; done
        fi
    done < <(find "$WAZUH_HOME" -name "*.sh" -type f -print0 2>/dev/null)
    if ! $ossec_sh_found; then
        pass "No '/var/ossec' paths in shell scripts" \
            "no /var/ossec paths" "none found"
    fi
else
    skip "$WAZUH_HOME not found" "no /var/ossec in scripts" "dir absent"
fi

log_subsection "11f. System user/group 'ossec' must not exist"
if id "ossec" &>/dev/null; then
    fail "System user 'ossec' still exists" "user absent" "user present"
else
    pass "System user 'ossec' does not exist" "user absent" "absent"
fi
if getent group "ossec" &>/dev/null; then
    fail "System group 'ossec' still exists" "group absent" "group present"
else
    pass "System group 'ossec' does not exist" "group absent" "absent"
fi

log_subsection "11g. Systemd: no ossec services installed or active"
ossec_units=$(systemctl list-units --all 2>/dev/null | grep -i ossec || true)
if [[ -n "$ossec_units" ]]; then
    fail "Found systemd units containing 'ossec'" "no ossec units" "units found"
    echo "$ossec_units" | while IFS= read -r line; do info "  $line"; done
else
    pass "No systemd units containing 'ossec'" "no ossec units" "none found"
fi

ossec_unit_files=$(systemctl list-unit-files 2>/dev/null | grep -i ossec || true)
if [[ -n "$ossec_unit_files" ]]; then
    fail "Found systemd unit files containing 'ossec'" "no ossec unit files" "files found"
    echo "$ossec_unit_files" | while IFS= read -r line; do info "  $line"; done
else
    pass "No systemd unit files containing 'ossec'" "no ossec unit files" "none found"
fi

log_subsection "11h. Installed packages: no 'ossec' packages"
if command -v dpkg &>/dev/null; then
    ossec_pkgs=$(dpkg -l 2>/dev/null | grep -i ossec || true)
    if [[ -n "$ossec_pkgs" ]]; then
        fail "Found dpkg packages containing 'ossec'" "no ossec packages" "packages found"
        echo "$ossec_pkgs" | while IFS= read -r line; do info "  $line"; done
    else
        pass "No dpkg packages containing 'ossec'" "no ossec packages" "none found"
    fi
elif command -v rpm &>/dev/null; then
    ossec_pkgs=$(rpm -qa 2>/dev/null | grep -i ossec || true)
    if [[ -n "$ossec_pkgs" ]]; then
        fail "Found rpm packages containing 'ossec'" "no ossec packages" "packages found"
        echo "$ossec_pkgs" | while IFS= read -r line; do info "  $line"; done
    else
        pass "No rpm packages containing 'ossec'" "no ossec packages" "none found"
    fi
else
    skip "Neither dpkg nor rpm found" "no ossec packages" "pkg manager absent"
fi

log_subsection "11i. Running processes: no 'ossec' processes"
ossec_procs=$(ps aux 2>/dev/null | grep -i ossec | grep -v grep || true)
if [[ -n "$ossec_procs" ]]; then
    fail "Found running processes containing 'ossec'" "no ossec processes" "processes found"
    echo "$ossec_procs" | while IFS= read -r line; do info "  $line"; done
else
    pass "No running processes containing 'ossec'" "no ossec processes" "none found"
fi

log_subsection "11j. Init scripts: no 'ossec' entries in /etc/init.d/"
if [[ -d /etc/init.d ]]; then
    ossec_initd=$(find /etc/init.d -name "*ossec*" 2>/dev/null || true)
    if [[ -n "$ossec_initd" ]]; then
        fail "Found init.d scripts containing 'ossec'" "no ossec init scripts" "scripts found"
        echo "$ossec_initd" | while IFS= read -r line; do info "  $line"; done
    else
        pass "No 'ossec' init.d scripts found" "no ossec init scripts" "none found"
    fi
else
    skip "/etc/init.d not found" "no ossec init scripts" "dir absent"
fi

log_subsection "11k. Logrotate: no 'ossec' entries"
if [[ -d /etc/logrotate.d ]]; then
    ossec_logrotate=$(find /etc/logrotate.d -name "*ossec*" 2>/dev/null || true)
    if [[ -n "$ossec_logrotate" ]]; then
        fail "Found logrotate configs containing 'ossec'" "no ossec logrotate" "configs found"
        echo "$ossec_logrotate" | while IFS= read -r line; do info "  $line"; done
    else
        pass "No 'ossec' logrotate configs found" "no ossec logrotate" "none found"
    fi
    while IFS= read -r -d '' f; do
        if grep -qiE '\bossec\b' "$f" 2>/dev/null; then
            fail "Found 'ossec' reference inside logrotate: $(basename "$f")" \
                "no 'ossec' in logrotate content" "found in $(basename "$f")"
            grep -inE '\bossec\b' "$f" 2>/dev/null | head -5 | \
                while IFS= read -r line; do info "    $line"; done
        fi
    done < <(find /etc/logrotate.d -name "*wazuh*" -type f -print0 2>/dev/null)
else
    skip "/etc/logrotate.d not found" "no ossec logrotate" "dir absent"
fi

log_subsection "11l. /etc: no 'ossec' config files or symlinks"
ossec_etc=$(find /etc -maxdepth 2 -name "*ossec*" 2>/dev/null || true)
if [[ -n "$ossec_etc" ]]; then
    fail "Found 'ossec' entries under /etc" "no ossec in /etc" "entries found"
    echo "$ossec_etc" | while IFS= read -r line; do info "  $line"; done
else
    pass "No 'ossec' entries found under /etc" "no ossec in /etc" "none found"
fi

log_subsection "11m. Cron jobs: no 'ossec' references"
cron_dirs=( /etc/cron.d /etc/cron.daily /etc/cron.weekly /etc/cron.monthly /var/spool/cron )
ossec_cron_found=false
for cdir in "${cron_dirs[@]}"; do
    if [[ -d "$cdir" ]]; then
        while IFS= read -r -d '' f; do
            if grep -qiE '\bossec\b' "$f" 2>/dev/null; then
                ossec_cron_found=true
                fail "Found 'ossec' in cron: $(basename "$f")" \
                    "no ossec in cron" "found in $(basename "$f")"
                grep -inE '\bossec\b' "$f" 2>/dev/null | head -3 | \
                    while IFS= read -r line; do info "    $line"; done
            fi
        done < <(find "$cdir" -maxdepth 2 -type f -print0 2>/dev/null)
    fi
done
if ! $ossec_cron_found; then
    pass "No 'ossec' references in cron jobs" "no ossec in cron" "none found"
fi

log_subsection "11n. Environment variables: no 'ossec' vars set"
ossec_env=$(env 2>/dev/null | grep -i ossec || true)
if [[ -n "$ossec_env" ]]; then
    warn "Found environment variables containing 'ossec'" "no ossec env vars" "vars found"
    echo "$ossec_env" | while IFS= read -r line; do info "  $line"; done
else
    pass "No 'ossec' environment variables found" "no ossec env vars" "none found"
fi

log_subsection "11o. Symlinks: no symlinks pointing to '/var/ossec'"
if [[ -d "$WAZUH_HOME" ]]; then
    ossec_links_found=false
    while IFS= read -r -d '' lnk; do
        target=$(readlink -f "$lnk" 2>/dev/null || true)
        if [[ "$target" == /var/ossec* ]]; then
            ossec_links_found=true
            fail "Symlink points to legacy /var/ossec: $lnk" \
                "target not /var/ossec" "target: $target"
        fi
    done < <(find "$WAZUH_HOME" -type l -print0 2>/dev/null)
    if ! $ossec_links_found; then
        pass "No symlinks pointing to /var/ossec in $WAZUH_HOME" \
            "target not /var/ossec" "ok"
    fi
fi

# =============================================================================
# Additional Sanity Checks
# =============================================================================
log_section "Additional Sanity Checks"

log_subsection "Wazuh manager service status"
if systemctl is-active --quiet wazuh-manager 2>/dev/null; then
    pass "wazuh-manager service is active" "service active" "active"
elif systemctl list-units --all --quiet wazuh-manager.service 2>/dev/null \
    | grep -q wazuh-manager; then
    warn "wazuh-manager service exists but is NOT active" "service active" "inactive"
else
    warn "wazuh-manager service not found via systemctl" "service active" "not found"
fi

log_subsection "Old service names must NOT be active"
for old_svc in wazuh ossec; do
    if systemctl is-active --quiet "$old_svc" 2>/dev/null; then
        fail "Old service '$old_svc' is still active" "service inactive" "active"
    else
        pass "Old service '$old_svc' is not active (expected)" "service inactive" "not active"
    fi
done

log_subsection "VERSION.json content"
if [[ -f "$WAZUH_HOME/VERSION.json" ]]; then
    version=$(python3 -c \
        "import json; d=json.load(open('$WAZUH_HOME/VERSION.json')); print(d.get('version','unknown'))" \
        2>/dev/null || true)
    info "Installed version: $version"
fi

log_subsection "wazuh-manager-control binary"
if [[ -x "$WAZUH_HOME/bin/wazuh-manager-control" ]]; then
    pass "wazuh-manager-control is executable" "executable" "executable"
    status_output=$("$WAZUH_HOME/bin/wazuh-manager-control" status 2>&1 || true)
    info "wazuh-manager-control status:"
    echo "$status_output" | while IFS= read -r line; do info "  $line"; done
else
    fail "wazuh-manager-control is not executable or not found" "executable" "not found"
fi

# =============================================================================
# Console summary
# =============================================================================
TOTAL=$((PASS + FAIL + WARN + SKIP))
echo ""
echo -e "${BLUE}${BOLD}════════════════════════════════════════════════════════${RESET}"
echo -e "${BLUE}${BOLD}  VALIDATION SUMMARY${RESET}"
echo -e "${BLUE}${BOLD}════════════════════════════════════════════════════════${RESET}"
echo ""
echo -e "  Total  : ${BOLD}$TOTAL${RESET}"
echo -e "  ${GREEN}PASS${RESET}   : $PASS"
echo -e "  ${RED}FAIL${RESET}   : $FAIL"
echo -e "  ${YELLOW}WARN${RESET}   : $WARN"
echo -e "  ${YELLOW}SKIP${RESET}   : $SKIP"
echo ""

if [[ "$FAIL" -eq 0 ]]; then
    echo -e "  ${GREEN}${BOLD}ALL CHECKS PASSED (with $WARN warnings and $SKIP skips)${RESET}"
else
    echo -e "  ${RED}${BOLD}$FAIL CHECK(S) FAILED — review the report for details${RESET}"
fi

# =============================================================================
# Generate markdown report
# =============================================================================
generate_markdown_report

echo ""
echo -e "Full report saved to: ${CYAN}$REPORT_FILE${RESET}"
echo ""
