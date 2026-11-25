# common.sh - sourced by every node step of the cluster flow. Run as root on the node. CL1: the paths come from the
# node's work directory (MIG_HOME, the inventory's work_dir, which migrate-cluster.sh passes), never from a lab account;
# deb and rpm nodes (the package family is chosen as migrate.sh chooses it).
set -Eeuo pipefail
BUNDLE_DIR="${BUNDLE_DIR:-/root/wazuh-migration-bundle}"      # outside every directory an installer deletes
MIG_HOME="${MIG_HOME:-/root/wazuh-migration}"                 # CL1: the inventory's work_dir on this node (migrate-cluster.sh stages it)
V4_TAR="${V4_TAR:-$MIG_HOME/v4/wazuh-install-files.tar}"     # 4.x wazuh-install-files.tar on this node
V4_ASSISTANT_FILE="${V4_ASSISTANT_FILE:-$MIG_HOME/v4/wazuh-install.sh}"   # the 4.x installation assistant (removal, reinstall)
V5_DIR="${V5_DIR:-$MIG_HOME/v5}"                              # the 5.0 assistant, artifact_urls.yaml (development builds only), config.yml (setup node)
V5_TAR="${V5_TAR:-$V5_DIR/wazuh-install-files.tar}"           # 5.0 wazuh-install-files.tar on this node
SRC="${SRC:-$MIG_HOME/src}"                                   # the tool's src/ tree, pushed whole by migrate-cluster.sh
IDENTITY_TOOL="${IDENTITY_TOOL:-$MIG_HOME/tools/wazuh-migrate-identity.py}"
RMIG_DIR="${RMIG_DIR:-$MIG_HOME/tools/ruleset-migration}"
WORK_DIR="${WORK_DIR:-$MIG_HOME/scratch}"                     # the assistants run here; the finish searches it for secrets
F3="${F3:-$MIG_HOME}"                                         # the lab-only steps' old name for the tools directory (k5.sh)
: "${WPK_REPO=}"                                              # CL1: never a development-build address by default (migrate.sh's default is not taken)
export MIG_HOME SRC IDENTITY_TOOL RMIG_DIR WORK_DIR WPK_REPO
STATE="$BUNDLE_DIR/state"; LOGS="$BUNDLE_DIR/logs"; mkdir -p "$STATE" "$LOGS"; chmod 700 "$BUNDLE_DIR"
ts()  { date -u +%Y-%m-%dT%H:%M:%SZ; }
log() { printf '[%s %s] %s\n' "$(ts)" "$(hostname -s)" "$*"; }
die() { log "FATAL: $*"; exit 1; }
mark() { sync; local t="$STATE/.$1.tmp"; ts > "$t"; sync "$t" 2>/dev/null || sync; mv -f "$t" "$STATE/$1"; sync "$STATE" 2>/dev/null || sync; }   # E2-rpm fix 03 (after the step's writes) and E3 fold (E3-rpm 2: whole or absent)
pw4() { tar -axf "$V4_TAR" wazuh-install-files/wazuh-passwords.txt -O 2>/dev/null | grep -P "'$1'" -A1 | sed -n "2s/.*password: '\(.*\)'/\1/p"; }
# CL1: deb and rpm, chosen as migrate.sh chooses (apt-get and dpkg-query present: deb). The installed version, empty when
# not installed; on deb only a package in state "installed" counts (half-configured is not installed).
if [ -z "${PKGFAM:-}" ]; then if command -v apt-get >/dev/null 2>&1 && command -v dpkg-query >/dev/null 2>&1; then PKGFAM=deb; else PKGFAM=rpm; fi; fi
pkgver() { if [ "$PKGFAM" = deb ]; then { dpkg-query -W -f='${db:Status-Status} ${Version}' "$1" 2>/dev/null || true; } | awk '$1=="installed"{print $2}'
           else rpm -q --qf '%{VERSION}-%{RELEASE}\n' "$1" 2>/dev/null | grep -v 'not installed' | head -n1 || true; fi; }
pkg_installed() { if [ "$PKGFAM" = deb ]; then [ -n "$(pkgver "$1")" ]; else rpm -q "$1" >/dev/null 2>&1; fi; }
pkgs() { # E5 fold (E5-cluster-deb gap 7): on deb only the packages installed (dpkg also lists removed ones it knows of)
         if [ "$PKGFAM" = deb ]; then { dpkg-query -W -f='${db:Status-Status} ${Package} ${Version}\n' 'wazuh-*' filebeat 2>/dev/null || true; } | awk '$1=="installed"{print $2" "$3}' | sort
         else rpm -qa --qf '%{NAME} %{VERSION}-%{RELEASE}\n' 'wazuh-*' filebeat 2>/dev/null | sort; fi; }
nodelabel() { # E3 fold (E3-cluster gap 6): the cluster node's own name (the manager's <node_name>, the indexer's node.name)
  # with the host, so a refusal says "wazuh-2 (ip-198-51-100-10)" and not only the host
  local n; n=$(sed -n 's#.*<node_name>[[:space:]]*\([^<[:space:]]*\)[[:space:]]*</node_name>.*#\1#p' /var/ossec/etc/ossec.conf 2>/dev/null | head -n1)
  [ -n "$n" ] || n=$(sed -n "s/^node\.name:[[:space:]]*['\"]\{0,1\}\([^'\"]*\)['\"]\{0,1\}[[:space:]]*$/\1/p" /etc/wazuh-indexer/opensearch.yml 2>/dev/null | head -n1)
  if [ -n "$n" ]; then echo "$n ($(hostname -s))"; else hostname -s; fi; }
source_version_gate() { # OF1 item 12 (decision of 2026-11-24): this node's 4.x manager, indexer and dashboard must be the latest
  # 4.14.x (manifest/builds.json source_min_version, or a newer 4.14.x); every installed one is checked, none may be older
  python3 "$SRC/mig_helper.py" source-version "$(nodelabel)" wazuh-manager "$(pkgver wazuh-manager)" \
    wazuh-indexer "$(pkgver wazuh-indexer)" wazuh-dashboard "$(pkgver wazuh-dashboard)" || die "this node's 4.x is not the latest 4.14.x: nothing changed"
}
bundle_verify() { # E5 fold (E5-cluster-deb 06): this node's bundle against its MANIFEST.sha256, without decisions.json:
  # that file is the node's copy of the user's answers, which migrate-cluster.sh replaces before and after every step
  # that can ask, so a manifest written at the export no longer matched once a later step asked (the master's installed
  # plan, the ruleset decision) and the whole-cluster way back refused the master. A bundle exported before this fold
  # still lists it: the line is left out of the check
  ( cd "$BUNDLE_DIR" && grep -v -E '  \./decisions\.json$' MANIFEST.sha256 | sha256sum --quiet -c - ); }
myip() { hostname -I | awk '{print $1}'; }
idxhost() { # the address this node's indexer listens on (migrate.sh idxhost: R2, network.host from opensearch.yml)
  local h; h=$(sed -n "s/^network.host:[[:space:]]*['\"]\{0,1\}\([^'\"]*\)['\"]\{0,1\}[[:space:]]*$/\1/p" /etc/wazuh-indexer/opensearch.yml 2>/dev/null | head -n1)
  case "$h" in ""|0.0.0.0|127.0.0.1|localhost|_local_*|"["*) echo 127.0.0.1;; *) echo "$h";; esac; }
mask_passwords() { # E2-deb G11; E5 fold (E5-cluster-deb gap 8): the value only (a token, or a quoted string), not the rest
  # of the line: the secret sweep's "kept (...)" line was blanked whole. Every value on the line is masked (g)
  sed -u -E 's/([Pp]assword|PASSWORD|[Tt]oken)([^:=]{0,40}[:=][[:space:]]*)("[^"]*"?|'"'"'[^'"'"']*'"'"'?|[^[:space:]]+)/\1\2MASKED/g'; }
v5cred() { # v5cred KEY : from the 5.0 wazuh-install-files.tar on this node. E5 fold (E5-cluster-deb 01 = E5-cluster-rpm
  # 01): empty, not a failure, while the 5.0 install files are not on this node yet. Every step before phase 5 that loads
  # aio_lib with IDX5_HOST set (node-facts, the settings and ruleset pre-copy) reads it, and under errexit and pipefail
  # the missing tar's exit 2 killed the step with no message
  { tar -xOf "$V5_TAR" wazuh-install-files/credentials.env 2>/dev/null || true; } | sed -nE "s/^$1=\"?([^\"]*)\"?$/\1/p" | tail -n1; }
leftovers() {
  local p
  for p in /var/ossec /var/lib/wazuh-indexer /etc/wazuh-indexer /usr/share/wazuh-indexer /var/log/wazuh-indexer \
           /etc/wazuh-dashboard /usr/share/wazuh-dashboard /var/lib/wazuh-dashboard /etc/filebeat /var/lib/filebeat /usr/share/filebeat \
           /var/log/filebeat /etc/yum.repos.d/wazuh.repo /etc/pki/rpm-gpg/GPG-KEY-WAZUH /etc/rc.d/init.d/wazuh-manager /var/log/wazuh-install.log \
           /etc/apt/sources.list.d/wazuh.list /etc/apt/sources.list.d/wazuh.sources /usr/share/keyrings/wazuh.gpg /usr/share/keyrings/wazuh.gpg~ /etc/init.d/wazuh-manager \
           /tmp/hsperfdata_wazuh-indexer; do
    [ -e "$p" ] && echo "path $p ($(du -sh "$p" 2>/dev/null | cut -f1))"
  done
  find /etc/systemd/system -name 'wazuh-*.service' -o -name 'filebeat.service' 2>/dev/null | sed 's/^/unit-link /' || true
  find /var/ossec /etc/wazuh-indexer /etc/wazuh-dashboard \( -name '*.rpmsave' -o -name '*.dpkg-old' -o -name '*.dpkg-dist' \) 2>/dev/null | head -n 20 | sed 's/^/kept-config /' || true
  pkgs | sed 's/^/package /' || true
  pgrep -a -f 'filebeat|wazuh|opensearch' | grep -v -E "pgrep|wazuh-install|$MIG_HOME" | cut -c1-120 | sed 's/^/process /' || true
  getent passwd wazuh wazuh-indexer wazuh-dashboard | cut -d: -f1,3 | sed 's/^/user /' || true
}
ca4() { # the 4.x root CA from the original 4.x install files (for talking to a reinstalled 4.x indexer before Filebeat exists)
  local p="$STATE/root-ca-4x.pem"; tar -axf "$V4_TAR" wazuh-install-files/root-ca.pem -O > "$p" 2>/dev/null; echo "$p"; }
aio_lib() { # CL1: the all-in-one's functions (migrate.sh up to its dispatcher), for the node steps that run its stages on
  # a cluster node, so one implementation serves both flows: settings (pc_settings, collect_base, settings_plan,
  # im_settings, im_groups_pre, fi_groups_post), ruleset (rmig, ruleset_build, im_ruleset), the unclassified-events
  # decision (op_decision, op_in_force), the listeners and the firewall (op_listeners, fw_*), the agents (ag_*, fu,
  # feed_wait), the finish (fi_raw_off). On a manager node of a cluster the indexer is another host: IDX5_HOST (one 5.0
  # indexer node, from the inventory) and the manager's own copy of the indexer CA replace the all-in-one's loopback.
  local f="$SRC/migrate.sh" lib
  [ -s "$f" ] || die "the tool's migrate.sh is not at $f: push the whole src/ tree"
  lib=$(sed '/^if \[ "\$CMD" = __step \]; then/,$d' "$f")
  set --; eval "$lib"
  HERE="$SRC"; HELPER="$SRC/mig_helper.py"; SELF="$f"
  if [ -n "${IDX5_HOST:-}" ]; then
    idxhost() { echo "$IDX5_HOST"; }
    idx5pw() { v5cred WAZUH_INDEXER_ADMIN_PASSWORD; }
    IDX5_CA="${IDX5_CA:-/etc/wazuh-manager/certs/indexer-ca.pem}"
    MIG_IDX5_HOST="$IDX5_HOST"; MIG_IDX5_PASSWORD="$(v5cred WAZUH_INDEXER_ADMIN_PASSWORD)"; export MIG_IDX5_HOST MIG_IDX5_PASSWORD IDX5_CA
  fi
  IDX5_CA="${IDX5_CA:-/etc/wazuh-indexer/certs/root-ca.pem}"; export IDX5_CA   # a node with its own indexer: the all-in-one's
  STATE="$BUNDLE_DIR/state"; LOGS="$BUNDLE_DIR/logs"; RESULTS="$BUNDLE_DIR/results"; mkdir -p "$RESULTS"
  # tests only (as MIG_OS_RELEASE): the product directories under a sandbox root
  if [ -n "${MIG_TEST_ROOT:-}" ]; then V4="$MIG_TEST_ROOT$V4"; V5="$MIG_TEST_ROOT$V5"; V5ETC="$MIG_TEST_ROOT$V5ETC"; fi
}
