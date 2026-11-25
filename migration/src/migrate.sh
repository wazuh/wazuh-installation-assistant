#!/usr/bin/env bash
# migrate.sh - the Wazuh 4.14.x -> 5.0 migration tool, merged canonical version: one entry point
# for the same-host flow on an all-in-one (deb or rpm, amd64 or arm64), the whole contract of the design as one
# re-runnable command. Built from P1 (from E1) with R2, F5, F6, F7, F10 and S5 folded in, and the stages beside it:
# identity_stage.py (G5+F7), history_load.py (H5+S5 over RD2's M3), indexer_stage.py (C23), fleet-upgrade.py (A5+A6),
# guard.sh (R2/F5+K5). Bash + Python 3.8+ standard library only.
#
#   sudo ./migrate.sh run [--from PHASE] [--only PHASE] [--through PHASE]   phases 1-8 (and the history), then stops
#   sudo ./migrate.sh confirm-no-return      phase 9: the explicit confirmation
#   sudo ./migrate.sh agents                 phase 10: upgrade the agents (needs phase 9)
#   sudo ./migrate.sh finish                 phase 11: close the legacy ports, delete the history data and the secrets
#   sudo ./migrate.sh back                   go back to 4.14.x from the bundle (offered from phase 5 to phase 9)
#   sudo ./migrate.sh status | guard | dashboards-rollback (rule 20: reset only what the dashboard step changed)
#   sudo ./migrate.sh discard                delete the secrets of a bundle abandoned before 4.x was removed (or after going back)
#   phases: assess precopy freeze verify_bundle replace import open verify history
#   HISTORY_LOAD=after-open (default): the outage ends at "open"; "history" loads, proves and switches it on afterwards.
#   ./migrate.sh cluster --inventory FILE <command>   a cluster, from a control host (migrate-cluster.sh, CL1)
#
set -Eeuo pipefail
if [ "${1:-}" = cluster ]; then shift; exec bash "$(dirname "$(readlink -f "$0")")/migrate-cluster.sh" "$@"; fi   # CL1

############ Values the user supplies ##########################################################
# 1. Where the export bundle lives. Must survive the removal of 4.x, a failed 5.0 install and a reboot.
BUNDLE_DIR="${BUNDLE_DIR:-/root/wazuh-migration-bundle}"
# 2. wazuh-install-files.tar of the 4.x assistant: the admin (indexer) and wazuh (Server API) passwords.
V4_INSTALL_FILES_TAR="${V4_INSTALL_FILES_TAR:-/root/wazuh-install-files.tar}"
# 3. The 4.x installation assistant (file or URL): removes 4.x, and reinstalls it when going back.
V4_ASSISTANT="${V4_ASSISTANT:-https://packages.wazuh.com/4.14/wazuh-install.sh}"
# 4. The 5.0 installation assistant (file or URL).
V5_ASSISTANT="${V5_ASSISTANT:-https://packages-staging.xdrsiem.wazuh.info/nightly/5.0.0/installation-assistant/wazuh-install-5.0.0-latest.sh}"
# 5. The 5.0 artifact manifest (file or URL). Only for development builds; empty for a published release.
V5_ARTIFACT_URLS="${V5_ARTIFACT_URLS-https://packages-staging.xdrsiem.wazuh.info/nightly/5.0.0/artifact-urls/artifact_urls_5.0.0-latest.yaml}"
# 6. wazuh-migrate-identity.py (wazuh/wazuh 5.0.0, tools/migration).
IDENTITY_TOOL="${IDENTITY_TOOL:-/root/mig-tools/wazuh-migrate-identity.py}"
# 7. The ruleset migration tool directory (wazuh/intelligence-data, tools/ruleset-migration).
RMIG_DIR="${RMIG_DIR:-/root/mig-tools/ruleset-migration}"
# 8. decisions.json for the ruleset tool, when the first plan leaves questions open. Optional.
RMIG_DECISIONS="${RMIG_DECISIONS:-}"
# 9. Addresses agents dial that the host cannot discover (NAT, load balancer, published name). Optional.
AGENT_ADDRESSES="${AGENT_ADDRESSES:-}"
# 10. What happens to events 5.0 cannot classify when the migrated rules did not verify cleanly. One or more of
#     verified (activate the migrated rules when rmig's verification has no failure; rmig activates all or none, so with a
#     failure none is activated and the run says so), activate-force (activate them anyway), raw (index unclassified
#     events until the finish), accept (record the loss), ask (stop before opening the listeners and ask), joined with +.
#     Empty: design decision 3 (2026-11-24), verified+raw: nothing is lost while raw is on, and the run does not stop to ask;
#     the finish switches raw off only once the migrated rules are active, or on an answer in the decisions file (2026-11-25).
UNCLASSIFIED_DECISION="${UNCLASSIFIED_DECISION:-}"
UNCLASSIFIED_DEFAULT="verified+raw"
# 11. Where the 5.0 manager fetches agent upgrade packages. Only for development builds; empty for a published release.
WPK_REPO="${WPK_REPO-packages-staging.xdrsiem.wazuh.info/nightly/5.0.0/wpk/}"
# 12. How long the migrated alerts are kept, counted from the newest day each monthly index holds (30d, 12h). Empty
#     (decision 5b, 2026-11-24): the retention the 4.x deployment had, read in pre-copy from the ISM policies that
#     cover its alert indices (their delete age); 365d when none deletes them. A value set here wins.
HISTORY_RETENTION="${HISTORY_RETENTION:-}"
# 12b. OF1 (decision 5a, 2026-11-24): the 4.x archives (wazuh-archives-4.x-*) are carried only on request; assess
#     reports their size. 1 asks for them: refused by this version, which loads alerts only (MERGE-LOG, OF1 item 9 says
#     what the loader and the bundle check still lack).
HISTORY_ARCHIVES="${HISTORY_ARCHIVES:-0}"
# 13. Roles that name finding streams exactly lose every module when the history is switched on: 1 accepts that.
ACCEPT_ROLE_LOSS="${ACCEPT_ROLE_LOSS:-0}"
# 15. F6: what phase 11 does about agents that are registered but never connected (no version on record). keep (default):
#     the legacy ports stay open for them and the finish says so; close: close the legacy ports anyway (such a key can then
#     only be used by a 5.0 agent, on 1517); remove: delete them from the registry, then close.
NEVER_CONNECTED_AT_FINISH="${NEVER_CONNECTED_AT_FINISH:-keep}"
# 14. P1: helper names of the target engine for the ruleset tool (5.0, or 5.0-rc1 for builds before the engine renamed its helpers).
#     Empty: from the 5.0 build (the staged assistant's stage in phase 2, the installed manager's revision in phase 6).
RMIG_ENGINE_HELPERS="${RMIG_ENGINE_HELPERS:-}"
# 15. R2: who installs 5.0 in phase 5 and reinstalls 4.x when going back. "assistant" (packages, as P1); "external" for a
#     deployment owned by something else (an Ansible playbook): the step stops with exit 10 and says what to run, and the
#     next run of this command goes on from there. The recipe on the control node runs the playbook in between.
V5_INSTALLER="${V5_INSTALLER:-assistant}"
V4_REINSTALLER="${V4_REINSTALLER:-$V5_INSTALLER}"
# 16. R2: 1 when this host is a NEW host for 5.0 (an image launched beside the 4.x one): the 4.x phases 1-4 ran on the
#     4.x host into the same BUNDLE_DIR, which was then copied here; phase 5 removes nothing on this host.
#     V5_INSTALLER=image: 5.0 came installed and running in the image (AMI, OVA): phase 5 removes the image's own
#     pre-enrolled agent from the registry (it holds id 001, which the 4.x fleet holds too) and closes the listeners.
NEW_HOST="${NEW_HOST:-0}"
# 17. F7: 1 keeps the 4.x packages in the bundle (the 4.x assistant's own offline set, downloaded in phase 2 while 4.x
#     is live) and going back reinstalls from them; 0 downloads them again when going back. Recommended (design: it costs
#     about 1.8 GB and 84 s before the outage, saves about 68 s of the way back and removes the internet from it).
V4_PACKAGES_CACHE="${V4_PACKAGES_CACHE:-0}"
# 19. G5: the Server API's request limit during the identity import. "raise" (default): saved, raised for the import and
#     restored before the stage ends (4 min 2 s for 12,000 agents); "stock": the shipped limit (50 min 25 s), for sites
#     that forbid touching api.yaml.
IDENTITY_LIMIT_MODE="${IDENTITY_LIMIT_MODE:-raise}"
# 21. The flow's decisions file: every question the flow asks a person and cannot answer itself is written here as an
#     entry with "action": null, the run stops, and the next run reads the answers. Sections: "settings" and
#     "groups-pre-upgrade" / "groups-post-upgrade" (the settings converter, C4), "ruleset" (rmig's decisions.json,
#     unless RMIG_DECISIONS names a file of its own). Default: inside the bundle.
MIGRATION_DECISIONS="${MIGRATION_DECISIONS:-$BUNDLE_DIR/decisions.json}"
# 22. C4: 1 converts the 4.x manager settings and merges them into the installed 5.0 files in phase 6 (rules 21, 22),
#     and cleans the group files in two passes (phase 6, phase 11). 0 leaves the installed 5.0 settings and the group
#     files as the identity import wrote them.
CARRY_SETTINGS="${CARRY_SETTINGS:-1}"
# 23. Clusters only: directories holding the other nodes' candidate wazuh-manager.conf, for the cross-node check (C4)
#     before anything is staged on this node. Space separated. Empty on an all-in-one.
CLUSTER_CANDIDATES="${CLUSTER_CANDIDATES:-}"
# 20. H5: worker processes for the history's Python shaping (the corrected map runs in Python; threads cap at one core:
#     about 1,000 alerts a second, 8 processes about 5,000). Default half the CPUs, at most 8: after the opening the
#     load shares the host with live traffic (F10). 0 uses threads.
_np=$(nproc 2>/dev/null || echo 2); _hp=$(( _np / 2 )); [ "$_hp" -ge 1 ] || _hp=1; [ "$_hp" -le 8 ] || _hp=8
HISTORY_PROCS="${HISTORY_PROCS:-$_hp}"
# 18. F10: when the 4.x alert history is loaded. "after-open" (F10's proposed contract order): phase 6 imports identity,
#     ruleset and security, phase 7 opens the listeners, phase 8 verifies everything but the history, and a new phase,
#     history, loads, proves and only then switches the aliases on while the agents are already served.
#     "before-open" (the contract as it was): the load, the proof and the aliases are part of phase 6, inside the outage.
HISTORY_LOAD="${HISTORY_LOAD:-after-open}"
# 24. Rule 14: how long phase 10 (before its gate) and the finish (before its restart) wait for the vulnerability feed's
#     initial load, in seconds. Measured 8 to 26 min on an all-in-one. A restart during the load throws it away and
#     upgraded agents send no packages, OS or vulnerabilities until it completes. 0: do not wait, only report the state
#     (an air-gapped site whose manager cannot reach the feed).
FEED_WAIT_MAX="${FEED_WAIT_MAX:-3600}"

############ Defaults a user may change, none required ###########################################
CARRY_INDEXER_SECURITY="${CARRY_INDEXER_SECURITY:-1}"
CARRY_SAVED_OBJECTS="${CARRY_SAVED_OBJECTS:-1}"
ALLOW_OLD_AGENTS="${ALLOW_OLD_AGENTS:-0}"        # 1: do not stop on agents older than 4.14.0
FORCE_BUILDS="${FORCE_BUILDS:-0}"                # 1: go on with a build this script was not validated on
AGENT_WAIT_SECS="${AGENT_WAIT_SECS:-900}"
WORK_DIR="${WORK_DIR:-/root/mig-work}"           # scratch: the assistants run here, never inside the bundle
RMIG_SAMPLES="${RMIG_SAMPLES:-}"
RMIG_ACTIVATE_ARGS="${RMIG_ACTIVATE_ARGS:-}"     # P1 lab repair only (P-D6): e.g. --include-foreign-changes
# Lab switches for the break tests. Never set in a real run.
TEST_KILL_AT="${TEST_KILL_AT:-}"                 # step marker: SIGKILL this script right after that step ends (before its marker)
TEST_KILL_BEFORE="${TEST_KILL_BEFORE:-}"         # step marker: SIGKILL this script right before that step starts
TEST_HISTORY_STOP_AFTER="${TEST_HISTORY_STOP_AFTER:-}"   # N: the history load exits hard after N files
LAB_HOOK="${LAB_HOOK:-}"                         # script called as "$LAB_HOOK <point>" at freeze and after the load (lab proof only)
LAB_BACK_GUARD="${LAB_BACK_GUARD:-1}"            # F7: 0 goes back WITHOUT the agent guard (to reproduce the lockout)
TEST_V5_START_FAIL="${TEST_V5_START_FAIL:-}"     # F7: 1 makes the 5.0 manager's first start fail (ExecStartPre=/bin/false drop-in, as F4)

# Rule 4 / Supported builds: the validated builds come from the build manifest shipped with the tool, not from this code.
_manifest_list() { python3 -c 'import json,sys; print(" ".join(json.load(open(sys.argv[1])).get(sys.argv[2], [])))' "$(dirname "$(readlink -f "$0")")/manifest/builds.json" "$1" 2>/dev/null || true; }   # missing manifest: the defaults below
VALIDATED_4X="$(_manifest_list source_4x)"; VALIDATED_4X="${VALIDATED_4X:-4.14.10}"   # source builds this tool was run on
VALIDATED_5X="$(_manifest_list target_5x)"; VALIDATED_5X="${VALIDATED_5X:-5.0.0}"     # target version; the nightly's manifest hash changes daily and is recorded, not pinned
PHASES=(assess precopy freeze verify_bundle replace import open verify history)   # F10: history (a no-op with HISTORY_LOAD=before-open)
SELF="$(readlink -f "$0")"
HERE="$(dirname "$SELF")"
# Each step body runs in a fresh bash process (see step): everything it reads from the caller has to be in the environment.
export BUNDLE_DIR V4_INSTALL_FILES_TAR V4_ASSISTANT V5_ASSISTANT V5_ARTIFACT_URLS IDENTITY_TOOL RMIG_DIR RMIG_DECISIONS AGENT_ADDRESSES \
       UNCLASSIFIED_DECISION WPK_REPO HISTORY_RETENTION HISTORY_ARCHIVES ACCEPT_ROLE_LOSS CARRY_INDEXER_SECURITY CARRY_SAVED_OBJECTS ALLOW_OLD_AGENTS \
       FORCE_BUILDS AGENT_WAIT_SECS WORK_DIR RMIG_SAMPLES RMIG_ENGINE_HELPERS RMIG_ACTIVATE_ARGS TEST_KILL_AT TEST_KILL_BEFORE TEST_HISTORY_STOP_AFTER LAB_HOOK \
       V5_INSTALLER V4_REINSTALLER NEW_HOST V4_PACKAGES_CACHE LAB_BACK_GUARD TEST_V5_START_FAIL HISTORY_LOAD NEVER_CONNECTED_AT_FINISH IDENTITY_LIMIT_MODE HISTORY_PROCS MIGRATION_DECISIONS CARRY_SETTINGS CLUSTER_CANDIDATES
HELPER="$HERE/mig_helper.py"
STATE="$BUNDLE_DIR/state"; LOGS="$BUNDLE_DIR/logs"; RESULTS="$BUNDLE_DIR/results"; JOURNAL="$BUNDLE_DIR/journal.ndjson"
HIST="$BUNDLE_DIR/history"
V4=/var/ossec; V5=/var/wazuh-manager; V5ETC=/etc/wazuh-manager
# Directories something in this flow deletes: the 4.x removal, the 5.0 assistant's rollback, -o and -u, a reboot.
UNSAFE_PATHS=(/var/ossec /var/lib/wazuh-indexer /etc/wazuh-indexer /usr/share/wazuh-indexer /var/log/wazuh-indexer
              /etc/wazuh-dashboard /usr/share/wazuh-dashboard /var/lib/wazuh-dashboard /run/wazuh-dashboard
              /etc/filebeat /var/lib/filebeat /usr/share/filebeat /var/log/filebeat
              /var/wazuh-manager /etc/wazuh-manager /tmp /var/tmp /run /dev/shm "$WORK_DIR")

CMD="${1:-}"; [ $# -gt 0 ] && shift
FROM=""; ONLY=""; THROUGH=""
[ "$CMD" = __step ] || while [ $# -gt 0 ]; do case "$1" in
  --from) FROM="$2"; shift;; --only) ONLY="$2"; shift;; --through) THROUGH="$2"; shift;;
  -h|--help) sed -n '2,16p' "$0"; exit 0;; *) echo "unknown option $1" >&2; exit 2;; esac; shift; done

ts()   { date -u +%Y-%m-%dT%H:%M:%SZ; }
log()  { printf '[%s] %s\n' "$(ts)" "$*"; }
die()  { log "FATAL: $*"; exit 1; }
# E2-rpm fix 03 (rule 10): a marker is written only once what its step wrote is on disk. Without the sync a power cut
# (sysrq b) 0.25 s after import.identity was marked left the marker and emptied authd.pass, client.keys, api.yaml and the
# identity stage's saved original and state (XFS keeps renamed files' data in memory up to 30 s): the rerun skipped the
# import and the manager could not start.
mark() { sync; stamp "$1"; }   # E2-rpm fix 03: what the step wrote is on disk before its marker exists
stamp() { # E3 fold (E3-rpm 2 and 6): a marker or a recorded time is whole or absent after a power cut. The sync came before
  # the write only, so replace.gate, phase.replace, open.decision and T_import_begin were 0-byte files after a cut (the
  # times lost, and T_import_begin never written again). Written beside, synced, renamed, the directory synced.
  local f="$STATE/$1" t="$STATE/.$1.tmp"
  printf '%s\n' "$(ts)" > "$t"; sync "$t" 2>/dev/null || sync; mv -f "$t" "$f"; sync "$STATE" 2>/dev/null || sync; }
done_() { [ -e "$STATE/$1" ]; }
jr()   { # jr <step> <event> [detail]: one journal line
  python3 - "$JOURNAL" "$1" "$2" "${3:-}" <<'EOF'
import json, sys, time
open(sys.argv[1], "a").write(json.dumps({"ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "step": sys.argv[2], "event": sys.argv[3], "detail": sys.argv[4]}) + "\n")
EOF
}
result() { # result <step> <rc> <start-epoch> <description>
  python3 - "$RESULTS/$1.json" "$1" "$2" "$3" "$4" <<'EOF'
import json, sys, time
p, step, rc, t0, d = sys.argv[1:6]
tail = ""
try: tail = open(p[:-5] + ".log", errors="replace").read()[-1500:]
except OSError: pass
json.dump({"step": step, "description": d, "exit": int(rc), "result": "ok" if rc == "0" else "failed", "started_epoch": int(t0),
           "ended": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "seconds": int(time.time()) - int(t0), "output_tail": tail},
          open(p, "w"), indent=1)
EOF
}
step() { # step <marker> <description> <function>: run once, skip when the marker exists; result file and journal either way
  # The body runs in a fresh bash process with errexit. A subshell "( set -e; f )" is not enough: bash ignores errexit
  # in everything a function runs when the function was reached from an if or while test, a "!" or a non-final
  # member of an && or || list, so a failed command inside the step would be passed over and the step marked done
  # (evidence/40-patches/01-errexit-in-and-list-repro.txt). For the same reason a failed step ends the run (exit),
  # instead of returning a status a caller in such a context would drop.
  local m=$1 d=$2 f=$3 rc t0
  if done_ "$m"; then log "  skip  $d (done $(cat "$STATE/$m"))"; jr "$m" skip; return 0; fi
  if [ "$TEST_KILL_BEFORE" = "$m" ]; then log "  LAB SWITCH: SIGKILL before step $m"; jr "$m" lab-kill-before; kill -9 $$; fi
  log "  step  $d"
  jr "$m" begin "$d"; t0=$(date +%s)
  # "|| rc=" and not "set +e": the ERR trap of main is not switched off by set +e, so before this a failed step ended
  # in the trap ("ERROR: line 112") and its result file, FAIL line and journal entry were never written.
  rc=0; bash "$SELF" __step "$f" 2>&1 | tee "$RESULTS/$m.log" || rc=${PIPESTATUS[0]}
  result "$m" "$rc" "$t0" "$d"
  if [ "$rc" != 0 ]; then jr "$m" fail "exit $rc"; log "  FAIL  $d (exit $rc); see $RESULTS/$m.log"; trap - ERR; exit "$rc"; fi
  if [ "$TEST_KILL_AT" = "$m" ]; then log "  LAB SWITCH: SIGKILL after step $m, before its marker"; jr "$m" lab-kill-after; kill -9 $$; fi
  mark "$m"; jr "$m" end "$(( $(date +%s) - t0 )) s"; log "  done  $d ($(( $(date +%s) - t0 )) s)"
}
# P1: the package family decides the package queries, the manifest keys and the repository file (DECISIONS P-D3)
if command -v apt-get >/dev/null 2>&1 && command -v dpkg-query >/dev/null 2>&1; then PKGFAM=deb; else PKGFAM=rpm; fi
pkgver() { if [ "$PKGFAM" = deb ]; then { dpkg-query -W -f='${db:Status-Status} ${Version}' "$1" 2>/dev/null || true; } | awk '$1=="installed"{print $2}'
           else rpm -q --qf '%{VERSION}-%{RELEASE}\n' "$1" 2>/dev/null | grep -v 'not installed' | head -n1 || true; fi; }
pkgarch() { if [ "$PKGFAM" = deb ]; then dpkg --print-architecture; else uname -m; fi; }   # the manifest's names: amd64/arm64 (deb), x86_64/aarch64 (rpm)
pkglist() { local p; for p in wazuh-manager wazuh-indexer wazuh-dashboard filebeat; do echo "$p $(pkgver $p)"; done; }
pkgall() { if [ "$PKGFAM" = deb ]; then dpkg-query -W -f='${Package} ${db:Status-Abbrev} ${Version}\n' 'wazuh-*' filebeat 2>/dev/null || true
           else rpm -qa --qf '%{NAME} %{VERSION}-%{RELEASE}\n' 'wazuh-*' 'filebeat*' 2>/dev/null || true; fi; }
REPO_FILES=(/etc/apt/sources.list.d/wazuh.list /etc/apt/sources.list.d/wazuh.sources /usr/share/keyrings/wazuh.gpg /usr/share/keyrings/wazuh.gpg~ /etc/yum.repos.d/wazuh.repo)   # R2: wazuh.sources is what the 4.x Ansible roles write; E5 fold: wazuh.gpg~ is the keyring's backup copy (E5-cluster-deb)
v4pw()  { tar -axf "$1" wazuh-install-files/wazuh-passwords.txt -O 2>/dev/null | grep -P "'$2'" -A1 | sed -n "2s/.*password: '\(.*\)'/\1/p"; }
v5env() { sed -n "s/^$2=//p" "$1" | head -n1 | sed "s/^'\(.*\)'$/\1/"; }
# E2-deb G11: an assistant's output is masked as it is written: the 4.x assistant prints the reinstall's admin password in
# its summary ("    Password: ..."), and back-install-4x.log kept it in clear in every bundle that went back
mask_passwords() { # E2-deb G11; E5 fold (E5-cluster-deb gap 8): the value only (a token, or a quoted string), not the rest
  # of the line: the secret sweep's "kept (...)" line was blanked whole. Every value on the line is masked (g)
  sed -u -E 's/([Pp]assword|PASSWORD|[Tt]oken)([^:=]{0,40}[:=][[:space:]]*)("[^"]*"?|'"'"'[^'"'"']*'"'"'?|[^[:space:]]+)/\1\2MASKED/g'; }
fetch() { if [[ "$1" =~ ^https?:// ]]; then curl -fsSL --retry 3 -o "$2" "$1"; else cp -f "$1" "$2"; fi; }
host_state() { local m; m=$(pkgver wazuh-manager); case "$m" in 4.*) echo v4;; 5.*) echo v5;; "") echo none;; *) echo "unknown:$m";; esac; }
# R2: the indexer address. The assistant's all-in-one listens on loopback; the 5.0 Ansible role sets network.host to
# the host's private address only, so 127.0.0.1:9200 is refused there. Read it from the indexer's own configuration.
idxhost() { local h; h=$(sed -n "s/^network.host:[[:space:]]*['\"]\{0,1\}\([^'\"]*\)['\"]\{0,1\}[[:space:]]*$/\1/p" /etc/wazuh-indexer/opensearch.yml 2>/dev/null | head -n1)
            case "$h" in ""|0.0.0.0|127.0.0.1|localhost|_local_*|"["*) echo 127.0.0.1;; *) echo "$h";; esac; }
idx4() { local m=$1 p=$2; shift 2; curl -sS -k -u "admin:$V4_INDEXER_ADMIN_PASSWORD" -X "$m" "https://$(idxhost):9200$p" -H 'Content-Type: application/json' "$@"; }
idx5pw() { v5env /etc/wazuh-indexer/export/credentials.env WAZUH_INDEXER_ADMIN_PASSWORD; }
idx5() { local m=$1 p=$2; shift 2; curl -sS --cacert /etc/wazuh-indexer/certs/root-ca.pem -u "admin:$(idx5pw)" -X "$m" "https://$(idxhost):9200$p" -H 'Content-Type: application/json' "$@"; }
wait_indexer() { local i; for i in $(seq 1 60); do "$1" GET /_cluster/health 2>/dev/null | grep -q '"status"' && return 0; sleep 5; done; return 1; }
wait_api5() { local i; for i in $(seq 1 "${1:-60}"); do curl -sk -o /dev/null -m 5 https://localhost:55000/ && return 0; sleep 3; done; return 1; }
wait_clusterd() { # rule 4 (G5): after a manager restart "ready" also means the cluster daemon answers. At 12,000 agents
  # 5.0's cluster daemon blocked about 5 minutes in every 15 and cluster_control and the cluster API timed out meanwhile.
  local i out
  [ -x $V5/bin/cluster_control ] || return 0
  for i in $(seq 1 ${CLUSTERD_TRIES:-15}); do
    out=$(timeout 30 $V5/bin/cluster_control -l 2>&1) && return 0
    grep -qi "disabled" <<<"$out" && return 0
    sleep 30
  done
  echo "the cluster daemon does not answer (cluster_control -l): $(tail -n 1 <<<"$out")"; return 1
}
manager5_up() { # the 5.0 unit is Type=forking with RemainAfterExit=yes: after an unclean stop it stays "active" with every
                # daemon dead, and waiting for the API then only times out. Look at the daemons, restart when they died.
  local st; st=$($V5/bin/wazuh-manager-control status 2>/dev/null || true)   # not "status | grep -q": SIGPIPE under pipefail inverts it
  if ! grep -q "not running" <<<"$st"; then
    # E3 fold (E3-rpm 4): every daemon running but the API silent (seen once after a hard reboot: apid up, nothing on
    # 55000 until a restart). Before, this waited about 3 min, then blamed dead daemons with an empty list. A shorter
    # wait (API5_WAIT_TRIES, 20 tries of 3 s and up to 5 s each) when the daemons run, then say what was seen.
    wait_api5 "${API5_WAIT_TRIES:-20}" && { wait_clusterd; return; }
    echo "the 5.0 manager's daemons are running but the Server API did not answer on https://localhost:55000/ within the wait: restarting the unit"
  else
    echo "the 5.0 manager's unit is '$(systemctl is-active wazuh-manager)' but its daemons are not running (an unclean stop): restarting it"
    grep "not running" <<<"$st" | tr '\n' ' '; echo
  fi
  systemctl restart wazuh-manager
  wait_api5 || { echo "the Server API does not answer after the restart"; return 1; }
  wait_clusterd
}
# P1: firewalld. Neither assistant opens or closes a port (the 5.0 one only warns when firewalld runs); the agent ports
# are the migration's to manage when it is active (DECISIONS P-D9). CL1: ufw too (the design says assess reports both;
# deb nodes of a cluster commonly run ufw): the first active one of firewalld and ufw is the one managed, none otherwise.
fw_kind() { if command -v firewall-cmd >/dev/null 2>&1 && firewall-cmd --state >/dev/null 2>&1; then echo firewalld
            elif command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q '^Status: active'; then echo ufw
            else echo none; fi; }
fw_active() { [ "$(fw_kind)" != none ]; }
fw_zone() { [ "$(fw_kind)" = ufw ] && { echo "(ufw)"; return 0; }
            local i z; i=$(ip route show default 2>/dev/null | awk '{print $5; exit}')
            z=$( [ -n "$i" ] && firewall-cmd --get-zone-of-interface="$i" 2>/dev/null || true ); echo "${z:-$(firewall-cmd --get-default-zone)}"; }
fw_how() { # fw_how <port>: "port", "service:<name>" or "" (not allowed) for <port>/tcp in the zone agents arrive in
  local z p=$1 sv
  if [ "$(fw_kind)" = ufw ]; then   # CL1: "1517/tcp ALLOW Anywhere" or "1517 ALLOW ..." (ufw allow 1517)
    ufw status 2>/dev/null | grep -qE "^$p(/tcp)?[[:space:]]+ALLOW" && echo port || echo ""; return 0; fi
  z=$(fw_zone)
  firewall-cmd --zone="$z" --query-port="$p/tcp" >/dev/null 2>&1 && { echo port; return 0; }
  for sv in $(firewall-cmd --zone="$z" --list-services 2>/dev/null); do
    firewall-cmd --info-service="$sv" 2>/dev/null | grep -E '^\s*ports:' | grep -qw "$p/tcp" && { echo "service:$sv"; return 0; }
  done; echo ""; }
fw_port() { # fw_port add|remove <port>: runtime and permanent, in the zone agents arrive in (ufw: its rules persist)
  if [ "$(fw_kind)" = ufw ]; then if [ "$1" = add ]; then ufw allow "$2/tcp" >/dev/null; else ufw delete allow "$2/tcp" >/dev/null; fi; return; fi
  local z; z=$(fw_zone); firewall-cmd --zone="$z" --"$1"-port="$2/tcp" >/dev/null && firewall-cmd --permanent --zone="$z" --"$1"-port="$2/tcp" >/dev/null; }
# R2: the agent guard. A host firewall rule that refuses the agent ports (1514, 1515, 1517) to everything but loopback,
# whatever the manager's configuration says. Needed wherever something other than this command may rewrite the
# listeners while the registry is not yet imported or restored: the 5.0 Ansible role sets every <bind_addr> to 0.0.0.0
# on each run, an image starts its manager on first boot, and a fresh 4.x manager hands out keys with no password.
guard() { # guard on|off|status [agent|cluster]. Merged: one implementation, src/guard.sh (R2/F5 + K5), shared with the
  # cluster node steps. The guard is node state: recorded in $STATE/guard.required.<name> and re-applied by a wazuh-manager
  # drop-in before any manager starts, so a reboot cannot open the ports (K5, rule 11).
  local rc=0 name=${2:-agent}
  bash "$HERE/guard.sh" "$1" "$name" "$STATE" || rc=$?
  if [ "$1" = on ] && [ "$rc" = 3 ]; then
    # R2: Amazon Linux 2023 images ship neither iptables nor nft. Where 5.0 comes from the assistant (listeners closed by
    # its installation variables) the configuration holds the listeners closed; where a playbook may rewrite them
    # (V5_INSTALLER=external) a guard is required.
    if [ "$V5_INSTALLER" = external ]; then echo "no iptables or nft on this host: the agent guard is required with V5_INSTALLER=external (install nftables, or hold 1514, 1515 and 1517 closed in the cloud security group)"; return 1; fi
    return 0
  fi
  if [ "$1" = on ] && [ "$name" = agent ]; then ts > "$STATE/guard.on"; fi    # F5's record, kept for bundles of earlier runs
  if [ "$1" = off ] && [ "$name" = agent ]; then rm -f "$STATE/guard.on"; fi
  return $rc
}
# F5: the guard lives in the kernel's firewall tables, which a reboot empties, while its marker lives in the bundle.
# Every command that resumes a run puts it back when the marker says it should be on (a reboot during phases 5 to 7,
# or during going back before the restored 4.x manager runs, would otherwise resume with the agents unguarded).
guard_resume() {
  local g
  for g in agent cluster; do
    [ -e "$STATE/guard.required.$g" ] || { [ "$g" = agent ] && [ -e "$STATE/guard.on" ]; } || continue
    [ "$(guard status $g)" = off ] || continue
    echo "the $g guard is recorded on but is not in the firewall (a reboot empties it): putting it back"
    guard on $g
  done
  return 0
}
# F5: the package database after a crash. A reboot during a deb maintainer script leaves the package half-configured
# and dpkg's journal pending ("dpkg was interrupted"); every apt-get call then fails, and the 5.0 assistant's -o and -u
# report the failed removal as a warning, delete the package's directories anyway, and stop (the indexer it could not
# remove keeps running from deleted files and holds 9200). A crash during an rpm unpack leaves files under rpm's
# temporary names (name;xxxxxxxx), mostly empty, that no package owns. Repair before any assistant runs.
pkgdb_problems() { # one line per problem; nothing when the package database can be worked with
  if [ "$PKGFAM" = deb ]; then
    [ -z "$(ls -A /var/lib/dpkg/updates 2>/dev/null)" ] || echo "dpkg was interrupted: $(ls /var/lib/dpkg/updates | wc -l) pending journal entr(ies)"
    dpkg-query -W -f='${Package} ${db:Status-Status}\n' 'wazuh-*' filebeat 2>/dev/null \
      | awk 'NF==2 && $2!="installed" && $2!="not-installed" && $2!="config-files" {print "package " $1 " is " $2}'
  else
    local n; n=$(find /var/wazuh-manager /etc/wazuh-manager /usr/share/wazuh-manager /var/lib/wazuh-indexer /etc/wazuh-indexer /usr/share/wazuh-indexer \
                      /etc/wazuh-dashboard /usr/share/wazuh-dashboard /etc/rc.d/init.d /usr/lib/systemd/system /usr/share/licenses -name '*;*' 2>/dev/null | wc -l)
    [ "$n" = 0 ] || echo "$n file(s) under rpm's temporary names (an unpack cut short; no package owns them)"
  fi
  return 0
}
pkg_repair() { # pkg_repair <context>
  local p s; p=$(pkgdb_problems)
  [ -n "$p" ] || { echo "package database: clean"; return 0; }
  echo "package database NOT clean ($1):"; sed 's/^/  /' <<<"$p"
  systemctl stop wazuh-manager wazuh-indexer wazuh-dashboard 2>/dev/null || true   # nothing may run from a package about to be removed
  if [ "$PKGFAM" = deb ]; then
    if dpkg --configure -a > "$LOGS/dpkg-configure-a.$(date -u +%H%M%S).log" 2>&1; then echo "dpkg --configure -a: completed the interrupted configuration"
    else echo "dpkg --configure -a: exit $? ($(grep -E '^dpkg: error|^Errors' "$(ls -t "$LOGS"/dpkg-configure-a.*.log | head -n1)" | head -n 2 | tr '\n' ' '))"; fi
    for s in $(dpkg-query -W -f='${Package}:${db:Status-Status}\n' 'wazuh-*' 2>/dev/null | awk -F: '$2!="" && $2!="installed" && $2!="not-installed" && $2!="config-files" {print $1}'); do
      echo "package $s still $(dpkg-query -W -f='${db:Status-Status}' "$s"): dpkg --purge --force-remove-reinstreq $s"
      dpkg --purge --force-remove-reinstreq "$s" >> "$LOGS/dpkg-purge-$s.log" 2>&1 || { tail -n 5 "$LOGS/dpkg-purge-$s.log"; return 1; }
    done
  else
    find /var/wazuh-manager /etc/wazuh-manager /usr/share/wazuh-manager /var/lib/wazuh-indexer /etc/wazuh-indexer /usr/share/wazuh-indexer \
         /etc/wazuh-dashboard /usr/share/wazuh-dashboard /etc/rc.d/init.d /usr/lib/systemd/system /usr/share/licenses -name '*;*' -delete 2>/dev/null || true
    echo "deleted the files under rpm's temporary names"
  fi
  p=$(pkgdb_problems); [ -z "$p" ] || { echo "the package database is still not clean:"; sed 's/^/  /' <<<"$p"; return 1; }
  echo "package database: clean after the repair: $(pkgall | tr '\n' ';')"
}
# R2: a listener state that only this command sets. The Ansible role sets every <bind_addr> back to 0.0.0.0 on each run
# and starts the manager; until the import is verified the agent listener is closed again here, and the guard holds.
close_listeners5() {
  local c=$V5ETC/wazuh-manager.conf
  sed -i -e '/<https>/,/<\/https>/s|<bind_addr>.*</bind_addr>|<bind_addr>127.0.0.1</bind_addr>|' \
         -e '/<legacy>/,/<\/legacy>/s|<enabled>.*</enabled>|<enabled>no</enabled>|' "$c"
  $V5/bin/wazuh-manager-conf validate
  systemctl restart wazuh-manager
  wait_api5 || { echo "the Server API did not come back after closing the listeners"; return 1; }
  sleep 5; echo "listening after closing: $(ss -ltnH | awk '{print $4}' | grep -E ':(1514|1515|1517)$' | sort | tr '\n' ' ')"
}
load_v4_passwords() {
  local tar="$V4_INSTALL_FILES_TAR"; [ -s "$tar" ] || tar="$BUNDLE_DIR/v4/rollback/wazuh-install-files.tar"
  export V4_INDEXER_ADMIN_PASSWORD="${V4_INDEXER_ADMIN_PASSWORD:-$(v4pw "$tar" admin)}"
  export V4_API_PASSWORD="${V4_API_PASSWORD:-$(v4pw "$tar" wazuh)}"
}
under_unsafe() { local p u; p=$(readlink -m "$1"); for u in "${UNSAFE_PATHS[@]}"; do case "$p/" in "$u"/*) echo "$u"; return 0;; esac; done; return 1; }
manifest_write() { ( cd "$BUNDLE_DIR" && find . -type f ! -path './state/*' ! -path './logs/*' ! -path './results/*' ! -path './history/load-state/*' ! -path './fleet/*' ! -path './work/*' ! -path './settings/*' ! -path ./decisions.json \
                     ! -name journal.ndjson ! -name MANIFEST.sha256 ! -name '*.tmp' -print0 | sort -z | xargs -0 sha256sum > MANIFEST.sha256 ); }
manifest_check() { ( cd "$BUNDLE_DIR" && sha256sum --quiet -c MANIFEST.sha256 ); }
# OF1 (E2-deb G4): the per-agent databases (queue/db/NNN.db, with any -wal/-shm beside them): package and OS inventory,
# FIM baselines and SCA state. Going back without them left an agent with no package inventory for minutes.
agent_dbs() { find "$1/queue/db" -maxdepth 1 -type f -regextype posix-extended -regex '.*/[0-9]+\.db(-wal|-shm)?' -printf '%f %s\n' 2>/dev/null | sort || true; }
agent_dbs_check() { # agent_dbs_check <archive> <list>: every listed per-agent database is in the archive with its size
  python3 - "$1" "$2" <<'PY'
import os, sys, tarfile
want = {l.split()[0]: int(l.split()[1]) for l in open(sys.argv[2]) if l.strip()}
have = {}
with tarfile.open(sys.argv[1]) as t:
    for m in t:
        if m.isfile() and "/queue/db/" in "/" + m.name:
            have[os.path.basename(m.name)] = m.size
bad = sorted(n for n, s in want.items() if have.get(n) != s)
print("per-agent databases in the rollback archive: %d of %d at their recorded size%s" % (len(want) - len(bad), len(want), ("; missing or another size: " + " ".join(bad[:10])) if bad else ""))
sys.exit(1 if bad else 0)
PY
}
usable_keys() { awk '!/^[[:space:]]*(#|$)/ && $2 !~ /^!/ && NF >= 4' "$1" 2>/dev/null | wc -l; }   # F6: agents a client.keys holds
noagents() { [ -e "$BUNDLE_DIR/identity-noagents/MANIFEST" ]; }                                    # F6: the source had no agent (U017)
py4() { if [ -x $V4/framework/python/bin/python3 ]; then echo $V4/framework/python/bin/python3; else echo python3; fi; }

########################################################################## 1. ASSESS (read-only on 4.x)
FAILS=0; WARNS=0
ok()   { log "  PASS  $*"; }
bad()  { log "  FAIL  $*"; FAILS=$((FAILS + 1)); }
warn() { log "  WARN  $*"; WARNS=$((WARNS + 1)); }

bundle_path_check() { # before ANYTHING is created: the bundle location
  local u
  if u=$(under_unsafe "$BUNDLE_DIR"); then
    echo "[$(ts)] FATAL: the bundle directory $BUNDLE_DIR is under $u, which the 4.x removal, the 5.0 assistant (-o, -u, failure rollback) or a reboot deletes. Nothing was created or changed. Choose a location such as /root, /opt, /srv or /var/backups." >&2
    exit 2
  fi
  local parent; parent=$(readlink -m "$BUNDLE_DIR"); while [ ! -d "$parent" ]; do parent=$(dirname "$parent"); done
  if [ "$(stat -f -c %T "$parent" 2>/dev/null)" = tmpfs ]; then
    echo "[$(ts)] FATAL: the bundle directory $BUNDLE_DIR is on a tmpfs ($parent): it does not survive a reboot. Nothing was created or changed." >&2; exit 2
  fi
}
assess_tools() { # what the run needs whatever state the host is in
  local tok p
  [ -f "$IDENTITY_TOOL" ] && ok "identity tool: $(python3 "$IDENTITY_TOOL" --version 2>&1 | head -n1)" || bad "identity tool not found at $IDENTITY_TOOL"
  [ -d "$RMIG_DIR/rmig" ] && ok "ruleset tool found at $RMIG_DIR" || bad "ruleset tool not found at $RMIG_DIR"
  for p in dump.py history_load.py history_migrate.py apply_map.py loader_map.py history-loader-map.json load_unchanged.py fleet-facts-4x.py fleet-upgrade.py mig_helper.py identity_stage.py indexer_stage.py stock-4.14.10.json guard.sh settings_stage.py converter/convert_manager_conf.py converter/clean_agent_conf.py converter/cluster_check.py converter/ranges-5.0.0.json converter/refs/base-5.0.0-aio/wazuh-manager.conf manifest/builds.json; do [ -f "$HERE/$p" ] || bad "missing $HERE/$p"; done
  python3 -c 'import sys; sys.exit(sys.version_info < (3, 8))' && ok "python3 $(python3 -V | cut -d' ' -f2)" || bad "python3 3.8 or later is needed"   # design: 3.8+ (runs compared on 3.9 and 3.12)
  for tok in $(tr '+' ' ' <<<"$UNCLASSIFIED_DECISION"); do case "$tok" in verified|activate-force|raw|accept|ask) ;; *) bad "UNCLASSIFIED_DECISION: unknown answer '$tok' (verified, activate-force, raw, accept, ask, joined with +)";; esac; done
  if [ -n "$UNCLASSIFIED_DECISION" ]; then ok "decision on unclassified events if the migrated rules do not verify cleanly: $UNCLASSIFIED_DECISION"
  else ok "decision on unclassified events: the default, $UNCLASSIFIED_DEFAULT (decision 3): the migrated rules are activated when their verification has no failure, and raw event indexing is on until the finish; the finish switches it off only once the migrated rules are active or you answer for it (decision 3); UNCLASSIFIED_DECISION=ask stops before opening instead"; fi
}
assess_archives() { # OF1 (decision 5a): archives only on request; their size is said, with the setting that would carry them
  local n d b
  read -r n d b < <(idx4 GET "/_cat/indices/wazuh-archives-4.x-*?h=docs.count,store.size&bytes=b" | awk 'NF>=2 {n++; d+=$1; s+=$2} END{print n+0, d+0, s+0}')
  if [ "${n:-0}" = 0 ]; then ok "archives: no wazuh-archives-4.x-* index (nothing to decide)"; return 0; fi
  if [ "$HISTORY_ARCHIVES" = 1 ]; then
    bad "archives: HISTORY_ARCHIVES=1 asks to carry $d archived events ($n daily indices, $((b / 1048576)) MB), but this version loads alerts only: the history loader skips every index that is not an alert index and the bundle check compares alert indices only. Run with HISTORY_ARCHIVES=0 (the archives stay on 4.x until it is removed) or keep a snapshot of them"
  else
    warn "archives: $d archived events in $n daily indices ($((b / 1048576)) MB) are NOT carried (decision 5a: alerts always, archives only on request; carrying them would add about $((b * 2 / 1048576)) MB of disk and the time of a second load). HISTORY_ARCHIVES=1 is the setting that asks for them; this version refuses it (it loads alerts only). Export them yourself before phase 5 if you need them"
  fi
}
source_min() { python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); print(d.get("source_min_version") or d["source_4x"][-1])' "$HERE/manifest/builds.json" 2>/dev/null || echo 4.14.10; }
source_version_gate() { # OF1 item 12: this host's manager, indexer and dashboard against the manifest's latest 4.14.x
  python3 "$HELPER" source-version "$(hostname -s 2>/dev/null || hostname)" wazuh-manager "$(pkgver wazuh-manager)" \
    wazuh-indexer "$(pkgver wazuh-indexer)" wazuh-dashboard "$(pkgver wazuh-dashboard)"
}
source_version_or_die() { # every command that starts a migration (pre-copy and freeze on a 4.x host; assess reports it)
  local sv; sv=$(source_version_gate) || { echo "$sv" | grep REFUSED >&2; die "the 4.x source is not the latest 4.14.x: nothing was changed by this step"; }
}
phase_assess() {
  local st; st=$(host_state)
  [ "$(id -u)" = 0 ] && ok "running as root" || bad "must run as root"
  . /etc/os-release; ok "operating system: $PRETTY_NAME $(pkgarch) ($PKGFAM packages)"
  ok "bundle directory $BUNDLE_DIR is outside every directory this flow deletes (checked before it was created)"
  if [ -e "$STATE/T_manager4_stop_begin" ]; then
    # A rerun past the freeze. The 4.x manager is stopped, 4.x may be half removed or gone and the bundle holds the
    # dump: assessing the live source again fails on states this tool created itself (a stopped service, a package the
    # interrupted removal already took, disk the dump uses) and would block the resume. Each phase checks the real
    # state it needs before it acts; assess only checks what the run needs from here.
    ok "this bundle's run is past the freeze (4.x manager stopped by this tool at $(cat "$STATE/T_manager4_stop_begin"); host state now $st): the 4.x source is not assessed again, the journal says where to resume"
    assess_tools
    log "  assess: $FAILS blocker(s), $WARNS warning(s)"; [ "$FAILS" = 0 ] || die "assess failed: the run was not resumed; the host is as the interrupted run left it"; return 0
  fi
  if [ "$st" != v4 ]; then
    bad "no 4.x Wazuh manager package on this host (state: $st) and no run of this bundle past the freeze"
    log "  assess: $FAILS blocker(s), $WARNS warning(s)"; die "assess failed: nothing was changed on this host"
  fi
  local p v l sv
  for p in wazuh-manager wazuh-indexer wazuh-dashboard filebeat; do
    v=$(pkgver $p)
    if [ -z "$v" ]; then bad "package $p is not installed: this flow is for an all-in-one"; continue; fi
    ok "$p $v"
  done
  # OF1 item 12 (decision of 2026-11-24): only the latest 4.14.x is a source, for the manager, the indexer and the dashboard;
  # FORCE_BUILDS does not lift it. A 4.14.x newer than the manifest's minimum (published after the tool) is accepted.
  if sv=$(source_version_gate); then ok "source version: every central component is $(source_min) or a newer 4.14.x"
  else while read -r l; do case "$l" in "SOURCE VERSION REFUSED: "*) bad "${l#SOURCE VERSION REFUSED: }";; esac; done <<<"$sv"; fi
  v=$(pkgver wazuh-manager); v=${v%%-*}
  if grep -qw "$v" <<<"$VALIDATED_4X"; then ok "source build $v is one this script was validated on ($VALIDATED_4X)"
  else warn "source build $v is newer than the builds this script was validated on ($VALIDATED_4X): accepted as the latest 4.14.x (decision of 2026-11-24)"; fi
  for p in wazuh-manager wazuh-indexer wazuh-dashboard; do
    systemctl is-active -q $p && ok "service $p is active" || bad "service $p is not active"
  done
  grep -A12 '<cluster>' $V4/etc/ossec.conf | grep -q '<disabled>yes</disabled>' && ok "manager cluster is disabled (single node)" \
    || bad "the manager cluster is enabled: out of scope for the all-in-one flow"

  load_v4_passwords
  if [ -z "$V4_INDEXER_ADMIN_PASSWORD" ] || [ -z "$V4_API_PASSWORD" ]; then
    bad "cannot read the admin and wazuh passwords from $V4_INSTALL_FILES_TAR (set V4_INDEXER_ADMIN_PASSWORD and V4_API_PASSWORD)"
    log "  assess: $FAILS blocker(s), $WARNS warning(s)"; die "assess failed: nothing was changed on this host"
  fi
  idx4 GET /_cluster/health | grep -q '"status"' && ok "indexer login as admin works" || bad "indexer login as admin failed"
  local nodes; nodes=$(idx4 GET '/_cat/nodes?h=name' | wc -l)
  [ "$nodes" = 1 ] && ok "indexer has one node" || bad "indexer has $nodes nodes: out of scope"
  curl -sk -u "wazuh:$V4_API_PASSWORD" -X POST "https://localhost:55000/security/user/authenticate?raw=true" | grep -q '^ey' \
    && ok "Server API login as wazuh works" || bad "Server API login as wazuh failed"

  # history: size, shards, disk, creation version
  local bytes docs nidx free need shards have
  read -r nidx docs bytes shards < <(idx4 GET "/_cat/indices/wazuh-alerts-4.x-*?h=docs.count,store.size,pri&bytes=b" | awk '{n++; d+=$1; s+=$2; p+=$3} END{print n+0, d+0, s+0, p+0}')
  free=$(df --output=avail -B1 "$(readlink -m "$BUNDLE_DIR" | sed 's|/[^/]*$||')" 2>/dev/null | tail -n1 || echo 0)
  local adb; adb=$(agent_dbs $V4 | awk '{s+=$2} END{print s+0}')   # OF1 (E2-deb G4): the per-agent databases go into the rollback archive
  need=$((bytes * 2 + adb + 6 * 1024 * 1024 * 1024))   # dump files (about 0.3x), the 5.0 copy (about 1x), per-agent databases, packages and work space
  have=$(du -sb "$BUNDLE_DIR" 2>/dev/null | cut -f1); need=$((need - ${have:-0})); [ "$need" -gt 0 ] || need=0   # a rerun: what the bundle already holds is used already
  ok "history: $docs alerts in $nidx daily indices ($shards shards, $((bytes / 1048576)) MB); on 5.0 it becomes one or two indices per month"
  ok "per-agent databases (inventory, FIM baselines, SCA state, kept for going back): $(agent_dbs $V4 | grep -c . || true) file(s), $((adb / 1048576)) MB"
  assess_archives
  [ "${free:-0}" -ge "$need" ] && ok "disk: need about $((need / 1048576)) MB for the dump, the 5.0 copy and the packages; free $((free / 1048576)) MB" \
    || bad "disk: need about $((need / 1048576)) MB; free $((free / 1048576)) MB"
  local old; old=$(idx4 GET "/wazuh-alerts-4.x-*/_settings/index.version.created?flat_settings=true" \
    | python3 -c 'import json,sys; d=json.load(sys.stdin); print(" ".join(sorted(k for k,v in d.items() if int(v["settings"]["index.version.created"]) < 136217827)))' 2>/dev/null || true)
  [ -z "$old" ] && ok "every alert index was created on OpenSearch 2.x" \
    || warn "indices created before OpenSearch 2.x: $old. Dump and load reads documents, so they are carried; they would block the snapshot and adopt transports"

  # enrollment password
  if sed -n '/<auth>/,/<\/auth>/p' $V4/etc/ossec.conf | grep -q '<use_password>yes</use_password>'; then
    if [ -s $V4/etc/authd.pass ]; then
      local n; n=$(tr -d '\n' < $V4/etc/authd.pass | wc -c)
      [ "$n" -ge 16 ] && ok "enrollment password is $n bytes (5.0 needs 16 or more)" \
        || bad "enrollment password is $n bytes: 5.0 refuses fewer than 16. Change it on 4.x and on every agent that still enrolls, or do not carry it"
    else warn "use_password is yes but etc/authd.pass is missing: 5.0 will generate a new password"; fi
  else local en; en=$(enrollment_off_note "$CARRY_SETTINGS"); warn "$(head -n1 <<<"$en")"; tail -n +2 <<<"$en" | while IFS= read -r l; do log "        $l"; done; fi

  # fleet facts: versions, protocol, the address each agent dials (only a 4.x manager can answer this)
  local ff; ff=$(mktemp -d /root/.mig-assess.XXXXXX)
  WAZUH_API_PASSWORD="$V4_API_PASSWORD" python3 "$HERE/fleet-facts-4x.py" --insecure --out "$ff/fleet-facts.json" | sed "s/^/[$(ts)]   info  /"
  python3 - "$ff/fleet-facts.json" "$ALLOW_OLD_AGENTS" > "$ff/summary.txt" <<'EOF'
import json, re, sys
f = json.load(open(sys.argv[1]))["agents"]
old, udp, unknown, noossl, nover = [], [], [], [], []
for i, a in sorted(f.items()):
    m = re.search(r"v(\d+)\.(\d+)\.(\d+)", a.get("version") or "")
    if not m: nover.append(f"{i}:{a['name']}:{a.get('status')}")
    elif tuple(map(int, m.groups())) < (4, 14, 0): old.append(f"{i}:{a['name']}:{a.get('version')}")
    if "udp" in a.get("protocol", []): udp.append(f"{i}:{a['name']}")
    if not a.get("dialed"): unknown.append(f"{i}:{a['name']}")
    if (a.get("os") or {}).get("platform") not in ("windows", "darwin") and a.get("openssl") in (None,): noossl.append(f"{i}:{a['name']}")
print("nover=" + " ".join(nover)); print("old=" + " ".join(old)); print("udp=" + " ".join(udp)); print("unknown=" + " ".join(unknown)); print("noossl=" + " ".join(noossl))
print("dial=" + " ".join(sorted({d for a in f.values() for d in a.get("dialed", [])})))
print("count=%d" % len(f))
EOF
  local old_ udp unknown noossl dial count nover
  nover=$(sed -n 's/^nover=//p' "$ff/summary.txt")
  old_=$(sed -n 's/^old=//p' "$ff/summary.txt"); udp=$(sed -n 's/^udp=//p' "$ff/summary.txt"); unknown=$(sed -n 's/^unknown=//p' "$ff/summary.txt")
  noossl=$(sed -n 's/^noossl=//p' "$ff/summary.txt"); dial=$(sed -n 's/^dial=//p' "$ff/summary.txt"); count=$(sed -n 's/^count=//p' "$ff/summary.txt")
  ok "fleet: $count agent(s) on record"
  # F6 (DECISIONS F6-D7): a source with no agent is valid; the identity tool refuses it, so the freeze carries the
  # enrollment password and the API users itself. Said here, before the outage, instead of failing in the freeze.
  [ "$(usable_keys $V4/etc/client.keys)" != 0 ] || warn "no agent in client.keys: the identity tool is not used; the freeze carries the enrollment password and the API users and roles (rbac.db) as files"
  if [ -z "$old_" ]; then ok "every agent that reported a version is at 4.14.0 or later"
  elif [ "$ALLOW_OLD_AGENTS" = 1 ]; then warn "agents below 4.14.0 (two-step upgrade): $old_"
  else bad "agents below 4.14.0 cannot be upgraded directly to 5.0 (ALLOW_OLD_AGENTS=1 to go on): $old_"; fi
  [ -z "$nover" ] || warn "agents that never reported a version (never connected): carried over, but nothing is known about them: $nover"
  [ -z "$udp" ] || warn "agents on UDP are never offered a remote upgrade by a 5.0 manager; the legacy port stays open for them: $udp"
  [ -z "$unknown" ] && ok "every agent reported the address it dials" || warn "agents not connected: the address they dial is unknown and cannot be checked against the certificate: $unknown"
  [ -z "$noossl" ] || warn "Linux agents without the openssl package end a remote upgrade verifying nothing: $noossl"
  local san missing="" d
  san=$( { hostname -I | tr ' ' '\n' | { grep -v -E '^(127\.|169\.254\.|fe[89ab]|::1|$)' || true; }; hostname -f; hostname; } | sort -u)
  dial=$( { tr ' ' '\n' <<<"$dial"; tr ' ,' '\n\n' <<<"$AGENT_ADDRESSES"; } | { grep -v '^$' || true; } | sort -u)
  for d in $dial; do grep -qxF "$d" <<<"$san" || missing="$missing $d"; done
  log "  info  the 5.0 listener certificate names by itself: $(echo $san)"
  log "  info  addresses the agents dial: $(echo $dial)"
  [ -z "$missing" ] && ok "every dialled address is one the 5.0 certificate names by itself" \
    || warn "dialled addresses the 5.0 certificate would not name:$missing (the install passes each with -as, and a handshake proves each before the listeners open)"
  rm -rf "$ff"   # assess writes nothing into the bundle: the facts the later phases use are taken by the pre-copy (precopy.fleet)

  # roles that read the alerts: what the history switch will mean for them
  idx4 GET /_plugins/_security/api/roles | python3 -c '
import json, sys
d = json.load(sys.stdin)
for n, r in sorted(d.items()):
    if r.get("reserved") or r.get("static"): continue
    for ip in r.get("index_permissions", []):
        if any(p.startswith("wazuh-alerts") for p in ip.get("index_patterns", [])):
            print("custom role %s reads %s%s%s" % (n, ip["index_patterns"], " with document-level security " + ip["dls"] if ip.get("dls") else "", " with field-level security " + str(ip["fls"]) if ip.get("fls") else ""))' \
    | sed "s/^/[$(ts)]   info  /"

  # the tools and the decision
  assess_tools
  ss -ltnH 'sport = :1517' | grep -q . && bad "port 1517 (5.0 agents) is already in use" || ok "port 1517 is free"
  if fw_active; then
    local fp fh; for fp in 1514 1515 1517 443; do fh=$(fw_how $fp); if [ -n "$fh" ]; then fh="allowed ($fh)"; else fh="NOT allowed"; fi; log "  info  $(fw_kind) zone $(fw_zone): $fp/tcp $fh"; done
    [ -n "$(fw_how 1517)" ] || warn "$(fw_kind) is active and does not allow 1517/tcp (5.0 agents): the open phase adds it; phase 11 removes 1514 and 1515 where they were opened as ports"
  else ok "no host firewall is active (firewalld or ufw): no port to open or close"; fi
  log "  assess: $FAILS blocker(s), $WARNS warning(s)"
  [ "$FAILS" = 0 ] || die "assess failed: nothing was changed on this host"
}

########################################################################## 2. PRE-COPY (4.x live)
pc_truth() { python3 "$HELPER" truth4 "$BUNDLE_DIR/truth4"; }
pc_stage() {
  mkdir -p "$BUNDLE_DIR/v5" "$BUNDLE_DIR/v4"
  fetch "$V5_ASSISTANT" "$BUNDLE_DIR/v5/wazuh-install.sh"; echo "5.0 assistant staged: sha256 $(sha256sum "$BUNDLE_DIR/v5/wazuh-install.sh" | cut -d' ' -f1)"
  if [ -n "$V5_ARTIFACT_URLS" ]; then
    fetch "$V5_ARTIFACT_URLS" "$BUNDLE_DIR/v5/artifact_urls.yaml"; echo "5.0 artifact manifest staged: sha256 $(sha256sum "$BUNDLE_DIR/v5/artifact_urls.yaml" | cut -d' ' -f1)"
    local arch url code p; arch=$(pkgarch)
    for p in wazuh_indexer wazuh_manager wazuh_dashboard; do
      url=$(sed -n "s/^${p}_${arch}_${PKGFAM}: *\"\(.*\)\"/\1/p" "$BUNDLE_DIR/v5/artifact_urls.yaml")
      [ -n "$url" ] || { echo "the 5.0 manifest has no ${p}_${arch}_${PKGFAM} entry"; return 1; }
      code=$(curl -s -o /dev/null -I -w '%{http_code}' "$url" || true)
      [ "$code" = 200 ] && echo "5.0 package reachable: ${url##*/}" || { echo "5.0 package not reachable (HTTP $code): $url"; return 1; }
    done
  fi
  fetch "$V4_ASSISTANT" "$BUNDLE_DIR/v4/wazuh-install.sh"; echo "4.x assistant staged (removal, and the reinstall when going back): sha256 $(sha256sum "$BUNDLE_DIR/v4/wazuh-install.sh" | cut -d' ' -f1)"
  pkglist > "$BUNDLE_DIR/v4/packages.txt"; cat "$BUNDLE_DIR/v4/packages.txt"
  if [ "$V4_PACKAGES_CACHE" = 1 ]; then v4_cache_packages; fi
}
v4_cache_packages() { # F7: the 4.x assistant's offline set (-dw), plus the OS packages its offline mode requires installed
  local d="$BUNDLE_DIR/v4/offline" t0=$SECONDS
  if [ -s "$d/wazuh-offline.tar.gz" ] && [ -s "$d/wazuh-offline.tar.gz.sha256" ] && ( cd "$d" && sha256sum --quiet -c wazuh-offline.tar.gz.sha256 ); then
    echo "4.x offline package set already in the bundle"; return 0; fi
  rm -rf "$d"; mkdir -p "$d"; cp -f "$BUNDLE_DIR/v4/wazuh-install.sh" "$d/"
  ( cd "$d" && bash ./wazuh-install.sh -dw "$PKGFAM" -da "$(pkgarch)" ) > "$LOGS/v4-download-offline.log" 2>&1 || { tail -n 15 "$LOGS/v4-download-offline.log"; return 1; }   # -da is required with -dw
  grep -E 'INFO|ERROR' "$LOGS/v4-download-offline.log" | tail -n 4
  rm -f "$d/wazuh-install.sh"
  ( cd "$d" && sha256sum wazuh-offline.tar.gz > wazuh-offline.tar.gz.sha256 )
  tar -tzf "$d/wazuh-offline.tar.gz" | grep -E '\.(rpm|deb)$' | sed 's/^/  /'
  # The assistant's offline mode refuses to start unless curl, tar, gnupg, openssl and lsof are installed packages; its own
  # online install removes lsof again at the end, so the 4.x host usually lacks it. Keep those packages too.
  mkdir -p "$d/os-deps"
  if [ "$PKGFAM" = rpm ]; then ( cd "$d/os-deps" && dnf -q download --resolve lsof ) || echo "WARNING: could not download lsof for the offline reinstall"   # --resolve: libtirpc goes when the assistant removes lsof
  else ( cd "$d/os-deps" && apt-get -q download lsof ) || echo "WARNING: could not download lsof for the offline reinstall"; fi
  ls -l "$d/os-deps"
  echo "4.x offline package set kept in the bundle: $(du -sh "$d" | cut -f1) in $((SECONDS - t0)) s"
}
history_dump() { # run 1 is the bulk copy while live; a later run is the delta
  python3 "$HERE/dump.py" --url https://$(idxhost):9200 --user admin --password-env V4_INDEXER_ADMIN_PASSWORD --insecure --out "$HIST" --workers 4
}
pc_history() { history_dump; }
pc_retention() { python3 "$HELPER" retention-4x "$BUNDLE_DIR/retention-4x.json"; history_retention > /dev/null; cat "$STATE/history.retention"; }
history_retention() { # OF1 (decision 5b): the retention the history is loaded with, and why (in $STATE/history.retention)
  local v why n f="$BUNDLE_DIR/retention-4x.json"
  if [ -n "$HISTORY_RETENTION" ]; then v=$HISTORY_RETENTION; why="set explicitly (HISTORY_RETENTION=$HISTORY_RETENTION)"
  elif n=$(python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); n=d.get("retention_days"); print(n) if n is not None else sys.exit(1)' "$f" 2>/dev/null); then
    v="${n}d"; why="the 4.x deployment's own retention: $(python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); print("; ".join("ISM policy %s deletes alert indices after %s days" % (p["policy_id"], p["delete_after_days"]) for p in d["policies"] if p["delete_after_days"] is not None))' "$f")"
  elif [ -s "$f" ]; then v=365d; why="no ISM policy deleted the 4.x alert indices (read at pre-copy): the default, 365 days"
  else v=365d; why="the 4.x retention was not read (this bundle's pre-copy predates OF1): the default, 365 days"; fi
  echo "history retention: $v: $why" > "$STATE/history.retention.tmp" && mv -f "$STATE/history.retention.tmp" "$STATE/history.retention"
  echo "$v"
}
pc_ruleset_src() { # what the ruleset tool reads: the custom content and the stock ruleset, copied while live
  local d="$BUNDLE_DIR/ruleset-src"; rm -rf "$d"; mkdir -p "$d/etc"
  cp -a $V4/etc/rules $V4/etc/decoders $V4/etc/lists "$d/etc/"; cp -f $V4/etc/ossec.conf "$d/etc/"; cp -a $V4/ruleset "$d/ruleset"
  ( cd "$d" && find etc/rules etc/decoders etc/lists -type f -print0 | sort -z | xargs -0 sha256sum ) > "$d/custom-content.sha256"
  echo "custom content: $(wc -l < "$d/custom-content.sha256") file(s)"
}
rmig() { ( cd "$RMIG_DIR" && WAZUH_INDEXER_URL=https://$(idxhost):9200 WAZUH_INDEXER_USER=admin WAZUH_INDEXER_PASSWORD="$(idx5pw 2>/dev/null || true)" python3 -m rmig "$@" ); }
# P1 (DECISIONS P-D6): the engine's helper names changed between 5.0.0-rc2 and the rc3 nightly: a
# ruleset built for one is refused by the other ("Operation builder 'in_cidr' not found" on rc2).
dialect_for_stage() { # the build manifest's table (rule 4 / Supported builds); the case is its fallback
  local d; d=$(python3 -c 'import json,re,sys; t=json.load(open(sys.argv[1])).get("ruleset_engine_helpers",{}); s=sys.argv[2]
k=next((k for k in t if k!="default" and re.fullmatch(re.escape(k)+r"\d*", s)), None); print(t.get(k, t.get("default","")))' "$HERE/manifest/builds.json" "$1" 2>/dev/null || true)
  [ -n "$d" ] && { echo "$d"; return; }
  case "$1" in alpha*|beta*|rc1|rc2) echo 5.0-rc1;; *) echo 5.0;; esac; }
rmig_dialect_planned() { [ -n "$RMIG_ENGINE_HELPERS" ] && { echo "$RMIG_ENGINE_HELPERS"; return; }
  dialect_for_stage "$(sed -n 's/^staging_url_stage="\(.*\)"/\1/p' "$BUNDLE_DIR/v5/wazuh-install.sh" | head -n1)"; }
rmig_dialect_installed() { [ -n "$RMIG_ENGINE_HELPERS" ] && { echo "$RMIG_ENGINE_HELPERS"; return; }
  dialect_for_stage "$($V5/bin/wazuh-manager-control info 2>/dev/null | sed -n 's/^WAZUH_REVISION="\(.*\)"/\1/p')"; }
pc_ruleset_build() { # offline: scan, plan, build. The check against a 5.0 engine can only run after the install (phase 6).
  ruleset_build "$BUNDLE_DIR/ruleset-migration" "$(rmig_dialect_planned)"; }
ruleset_build() { # ruleset_build <workdir> <engine helper dialect>
  local w="$1" s="$BUNDLE_DIR/ruleset-src" rc=0 dl="$2"
  rm -rf "$w"
  echo "engine helper names: $dl"
  rmig migrate --source "$s/etc" --stock-dir "$s/ruleset" --workdir "$w" --engine-helpers "$dl" > "$LOGS/rmig-1-migrate.log" 2>&1 || rc=$?
  tail -n 4 "$LOGS/rmig-1-migrate.log"; echo "rmig migrate exit $rc (1 = questions open in decisions.json)"
  [ "$rc" -le 1 ] || return 1
  if [ "$rc" = 1 ]; then
    if [ -n "$RMIG_DECISIONS" ] && [ -f "$RMIG_DECISIONS" ]; then cp -f "$RMIG_DECISIONS" "$w/decisions.json"
    elif python3 "$HELPER" decisions-section get "$MIGRATION_DECISIONS" ruleset "$w/decisions.answered.json" && \
         python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); sys.exit(0 if d != json.load(open(sys.argv[2])) else 1)' "$w/decisions.answered.json" "$w/decisions.json"; then
      mv -f "$w/decisions.answered.json" "$w/decisions.json"   # merged: the ruleset's questions live in the flow's decisions file
    else
      rm -f "$w/decisions.answered.json"; python3 "$HELPER" decisions-section put "$MIGRATION_DECISIONS" ruleset "$w/decisions.json"
      echo "decisions are open: answer the \"ruleset\" section of $MIGRATION_DECISIONS (rmig's decisions.json) and run again (RMIG_DECISIONS still names a file of its own)"; return 1
    fi
    rc=0
    rmig plan --workdir "$w" > "$LOGS/rmig-2-plan.log" 2>&1 || rc=$?; tail -n 2 "$LOGS/rmig-2-plan.log"; [ "$rc" -le 1 ] || return 1; rc=0
    rmig build --workdir "$w" --source "$s/etc" --stock-dir "$s/ruleset" --engine-helpers "$dl" > "$LOGS/rmig-3-build.log" 2>&1 || rc=$?; tail -n 2 "$LOGS/rmig-3-build.log"
    echo "rmig build exit $rc"; [ "$rc" -le 1 ] || return 1
  fi
  echo "$dl" > "$w/ENGINE_HELPERS"
  ls "$w" | tr '\n' ' '; echo
}
pc_saved_objects() { mkdir -p "$BUNDLE_DIR/dashboard"; python3 "$HELPER" export-saved-objects "$BUNDLE_DIR/dashboard/saved-objects.ndjson"; }
pc_indexer_security() {
  local d="$BUNDLE_DIR/indexer-security"
  mkdir -p "$d/rest" "$d/backup"
  python3 "$HELPER" export-security-rest "$d/rest"
  # the indexer user has to reach the directory, and the bundle root is root-only: the backup is taken beside the data and moved
  local tmpd; tmpd=$(mktemp -d /var/lib/wazuh-indexer/security-backup.XXXXXX); chown wazuh-indexer "$tmpd"
  /usr/share/wazuh-indexer/bin/indexer-security-init.sh --options "-backup $tmpd -icl -nhnv" > "$LOGS/indexer-security-backup.log" 2>&1 \
    || { tail -n 20 "$LOGS/indexer-security-backup.log"; rm -rf "$tmpd"; return 1; }
  cp -f "$tmpd"/*.yml "$d/backup/"; rm -rf "$tmpd"; chown -R root:root "$d"; chmod -R go= "$d"
  ls "$d/backup" | tr '\n' ' '; echo
  [ -s "$d/backup/internal_users.yml" ] && [ -s "$d/backup/roles.yml" ] || return 1
  # Merged: C23's indexer stage reads the live security configuration (hashes, authentication backends, settings,
  # keystore entry names, notification channels) with the admin certificate and classifies it against stock 4.14.10.
  # The REST export and the securityadmin backup above stay: going back restores from the backup.
  python3 "$HERE/indexer_stage.py" export --bundle "$BUNDLE_DIR" --url "https://$(idxhost):9200" $(idx_cert_args) > "$LOGS/indexer-stage-export.log" 2>&1 \
    || { tail -n 20 "$LOGS/indexer-stage-export.log"; return 1; }
  tail -n 3 "$LOGS/indexer-stage-export.log"; chown -R root:root "$BUNDLE_DIR/indexer"; chmod -R go= "$BUNDLE_DIR/indexer"
}
idx_cert_args() { # the indexer's admin certificate (4.x and 5.0 assistants both place it here)
  local c=/etc/wazuh-indexer/certs; echo "--cacert $c/root-ca.pem --cert $c/admin.pem --key $c/admin-key.pem"; }
pc_settings() { # the files the settings converter reads, unmodified
  local d="$BUNDLE_DIR/v4/config"; mkdir -p "$d/shared"
  cp -f $V4/etc/ossec.conf $V4/etc/local_internal_options.conf $V4/api/configuration/api.yaml "$d/"
  local g; for g in $V4/etc/shared/*/; do g=$(basename "$g"); mkdir -p "$d/shared/$g"; cp -f "$V4/etc/shared/$g/agent.conf" "$d/shared/$g/" 2>/dev/null || true; done
  cp -f /etc/filebeat/filebeat.yml "$d/" 2>/dev/null || true
  # CL1 (E4-cluster gap 2a): a manager-only node of a cluster has no indexer or dashboard files; a plain cp stopped the step
  # there under errexit. They are copied where they exist (the converter itself reads none of them), and said otherwise.
  local f2 miss=""; for f2 in /etc/wazuh-indexer/opensearch.yml:opensearch.yml /etc/wazuh-indexer/jvm.options:indexer-jvm.options \
      /etc/wazuh-dashboard/opensearch_dashboards.yml:opensearch_dashboards.yml; do
    if [ -f "${f2%%:*}" ]; then cp -f "${f2%%:*}" "$d/${f2#*:}"; else miss="$miss ${f2%%:*}"; fi; done
  [ -z "$miss" ] || echo "not on this node (a manager-only node of a cluster):$miss"
  cp -f /usr/share/wazuh-dashboard/data/wazuh/config/wazuh.yml "$d/dashboard-wazuh.yml" 2>/dev/null || true
  # merged (C4, rules 21 and 22): the rest of what the converter reads, the group folders whole (the files an agent.conf
  # names are carried by the pre-upgrade pass) and the 4.x stock reference
  cp -f $V4/etc/internal_options.conf "$d/" 2>/dev/null || true
  local cj; cj=$(cd /tmp && $(py4) -c 'import os, wazuh.core.cluster.utils as u; print(os.path.join(os.path.dirname(u.__file__), "cluster.json"))' 2>/dev/null || true)
  [ -s "$cj" ] || cj=$V4/framework/wazuh/core/cluster/cluster.json
  [ ! -s "$cj" ] || cp -f "$cj" "$d/cluster.json"
  rm -rf "$BUNDLE_DIR/groups4"; mkdir -p "$BUNDLE_DIR/groups4"
  for g in $V4/etc/shared/*/; do g=$(basename "$g"); mkdir -p "$BUNDLE_DIR/groups4/$g"
    find "$V4/etc/shared/$g" -maxdepth 1 -type f ! -name merged.mg -exec cp -p {} "$BUNDLE_DIR/groups4/$g/" \; ; done
  settings_stock "$d/stock"
  find "$d" -type f | sed "s|$d/||" | sort | tr '\n' ' '; echo
  echo "group folders for the two group passes: $(ls "$BUNDLE_DIR/groups4" | tr '\n' ' ')"
}
settings_stock() { # settings_stock <dir>: what the 4.x package itself would write, so that only the site's changes are carried (C4 D3)
  local o=$1 gen=$V4/packages_files/manager_installation_scripts/gen_ossec.sh ref
  . "${MIG_OS_RELEASE:-/etc/os-release}"   # MIG_OS_RELEASE: tests only
  # OF1 (E2-deb G5): the shipped reference made for this distribution and release when the tool has one, else the
  # Ubuntu 24 one (the reference C4 validated), and the choice is said in SOURCE, which the settings report repeats
  ref="$HERE/converter/refs/stock-4.14.10-${ID:-unknown}${VERSION_ID%%.*}"
  [ -d "$ref" ] || ref="$HERE/converter/refs/stock-4.14.10-ubuntu24"
  rm -rf "$o"; mkdir -p "$o"; cp -f "$ref/"* "$o/"
  local which="the shipped reference $(basename "$ref") ($( [ "$(basename "$ref")" = "stock-4.14.10-${ID:-unknown}${VERSION_ID%%.*}" ] && echo "made for this distribution and release" || echo "made for another distribution: none ships for ${ID:-unknown} ${VERSION_ID:-}"), generated in a container)"
  if [ "$PKGFAM" = deb ]; then
    # OF1 (E2-deb G5): on deb the 4.x package's postinst deletes /var/ossec/packages_files (its WAZUH_GLOBAL_TMP_DIR), so the
    # generator is never there: the shipped reference is the deb path by design, not a fallback
    echo "stock reference: deb host: $which, used on purpose: the 4.x deb package deletes its own generator (packages_files) after installing. Host-dependent blocks (the resolver white_list entries, journald or file localfile entries) that differ from a container's are carried as customisations unless they equal the reference: check them in the settings report" | tee "$o/SOURCE"
    return 0
  fi
  # C4 D3 (rpm): a container's generated ossec.conf differs from a real host's (resolvers, journald): generate it on this
  # host with the package's own generator, which the rpm package keeps
  if [ -f "$gen" ] && ( cd "$(dirname "$gen")" && bash "$gen" conf manager "$ID" "${VERSION_ID%%.*}" "$V4" ) > "$o/ossec.conf.host" 2>/dev/null \
     && python3 -c 'import sys,re; t=open(sys.argv[1]).read(); sys.exit(0 if re.search(r"<ossec_config>", t) else 1)' "$o/ossec.conf.host"; then
    mv -f "$o/ossec.conf.host" "$o/ossec.conf"; echo "stock reference: ossec.conf generated on this host by the 4.x package's generator; the other files from $(basename "$ref")" | tee "$o/SOURCE"
  else rm -f "$o/ossec.conf.host"; echo "stock reference: rpm host without the 4.x package's generator ($gen): $which (host-dependent blocks may be carried)" | tee "$o/SOURCE"; fi
}
settings_plan() { # settings_plan <base-dir> <work-dir>: every question of the converter and of both group passes, into the decisions file
  python3 "$HERE/settings_stage.py" plan --v4 "$BUNDLE_DIR/v4/config" --stock "$BUNDLE_DIR/v4/config/stock" --base "$1" \
    --decisions "$MIGRATION_DECISIONS" --work "$2" --groups "$BUNDLE_DIR/groups4"
}
pc_settings_plan() { # merged (C4): asked while 4.x still serves, against the 5.0 files this build installs (a shipped copy)
  [ "$CARRY_SETTINGS" = 1 ] || { echo "CARRY_SETTINGS=0: the 5.0 settings stay as installed"; return 0; }
  # E5 fold: a cluster node passes its own base (PRECOPY_BASE: the shipped one with the node's <cluster>, settings-node.sh)
  local rc=0; settings_plan "${PRECOPY_BASE:-$HERE/converter/refs/base-5.0.0-aio}" "$BUNDLE_DIR/settings/plan-precopy" || rc=$?
  [ "$rc" = 0 ] || echo "the run stops here, before the freeze: answer the open entries in $MIGRATION_DECISIONS and run again"
  return $rc
}
pc_fleet() {
  mkdir -p "$BUNDLE_DIR/preflight"
  WAZUH_API_PASSWORD="$V4_API_PASSWORD" python3 "$HERE/fleet-facts-4x.py" --insecure --out "$BUNDLE_DIR/preflight/fleet-facts.json"
  local san dial missing="" d
  san=$( { hostname -I | tr ' ' '\n' | { grep -v -E '^(127\.|169\.254\.|fe[89ab]|::1|$)' || true; }; hostname -f; hostname; } | sort -u)
  dial=$( { python3 -c 'import json,sys; [print(x) for a in json.load(open(sys.argv[1]))["agents"].values() for x in a.get("dialed", [])]' "$BUNDLE_DIR/preflight/fleet-facts.json"; tr ' ,' '\n\n' <<<"$AGENT_ADDRESSES"; } | { grep -v '^$' || true; } | sort -u)
  for d in $dial; do grep -qxF "$d" <<<"$san" || missing="$missing $d"; done
  printf '%s\n' $dial > "$BUNDLE_DIR/preflight/dialed-addresses.txt"; printf '%s\n' $missing > "$BUNDLE_DIR/preflight/agent-san-extra.txt"
  echo "certificate plan: dialled $(echo $dial); to add with -as:${missing:- none}"
}
pc_manifest() { manifest_write; echo "bundle: $(wc -l < "$BUNDLE_DIR/MANIFEST.sha256") file(s) checksummed, $(du -sh "$BUNDLE_DIR" | cut -f1)"; manifest_check && echo "gate: every bundle file is checksummed and reads back equal"; }
phase_precopy() {
  [ "$(host_state)" = v4 ] || { done_ precopy.gate && { log "  pre-copy already complete and 4.x is gone"; return 0; } || die "4.x is not installed and the pre-copy is not complete"; }
  source_version_or_die   # OF1 item 12
  load_v4_passwords
  step precopy.truth            "record the 4.x state while it is live (truth)"          pc_truth
  step precopy.stage            "stage both assistants; check the 5.0 packages answer"   pc_stage
  step precopy.retention        "history: the 4.x retention (ISM delete policies on the alert indices; decision 5b)" pc_retention
  step precopy.history          "history: dump the alerts while 4.x is live"             pc_history
  step precopy.ruleset_src      "ruleset: copy the custom and stock content"             pc_ruleset_src
  step precopy.ruleset_build    "ruleset: scan, plan and build offline"                  pc_ruleset_build
  step precopy.indexer_security "indexer security configuration (REST and backup)"      pc_indexer_security
  step precopy.saved_objects    "dashboard saved objects"                                pc_saved_objects
  step precopy.settings         "settings files"                                         pc_settings
  step precopy.settings_plan    "settings: plan the conversion; every open question into the decisions file (C4)" pc_settings_plan
  step precopy.fleet            "fleet facts and the certificate plan"                   pc_fleet
  step precopy.gate             "gate: checksum every bundle file"                       pc_manifest
}

########################################################################## 3. FREEZE (the outage starts)
fz_stop_manager() {
  ts > "$STATE/T_manager4_stop_begin"
  systemctl stop wazuh-manager; systemctl disable wazuh-manager >/dev/null 2>&1 || true
  ts > "$STATE/T_manager4_stopped"
  echo "4.x manager stopped at $(cat "$STATE/T_manager4_stopped"): the agents are without a manager from here"
}
fz_filebeat_drain() {
  local f=$V4/logs/alerts/alerts.json size off i
  for i in $(seq 1 60); do
    size=$(stat -c %s "$f"); off=$(grep -F "\"source\":\"$f\"" /var/lib/filebeat/registry/filebeat/log.json 2>/dev/null | tail -n1 | grep -o '"offset":[0-9]*' | cut -d: -f2)
    [ "${off:-0}" -ge "$size" ] && break; sleep 2
  done
  echo "Filebeat offset ${off:-?} of $size bytes of alerts.json"
  [ "${off:-0}" -ge "$size" ] || echo "WARNING: Filebeat had not shipped all of alerts.json after 120 s"
  sleep 3; idx4 POST '/wazuh-alerts-4.x-*/_refresh' >/dev/null; systemctl stop filebeat; systemctl disable filebeat >/dev/null 2>&1 || true
  echo "Filebeat stopped: nothing writes to the alert indices any more"
}
fz_guard() { # a marker can lie: the service is what counts
  if systemctl is-active -q wazuh-manager || systemctl is-active -q filebeat; then
    echo "the 4.x manager or Filebeat is running although the freeze markers say they were stopped: stopping them again and redoing the delta"
    systemctl stop wazuh-manager filebeat || true
    rm -f "$STATE/freeze.history_delta" "$STATE/freeze.identity" "$STATE/freeze.raw_copy" "$STATE/freeze.fingerprint" "$STATE/freeze.gate"
    rm -rf "$BUNDLE_DIR/identity"
    sleep 5; idx4 POST '/wazuh-alerts-4.x-*/_refresh' >/dev/null || true
  fi
}
fz_history_delta() { history_dump; }
fz_identity() {
  systemctl is-active -q wazuh-manager && { echo "the 4.x manager is running"; return 1; }
  if [ "$(usable_keys $V4/etc/client.keys)" = 0 ]; then   # F6 (DECISIONS F6-D7)
    local d="$BUNDLE_DIR/identity-noagents"; rm -rf "${d:?}"; mkdir -p "$d"; chmod 700 "$d"
    [ -s $V4/etc/authd.pass ] && cp -p $V4/etc/authd.pass "$d/authd.pass"
    cp -p $V4/api/configuration/security/rbac.db "$d/rbac.db"
    { echo "source: 4.x manager with no agent in client.keys, $(ts)"; ( cd "$d" && sha256sum authd.pass rbac.db 2>/dev/null ); } > "$d/MANIFEST"
    echo "no agent in client.keys: the identity tool refuses such a source ('nothing to migrate'), so it is not run."
    echo "carried as files instead: $(ls "$d" | grep -v MANIFEST | tr '\n' ' ')(the enrollment password and the API users, roles and policies)"
    return 0
  fi
  [ -e "$BUNDLE_DIR/identity/manifest.json" ] || rm -rf "$BUNDLE_DIR/identity"   # a partial export from an interrupted run
  if [ ! -e "$BUNDLE_DIR/identity/manifest.json" ]; then
    $(py4) "$IDENTITY_TOOL" export "$BUNDLE_DIR/identity" --with-password --with-rbac --dry-run > "$LOGS/identity-export-dry-run.log" 2>&1 \
      || { tail -n 30 "$LOGS/identity-export-dry-run.log"; return 1; }
    $(py4) "$IDENTITY_TOOL" export "$BUNDLE_DIR/identity" --with-password --with-rbac > "$LOGS/identity-export.log" 2>&1 \
      || { tail -n 30 "$LOGS/identity-export.log"; return 1; }
  fi
  grep -v '^$' "$LOGS/identity-export.log" | head -n 14
  echo "the review of what stops at cutover is in $LOGS/identity-export.log"
}
fz_raw_copy() {
  local d="$BUNDLE_DIR/v4"
  rm -rf "$d/etc"; cp -a $V4/etc "$d/etc"
  mkdir -p "$d/alerts" "$d/rollback"
  find $V4/logs/alerts -name '*.json' -o -name '*.json.gz' | while read -r f; do cp -f "$f" "$d/alerts/$(echo "${f#$V4/logs/alerts/}" | tr / _)"; done
  # enough to put 4.14 back on this host: reinstall the packages, then these
  # OF1 (E2-deb G4): the per-agent databases go too (inventory, FIM baselines, SCA state), listed with their sizes
  agent_dbs $V4 > "$d/rollback/agent-dbs.txt"
  local o=${V4#/}
  tar -czf "$d/rollback/var-ossec.tar.gz" -C / $o/etc $o/api/configuration $o/queue/db/global.db $o/queue/agent-groups \
      $o/integrations $o/active-response/bin $(sed "s|^\([^ ]*\) .*|$o/queue/db/\1|" "$d/rollback/agent-dbs.txt") 2>/dev/null || true
  echo "per-agent databases: $(grep -c . "$d/rollback/agent-dbs.txt" || true) file(s), $(awk '{s+=$2} END{print int(s/1048576)}' "$d/rollback/agent-dbs.txt") MB (package and OS inventory, FIM baselines, SCA state)"
  agent_dbs_check "$d/rollback/var-ossec.tar.gz" "$d/rollback/agent-dbs.txt" || return 1
  tar -czf "$d/rollback/etc-indexer-dashboard-filebeat.tar.gz" -C / etc/wazuh-indexer etc/wazuh-dashboard etc/filebeat usr/share/wazuh-dashboard/data/wazuh/config 2>/dev/null || true
  local tar="$V4_INSTALL_FILES_TAR"; [ -s "$tar" ] && cp -f "$tar" "$d/rollback/wazuh-install-files.tar"
  [ -s "$d/rollback/wazuh-install-files.tar" ] || { echo "the 4.x passwords file is not in the bundle"; return 1; }
  du -sh "$d/etc" "$d/alerts" "$d/rollback" | tr '\n' ';'; echo
  # the custom content the ruleset was built from must still be what is on disk
  if ! ( cd "$d" && sha256sum --quiet -c "$BUNDLE_DIR/ruleset-src/custom-content.sha256" ); then
    echo "the custom rules, decoders or lists changed since the pre-copy: rebuilding the ruleset from the frozen copy"
    pc_ruleset_src; pc_ruleset_build
  else echo "custom rules, decoders and lists are unchanged since the pre-copy"; fi
}
fz_fingerprint() { python3 "$HELPER" fingerprint "$BUNDLE_DIR/fingerprint"; [ -z "$LAB_HOOK" ] || "$LAB_HOOK" freeze; }
fz_gate() { [ -s "$BUNDLE_DIR/fingerprint/FINGERPRINT" ] || return 1; manifest_write; echo "gate: fingerprint $(cut -c1-16 "$BUNDLE_DIR/fingerprint/FINGERPRINT")… recorded; bundle manifest rewritten: $(wc -l < "$BUNDLE_DIR/MANIFEST.sha256") file(s), $(du -sh "$BUNDLE_DIR" | cut -f1)"; }
phase_freeze() {
  done_ precopy.gate || die "the pre-copy is not complete"
  [ "$(host_state)" = v4 ] || { done_ freeze.gate && { log "  freeze already complete and 4.x is gone"; return 0; } || die "4.x is not installed and the freeze is not complete"; }
  done_ freeze.stop_manager || source_version_or_die   # OF1 item 12: before the outage starts
  load_v4_passwords
  step freeze.stop_manager   "stop the 4.x manager (THE OUTAGE STARTS)"                fz_stop_manager
  step freeze.filebeat_drain "let Filebeat ship the last alerts, then stop it"         fz_filebeat_drain
  fz_guard
  step freeze.history_delta  "history: final delta since the pre-copy"                 fz_history_delta
  step freeze.identity       "identity export (--with-password --with-rbac)"           fz_identity
  step freeze.raw_copy       "copy of etc/, the alert logs and what going back needs"  fz_raw_copy
  step freeze.fingerprint    "fingerprint of the frozen source"                        fz_fingerprint
  step freeze.gate           "gate: fingerprint recorded, bundle manifest final"       fz_gate
}

########################################################################## 4. VERIFY BUNDLE (nothing is removed before this passes)
vb_checksums() { manifest_check && echo "every one of $(wc -l < "$BUNDLE_DIR/MANIFEST.sha256") bundle file(s) reads back equal to its checksum from $BUNDLE_DIR"; }
vb_history() {
  python3 "$HELPER" bundle-ids "$HIST"
  python3 - "$HIST/manifest.json" "$BUNDLE_DIR/fingerprint/indices.json" <<'EOF'
import json, re, sys
man = json.load(open(sys.argv[1]))["indices"]; fp = {k: v for k, v in json.load(open(sys.argv[2])).items() if re.match(r"wazuh-alerts-4\.x-", k)}
bad = sorted(k for k in set(man) | set(fp) if (man.get(k) or {}).get("docs_expected") != fp.get(k))
print("history: %d source indices and %d alerts at the freeze; the dump manifest has %d indices and %d alerts; %d differ %s"
      % (len(fp), sum(fp.values()), len(man), sum(v["docs_expected"] for v in man.values()), len(bad), bad[:5]))
sys.exit(1 if bad else 0)
EOF
}
vb_parts() {
  if noagents; then echo "no agents: identity carried as files ($(ls "$BUNDLE_DIR/identity-noagents" | tr '\n' ' '))"
  else [ -s "$BUNDLE_DIR/identity/manifest.json" ] && echo "identity bundle present" || { echo "identity bundle missing"; return 1; }; fi
  [ -s "$BUNDLE_DIR/v5/wazuh-install.sh" ] && echo "5.0 assistant staged" || { echo "5.0 assistant missing"; return 1; }
  [ -s "$BUNDLE_DIR/v4/wazuh-install.sh" ] && [ -s "$BUNDLE_DIR/v4/rollback/var-ossec.tar.gz" ] && [ -s "$BUNDLE_DIR/v4/rollback/wazuh-install-files.tar" ] \
    && echo "what going back needs is in the bundle (4.x assistant, registry and configuration, passwords file)" || { echo "going-back files missing"; return 1; }
  if [ ! -f "$BUNDLE_DIR/v4/rollback/agent-dbs.txt" ]; then echo "note: this bundle was frozen before OF1 and holds no per-agent databases: going back rebuilds inventory, FIM baselines and SCA state from the agents"
  else agent_dbs_check "$BUNDLE_DIR/v4/rollback/var-ossec.tar.gz" "$BUNDLE_DIR/v4/rollback/agent-dbs.txt" || { echo "the per-agent databases are not all in the rollback archive (OF1, E2-deb G4)"; return 1; }; fi
  [ -s "$BUNDLE_DIR/preflight/fleet-facts.json" ] && echo "fleet facts present" || { echo "fleet facts missing"; return 1; }
  [ -d "$BUNDLE_DIR/ruleset-migration" ] && echo "ruleset build present" || { echo "ruleset build missing"; return 1; }
}
vb_source() { # F6 (DECISIONS F6-D2): the source must still be the one this bundle froze. A rerun skips the freeze by its
  # markers, so a 4.x that served again after the freeze (started by the user, by a reboot, after going back) would
  # otherwise be removed with a stale export: every alert, agent and keepalive since then lost.
  local since t m fs rc=0 d
  since=$(date -d "$(cat "$STATE/T_manager4_stopped")" +%s)
  for m in wazuh-manager filebeat; do
    if systemctl is-active -q $m; then echo "REFUSED: $m is running now, although this bundle froze the source at $(cat "$STATE/T_manager4_stopped")"; rc=1; fi
    # systemd forgets this once the unit (disabled by the freeze) stops and is unloaded: empty then, and "date -d ''" is
    # today's midnight, so an empty value must be skipped, never compared. The re-read below is the check that holds.
    t=$(systemctl show $m -p ActiveEnterTimestamp --value 2>/dev/null || true)
    if [ -n "$t" ] && [ "$(date -d "$t" +%s 2>/dev/null || echo 0)" -gt "$since" ]; then echo "REFUSED: $m was started again at $t, after this bundle's freeze at $(cat "$STATE/T_manager4_stopped")"; rc=1; fi
  done
  # what systemd forgets at a reboot the source itself still shows: read the frozen parts again and compare
  d=$(mktemp -d "$WORK_DIR/refingerprint.XXXXXX")
  python3 "$HELPER" fingerprint "$d" > /dev/null || { echo "cannot read the source again to compare it with the freeze"; return 1; }
  python3 - "$BUNDLE_DIR/fingerprint" "$d" <<'PYEOF' || rc=1
import json, os, re, sys
a, b = sys.argv[1:3]
L = lambda d, f: json.load(open(os.path.join(d, f)))
diff = []
for f in ("agents.json", "groups.json", "rbac_db.json", "client_keys.json", "group_files.json", "enrollment.json", "ruleset_files.json", "manager_settings.json"):
    if L(a, f) != L(b, f):
        diff.append(f)
ia = {k: v for k, v in L(a, "indices.json").items() if re.match(r"wazuh-alerts-4\.x-", k)}
ib = {k: v for k, v in L(b, "indices.json").items() if re.match(r"wazuh-alerts-4\.x-", k)}
if ia != ib:
    diff.append("alert indices (%d alerts at the freeze, %d now)" % (sum(ia.values()), sum(ib.values())))
if diff:
    print("REFUSED: the 4.x source changed since this bundle's freeze: " + "; ".join(diff))
    ka = {x["id"]: x.get("lastKeepAlive") for x in L(a, "agents.json")}
    for x in L(b, "agents.json"):
        if ka.get(x["id"]) != x.get("lastKeepAlive"):
            print("   agent %s %s: last keepalive %s at the freeze, %s now" % (x["id"], x["name"], ka.get(x["id"]), x.get("lastKeepAlive")))
    sys.exit(1)
print("the source reads the same as at the freeze: registry, keys, groups, API security, enrollment password, rules, settings, alert counts")
PYEOF
  rm -rf "$d"
  if [ "$rc" != 0 ]; then
    echo "This bundle is stale: 4.x is NOT removed. Take the freeze again into a new bundle (a new BUNDLE_DIR), or, to reuse this"
    echo "pre-copy, delete $STATE/freeze.* $STATE/phase.freeze $STATE/phase.verify_bundle and run again (the freeze then takes a new delta, identity export and fingerprint)."
    return 1
  fi
}
phase_verify_bundle() {
  done_ freeze.gate || die "the freeze is not complete"
  if done_ replace.remove4x; then log "  4.x is already removed: the bundle was verified before that"; return 0; fi
  rm -f "$STATE"/verify_bundle.*      # always verified again right before the removal
  load_v4_passwords
  step verify_bundle.source    "the source is still as frozen (not served again since the freeze)" vb_source
  step verify_bundle.checksums "checksums of every bundle file, read from its location" vb_checksums
  step verify_bundle.history   "history: distinct documents per index equal the source at the freeze" vb_history
  step verify_bundle.parts     "identity, assistants, going-back files, fleet facts, ruleset build" vb_parts
  mark verify_bundle.gate; jr verify_bundle.gate end "bundle verified: 4.x may be removed"
}

########################################################################## 5. REPLACE
leftovers() { # what of 4.x is still on the host
  local p
  for p in /var/ossec /var/lib/wazuh-indexer /etc/wazuh-indexer /usr/share/wazuh-indexer /var/log/wazuh-indexer \
           /etc/wazuh-dashboard /usr/share/wazuh-dashboard /var/lib/wazuh-dashboard /etc/filebeat /var/lib/filebeat /usr/share/filebeat \
           /var/log/filebeat "${REPO_FILES[@]}" /etc/systemd/system/wazuh-manager.service \
           /etc/init.d/wazuh-manager /etc/ossec-init.conf /var/log/wazuh-install.log; do
    [ -e "$p" ] && echo "path $p ($(du -sh "$p" 2>/dev/null | cut -f1))"
  done
  pkgall | sed 's/^/package /' || true
  getent passwd wazuh wazuh-indexer wazuh-dashboard filebeat | cut -d: -f1 | sed 's/^/user /' || true
  pgrep -a -f '/usr/share/filebeat|/var/ossec/bin' | sed 's/^/process /' || true
}
rp_remove4x() {
  done_ verify_bundle.gate || { echo "the bundle is not verified: not removing 4.x"; return 1; }
  manifest_check || { echo "the bundle does not match its manifest: not removing 4.x"; return 1; }
  guard on   # R2: from here until the listeners are opened in phase 7, whatever installs 5.0
  if [ "$NEW_HOST" = 1 ]; then # R2: never run the 4.x removal here: on an image it would remove the 5.0 packages
    [ "$(host_state)" != v4 ] || { echo "NEW_HOST=1 but this host runs a 4.x manager package"; return 1; }   # an image may hold a 5.0 agent in /var/ossec
    echo "new host: no 4.x on this host, nothing to remove; the 4.x host keeps its 4.x (stopped by the freeze) for going back"
    return 0
  fi
  # rule 10 ("before either assistant runs"): F5 put the repair before the 5.0 assistant and the 5.0 removal; the 4.x
  # assistant's removal meets the same interrupted database after a reboot during it (merged: extended here)
  pkg_repair "before the 4.x removal" || return 1
  if [ "$(host_state)" = v4 ] || [ -n "$(pkgver wazuh-indexer)$(pkgver wazuh-dashboard)$(pkgver filebeat)" ]; then
    mkdir -p "$WORK_DIR/v4-uninstall"; cp -f "$BUNDLE_DIR/v4/wazuh-install.sh" "$WORK_DIR/v4-uninstall/"
    ts > "$STATE/T_remove4x_begin"
    ( cd "$WORK_DIR/v4-uninstall" && bash ./wazuh-install.sh -u ) > "$LOGS/remove-4x.$(date -u +%H%M%S).log" 2>&1 || { tail -n 20 "$(ls -t "$LOGS"/remove-4x.*.log | head -n1)"; return 1; }
    tail -n 4 "$(ls -t "$LOGS"/remove-4x.*.log | head -n1)"
  else echo "no 4.x package is installed any more (an earlier run removed it)"; fi
  # the tool's own cleanup: what the 4.x assistant leaves on some systems
  pkill -f /usr/share/filebeat/bin/filebeat 2>/dev/null && echo "killed a Filebeat process left running" || true
  rm -f "${REPO_FILES[@]}" 2>/dev/null || true
  leftovers > "$LOGS/leftovers-after-4x-removal.txt"
  echo "left on the host after the 4.x removal: $(grep -c . "$LOGS/leftovers-after-4x-removal.txt") item(s)"; sed 's/^/  /' "$LOGS/leftovers-after-4x-removal.txt"
  [ -z "$(pkgver wazuh-manager)$(pkgver wazuh-indexer)$(pkgver wazuh-dashboard)" ] || { echo "a 4.x package is still installed"; return 1; }
  local p; for p in /var/ossec /var/lib/wazuh-indexer /etc/wazuh-indexer; do [ ! -e "$p" ] || { echo "$p survived the removal: 5.0 must never be installed over it"; return 1; }; done
  manifest_check || { echo "the bundle changed during the 4.x removal"; return 1; }
  echo "bundle intact after the removal"
}
rp_install5() {
  if [ "$V5_INSTALLER" = external ]; then rp_install5_external; return; fi
  if [ "$V5_INSTALLER" = image ]; then image_prepare; ts > "$STATE/T_install5_end"; return; fi
  local d="$WORK_DIR/v5-install" a args=(-a -id) rc=0
  mkdir -p "$d"; cp -f "$BUNDLE_DIR/v5/wazuh-install.sh" "$d/"
  if [ -s "$BUNDLE_DIR/v5/artifact_urls.yaml" ]; then cp -f "$BUNDLE_DIR/v5/artifact_urls.yaml" "$d/"; args+=(-d local); fi
  while read -r a; do [ -n "$a" ] && args+=(-as "$a"); done < "$BUNDLE_DIR/preflight/agent-san-extra.txt"
  [ "$(host_state)" != v4 ] || { echo "4.x is still installed: not running the 5.0 assistant"; return 1; }
  [ ! -e /var/ossec ] || { echo "/var/ossec exists: not installing 5.0 over 4.x leftovers"; return 1; }
  pkg_repair "before the 5.0 assistant" || return 1   # F5
  # An interrupted or failed 5.0 install leaves packages or directories, and the assistant then answers "already
  # installed" until it is given -o. Safe here and only here: 4.x is gone and the bundle is outside what -o deletes.
  local p partial=""
  for p in /var/lib/wazuh-indexer /etc/wazuh-indexer /usr/share/wazuh-indexer /var/wazuh-manager /etc/wazuh-dashboard /usr/share/wazuh-dashboard /var/lib/wazuh-dashboard; do if [ -e "$p" ]; then partial="$partial $p"; fi; done
  partial="$partial$(pkgver wazuh-indexer)$(pkgver wazuh-manager)$(pkgver wazuh-dashboard)"
  if [ -n "$partial" ]; then args+=(-o); echo "a partial 5.0 installation is on the host ($partial): adding -o"; fi
  if [ "$TEST_V5_START_FAIL" = 1 ]; then # F7 lab switch: the manager's first start fails (as F4 did on the master)
    mkdir -p /etc/systemd/system/wazuh-manager.service.d
    printf '[Service]\nExecStartPre=/bin/false\n' > /etc/systemd/system/wazuh-manager.service.d/f7-lab-start-fail.conf
    systemctl daemon-reload; echo "LAB SWITCH TEST_V5_START_FAIL=1: drop-in ExecStartPre=/bin/false on wazuh-manager.service"
  fi
  local envs=(WAZUH_REMOTE_HTTPS_BIND_ADDR=127.0.0.1 WAZUH_REMOTE_LEGACY_ENABLED=no)
  echo "env ${envs[*]} bash wazuh-install.sh ${args[*]}"
  ts > "$STATE/T_install5_begin"
  ( cd "$d" && env "${envs[@]}" bash ./wazuh-install.sh "${args[@]}" ) > "$LOGS/install-5.0.$(date -u +%H%M%S).log" 2>&1 || rc=$?
  local l; l=$(ls -t "$LOGS"/install-5.0.*.log | head -n1)
  grep -E 'INFO|WARNING|ERROR' "$l" | sed -E 's/(Password|password|token)[:=].*/\1: MASKED/I' | tail -n 25
  [ "$rc" = 0 ] || { echo "the 5.0 assistant exited $rc; host state now: $(host_state); see $l and /var/log/wazuh-install.log"; return 1; }
  ts > "$STATE/T_install5_end"
}
rp_install5_external() { # R2: 5.0 is installed by the deployment's own tool (the 5.0 playbook); this step waits for it
  [ ! -e /var/ossec ] || { echo "/var/ossec exists: 5.0 must not be installed over 4.x leftovers"; return 1; }
  [ "$(guard status)" = on ] || guard on
  if [ "$(host_state)" != v5 ] || [ -z "$(pkgver wazuh-indexer)" ] || [ -z "$(pkgver wazuh-dashboard)" ]; then
    ts > "$STATE/T_install5_begin"
    echo "WAITING FOR THE EXTERNAL INSTALLER: 4.x is removed, the bundle is verified and the agent guard is on."
    echo "Run the 5.0 deployment now (for Ansible: the 5.0 playbook against this host), then run this command again."
    echo "Certificate names agents dial that the host does not carry by itself: $(tr '\n' ' ' < "$BUNDLE_DIR/preflight/agent-san-extra.txt")"
    return 10
  fi
  echo "5.0 installed by the external installer: $(pkglist | tr '\n' ';')"
  ts > "$STATE/T_install5_end"
  close_listeners5
}
image_prepare() { # R2: a 5.0 image (AMI, OVA) as the target: installed and running, with its own agent enrolled
  [ "$(guard status)" = on ] || guard on
  [ "$(host_state)" = v5 ] && [ -n "$(pkgver wazuh-indexer)" ] && [ -n "$(pkgver wazuh-dashboard)" ] || { echo "this host is not a 5.0 image (manager $(pkgver wazuh-manager), indexer $(pkgver wazuh-indexer))"; return 1; }
  manager5_up || return 1
  local pw ids n wait_s
  pw=$(v5env $V5ETC/export/credentials.env WAZUH_MANAGER_API_PASSWORD)
  ids=$(grep -v -E '^\s*(#|$)' $V5ETC/client.keys 2>/dev/null | awk '$2 !~ /^!/ {print $1}' | paste -sd, - || true)
  if [ -n "$ids" ]; then
    echo "the image's registry holds agent(s) $ids before the import: $(grep -v -E '^\s*(#|$)' $V5ETC/client.keys | awk '{print $1":"$2}' | tr '\n' ' ')"
    grep -v -E '^\s*(#|$)' $V5ETC/client.keys | awk '{print $2}' > "$STATE/image.local_agents"
    if systemctl list-unit-files wazuh-agent.service >/dev/null 2>&1; then systemctl stop wazuh-agent || true; systemctl disable wazuh-agent >/dev/null 2>&1 || true; echo "the image's own agent (wazuh-agent on this host) stopped and disabled"; fi
    local tok; tok=$(curl -sk -u "wazuh:$pw" -X POST "https://localhost:55000/security/user/authenticate?raw=true")
    curl -sk -X DELETE "https://localhost:55000/agents?agents_list=$ids&status=all&older_than=0s" -H "Authorization: Bearer $tok" | python3 -c 'import json,sys; d=json.load(sys.stdin); print("deleted:", d.get("data",{}).get("affected_items"), "failed:", d.get("data",{}).get("failed_items"))'
    date +%s > "$STATE/T_image_agent_deleted_epoch"
  else echo "the image's registry holds no agent"; fi
  if [ -s "$STATE/T_image_agent_deleted_epoch" ]; then # a rerun honours the wait of the first run
    wait_s=$(cat $V5ETC/*internal*options*.conf 2>/dev/null | sed -n 's/^authd.purge_delay=//p' | head -n1 || true); wait_s=${wait_s:-120}
    n=$(( $(cat "$STATE/T_image_agent_deleted_epoch") + wait_s + 20 - $(date +%s) ))
    if [ "$n" -gt 0 ]; then echo "waiting $n s: 5.0 refuses a deleted id until the indexer purge of its old owner ran (authd.purge_delay $wait_s s)"; sleep "$n"; fi
  fi
  n=$(grep -v -E '^\s*(#|$)' $V5ETC/client.keys 2>/dev/null | awk '$2 !~ /^!/' | wc -l || true)
  [ "${n:-0}" = 0 ] || { echo "the registry still holds $n agent(s)"; return 1; }
  image_cert_plan
  close_listeners5
}
image_agent_back() { # R2: after the listeners opened, the image's own agent (removed in phase 5) enrolls again, with a new id
  [ -s "$STATE/image.local_agents" ] || { echo "the image had no agent of its own"; return 0; }
  [ -x /var/ossec/bin/wazuh-agent-auth ] || { echo "no 5.0 agent on this host"; return 0; }
  local t; t=$(mktemp /root/.r2-token.XXXXXX)
  $V5/bin/wazuh-manager-authd --create-enrollment-token --address 127.0.0.1 --ttl 1h > "$t"
  systemctl stop wazuh-agent || true
  /var/ossec/bin/wazuh-agent-auth --token-file "$t" --force-enroll; rm -f "$t"
  systemctl enable wazuh-agent >/dev/null 2>&1 || true; systemctl start wazuh-agent
  echo "the image's own agent: $(cut -d' ' -f1,2 /var/ossec/etc/client.keys) (was $(tr '\n' ' ' < "$STATE/image.local_agents"))"
}
image_cert_plan() { # R2: an image issues its listener certificate at first boot for its own names; nothing passes -as.
  # Every address the fleet dials (fleet facts in the bundle, AGENT_ADDRESSES) must be on it: add the missing names to
  # WAZUH_MANAGER_REMOTED_CERT_SANS in local.env and let the manager's own resolver issue a new pair from the image's CA
  # (--install issues what is missing; --prestart does not). Passwords, registry and rbac.db are left as they are.
  local san want missing="" d
  san=$(openssl x509 -in $V5ETC/certs/remoted.pem -noout -ext subjectAltName 2>/dev/null | tail -n1 | tr -d ' ' | tr ',' '\n' | sed 's/^[A-Za-z ]*://')
  want=$( { tr ' ,' '\n\n' <<<"$AGENT_ADDRESSES"; cat "$BUNDLE_DIR/preflight/dialed-addresses.txt" 2>/dev/null || true; } | { grep -v '^$' || true; } | sort -u)
  for d in $want; do grep -qxF "$d" <<<"$san" || missing="$missing $d"; done
  if [ -z "$missing" ]; then echo "listener certificate names every dialled address ($(echo $want))"; return 0; fi
  echo "the image's listener certificate lacks:$missing; issuing a new pair from the image's CA with them"
  local e=$V5ETC/local.env add=""; for d in $missing; do if [[ "$d" =~ ^[0-9.]+$|: ]]; then add="$add,IP:$d"; else add="$add,DNS:$d"; fi; done
  [ ! -e "$e" ] || [ -e "$e.pre-migration" ] || cp -p "$e" "$e.pre-migration"
  if [ -e "$e" ] && grep -q '^WAZUH_MANAGER_REMOTED_CERT_SANS=' "$e"; then sed -i "s/^WAZUH_MANAGER_REMOTED_CERT_SANS=.*/&$add/" "$e"
  else # the OVA has no local.env: keep every name the current certificate carries (loopback names are always added)
    local cur; cur=$(openssl x509 -in $V5ETC/certs/remoted.pem -noout -ext subjectAltName 2>/dev/null | tail -n1 | tr -d ' ' | sed 's/IPAddress:/IP:/g' | tr ',' '\n' | grep -v -E '^(DNS:localhost|IP:127\.0\.0\.1|IP:0:0:0:0:0:0:0:1|IP:::1)$' | paste -sd, - || true)
    ( umask 077; echo "WAZUH_MANAGER_REMOTED_CERT_SANS=${cur}${add}" >> "$e" ); fi
  echo "WAZUH_MANAGER_REMOTED_CERT_SANS now: $(sed -n 's/^WAZUH_MANAGER_REMOTED_CERT_SANS=//p' "$e")"
  systemctl stop wazuh-manager
  mkdir -p "$BUNDLE_DIR/work/remoted-before"; mv -f $V5ETC/certs/remoted.pem $V5ETC/certs/remoted-key.pem "$BUNDLE_DIR/work/remoted-before/"
  $V5/bin/wazuh-manager-resolve-credentials --install | grep -E 'remoted|MISSING|INVALID|UNSAFE' || true
  [ -s $V5ETC/certs/remoted.pem ] || { echo "no new listener certificate: putting the old one back"; mv -f "$BUNDLE_DIR/work/remoted-before/"* $V5ETC/certs/; systemctl start wazuh-manager; return 1; }
  systemctl start wazuh-manager; wait_api5 || return 1
  echo "listener certificate now: $(openssl x509 -in $V5ETC/certs/remoted.pem -noout -ext subjectAltName | tail -n1 | tr -d ' ')"
}
rp_gate() { # "installed" means ready and synchronised, closed, and one handshake per dialled address
  local p i; for p in wazuh-indexer wazuh-manager wazuh-dashboard; do echo "$p $(pkgver $p) $(systemctl is-active $p)"; done
  $V5/bin/wazuh-manager-control info 2>/dev/null | tr '\n' ' ' || true; echo
  for i in $(seq 1 60); do python3 "$HELPER" setup-status > "$LOGS/setup-status.txt" 2>&1 && break; sleep 5; done
  cat "$LOGS/setup-status.txt"; grep -q 'setup-status: READY' "$LOGS/setup-status.txt" || { echo "the 5.0 setup did not become ready in 300 s"; return 1; }
  ss -ltnH | awk '{print $4}' | grep -E ':(1514|1515|1516|1517|55000|9200|443)$' | sort | tr '\n' ' '; echo
  ss -ltnH | awk '{print $4}' | grep -E ':(1514|1515)$' && { echo "legacy agent ports are open before the import"; return 1; } || true
  ss -ltnH | awk '{print $4}' | grep -E ':1517$' | grep -v -E '^(127\.0\.0\.1|\[::1\]):' && { echo "port 1517 is open to the network before the import"; return 1; } || true
  echo "agent listeners closed: 1514 and 1515 not listening, 1517 on loopback only"
  echo "listener certificate subjectAltName: $(openssl x509 -in $V5ETC/certs/remoted.pem -noout -ext subjectAltName 2>/dev/null | tail -n1 | tr -d ' ')"
  { hostname -I | tr ' ' '\n' | grep -v -E '^(127\.|169\.254\.|fe[89ab]|::1|$)' || true; cat "$BUNDLE_DIR/preflight/dialed-addresses.txt"; } | sort -u > "$WORK_DIR/handshake-addresses.txt"
  python3 "$HELPER" handshake "$WORK_DIR/handshake-addresses.txt" 1517
}
phase_replace() {
  done_ verify_bundle.gate || done_ replace.remove4x || die "the bundle is not verified: run the verify_bundle phase first"
  step replace.remove4x  "remove 4.x with the 4.x assistant (-u), then the tool's own cleanup"   rp_remove4x
  step replace.install5  "install 5.0 with the agent listeners closed and the planned names"   rp_install5
  step replace.gate      "gate: setup ready, content synchronised, listeners closed, one handshake per dialled address" rp_gate
  step replace.settings_plan "settings: plan again against the installed 5.0 files; stop before phase 6 on an open question" rp_settings_plan
}
settings_targets() { # candidate file -> the installed file the 5.0 daemons read (C4 D7: cluster.json beside the imported module)
  local cj; cj=$(cd /tmp && $V5/framework/python/bin/python3 -c 'import os, wazuh.core.cluster.utils as u; print(os.path.dirname(u.__file__))' 2>/dev/null || true)
  python3 -c 'import json,sys; print(json.dumps({k: v for k, v in zip(sys.argv[1::2], sys.argv[2::2]) if v}))' \
    wazuh-manager.conf "$V5ETC/wazuh-manager.conf" wazuh-manager-internal-options.conf "$V5ETC/wazuh-manager-internal-options.conf" \
    api.yaml "$V5/api/configuration/api.yaml" cluster.json "${cj:+$cj/cluster.json}"
}
collect_base() { # E3-rpm fix 01: the installed base, collected once and complete or not at all. A hard reboot 0.2 s
  # into the collection left base-installed/ with wazuh-manager.conf and api.yaml but no targets.json; the old guard
  # (wazuh-manager.conf present) then skipped the collection on the rerun, the step was marked, and import.settings
  # stopped on "the installed base was not collected". Now it is gathered in a .partial directory, synced, renamed.
  local b="$BUNDLE_DIR/settings/base-installed" p
  if [ -s "$b/wazuh-manager.conf" ] && [ -s "$b/api.yaml" ] && [ -s "$BUNDLE_DIR/settings/targets.json" ]; then return 0; fi
  p="$b.partial"; rm -rf "$p"; mkdir -p "$p"; chmod 700 "$BUNDLE_DIR/settings" "$p"
  cp -p $V5ETC/wazuh-manager.conf $V5ETC/wazuh-manager-internal-options.conf "$p/"
  cp -p $V5ETC/wazuh-manager.schema.json "$p/" 2>/dev/null || echo "WARNING: no wazuh-manager.schema.json on this build: the converter cannot check option types"
  cp -p $V5/api/configuration/api.yaml "$p/"
  local t; t=$(settings_targets); echo "$t" > "$BUNDLE_DIR/settings/targets.json"
  python3 -c 'import json,sys,shutil; t=json.load(open(sys.argv[1])); "cluster.json" in t and shutil.copy2(t["cluster.json"], sys.argv[2])' "$BUNDLE_DIR/settings/targets.json" "$p/cluster.json" || true
  ( cd /tmp && $V5/framework/python/bin/python3 -c 'import json; from api.validator import api_config_schema; print(json.dumps(api_config_schema, indent=1, default=str))' ) > "$p/api.schema.json" 2>/dev/null || rm -f "$p/api.schema.json"
  sync; rm -rf "$b"; mv "$p" "$b"; sync
}
rp_settings_plan() { # C4 collect-base.sh, then the plan with the real base: a question the shipped base did not raise stops here
  [ "$CARRY_SETTINGS" = 1 ] || { echo "CARRY_SETTINGS=0: nothing to plan"; return 0; }
  local b="$BUNDLE_DIR/settings/base-installed" rc=0
  collect_base   # collected once, before anything is staged: the base of every later conversion
  echo "installed base: $(ls "$b" | tr '\n' ' ')"
  settings_plan "$b" "$BUNDLE_DIR/settings/plan-installed" || rc=$?
  [ "$rc" = 0 ] || echo "the run stops before phase 6 (the outage goes on, listeners closed, guard on): answer the open entries in $MIGRATION_DECISIONS and run again"
  return $rc
}

########################################################################## 6. IMPORT
idw() { [ "$IDENTITY_LIMIT_MODE" = raise ] && echo 4 || echo 1; }   # G5: 4 insert workers with the limit raised (run R), 1 at the shipped limit
# E2 fold (E2-rpm fix 06, E2-deb fix 1, reconciled): once the pre-upgrade group pass has run, the identity stage's verify
# and repair take the agent.conf files it uploaded as the expected content (its record, settings_stage.py record_upload).
# Without this phase 8 failed for every group the pass cleaned, and a repair would upload the refused option again.
expected_conf() { EXP=(); local f="$BUNDLE_DIR/settings/groups-pre/uploaded.json"; [ ! -s "$f" ] || EXP=(--expected-conf "$f"); }   # sets EXP
im_identity() {
  local py=$V5/framework/python/bin/python3 n
  manager5_up || return 1
  if noagents; then   # F6 (DECISIONS F6-D7): what the identity tool does for its two secret files, without its agent import
    local d="$BUNDLE_DIR/identity-noagents" n
    if [ -s "$d/authd.pass" ]; then
      n=$(tr -d '\n' < "$d/authd.pass" | wc -c); [ "$n" -ge 16 ] || { echo "the enrollment password is $n bytes: 5.0 refuses fewer than 16"; return 1; }
      install -o wazuh-manager -g wazuh-manager -m 640 "$d/authd.pass" $V5ETC/authd.pass; echo "enrollment password carried ($n bytes)"
    fi
    install -o wazuh-manager -g wazuh-manager -m 640 "$d/rbac.db" $V5/api/configuration/security/rbac.db
    python3 -c 'import sqlite3,sys; c=sqlite3.connect(sys.argv[1]); c.execute("PRAGMA user_version = 0"); c.commit()' $V5/api/configuration/security/rbac.db
    echo "rbac.db carried and staged (user_version 0: the API rebuilds its 5.0 defaults and keeps the users, roles and policies)"
    return 0
  fi
  # Merged: the identity stage (G5, with G1's repair and F7's key check) replaces the identity tool's import. It pages
  # every list, renews its token, waits on a refusal, raises the API limit for the import and restores it (default, G5),
  # and refuses (exit 3) when the registry already holds agents that are not this bundle's by id, name and key (F7):
  # a cut import is resumed, a self-enrolled agent stops the run. Never a second import with --force.
  [ -s "$STATE/T_import_begin" ] || stamp T_import_begin   # E3 fold (E3-rpm 6): a 0-byte one left by a cut is written again
  $py "$HERE/identity_stage.py" run "$BUNDLE_DIR/identity" --state "$BUNDLE_DIR/identity-stage" --limit-mode "$IDENTITY_LIMIT_MODE" \
      --workers "$(idw)" $(pwflag) --with-rbac > "$LOGS/identity-stage-run.log" 2>&1 || { tail -n 30 "$LOGS/identity-stage-run.log"; return 1; }
  grep -E 'GATE|REFUSE|cut import|preflight:|limit' "$LOGS/identity-stage-run.log" | cut -c1-400 | tail -n 8
}
# E4-breaker fix 02: a 4.x source enrolling without a password (the 4.x assistant's default) has no authd.pass in the
# identity bundle; the stage's --with-password then blocks the import ("the bundle has no authd.pass"), although assess
# said "5.0 enables use_password and generates one" (E5 fold: it keeps it off, enrollment_off_note). Carry the password
# only when the source had one.
pwflag() { [ -s "$BUNDLE_DIR/identity/authd.pass" ] && echo --with-password || true; }
enrollment_off_note() { # E5 fold (E5-aio gap 4): what 5.0 does when 4.x enrolled without a password. The settings stage
  # carries the 4.x <use_password>no</use_password>, so 5.0 keeps enrolling without one (observed: a password-less
  # enrollment accepted on 1515 after the finish), with the unused password the 5.0 install generated beside it. Assess
  # and phase 8 said "5.0 enables use_password and generates one", which is true only without the settings stage.
  if [ "${1:-1}" = 1 ]; then
    echo "enrollment without a password on 4.x: 5.0 keeps it off (the settings stage carries use_password no), so agents keep enrolling without one, as on 4.x"
    echo "  to require a password after the migration: set <use_password>yes</use_password> in the <auth> section of /etc/wazuh-manager/wazuh-manager.conf, keep the password the 5.0 install generated in /etc/wazuh-manager/authd.pass (or put your own of 16 or more characters there), restart wazuh-manager, and give it to every agent that enrolls from then on"
  else
    echo "enrollment without a password on 4.x and CARRY_SETTINGS=0: 5.0 keeps its installed use_password yes and the password it generated (/etc/wazuh-manager/authd.pass): agents that enroll from now on need it"
  fi; }
cluster_nodes5() { # the cluster this node's installed file describes: "single" or "cluster <n> nodes"
  python3 - "$V5ETC/wazuh-manager.conf" <<'PY'
import sys, xml.etree.ElementTree as ET
try:
    c = ET.parse(sys.argv[1]).getroot().find("cluster")
except (OSError, ET.ParseError):
    c = None
nodes = [n.text.strip() for n in c.findall("nodes/node")] if c is not None else []
off = c is None or (c.findtext("disabled") or "").strip() == "yes"
real = [n for n in nodes if n not in ("127.0.0.1", "localhost", "::1", "NODE_IP")]
print("single" if off or not real else "cluster %d" % len(nodes))
PY
}
im_settings() { # rules 21 and 22, in C4's order (tool/node/live.sh): convert against the installed base, validate, cross-node
  # check (clusters), save the installed files once, stage, `wazuh-manager-control check`; a failed check puts the saved
  # files back and stops. The single restart is the next step (import.restart).
  [ "$CARRY_SETTINGS" = 1 ] || { echo "CARRY_SETTINGS=0: the installed 5.0 settings are kept"; return 0; }
  local S="$BUNDLE_DIR/settings" c="$BUNDLE_DIR/settings/candidate" topo
  if ! { [ -s "$S/targets.json" ] && [ -s "$S/base-installed/wazuh-manager.conf" ] && [ -s "$S/base-installed/api.yaml" ]; }; then
    # E3-rpm fix 01: a bundle whose collection was cut before this fix: complete it now, only while nothing is staged
    # (the live files still equal what was collected: no candidate was ever installed over them)
    if [ ! -e "$S/saved" ] && [ -s "$S/base-installed/wazuh-manager.conf" ] && cmp -s "$S/base-installed/wazuh-manager.conf" $V5ETC/wazuh-manager.conf; then
      echo "the installed base was incomplete (a cut during replace.settings_plan): collected again, nothing was staged yet"; collect_base
    else echo "the installed base was not collected (replace.settings_plan)"; return 1; fi
  fi
  python3 "$HERE/settings_stage.py" convert --v4 "$BUNDLE_DIR/v4/config" --stock "$BUNDLE_DIR/v4/config/stock" --base "$S/base-installed" \
    --decisions "$MIGRATION_DECISIONS" --out "$c" || return 1
  topo=$(cluster_nodes5)
  if [ "$topo" != single ]; then   # C4 / rule 21: nothing is staged on any node until the cross-node check passes
    [ -n "$CLUSTER_CANDIDATES" ] || { echo "this node is part of a $topo-node cluster: the cross-node check needs the other nodes' candidates (CLUSTER_CANDIDATES); nothing staged"; return 1; }
    if [ "$CLUSTER_CANDIDATES" = first-node ]; then
      # CL1 (order C): the master is the first node on 5.0 while its workers still serve on 4.x, so no other 5.0 file
      # exists yet; it is checked alone here, and each worker is checked against every node already on 5.0 before
      # anything is staged on it (migrate-cluster.sh workers phase)
      echo "the first node of the cluster on 5.0: its candidate is checked alone; each later node is checked against it"
      python3 "$HERE/converter/cluster_check.py" "$c" || { echo "the cross-node check failed: nothing staged on this node"; return 1; }
    else
    python3 "$HERE/converter/cluster_check.py" "$c" $CLUSTER_CANDIDATES || { echo "the cross-node check failed: nothing staged on this node"; return 1; }
    fi
  else echo "single node: no cross-node check"; fi
  python3 "$HERE/settings_stage.py" apply --candidate "$c" --saved "$S/saved" --targets "$(cat "$S/targets.json")" \
    --validate-cmd "$V5/bin/wazuh-manager-conf -f $c/wazuh-manager.conf validate" --check-cmd "$V5/bin/wazuh-manager-control check" || return 1
  ts > "$STATE/T_settings_staged"
}
im_groups_pre() { # C4 D5: the pre-upgrade pass while 4.x agents remain: only what a 4.x agent or the 5.0 API refuses is removed;
  # the files an agent.conf names (and the stock rootcheck files of default) are carried into the group folder
  [ "$CARRY_SETTINGS" = 1 ] || { echo "CARRY_SETTINGS=0: group files as the identity import wrote them"; return 0; }
  [ -d "$BUNDLE_DIR/groups4" ] || { echo "no 4.x group folders in the bundle"; return 0; }
  manager5_up || return 1
  python3 "$HERE/settings_stage.py" groups --phase pre-upgrade --groups "$BUNDLE_DIR/groups4" --decisions "$MIGRATION_DECISIONS" \
    --work "$BUNDLE_DIR/settings/groups-pre" --shared "$V5ETC/shared"
}
im_groups_noagents() { # F6 (DECISIONS F6-D7): a source with no agent can still have groups; the identity tool would carry
  # them (group, agent.conf, the SCA policies it loads) if it did not refuse the source, so this does the same through the API
  noagents || { echo "the source had agents: the identity tool carried the groups"; return 0; }
  manager5_up || return 1
  python3 - "$BUNDLE_DIR/v4/etc/shared" "$(v5env $V5ETC/export/credentials.env WAZUH_MANAGER_API_PASSWORD)" "$V5ETC/shared" <<'PY'
import base64, grp, json, os, pwd, re, shutil, ssl, sys, urllib.error, urllib.request
src, pw, dst = sys.argv[1:4]; ctx = ssl._create_unverified_context(); B = "https://localhost:55000"
def call(m, path, body=None, ct="application/json", tok=None):
    r = urllib.request.Request(B + path, method=m, data=body)
    r.add_header("Authorization", ("Bearer " + tok) if tok else "Basic " + base64.b64encode(("wazuh:" + pw).encode()).decode())
    if body is not None: r.add_header("Content-Type", ct)
    try: return json.load(urllib.request.urlopen(r, context=ctx, timeout=60))
    except urllib.error.HTTPError as e: return json.loads(e.read() or b"{}")
tok = call("POST", "/security/user/authenticate")["data"]["token"]
have = {g["name"] for g in call("GET", "/groups?limit=500", tok=tok)["data"]["affected_items"]}
bad = 0
for g in sorted(os.listdir(src)):
    d = os.path.join(src, g)
    if g == "default" or not os.path.isdir(d): continue
    if g not in have:
        r = call("POST", "/groups", json.dumps({"group_id": g}).encode(), tok=tok); print("group %s: create: %s" % (g, r.get("message", r)))
    conf = open(os.path.join(d, "agent.conf"), "rb").read() if os.path.exists(os.path.join(d, "agent.conf")) else b""
    for pol in re.findall(rb"<policy>\s*etc/shared/([^<\s]+)\s*</policy>", conf):
        f = pol.decode(); s = os.path.join(d, f); t = os.path.join(dst, g, f)
        if os.path.isfile(s):
            shutil.copyfile(s, t); os.chmod(t, 0o660); os.chown(t, pwd.getpwnam("wazuh-manager").pw_uid, grp.getgrnam("wazuh-manager").gr_gid)
            print("group %s: SCA policy %s installed" % (g, f))
        else:
            print("group %s: SCA policy %s named in agent.conf but not in the group folder" % (g, f)); bad += 1
    if conf.strip():
        r = call("PUT", "/groups/%s/configuration" % g, conf, ct="application/xml", tok=tok)
        ok = r.get("error") == 0; bad += not ok; print("group %s: agent.conf: %s" % (g, r.get("message", r)))
sys.exit(1 if bad else 0)
PY
}
im_restart() { # the clean stop and start after the identity import (memberships), and the single restart of the converted settings
  local t0=$SECONDS
  systemctl stop wazuh-manager
  echo "clean stop of the 5.0 manager took $((SECONDS - t0)) s"
  systemctl restart wazuh-manager
  if ! manager5_up; then
    if [ -e "$STATE/T_settings_staged" ] && [ -s "$BUNDLE_DIR/settings/saved/saved.json" ]; then   # rule 22: the saved files back
      echo "the manager did not come up on the converted settings: putting the saved installed files back"
      python3 "$HERE/settings_stage.py" restore --saved "$BUNDLE_DIR/settings/saved" --targets "$(cat "$BUNDLE_DIR/settings/targets.json")"
      rm -f "$STATE/T_settings_staged" "$STATE/import.settings"; systemctl restart wazuh-manager; manager5_up || true
    fi
    echo "the Server API did not come back"; return 1
  fi
  sleep 10
}
im_passwords() {
  local i
  for i in 1 2 3 4 5 6 7 8; do
    if v5env $V5ETC/export/credentials.env WAZUH_MANAGER_API_PASSWORD | $V5/bin/rbac_control change-password -u wazuh -p - \
       && v5env $V5ETC/export/credentials.env WAZUH_MANAGER_WUI_PASSWORD | $V5/bin/rbac_control change-password -u wazuh-internal-client -p -; then
      curl -sk -u "wazuh:$(v5env $V5ETC/export/credentials.env WAZUH_MANAGER_API_PASSWORD)" -X POST "https://localhost:55000/security/user/authenticate?raw=true" | grep -q '^ey' \
        && { echo "wazuh and wazuh-internal-client are back on the 5.0 passwords; login as wazuh works"; return 0; }
    fi
    sleep 10
  done
  return 1
}
im_reconcile() { # compare the real registry with the fingerprint; repair through the API; then the identity tool's own check must pass
  local rc=0
  manager5_up
  curl -sk -u "wazuh:$(v5env $V5ETC/export/credentials.env WAZUH_MANAGER_API_PASSWORD)" -X POST "https://localhost:55000/security/user/authenticate?raw=true" | grep -q '^ey' \
    || { echo "the Server API refuses the published password: resetting the two passwords again"; im_passwords; }
  if noagents; then   # F6: nothing to compare; what was carried is checked through the API
    local tok; tok=$(curl -sk -u "wazuh:$(v5env $V5ETC/export/credentials.env WAZUH_MANAGER_API_PASSWORD)" -X POST "https://localhost:55000/security/user/authenticate?raw=true")
    python3 - "$BUNDLE_DIR/truth4/api_security.json" "$tok" <<'PY'
import json, ssl, sys, urllib.request
want = json.load(open(sys.argv[1])); ctx = ssl._create_unverified_context(); bad = 0
for k in ("users", "roles", "policies", "rules"):
    req = urllib.request.Request("https://localhost:55000/security/%s?limit=500" % k, headers={"Authorization": "Bearer " + sys.argv[2]})
    have = {x.get("username") or x.get("name") for x in json.load(urllib.request.urlopen(req, context=ctx))["data"]["affected_items"]}
    w = {x.get("username") or x.get("name") for x in want[k] if int(x.get("id", 0)) >= 100}   # ids from 100 are the site's own; 5.0 rebuilds its defaults
    miss = sorted(w - have); bad += bool(miss)
    print("API %-8s the site's own on 4.x: %s; missing on 5.0: %s" % (k, sorted(w), miss))
sys.exit(1 if bad else 0)
PY
    return $?
  fi
  # Merged: the comparison is against both 4.x records of the freeze. The identity stage compares with the identity
  # bundle (paged, keys included) and repairs in bulk rounds; mig_helper compares with the fingerprint, read only, keys
  # included (F7). The identity tool's own `check` is not used: it reads at most 10,000 agents and 500 groups (G1).
  local py=$V5/framework/python/bin/python3; expected_conf
  if ! $py "$HERE/identity_stage.py" verify "$BUNDLE_DIR/identity" --state "$BUNDLE_DIR/identity-stage" "${EXP[@]}" > "$LOGS/identity-verify-1.json" 2>&1; then
    echo "differences from the identity bundle after the restart: running the identity stage again (it resumes and repairs in bulk)"
    $py "$HERE/identity_stage.py" run "$BUNDLE_DIR/identity" --state "$BUNDLE_DIR/identity-stage" --limit-mode "$IDENTITY_LIMIT_MODE" \
        --workers "$(idw)" $(pwflag) --with-rbac "${EXP[@]}" >> "$LOGS/identity-stage-run.log" 2>&1 || { tail -n 20 "$LOGS/identity-stage-run.log"; return 1; }
    im_passwords || return 1
    $py "$HERE/identity_stage.py" verify "$BUNDLE_DIR/identity" --state "$BUNDLE_DIR/identity-stage" "${EXP[@]}" > "$LOGS/identity-verify-2.json" 2>&1 \
      || { cat "$LOGS/identity-verify-2.json"; echo "the registry still differs from the identity bundle"; return 1; }
  fi
  python3 "$HELPER" reconcile-membership "$BUNDLE_DIR" || { echo "the registry differs from the fingerprint (see above); not opening"; return 1; }
}
RWORK() { echo "$BUNDLE_DIR/work/ruleset-migration"; }
im_ruleset() {
  local w ca=${IDX5_CA:-/etc/wazuh-indexer/certs/root-ca.pem} rc=0 alerts
  w=$(RWORK)
  # the ruleset tool writes its state and reports into its work directory: it works on a copy, the bundle stays as frozen
  if [ ! -d "$w" ]; then mkdir -p "$BUNDLE_DIR/work"; cp -a "$BUNDLE_DIR/ruleset-migration" "$w"; fi
  local want have; want=$(rmig_dialect_installed); have=$(cat "$w/ENGINE_HELPERS" 2>/dev/null || echo 5.0)
  if [ "$want" != "$have" ]; then
    echo "the ruleset was built for engine helpers '$have'; the installed 5.0 ($($V5/bin/wazuh-manager-control info 2>/dev/null | tr '\n' ' ')) needs '$want': rebuilding from the frozen copy"
    # rmig keeps its record in work/state.json (first version looked for state.json and never rolled back). Even so, a
    # rollback keeps wazuh4-base while its root is the policy root, so the rebuilt content meets the old root and
    # activate then stops on RM-P-FOREIGN-POLICY-CHANGE (DECISIONS P-D6): the dialect must be right at the first apply.
    if [ -s "$w/work/state.json" ]; then rmig rollback --workdir "$w" --ca $ca > "$LOGS/rmig-4b-rollback-before-rebuild.log" 2>&1 || true; tail -n 3 "$LOGS/rmig-4b-rollback-before-rebuild.log"; fi
    rm -rf "$w.$have"; mv "$w" "$w.$have"
    ruleset_build "$w" "$want" || return 1
  fi
  rmig apply --workdir "$w" --ca $ca --dry-run > "$LOGS/rmig-4-apply-dry-run.log" 2>&1 || true
  rmig apply --workdir "$w" --ca $ca > "$LOGS/rmig-5-apply.log" 2>&1 || rc=$?; tail -n 3 "$LOGS/rmig-5-apply.log"; echo "rmig apply exit $rc"
  [ "$rc" = 0 ] || return 1
  alerts=$(ls "$BUNDLE_DIR"/v4/alerts/* 2>/dev/null | tr '\n' ' ')
  rc=0; rmig verify --workdir "$w" --ca $ca --alerts $alerts ${RMIG_SAMPLES:+--samples "$RMIG_SAMPLES"} > "$LOGS/rmig-6-verify.log" 2>&1 || rc=$?
  tail -n 4 "$LOGS/rmig-6-verify.log"; echo "rmig verify exit $rc (0 = every rule reproduced, 1 = at least one was not)"
  echo "$rc" > "$STATE/ruleset.verify_rc"
  grep -E '^verify: REPRODUCED' "$LOGS/rmig-6-verify.log" | tail -n1 > "$STATE/ruleset.verify_summary" || true
  [ "$rc" -le 1 ] || return 1
}
ruleset_clean() { # exit 0 of the verification is not enough: with no sample for a rule nothing was checked (NO_SAMPLE)
  local s; s=$(cat "$STATE/ruleset.verify_summary" 2>/dev/null || true)
  [ "$(cat "$STATE/ruleset.verify_rc" 2>/dev/null || echo 9)" = 0 ] || return 1
  grep -q -E 'NOT_REPRODUCED 0, .*NOT_SILENCED 0, NO_SAMPLE 0' <<<"$s"
}
cluster_name5() { sed -n '/<cluster>/,/<\/cluster>/s/.*<name>\(.*\)<\/name>.*/\1/p' $V5ETC/wazuh-manager.conf | head -n1; }
# Merged history stage: H5's loader (RD2's corrected map, journal, fail-closed reads, --procs) with S5's `on`. The group
# stamp needs the 4.x registry (H1, C23); without the identity stage the ids are not the same agents (not-carried).
hload() { local c ids=carried reg=(); c=$(cluster_name5)
          if noagents || [ "${CARRY_AGENT_IDS:-1}" = 0 ]; then ids=not-carried; fi
          [ -s "$BUNDLE_DIR/history-registry.json" ] && reg=(--agent-registry "$BUNDLE_DIR/history-registry.json")
          INDEXER_PASSWORD="$(idx5pw)" python3 "$HERE/history_load.py" "$@" --bundle "$HIST" --url https://$(idxhost):9200 \
            --cacert /etc/wazuh-indexer/certs/root-ca.pem --cluster-name "${c:-wazuh}" --agent-ids "$ids" "${reg[@]}" --retention "$(history_retention)"; }
im_history_load() { wait_indexer idx5
  history_retention > /dev/null; cat "$STATE/history.retention"   # OF1 (decision 5b): which retention applies, and why
  [ -s "$BUNDLE_DIR/history-registry.json" ] || noagents || python3 "$HELPER" agent-registry "$BUNDLE_DIR" "$BUNDLE_DIR/history-registry.json"
  hload apply --procs "$HISTORY_PROCS" ${TEST_HISTORY_STOP_AFTER:+--stop-after-files "$TEST_HISTORY_STOP_AFTER"}; }
im_history_prove() { hload prove; [ -z "$LAB_HOOK" ] || "$LAB_HOOK" history-loaded; }
im_indexer_security() { # Merged: C23's indexer stage (users with their 4.x hashes, two-branch DLS, FLS and masking over every
  # field the history loader fills, generated from its own map; refuses to change a 5.0 object it did not create)
  python3 "$HERE/indexer_stage.py" import --bundle "$BUNDLE_DIR" --url "https://$(idxhost):9200" $(idx_cert_args) > "$LOGS/indexer-stage-import.log" 2>&1 \
    || { tail -n 30 "$LOGS/indexer-stage-import.log"; return 1; }
  tail -n 5 "$LOGS/indexer-stage-import.log"
  python3 "$HERE/indexer_stage.py" verify --bundle "$BUNDLE_DIR" --url "https://$(idxhost):9200" $(idx_cert_args) > "$LOGS/indexer-stage-verify.log" 2>&1 \
    || { tail -n 20 "$LOGS/indexer-stage-verify.log"; return 1; }
  tail -n 1 "$LOGS/indexer-stage-verify.log"
}
im_history_on() { # rule 9: only after the proof, and only after the roles that lose access are listed and fixed or accepted
  local acc=(); [ "$ACCEPT_ROLE_LOSS" = 1 ] && acc=(--accept-role-loss)
  hload audit-roles --json "$BUNDLE_DIR/indexer-security/role-audit.json" "${acc[@]}" || { echo "stopped: decide on the listed roles (ACCEPT_ROLE_LOSS=1 accepts)"; return 1; }
  hload on
}
im_history_roles() { # F10, after-open: the role decision of rule 9 is asked now, before the outage ends, not hours later
  local acc=(); [ "$ACCEPT_ROLE_LOSS" = 1 ] && acc=(--accept-role-loss)
  hload audit-roles --json "$BUNDLE_DIR/indexer-security/role-audit.json" "${acc[@]}" || { echo "stopped: decide on the listed roles (ACCEPT_ROLE_LOSS=1 accepts)"; return 1; }
  echo "role audit done before opening; the history itself is loaded after the opening (HISTORY_LOAD=after-open)"
}
im_saved_objects() { python3 "$HELPER" import-saved-objects "$BUNDLE_DIR/dashboard/saved-objects.ndjson"; }
im_gate() {
  local rc=0
  if ! noagents; then python3 "$HELPER" reconcile-membership "$BUNDLE_DIR" || rc=1; fi   # F6: a source with no agent has nothing to reconcile
  # rule 15 (G5): a setting changed for the tool's own work (the API limit) must be back before any later gate passes
  python3 - "$BUNDLE_DIR/identity-stage/state.json" "$BUNDLE_DIR/identity-stage/api.yaml.orig" "$V5/api/configuration/api.yaml" <<'PY' || rc=1
import json, os, sys
# E2 fold: the saved original against the live file, byte for byte, as well as the state: a power cut can empty the
# state file, and an unreadable state must not read as "nothing was changed" while a saved original exists
saved, live = sys.argv[2], sys.argv[3]
if os.path.isfile(saved):
    a, b = open(saved, "rb").read(), (open(live, "rb").read() if os.path.isfile(live) else b"")
    if not a or a != b:
        print("the Server API's api.yaml is not the original the identity stage saved (%d bytes saved, %d live): run identity_stage.py restore-limit" % (len(a), len(b)))
        sys.exit(1)
try:
    st = json.load(open(sys.argv[1]))
except (OSError, ValueError):
    print("the Server API limit is the original%s" % (" (api.yaml equals the saved original)" if os.path.isfile(saved) else " (no identity stage ran: nothing was changed)"))
    sys.exit(0)
lim = (st.get("limit") or {}).get("state")
if lim in ("raised", "restored-pending-restart"):
    print("the Server API limit raised for the identity import is not restored (state %s): run identity_stage.py restore-limit" % lim)
    sys.exit(1)
print("the Server API limit is the original (identity stage state: %s)" % (lim or "never raised"))
PY
  echo "ruleset verification exit: $(cat "$STATE/ruleset.verify_rc" 2>/dev/null || echo not-run)"
  if [ "$HISTORY_LOAD" = after-open ]; then
    [ "$rc" = 0 ] && echo "gate: identity equals the fingerprint, security objects imported; the history is NOT loaded yet (after-open: it follows the opening)"
  else
    hload status | tail -n 3
    [ "$rc" = 0 ] && echo "gate: identity equals the fingerprint, history proven and switched on, security objects imported"
  fi
  return $rc
}
phase_import() {
  [ "$(host_state)" = v5 ] || die "5.0 is not installed: run the replace phase first"
  done_ replace.gate || die "the 5.0 installation has not passed its gate"
  step import.identity   "identity import (--with-password --with-rbac)"                  im_identity
  step import.groups_noagents "no agents: groups, their agent.conf and SCA policies through the API" im_groups_noagents
  step import.settings   "settings: convert, validate, cross-node check, stage, wazuh-manager-control check (rules 21, 22)" im_settings
  step import.restart    "stop the manager cleanly and start it (group membership, converted settings)" im_restart
  step import.passwords  "set wazuh and wazuh-internal-client back to the 5.0 passwords"  im_passwords
  step import.reconcile  "compare agents and memberships with the fingerprint, repair, identity check" im_reconcile
  step import.groups_pre "group files: the pre-upgrade pass (C4), carried files installed"  im_groups_pre
  step import.ruleset    "ruleset: apply to the test space and verify with the 4.x alerts" im_ruleset
  if [ "$HISTORY_LOAD" = before-open ]; then
    step import.history_load  "history: load the dump through the shaping pipeline"         im_history_load
    step import.history_prove "history: proof per source index"                             im_history_prove
  fi
  if [ "$CARRY_INDEXER_SECURITY" = 1 ]; then step import.indexer_security "indexer users, roles and mappings (4.x alert roles translated)" im_indexer_security; fi
  if [ "$HISTORY_LOAD" = before-open ]; then
    step import.history_on "history: role audit, then the two aliases on"                   im_history_on
  else
    step import.history_roles "history: role audit (the aliases are switched on after the load, in the history phase)" im_history_roles
  fi
  # Conflict F10 x S5 (merged): the custom dashboards are a view of the history through its aliases, and S5's import
  # refuses while no alias exists. With the history loaded after the opening they are imported in the history phase,
  # after the aliases are on (F10's proposed phase 8b: "switch the aliases on, import the custom dashboards").
  if [ "$CARRY_SAVED_OBJECTS" = 1 ] && [ "$HISTORY_LOAD" = before-open ]; then step import.saved_objects "custom dashboards as a view of the history" im_saved_objects; fi
  step import.gate       "gate: every import verified against the bundle"                 im_gate
}

########################################################################## 7. OPEN (the outage ends)
op_decision() { # rule 8: before opening, what happens to events 5.0 cannot classify
  local w ca=${IDX5_CA:-/etc/wazuh-indexer/certs/root-ca.pem} vrc tok dec="$UNCLASSIFIED_DECISION"
  w=$(RWORK)
  date +"%Y/%m/%d %H:%M:%S" > "$STATE/T_decision_logtime"   # the manager log's own clock and format, for op_in_force
  vrc=$(cat "$STATE/ruleset.verify_rc" 2>/dev/null || echo 9)
  echo "ruleset verification: exit $vrc; $(cat "$STATE/ruleset.verify_summary" 2>/dev/null || echo 'no summary')"
  # OF1 (decision 3, 2026-11-24): with no answer given the default applies; the run no longer stops to ask
  if [ -z "$dec" ]; then dec=$UNCLASSIFIED_DEFAULT; echo "UNCLASSIFIED_DECISION not set: the default answer applies, $dec (decision 3): activate the rules that verified, raw event indexing on until the finish"; fi
  if ruleset_clean; then
    rmig activate --workdir "$w" --ca $ca --yes > "$LOGS/rmig-7-activate.log" 2>&1 || { tail -n 20 "$LOGS/rmig-7-activate.log"; return 1; }
    tail -n 3 "$LOGS/rmig-7-activate.log"; echo "the migrated rules verified cleanly and are activated"; echo "activate" > "$STATE/unclassified.applied"
    # F6 (DECISIONS F6-D1): raw indexing answers a different question (4.x agents whose events 5.0 drops before any rule
    # runs, such as the Windows event log), so clean rules do not make it unnecessary
    if grep -qw raw <<<"$(tr '+' ' ' <<<"$dec")"; then
      python3 "$HELPER" policy-unclassified on || return 1; echo raw >> "$STATE/unclassified.applied"
      echo "decision applied: unclassified events are indexed in wazuh-events-v5-unclassified until phase 11 switches it off"
    fi
    return 0
  fi
  if grep -qw ask <<<"$(tr '+' ' ' <<<"$dec")"; then
    echo "DECISION NEEDED (UNCLASSIFIED_DECISION=ask): the migrated rules did not verify cleanly (rules not reproduced, or rules with no 4.x alert to check them against; see $w/verification.md)."
    echo "Until something is decided, 5.0 drops every event it cannot classify, including every event only your custom decoders understood."
    echo "The agent listeners stay CLOSED. Run again with UNCLASSIFIED_DECISION set to one or more of (joined with +):"
    echo "  verified         activate the migrated rules if their verification has no failure (rmig activates all or none)"
    echo "  activate-force   activate the migrated rules anyway (rmig activate --yes --force, recorded)"
    echo "  raw              index events no integration classified, in wazuh-events-v5-unclassified (costs disk; the finish switches it off)"
    echo "  accept           open the listeners and accept losing those events until the rules are activated"
    return 3
  fi
  : > "$STATE/unclassified.applied.tmp"
  for tok in $(tr '+' ' ' <<<"$dec"); do
    case "$tok" in
      verified)
        if [ "$vrc" = 0 ]; then   # no NOT_REPRODUCED and no NOT_SILENCED: rmig's own bar for activate without --force
          rmig activate --workdir "$w" --ca $ca --yes > "$LOGS/rmig-7-activate.log" 2>&1 || { tail -n 20 "$LOGS/rmig-7-activate.log"; return 1; }
          tail -n 3 "$LOGS/rmig-7-activate.log"; echo "decision applied: the migrated rules have no failed verification (rules without a 4.x sample are not disproven) and are activated"
          tok=activate
        else
          echo "decision applied: the migrated rules are NOT activated: their verification has failures (exit $vrc; $(cat "$STATE/ruleset.verify_summary" 2>/dev/null || echo 'no summary'))."
          echo "  rmig activates all of the tool's content or none, so the rules that did verify cannot be activated alone. Fix the failing rules"
          echo "  (see $w/verification.md) and run 'rmig activate', or answer UNCLASSIFIED_DECISION=activate-force+raw to activate them anyway."
          tok=verified-none
        fi;;
      activate-force)
        rmig activate --workdir "$w" --ca $ca --yes --force ${RMIG_ACTIVATE_ARGS:-} > "$LOGS/rmig-7-activate.log" 2>&1 || { tail -n 20 "$LOGS/rmig-7-activate.log"; return 1; }
        tail -n 4 "$LOGS/rmig-7-activate.log"; echo "decision applied: migrated rules activated with --force (the failed verification is recorded in $w)";;
      raw)
        python3 "$HELPER" policy-unclassified on || return 1
        echo "decision applied: unclassified events are indexed in wazuh-events-v5-unclassified until phase 11 switches it off";;
      accept)
        echo "decision applied: the user accepts that events 5.0 cannot classify are dropped (recorded at $(ts))";;
    esac
    echo "$tok" >> "$STATE/unclassified.applied.tmp"
  done
  mv "$STATE/unclassified.applied.tmp" "$STATE/unclassified.applied"
}
op_in_force() { # F6-D3 (rule 8): the decision must be SEEN IN FORCE by the engine before the restart that opens the listeners
  local spaces="" t
  grep -qE '^(activate|activate-force)$' "$STATE/unclassified.applied" 2>/dev/null && spaces="custom"
  grep -qx raw "$STATE/unclassified.applied" 2>/dev/null && spaces="${spaces:+$spaces,}standard"
  t=$(cat "$STATE/T_decision_logtime" 2>/dev/null || true)
  [ -n "$t" ] || { [ -z "$spaces" ] && { echo "no policy change to wait for"; return 0; }; echo "no record of when the decision was applied: cannot prove it is in force"; return 1; }
  python3 "$HELPER" wait-in-force "$t" "$spaces" 300 "$V5/logs/wazuh-manager.log"
}
op_listeners() {
  local c=$V5ETC/wazuh-manager.conf
  [ -e "$c.closed-listeners.bak" ] || cp -p "$c" "$c.closed-listeners.bak"
  sed -i -e '/<https>/,/<\/https>/s|<bind_addr>.*</bind_addr>|<bind_addr>0.0.0.0</bind_addr>|' \
         -e '/<legacy>/,/<\/legacy>/s|<enabled>.*</enabled>|<enabled>yes</enabled>|' "$c"
  $V5/bin/wazuh-manager-conf validate
  if fw_active; then
    local fp; for fp in 1514 1515; do [ -n "$(fw_how $fp)" ] || echo "WARNING: $(fw_kind) does not allow $fp/tcp: 4.x agents cannot reach this manager (they could not reach 4.x either)"; done
    # E3 fold (item 17): recorded before it is added, so a cut between the two still lets going back remove it
    if [ -z "$(fw_how 1517)" ]; then echo 1517 >> "$STATE/fw.added"; sync "$STATE/fw.added" 2>/dev/null || sync; fw_port add 1517; echo "$(fw_kind): 1517/tcp added to zone $(fw_zone) (runtime and permanent) for 5.0 agents"
    else echo "$(fw_kind): 1517/tcp already allowed ($(fw_how 1517))"; fi
  fi
  systemctl enable wazuh-manager >/dev/null 2>&1 || true
  guard off   # R2
  local t0=$SECONDS; systemctl restart wazuh-manager; ts > "$STATE/T_listeners_open"
  echo "manager restarted in $((SECONDS - t0)) s; listeners open at $(cat "$STATE/T_listeners_open")"
  sleep 5; ss -ltnH | awk '{print $4}' | grep -E ':(1514|1515|1517)$' | sort | tr '\n' ' '; echo
}
op_wait_agents() { wait_api5; python3 "$HELPER" wait-agents "$BUNDLE_DIR/truth4" "$AGENT_WAIT_SECS" "$(cat "$STATE/T_listeners_open")"; ts > "$STATE/T_agents_back"; }
phase_open() {
  [ "$(host_state)" = v5 ] || die "5.0 is not installed"
  done_ import.gate || die "the import has not passed its gate: opening the listeners now would let agents meet an unverified registry"
  step open.decision    "apply the decision on unclassified events"                          op_decision
  step open.in_force    "wait until the engine has the decision in force (rule 8, F6-D3)"     op_in_force
  step open.listeners   "open the agent listeners and restart the manager"                   op_listeners
  step open.gate        "gate: a keepalive newer than the opening from every agent (THE OUTAGE ENDS)" op_wait_agents
}

########################################################################## 8. VERIFY
settings_carried() { [ "$CARRY_SETTINGS" = 1 ] && done_ import.settings && echo 1 || echo 0; }   # E2-rpm gap 8, E2-deb G7
vf_compare() {
  local rc=0 crc=0
  if noagents; then echo "no agents: identity check not applicable" > "$LOGS/identity-check-final.log"; else expected_conf
  $V5/framework/python/bin/python3 "$HERE/identity_stage.py" verify "$BUNDLE_DIR/identity" --state "$BUNDLE_DIR/identity-stage" "${EXP[@]}" > "$LOGS/identity-check-final.log" 2>&1 || rc=$?; fi   # merged: G5's paged verify, not the tool's check (G1); E2 fold: the pass's output expected
  echo "identity check exit $rc: $(tail -n 1 "$LOGS/identity-check-final.log")"
  noagents || python3 "$HELPER" settle-agents "$BUNDLE_DIR/truth4" "${VERIFY_SETTLE_SECS:-120}" || true   # E4-rpm gap 3
  python3 "$HELPER" truth5 "$BUNDLE_DIR/truth5"
  # F10: with the history loaded after the opening, its two lines read PENDING until the history phase has switched it on
  local hp=0; if [ "$HISTORY_LOAD" = after-open ] && ! done_ history.on; then hp=1; fi
  HISTORY_PENDING=$hp SETTINGS_CARRIED=$(settings_carried) python3 "$HELPER" compare "$BUNDLE_DIR/truth4" "$BUNDLE_DIR/fingerprint" "$BUNDLE_DIR/truth5" | tee "${VERIFY_REPORT:-$BUNDLE_DIR/REPORT-verify.txt}" || crc=${PIPESTATUS[0]}
  echo "ruleset: rmig verify exit $(cat "$STATE/ruleset.verify_rc" 2>/dev/null || echo not-run); decision applied: $(tr '\n' ' ' < "$STATE/unclassified.applied" 2>/dev/null || echo none)"
  leftovers > "$LOGS/leftovers-final.txt"; echo "4.x leftovers on the host: $(grep -c -E 'ossec|filebeat|wazuh.list' "$LOGS/leftovers-final.txt" || true) (see $LOGS/leftovers-final.txt)"
  echo "verify: identity check exit $rc, compare exit $crc"
  [ "$rc" = 0 ] && [ "$crc" = 0 ]
}
phase_verify() {
  [ "$(host_state)" = v5 ] || die "5.0 is not installed"
  if done_ phase.verify && done_ confirm.no_return; then vf_report_only; return 0; fi   # E3 fold (E3-deb N3)
  rm -f "$STATE/verify.compare"
  step verify.compare "compare 5.0 with the fingerprint; report to the user" vf_compare
}
vf_report_only() { # E3 fold (E3-deb N3): with the history after the opening, `run` came back through phase 8 to reach the
  # history, and phase 8 failed while an agent restarted for its upgrade (phase 10), so the history never started.
  # Phase 8 stays strict until it has passed and the point of no return is confirmed (its purpose: deciding whether to go
  # back); after that a rerun reports into REPORT-verify-rerun.txt and the history goes on. Its pass's report is kept.
  VERIFY_REPORT_ONLY=1
  log "  phase 8 passed at $(cat "$STATE/phase.verify") and the point of no return was confirmed at $(cat "$STATE/confirm.no_return"):"
  log "  this rerun only reports (agents may be restarting for their upgrade); the history phase goes on"
  local rc=0
  ( VERIFY_REPORT="$BUNDLE_DIR/REPORT-verify-rerun.txt" vf_compare ) 2>&1 | tee "$RESULTS/verify.rerun.log" || rc=${PIPESTATUS[0]}
  if [ "$rc" = 0 ]; then log "  phase 8 rerun: no difference"
  else log "  WARNING phase 8 rerun: exit $rc (an agent upgrading or down reads as not active): see $BUNDLE_DIR/REPORT-verify-rerun.txt; the history goes on"; fi
}

########################################################################## F10: HISTORY AFTER THE OPENING
hi_load() {
  [ -s "$STATE/T_history_load_begin" ] || ts > "$STATE/T_history_load_begin"
  echo "history load starts $(ts); the agent listeners opened at $(cat "$STATE/T_listeners_open" 2>/dev/null || echo '?'): the agents are served meanwhile"
  im_history_load
  ts > "$STATE/T_history_load_end"
}
hi_report() { # the final comparison, history included (the verify phase reported it as PENDING)
  local crc=0
  python3 "$HELPER" truth5 "$BUNDLE_DIR/truth5-history"
  HISTORY_PENDING=0 SETTINGS_CARRIED=$(settings_carried) python3 "$HELPER" compare "$BUNDLE_DIR/truth4" "$BUNDLE_DIR/fingerprint" "$BUNDLE_DIR/truth5-history" | tee "$BUNDLE_DIR/REPORT-verify-history.txt" || crc=${PIPESTATUS[0]}
  { history_retention > /dev/null; cat "$STATE/history.retention"; } | tee -a "$BUNDLE_DIR/REPORT-verify-history.txt"   # OF1 (decision 5b)
  ts > "$STATE/T_history_on"
  echo "history phase: compare exit $crc; history switched on at $(cat "$STATE/T_history_on"), $(( $(date -d "$(cat "$STATE/T_history_on")" +%s) - $(date -d "$(cat "$STATE/T_listeners_open")" +%s) )) s after the listeners opened"
  [ "$crc" = 0 ]
}
phase_history() {
  [ "$(host_state)" = v5 ] || die "5.0 is not installed"
  if [ "$HISTORY_LOAD" != after-open ]; then
    done_ import.history_on || die "HISTORY_LOAD=$HISTORY_LOAD but the history was not switched on in phase 6"
    log "  info  the history was loaded, proven and switched on in phase 6, before the opening (HISTORY_LOAD=$HISTORY_LOAD)"; return 0
  fi
  done_ open.gate || die "the listeners are not open: with HISTORY_LOAD=after-open the history is loaded after the opening"
  step history.load   "history: load the dump through the shaping pipeline (the agents are already served)" hi_load
  step history.prove  "history: proof per source index"                                im_history_prove
  step history.on     "history: role audit again, then the two aliases on (rule 9)"    im_history_on
  if [ "$CARRY_SAVED_OBJECTS" = 1 ]; then step history.saved_objects "custom dashboards as a view of the history (after the aliases are on)" im_saved_objects; fi
  step history.report "history: compare 5.0 with the fingerprint again, history included" hi_report
}

########################################################################## 9. POINT OF NO RETURN
history_pending() { [ "$HISTORY_LOAD" = after-open ] && ! done_ history.on; }
history_pending_note() { # OF1 (E2-deb G7, decisions 10 and 11): what the history's state means for phases 9 to 11
  local where="it has not started"
  if done_ history.load; then where="loaded, not yet proven and switched on"
  elif [ -s "$STATE/T_history_load_begin" ]; then where="its load started at $(cat "$STATE/T_history_load_begin") and has not finished"; fi
  log "    THE 4.x HISTORY IS STILL PENDING ($where): it loads after the opening (decision 10) and is not visible on 5.0 until"
  log "    it is proven and switched on. '$0 run' completes it. Confirming now is allowed; 'finish' waits for the history,"
  log "    and the bundle, the only copy of the 4.x alerts once 4.x is gone, is kept until the history is proven."
}
banner_phase9() {
  log "=== PHASE 9: POINT OF NO RETURN. Stopped here on purpose."
  log "    5.0 is serving the agents as 4.x agents. Until you confirm, '$0 back' returns this host to 4.14.x from the bundle;"
  log "    after the confirmation going back is refused (decision 11): problems are fixed forward on 5.0."
  if history_pending; then history_pending_note; fi
  log "    To go on: '$0 confirm-no-return', then '$0 agents' and '$0 finish'."
}
cmd_confirm() {
  done_ phase.verify || die "phases 1 to 8 are not complete: nothing to confirm"
  [ ! -e "$STATE/back.done" ] || die "this host went back to 4.x"
  mark confirm.no_return; jr confirm.no_return end "explicit confirmation"
  log "POINT OF NO RETURN confirmed at $(cat "$STATE/confirm.no_return"). Going back to 4.x from the bundle is no longer offered: an upgraded agent cannot return to a 4.x manager."
  if history_pending; then history_pending_note; fi
}

########################################################################## 10. AGENTS
fu() { # fleet-upgrade.py with the connection filled in
  local a=(--api https://localhost:55000 --ca $V5ETC/certs/root-ca.pem --fleet-facts "$BUNDLE_DIR/preflight/fleet-facts.json" --state "$BUNDLE_DIR/fleet/upgrade-state.json"
           --indexer https://$(idxhost):9200 --indexer-ca "${IDX5_CA:-/etc/wazuh-indexer/certs/root-ca.pem}" --manager-log $V5/logs/wazuh-manager.log --tasks-db $V5/queue/tasks/tasks.db)
  [ -z "$WPK_REPO" ] || a+=(--wpk-repo "$WPK_REPO")
  WAZUH_API_PASSWORD="$(v5env $V5ETC/export/credentials.env WAZUH_MANAGER_API_PASSWORD)" WAZUH_INDEXER_PASSWORD="$(idx5pw)" python3 "$HERE/fleet-upgrade.py" "$@" "${a[@]}"
}
ag_preflight() { mkdir -p "$BUNDLE_DIR/fleet"; fu preflight; }
ag_run() { fu run --report "$BUNDLE_DIR/fleet/report.json"; }
ag_trust() { # the trust each 5.x agent reports for itself, from the indexer; fleet-upgrade.py prints it and exits 0 whatever it found
  local i
  for i in $(seq 1 12); do   # an upgraded agent's configuration report reaches the indexer a little after it reconnects
    fu trust-audit > "$BUNDLE_DIR/fleet/trust-audit.txt" 2>&1 || true
    grep -q "NO configuration report" "$BUNDLE_DIR/fleet/trust-audit.txt" || break; sleep 15
  done
  cat "$BUNDLE_DIR/fleet/trust-audit.txt"
}
ag_gate() { # a verdict from evidence for every agent: fleet-upgrade.py's own state names, and the trust audit
  python3 - "$BUNDLE_DIR/fleet/upgrade-state.json" "$BUNDLE_DIR/fleet/trust-audit.txt" "$BUNDLE_DIR/preflight/fleet-facts.json" <<'EOF'
import json, re, sys
st = json.load(open(sys.argv[1])); ags = st.get("agents", {})
# E5 fold (E5-cluster-rpm gap 6): an agent the run's selection left out (FLEET_ARGS --agents or --groups) never reaches
# the orchestrator's state, so the gate said "0 left on 4.x on purpose" with one on 4.x. Every agent of the 4.x fleet
# (the pre-copy's fleet facts) that the state does not hold is named, as left on 4.x by the selection.
try:
    facts = json.load(open(sys.argv[3])).get("agents", {})
except (OSError, ValueError):
    facts = {}
outside = {i: f for i, f in facts.items() if i != "000" and i not in ags}
for i, f in outside.items():
    ags[i] = {"name": f.get("name", ""), "state": "skipped", "reason": "not in this run's selection (FLEET_ARGS --agents or --groups): still on 4.x"}
trust = {}
for l in open(sys.argv[2]):
    m = re.match(r"^(\d{3,})\s", l)
    if m: trust[m.group(1)] = l.rstrip()
# fleet-upgrade.py: TERMINAL_OK = upgraded, upgraded-trust-unconfirmed, upgraded-not-verifying, already-target;
# TERMINAL_BAD = failed, upgraded-not-connecting, expired, refused; OPEN = requested, delivering, installing,
# waiting-for-agent; not requested = planned, held, skipped (with a reason).
upgraded, left, bad = {}, {}, {}
for i, a in sorted(ags.items()):
    s, t = a.get("state"), trust.get(i, "")
    if s in ("upgraded", "already-target"):
        if "verification_mode=full" in t and "<--" not in t: upgraded[i] = "upgraded; trust from the agent's own report: " + t.split(None, 4)[-1]
        else: bad[i] = "upgraded, but trust is not proven: " + (t.split(None, 4)[-1] if t else "no line in the trust audit")
    elif s in ("upgraded-trust-unconfirmed", "upgraded-not-verifying"): bad[i] = s + ": " + a.get("reason", "")
    elif s in ("skipped", "held", "planned"): left[i] = "%s, still on 4.x: %s" % (s, a.get("reason", "not requested"))
    else: bad[i] = "%s: %s" % (s, a.get("reason", ""))
for i in sorted(ags):
    print("agent %s %-12s %s" % (i, ags[i].get("name", ""), upgraded.get(i) or left.get(i) or bad.get(i)))
# E3 fold (E3-deb N5): the agents left only because they were not active (pending or disconnected) are named together
late = [i for i, a in sorted(ags.items()) if i in left and re.search(r"agent is (pending|disconnected)", a.get("reason", ""))]
if late:
    print("not active at the preflight, still on 4.x: %s: run '%s agents' again once they are active" % (" ".join(late), "migrate.sh"))
if outside:
    print("left out by the agents selection, still on 4.x: %s: run the agents phase again without the selection (or with them in it) to upgrade them" % " ".join(sorted(outside)))
print("gate: %d agent(s): %d upgraded with trust proven, %d left on 4.x on purpose (the legacy ports stay open for them), %d failed or unproven %s"
      % (len(ags), len(upgraded), len(left), len(bad), sorted(bad)))
sys.exit(1 if bad or not ags else 0)
EOF
}
feed_wait() { # rule 14: wait for the feed's initial load, or with FEED_WAIT_MAX=0 only report it
  if [ "$FEED_WAIT_MAX" = 0 ]; then
    python3 "$HELPER" feed-status "$V5/logs/wazuh-manager.log" || echo "FEED_WAIT_MAX=0: not waiting; packages, OS and vulnerabilities of upgraded agents follow the feed's first complete load"
    return 0
  fi
  python3 "$HELPER" feed-wait "$V5/logs/wazuh-manager.log" "$FEED_WAIT_MAX" "$V5ETC/wazuh-manager.conf"
}
ag_feed() { feed_wait; }
cmd_agents() {
  done_ confirm.no_return || die "the point of no return is not confirmed: run '$0 confirm-no-return' first"
  CUR=agents; log "=== PHASE 10 agents BEGIN"; local t0=$SECONDS
  # E2-deb fix 4: the gate leaves agents "skipped, still on 4.x ... re-run when it is back", so every call runs the steps
  # again, as cmd_finish does for its own. fleet-upgrade.py's state file keeps finished agents finished and the request
  # guard holds, so only the late agents are asked. Before this a rerun skipped every step by its marker and upgraded nobody.
  rm -f "$STATE/agents.preflight" "$STATE/agents.run" "$STATE/agents.trust" "$STATE/agents.feed" "$STATE/agents.gate"
  if noagents; then mark phase.agents; log "=== PHASE 10 agents END: the source had no agent, nothing to upgrade (F6)"; return 0; fi
  step agents.preflight "agents: preflight (read-only)"                       ag_preflight
  step agents.run       "agents: upgrade in waves, verdicts from evidence"    ag_run
  step agents.trust     "agents: trust audit from the indexer"                ag_trust
  step agents.feed      "agents: wait for the vulnerability feed's initial load (rule 14; FEED_WAIT_MAX)" ag_feed
  step agents.gate      "gate: a verdict from evidence for every agent"       ag_gate
  mark phase.agents; log "=== PHASE 10 agents END ($((SECONDS - t0)) s)"
}

########################################################################## 11. FINISH
fi_legacy() { # F6 (DECISIONS F6-D4): closing is a decision when the only agents below 5.0 are never-connected ones, and
  # keeping the ports open is a result, not a failure: the steps after this one (raw off, secrets) must still run
  # E5 fold (E5-cluster-rpm gap 5, E5-cluster-deb gap 10): once the legacy ports are closed, a later finish (after the
  # raw-at-finish answer, say) does not close them again: that was one more manager restart for nothing
  if [ -s "$STATE/legacy.closed" ]; then rm -f "$STATE/legacy.open"; echo "the legacy ports were closed at $(cat "$STATE/legacy.closed") (state/legacy.closed): not closed again"; return 0; fi
  fu legacy-status | tee "$LOGS/legacy-status.txt"
  rm -f "$STATE/legacy.open"
  if ! grep -q 'legacy channel can be closed: YES' "$LOGS/legacy-status.txt"; then
    local old nc others sess
    old=$(sed -n 's/^agents not on 5.x in the registry: [0-9]*: //p' "$LOGS/legacy-status.txt" | sed 's/), /)\n/g')   # "002 (None, never_connected), 004 (v4.14.10, active)"
    nc=$(grep -E '\(None, never_connected\)' <<<"$old" | awk '{print $1}' | tr '\n' ' ' || true)
    others=$(grep -v -E '\(None, never_connected\)' <<<"$old" | grep . || true)
    sess=$(sed -n 's/^legacy TCP sessions per node: //p' "$LOGS/legacy-status.txt" | tr ',' '\n' | awk -F= '$2 != 0' | grep . || true)
    if [ -n "$others" ] || [ -n "$sess" ]; then
      echo "LEGACY PORTS KEPT OPEN: agents below 5.0 that reported a version, or open legacy sessions: $(echo $others $sess)"
      echo "keep legacy: $(echo $others $sess)" > "$STATE/legacy.open"; return 0
    fi
    echo "the only agents below 5.0 on record never connected: $nc(no version, no address; a host may still install an agent with one of these keys)"
    case "$NEVER_CONNECTED_AT_FINISH" in
      keep) echo "LEGACY PORTS KEPT OPEN for them (NEVER_CONNECTED_AT_FINISH=keep). To close: NEVER_CONNECTED_AT_FINISH=close (their keys then work only for a 5.0 agent, on 1517) or =remove (delete them), and run finish again"
            echo "keep never-connected: $nc" > "$STATE/legacy.open"; return 0;;
      remove) local tok; tok=$(curl -sk -u "wazuh:$(v5env $V5ETC/export/credentials.env WAZUH_MANAGER_API_PASSWORD)" -X POST "https://localhost:55000/security/user/authenticate?raw=true")
              curl -sk -X DELETE "https://localhost:55000/agents?agents_list=$(echo $nc | tr ' ' ',')&status=all&older_than=0s" -H "Authorization: Bearer $tok"; echo
              echo "removed from the registry by the user's decision: $nc";;
      close) echo "closing the legacy ports by the user's decision; still registered: $nc";;
      *) echo "NEVER_CONNECTED_AT_FINISH: unknown answer '$NEVER_CONNECTED_AT_FINISH' (keep, close, remove)"; return 1;;
    esac
  fi
  # rule 14 (MAC1-G6): the restart below would throw away a feed load in progress, so wait for it before touching
  # the configuration (a timeout then leaves the legacy listener as it was)
  feed_wait || return 1
  local c=$V5ETC/wazuh-manager.conf
  # F5: a rerun after a kill in this step finds the configuration already edited; copying it again would replace the
  # only copy with the legacy listener on (observed: cut 4a). Keep the first copy, as op_listeners does for its own.
  [ -e "$c.before-legacy-off" ] || cp -p "$c" "$c.before-legacy-off"
  sed -i '/<legacy>/,/<\/legacy>/ s#<enabled>yes</enabled>#<enabled>no</enabled>#' "$c"
  $V5/bin/wazuh-manager-conf validate
  systemctl restart wazuh-manager; ts > "$STATE/T_legacy_closed"; sleep 20
  grep -E "Legacy listener disabled|Port 1515 was set as disabled" $V5/logs/wazuh-manager.log | tail -n 2
  echo "listening: $(ss -ltnH | awk '{print $4}' | grep -E ':(1514|1515|1517)$' | sort | tr '\n' ' ')"
  ss -ltnH | awk '{print $4}' | grep -E ':(1514|1515)$' && { echo "a legacy port is still open"; return 1; } || true
  fw_close_legacy
  mark legacy.closed
}
fw_close_legacy() { # the legacy ports leave the host firewall where they were opened as ports (CL1: shared with the cluster finish)
  fw_active || return 0
  local fp fh k; k=$(fw_kind)
  for fp in 1514 1515; do fh=$(fw_how $fp)
    case "$fh" in
      port) fw_port remove $fp; echo "$k: $fp/tcp removed from zone $(fw_zone)";;
      service:*) echo "$k: $fp/tcp is allowed by the service '${fh#service:}', which the tool does not edit: remove it yourself if nothing else needs it";;
      *) echo "$k: $fp/tcp was not allowed";;
    esac; done
  if [ "$k" = firewalld ]; then echo "firewalld zone $(fw_zone) now: ports $(firewall-cmd --zone="$(fw_zone)" --list-ports) services $(firewall-cmd --zone="$(fw_zone)" --list-services)"
  else echo "ufw now: $(ufw status 2>/dev/null | grep -E 'ALLOW' | tr -s ' ' | tr '\n' ';')"; fi
}
fi_agents_after() { [ -e "$STATE/legacy.open" ] && { echo "legacy ports kept open ($(cat "$STATE/legacy.open")): no listener changed, nothing to wait for"; return 0; }
  wait_api5; python3 "$HELPER" wait-agents "$BUNDLE_DIR/truth4" 300 "$(cat "$STATE/T_legacy_closed")"; }
synced_after() { awk -v a="$1" '$0 ~ /Successfully synchronized space .standard./ && ($1" "$2) > a {print $1" "$2}' $V5/logs/wazuh-manager.log | tail -n1; }
fi_raw_off() { # F6 (DECISIONS F6-D5): raw indexing was for 4.x agents; switch it off when none that reported a version is left
  grep -qw raw "$STATE/unclassified.applied" 2>/dev/null || { echo "raw indexing was not part of the decision: nothing to switch off"; return 0; }
  # E5 fold (E5-aio gap 7, E5-cluster-rpm gap 4): the rules and custom decoders a refusal names go on record now, before
  # this finish's secret sweep deletes ruleset-src (a later finish then still names the decoders)
  python3 "$HELPER" raw-facts "$STATE" "$(RWORK)" "$BUNDLE_DIR/ruleset-src" || true
  if grep -q '^keep legacy' "$STATE/legacy.open" 2>/dev/null; then echo "RAW INDEXING KEPT ON: 4.x agents remain ($(cat "$STATE/legacy.open")); run finish again after their upgrade"; return 0; fi
  # design decision 3 follow-up (2026-11-25): only with every migrated rule active, or on an explicit answer
  local rd=0; python3 "$HELPER" raw-decision "$MIGRATION_DECISIONS" "$STATE" "$(RWORK)" "$BUNDLE_DIR/ruleset-src" || rd=$?
  case "$rd" in 0) ;; 4) echo "RAW INDEXING KEPT ON by your answer (keep-raw): switch it off yourself later (mig_helper.py policy-unclassified off)"; return 0;; *) return "$rd";; esac
  local m i t; m=$(date -u +"%Y/%m/%d %H:%M:%S")
  python3 "$HELPER" policy-unclassified off || return 1
  # a policy change acts only once the engine has synchronised the space (about 85 s here): report it switched off then
  for i in $(seq 1 60); do t=$(synced_after "$m"); [ -n "$t" ] && { echo "the engine loaded the standard policy without raw indexing at $t"; return 0; }; sleep 5; done
  echo "the engine did not report the standard space synchronised within 300 s"; return 1
}
fi_secrets() { # F6 (DECISIONS F6-D6): the bundle's secrets, found by their values, not by a list of directories.
  # E2 fold: one implementation, bundle_secrets.py, shared with going back (back.secrets), discard and the cluster finish;
  # it also opens archives (E2-rpm gap 5) and no longer names the identity stage's state as another bundle (E2-deb G7)
  python3 "$HERE/bundle_secrets.py" sweep --bundle "$BUNDLE_DIR" --search "$WORK_DIR" \
    --outside "$V4_INSTALL_FILES_TAR" --outside "$V5ETC/authd.pass.pre-migration" || return 1
  du -sh "$BUNDLE_DIR"
}
fi_groups_post() { # C4 D5: per group, once every agent of the group runs 5.0; a group with a 4.x agent keeps the pre-upgrade files
  [ "$CARRY_SETTINGS" = 1 ] && [ -d "$BUNDLE_DIR/groups4" ] || { echo "no group pass to run"; return 0; }
  wait_api5; local v; v=$(python3 "$HELPER" group-versions) || return 1
  python3 "$HERE/settings_stage.py" groups --phase post-upgrade --groups "$BUNDLE_DIR/groups4" --decisions "$MIGRATION_DECISIONS" \
    --work "$BUNDLE_DIR/settings/groups-post" --shared "$V5ETC/shared" --versions "$v"
}
fi_history_data() { # H5: after a passing proof, the alert content leaves the bundle; what proves the history stays
  [ -d "$HIST" ] || { echo "no history in this bundle"; return 0; }
  wait_indexer idx5; hload remove-bundle
}
cmd_finish() {
  done_ phase.agents || die "the agents phase is not complete"
  # F10: finish deletes history/data from the bundle, the only copy of the 4.x alerts once 4.x is gone
  done_ import.history_on || done_ history.on || die "the history is not loaded, proven and switched on yet: finish would delete its only copy (history/data). Run '$0 run' to complete the history phase first"
  CUR=finish; log "=== PHASE 11 finish BEGIN"; local t0=$SECONDS
  rm -f "$STATE/finish.legacy" "$STATE/finish.agents" "$STATE/finish.raw_off" "$STATE/finish.groups_post"   # F6: rerun after the user's decision or later upgrades
  step finish.legacy  "close the legacy ports (only when no agent below 5.0 remains, or as decided)"  fi_legacy
  step finish.agents  "every agent sends a keepalive after the legacy ports closed"    fi_agents_after
  step finish.raw_off "switch raw event indexing off once no 4.x agent remains"        fi_raw_off
  step finish.groups_post "group files: the post-upgrade pass for every group whose agents all run 5.0 (C4)" fi_groups_post
  step finish.history_data "history: delete the alert files once proven, keep manifest and journal (H5)" fi_history_data
  step finish.secrets "delete the bundle's secrets, then search for their values"     fi_secrets
  if [ -e "$STATE/legacy.open" ]; then log "=== PHASE 11 finish END ($((SECONDS - t0)) s): secrets deleted; LEGACY PORTS STILL OPEN ($(cat "$STATE/legacy.open")); run finish again when that changes"
  else mark phase.finish; log "=== PHASE 11 finish END ($((SECONDS - t0)) s)"; fi
}


########################################################################## GOING BACK (phase 5 to phase 9)
bk_stop_history() { # F10: with the history loaded after the opening, a load may still be running when the user goes back
  local p
  p=$(pgrep -f 'migrate\.sh run' | tr '\n' ' ' || true)
  if [ -n "$p" ]; then echo "a 'migrate.sh run' is still running (pid $p): stopping it, so it does not go on to its next step"; pkill -TERM -f 'migrate\.sh run' || true; fi
  p=$(pgrep -f 'history_load\.py apply' | tr '\n' ' ' || true)
  if [ -n "$p" ]; then
    echo "a history load is running (pid $p): stopping it before 5.0 is removed (the dump in the bundle is only read by it)"
    pkill -TERM -f 'history_load\.py apply' || true; pkill -TERM -f 'migrate\.sh __step hi_load' || true
    local i; for i in $(seq 1 20); do pgrep -f 'history_load\.py apply' >/dev/null || break; sleep 1; done
    pkill -KILL -f 'history_load\.py apply' 2>/dev/null || true
  else echo "no history load running"; fi
  pgrep -f 'history_load\.py apply' >/dev/null && { echo "the history load did not stop"; return 1; }
  [ ! -e "$STATE/history.load" ] || echo "the history load had finished ($(cat "$STATE/history.load"))"
  return 0
}
bk_stop5() {
  ts > "$STATE/T_back_begin"
  # R2/F7: the guard goes on before the 5.0 manager stops and comes off only once the restored 4.x manager runs (bk_verify):
  # until the 4.x registry is restored, a fresh 4.x manager hands out keys with no password (F7: an agent re-keyed under
  # another agent's id 7 s after 1515 opened)
  if [ "$LAB_BACK_GUARD" = 0 ]; then guard off; echo "LAB SWITCH LAB_BACK_GUARD=0: going back WITHOUT the agent guard"
  else guard on; fi
  bk_stop_history   # F10: a history load running after the opening is stopped before 5.0 is removed
  systemctl stop wazuh-manager wazuh-dashboard 2>/dev/null || true
  echo "5.0 manager stopped at $(ts): the agents are without a manager from here"
  if [ -s "$STATE/fw.added" ] && fw_active; then local fp; for fp in $(sort -u "$STATE/fw.added"); do fw_port remove "$fp" || true; echo "$(fw_kind): $fp/tcp removed again (the migration had added it)"; done; fi
}
bk_remove5() {
  pkg_repair "before the 5.0 removal" || return 1   # F5
  if [ -n "$(pkgver wazuh-manager)$(pkgver wazuh-indexer)$(pkgver wazuh-dashboard)" ] && [ "$(host_state)" != v4 ]; then
    mkdir -p "$WORK_DIR/v5-uninstall"; cp -f "$BUNDLE_DIR/v5/wazuh-install.sh" "$WORK_DIR/v5-uninstall/"
    ( cd "$WORK_DIR/v5-uninstall" && bash ./wazuh-install.sh -u ) > "$LOGS/back-remove-5.0.log" 2>&1 || { tail -n 20 "$LOGS/back-remove-5.0.log"; return 1; }
    tail -n 3 "$LOGS/back-remove-5.0.log"
  fi
  local p; for p in /var/wazuh-manager /etc/wazuh-manager /var/lib/wazuh-indexer /etc/wazuh-indexer /usr/share/wazuh-indexer /etc/wazuh-dashboard /usr/share/wazuh-dashboard /var/lib/wazuh-dashboard; do
    if [ -e "$p" ]; then echo "left by the 5.0 removal, deleted by the tool: $p"; rm -rf "$p"; fi; done
  [ "$(host_state)" = none ] || [ "$(host_state)" = v4 ] || { echo "a 5.0 package is still installed"; return 1; }
  back_manifest || { echo "the bundle changed during the 5.0 removal"; return 1; }
  echo "5.0 removed; bundle intact"
}
bk_install4() {
  if [ "$V4_REINSTALLER" = external ]; then # R2: the deployment's own 4.x tool (the user's v4.14.x playbook) reinstalls 4.x
    [ "$(guard status)" = on ] || guard on
    if [ "$(host_state)" != v4 ] || [ -z "$(pkgver wazuh-indexer)" ] || [ -z "$(pkgver wazuh-dashboard)" ] || [ -z "$(pkgver filebeat)" ]; then
      echo "WAITING FOR THE EXTERNAL INSTALLER: 5.0 is removed and the agent guard is on. Run the 4.x deployment (the user's"
      echo "v4.14.x playbook, same inventory and variables) against this host, then run this command again."
      return 10
    fi
    pkglist | tee "$WORK_DIR/back-packages.txt"
    diff "$BUNDLE_DIR/v4/packages.txt" "$WORK_DIR/back-packages.txt" && echo "the same package versions as before the migration" || { echo "the reinstalled packages are not the versions the bundle was taken from"; return 1; }
    return 0
  fi
  if [ "$(host_state)" = v4 ] && [ -n "$(pkgver wazuh-indexer)" ] && [ -n "$(pkgver wazuh-dashboard)" ] && [ -n "$(pkgver filebeat)" ]; then echo "4.x packages are installed already"; return 0; fi
  local d="$WORK_DIR/v4-install" args=(-a) rc=0
  rm -rf "$d"; mkdir -p "$d"; cp -f "$BUNDLE_DIR/v4/wazuh-install.sh" "$d/"
  [ -z "$(pkgver wazuh-manager)$(pkgver wazuh-indexer)$(pkgver wazuh-dashboard)$(pkgver filebeat)" ] || args+=(-o)
  local off="$BUNDLE_DIR/v4/offline"
  if [ "$V4_PACKAGES_CACHE" = 1 ] && [ -s "$off/wazuh-offline.tar.gz" ]; then # F7: reinstall from the packages kept in the bundle
    ( cd "$off" && sha256sum --quiet -c wazuh-offline.tar.gz.sha256 ) || { echo "the 4.x package set in the bundle does not match its checksum"; return 1; }
    cp -f "$off/wazuh-offline.tar.gz" "$d/"
    if [ "$PKGFAM" = rpm ]; then rpm -q lsof >/dev/null 2>&1 || { rpm -Uvh --replacepkgs "$off"/os-deps/*.rpm && echo "lsof installed from the bundle (the offline mode requires it)"; }
    else dpkg -s lsof >/dev/null 2>&1 || { dpkg -i "$off"/os-deps/lsof_*.deb && echo "lsof installed from the bundle (the offline mode requires it)"; }; fi
    args+=(-of); echo "reinstalling 4.x from the package set kept in the bundle (offline mode, nothing downloaded)"
    if [ "${LAB_GNUPG_SHIM:-0}" = 1 ] && [ "$PKGFAM" = rpm ]; then
      # F7 lab shim, recorded in DECISIONS: the 4.14 assistant's offline mode checks "yum list installed" for a package
      # named gnupg, which RHEL calls gnupg2; the shim adds that one line to the listing and changes nothing else.
      yum() { if [ "${1:-}" = list ] && [ "${2:-}" = installed ]; then command yum "$@"; rpm -q gnupg2 >/dev/null 2>&1 && echo "gnupg.x86_64 shim-for-gnupg2 @f7"; else command yum "$@"; fi; }
      export -f yum; echo "LAB SHIM: yum list installed reports gnupg2 also as gnupg"
    fi
  else echo "reinstalling 4.x with the 4.x assistant from the internet"; fi
  ts > "$STATE/T_install4_begin"
  ( cd "$d" && bash ./wazuh-install.sh "${args[@]}" ) 2>&1 | mask_passwords > "$LOGS/back-install-4x.log" || rc=${PIPESTATUS[0]}   # E2-deb G11
  ts > "$STATE/T_install4_end"
  grep -E 'INFO|WARNING|ERROR' "$LOGS/back-install-4x.log" | sed -E 's/(Password|password)[:=].*/\1: MASKED/I' | tail -n 8
  [ "$rc" = 0 ] || return 1
  pkglist | tee "$WORK_DIR/back-packages.txt"
  diff "$BUNDLE_DIR/v4/packages.txt" "$WORK_DIR/back-packages.txt" && echo "the same package versions as before the migration" || { echo "the reinstalled packages are not the versions the bundle was taken from"; return 1; }
}
bk_restore() {
  local R="$BUNDLE_DIR/v4/rollback"
  export V4_INDEXER_ADMIN_PASSWORD; V4_INDEXER_ADMIN_PASSWORD=$(v4pw "$R/wazuh-install-files.tar" admin); export V4_API_PASSWORD; V4_API_PASSWORD=$(v4pw "$R/wazuh-install-files.tar" wazuh)
  systemctl stop wazuh-manager filebeat wazuh-dashboard wazuh-indexer
  echo "1. the 4.x configuration, certificates and keystores of the indexer, dashboard and Filebeat"
  tar -xzf "$R/etc-indexer-dashboard-filebeat.tar.gz" -C /
  cp -f "$BUNDLE_DIR"/indexer-security/backup/*.yml /etc/wazuh-indexer/opensearch-security/
  chown -R wazuh-indexer:wazuh-indexer /etc/wazuh-indexer; chown -R wazuh-dashboard:wazuh-dashboard /etc/wazuh-dashboard /usr/share/wazuh-dashboard/data/wazuh/config
  echo "2. the manager's etc/, API configuration (rbac.db), agent registry (global.db), per-agent databases, integrations"
  bk_agent_dbs_prepare "$R"
  tar -xzf "$R/var-ossec.tar.gz" -C /
  bk_agent_dbs_check "$R"
  cp -f "$R/wazuh-install-files.tar" "$V4_INSTALL_FILES_TAR"
  echo "3. the indexer, with the 4.x security configuration (users, roles, mappings, passwords)"
  systemctl start wazuh-indexer
  local i; for i in $(seq 1 60); do curl -sk -o /dev/null https://127.0.0.1:9200 && break; sleep 3; done
  /usr/share/wazuh-indexer/bin/indexer-security-init.sh > "$LOGS/back-securityadmin.log" 2>&1 || { tail -n 15 "$LOGS/back-securityadmin.log"; return 1; }
  wait_indexer idx4 || { echo "the restored indexer does not accept the 4.x admin password"; return 1; }
  echo "4. the alerts, from the dump, under their own index names and ids"
  idx4 DELETE '/wazuh-alerts-4.x-*?ignore_unavailable=true&expand_wildcards=all' | cut -c1-120; echo
  rm -rf "$WORK_DIR/back-load-state"
  python3 "$HERE/load_unchanged.py" --bundle "$HIST" --url https://127.0.0.1:9200 --user admin --password-env V4_INDEXER_ADMIN_PASSWORD --insecure --state-dir "$WORK_DIR/back-load-state" --workers 4 2>&1 | tail -n 6
  echo "5. the manager's and Filebeat's indexer credentials (both keystores are outside the restored directories), then start everything"
  $V4/bin/wazuh-keystore -f indexer -k username -v admin; $V4/bin/wazuh-keystore -f indexer -k password -v "$V4_INDEXER_ADMIN_PASSWORD"
  # Filebeat keeps its keystore in /var/lib/filebeat: the reinstall wrote it with ITS admin password, which the restored
  # security configuration no longer accepts. Left alone, Filebeat gets 401 and no alert is indexed while every service is active.
  filebeat keystore create --force >/dev/null; printf 'admin' | filebeat keystore add username --stdin --force >/dev/null
  printf '%s' "$V4_INDEXER_ADMIN_PASSWORD" | filebeat keystore add password --stdin --force >/dev/null
  systemctl enable wazuh-manager filebeat >/dev/null 2>&1 || true
  systemctl start wazuh-manager; ts > "$STATE/T_back_manager4_started"; systemctl start filebeat wazuh-dashboard
  for i in $(seq 1 60); do curl -sk -u "wazuh:$V4_API_PASSWORD" -X POST "https://localhost:55000/security/user/authenticate?raw=true" | grep -q '^ey' && break; sleep 3; done; sleep 10
  echo "6. the custom dashboard (the .kibana index is not in the bundle): import the exported saved objects"
  local code; for i in $(seq 1 40); do
    code=$(curl -sk -o "$WORK_DIR/back-so.out" -w '%{http_code}' -u "admin:$V4_INDEXER_ADMIN_PASSWORD" -X POST "https://127.0.0.1:443/api/saved_objects/_import?overwrite=true" -H 'osd-xsrf: true' --form file=@"$BUNDLE_DIR/dashboard/saved-objects.ndjson;filename=v4.ndjson" || true)   # R2: refused while the 4.x dashboard starts (curl exit 7 ended the step on the AMI)
    [ "$code" = 200 ] && break; sleep 5
  done
  echo "saved objects import: HTTP $code $(cut -c1-160 "$WORK_DIR/back-so.out")"
}
bk_agent_dbs_prepare() { # OF1 (E2-deb G4): a -wal or -shm the reinstall left beside a database the archive replaces would be
  # replayed into the restored file by SQLite; the manager is stopped here, so they are only leftovers
  local f n
  for f in "$V4/queue/db/global.db" $(sed "s|^\([^ ]*\) .*|$V4/queue/db/\1|" "$1/agent-dbs.txt" 2>/dev/null | grep '\.db$' || true); do
    for n in "$f-wal" "$f-shm"; do [ ! -e "$n" ] || { rm -f "$n"; echo "   removed $n left by the reinstall (the restored database replaces it)"; }; done
  done
}
bk_agent_dbs_check() {
  if [ ! -f "$1/agent-dbs.txt" ]; then
    echo "   this bundle holds no per-agent databases (taken before OF1): inventory, FIM baselines and SCA state are rebuilt from the agents' next scans"; return 0; fi
  local n bad=""; while read -r n s; do [ -n "$n" ] || continue
    [ "$(stat -c %s "$V4/queue/db/$n" 2>/dev/null || echo -1)" = "$s" ] || bad="$bad $n"; done < "$1/agent-dbs.txt"
  [ -z "$bad" ] || { echo "per-agent databases not restored at their frozen size:$bad"; return 1; }
  echo "   per-agent databases restored: $(grep -c . "$1/agent-dbs.txt" || true) file(s) (package and OS inventory, FIM baselines, SCA state as at the freeze)"
}
bk_verify() {
  local R="$BUNDLE_DIR/v4/rollback"
  if [ "$(guard status)" = on ]; then # F7: what the guard refused while it was on (the counters are reset by "off")
    if command -v iptables >/dev/null 2>&1; then iptables -L MIGGUARD -n -v -x 2>/dev/null | sed "s/^/  guard: /"; else nft list table inet migguard 2>/dev/null | sed "s/^/  guard: /"; fi
  fi
  guard off   # R2: the 4.x registry is restored
  export V4_INDEXER_ADMIN_PASSWORD; V4_INDEXER_ADMIN_PASSWORD=$(v4pw "$R/wazuh-install-files.tar" admin); export V4_API_PASSWORD; V4_API_PASSWORD=$(v4pw "$R/wazuh-install-files.tar" wazuh)
  python3 - "$BUNDLE_DIR/truth4" "$(cat "$STATE/T_back_manager4_started")" "$AGENT_WAIT_SECS" <<'EOF'
import base64, json, os, ssl, sys, time, urllib.request
t4, started, secs = sys.argv[1], sys.argv[2], int(sys.argv[3])
ctx = ssl._create_unverified_context()
def call(path, token=None):
    req = urllib.request.Request("https://localhost:55000" + path, method="GET" if token else "POST")
    req.add_header("Authorization", ("Bearer " + token) if token else "Basic " + base64.b64encode(("wazuh:" + os.environ["V4_API_PASSWORD"]).encode()).decode())
    return json.load(urllib.request.urlopen(req, context=ctx, timeout=30))
want = {a["id"]: a for a in json.load(open(os.path.join(t4, "agents.json"))) if a["id"] != "000" and a["status"] == "active"}
end, seen = time.time() + secs, {}
while time.time() < end and len(seen) < len(want):
    try:
        tok = call("/security/user/authenticate")["data"]["token"]
        for a in call("/agents?select=id,name,status,lastKeepAlive,group,version&limit=100000", tok)["data"]["affected_items"]:
            ka = (a.get("lastKeepAlive") or "").replace("+00:00", "Z")
            if a["id"] in want and a["status"] == "active" and ka >= started and a["id"] not in seen:
                seen[a["id"]] = a; print("back: agent %s %s active on the restored 4.x manager, keepalive %s, groups %s, %s" % (a["id"], a["name"], ka, a.get("group"), a.get("version")), flush=True)
    except Exception as e:
        print("back: waiting for the API:", str(e)[:80], flush=True)
    time.sleep(5)
bad = [i for i in want if i not in seen or seen[i].get("group") != want[i].get("group") or seen[i]["name"] != want[i]["name"]]
print("back: %d of %d agent(s) reconnected with a keepalive newer than the restart; with a different name or membership: %s" % (len(seen), len(want), bad))
sys.exit(1 if bad else 0)
EOF
  ts > "$STATE/T_back_agents"
  # reconnecting is not enough: new alerts of every agent must reach the indexer again
  filebeat test output 2>&1 | tail -n 2 | tr '\n' ' '; echo
  filebeat test output >/dev/null 2>&1 || { echo "Filebeat cannot talk to the restored indexer: nothing is being indexed"; return 1; }
  python3 - "$BUNDLE_DIR/truth4" "$(cat "$STATE/T_back_manager4_started")" <<'EOF'
import base64, json, os, ssl, sys, time, urllib.request
t4, started = sys.argv[1], sys.argv[2]
ctx = ssl._create_unverified_context()
want = sorted(a["id"] for a in json.load(open(os.path.join(t4, "agents.json"))) if a["id"] != "000" and a["status"] == "active")
def counts():
    req = urllib.request.Request("https://127.0.0.1:9200/wazuh-alerts-4.x-*/_search?size=0", method="POST",
        data=json.dumps({"query": {"range": {"timestamp": {"gte": started}}}, "aggs": {"a": {"terms": {"field": "agent.id", "size": 10000}}}}).encode())
    req.add_header("Authorization", "Basic " + base64.b64encode(("admin:" + os.environ["V4_INDEXER_ADMIN_PASSWORD"]).encode()).decode()); req.add_header("Content-Type", "application/json")
    d = json.load(urllib.request.urlopen(req, context=ctx, timeout=60))
    return {b["key"]: b["doc_count"] for b in d["aggregations"]["a"]["buckets"]}
end = time.time() + 300; c = {}
while time.time() < end:
    try: c = counts()
    except Exception as e: print("back: waiting for the indexer:", str(e)[:80], flush=True)
    if all(c.get(i) for i in want): break
    time.sleep(10)
missing = [i for i in want if not c.get(i)]
print("back: alerts indexed again since the 4.x manager started (%s), per agent id: %s; agents with none: %s" % (started, {i: c.get(i, 0) for i in want + ["000"]}, missing))
sys.exit(1 if missing else 0)
EOF
  ts > "$STATE/T_back_events"
  SHIPPED_DIR="$BUNDLE_DIR/indexer-security/shipped" python3 "$HELPER" truth4 "$BUNDLE_DIR/truth4-after-back" >/dev/null
  python3 - "$BUNDLE_DIR/truth4" "$BUNDLE_DIR/truth4-after-back" "$BUNDLE_DIR/fingerprint" <<'EOF'
import json, sys, os, re
a, b, fp = sys.argv[1:4]
L = lambda d, f: json.load(open(os.path.join(d, f)))
bad = 0
for f in ("client_keys.json", "group_files.json", "groups_api.json", "api_security.json", "enrollment.json", "ruleset_files.json", "manager_settings.json", "saved_objects.json"):
    x, y = L(fp if f in ("client_keys.json", "group_files.json", "enrollment.json", "ruleset_files.json", "manager_settings.json", "saved_objects.json") else a, f), L(b, f)
    if f == "groups_api.json":
        x, y = sorted(g["name"] for g in x), sorted(g["name"] for g in y)
    same = x == y; bad += not same
    print(f"{f:26} {'SAME' if same else 'DIFFERENT'}")
# indexer users, roles and mappings: every object of the export taken before the migration, against the live indexer now
import base64, ssl, urllib.request
ctx = ssl._create_unverified_context()
def live(kind):
    req = urllib.request.Request("https://127.0.0.1:9200/_plugins/_security/api/" + kind)
    req.add_header("Authorization", "Basic " + base64.b64encode(("admin:" + os.environ["V4_INDEXER_ADMIN_PASSWORD"]).encode()).decode())
    return json.load(urllib.request.urlopen(req, context=ctx, timeout=60))
strip = lambda o: {k: v for k, v in o.items() if k not in ("hash",)} if isinstance(o, dict) else o
for kind in ("internalusers", "roles", "rolesmapping"):
    x = {k: strip(v) for k, v in json.load(open(os.path.join(os.path.dirname(fp), "indexer-security", "rest", kind + ".json"))).items()}
    y = {k: strip(v) for k, v in live(kind).items()}
    diff = sorted(k for k in set(x) | set(y) if x.get(k) != y.get(k))
    bad += bool(diff)
    print(f"{'indexer ' + kind:26} {'SAME' if not diff else 'DIFFERENT'}  {len(x)} object(s) in the export, {len(y)} now{'; differing: ' + str(diff[:6]) if diff else ''}")
ag = lambda d: sorted((x["id"], x["name"], tuple(x.get("group") or [])) for x in L(d, "agents.json") if x["id"] != "000")
same = ag(a) == ag(b); bad += not same
print(f"{'agents (id, name, groups)':26} {'SAME' if same else 'DIFFERENT'}  {ag(b)}")
fin = {k: v for k, v in L(fp, "indices.json").items() if re.match(r"wazuh-alerts-4\.x-", k)}
now = {k: v for k, v in L(b, "indices.json").items() if re.match(r"wazuh-alerts-4\.x-", k)}
less = sorted(k for k in fin if now.get(k, 0) < fin[k])
print(f"{'alert documents':26} {'ALL BACK' if not less else 'MISSING'}  {sum(fin.values())} at the freeze in {len(fin)} indices; now {sum(now.values())} in {len(now)} (new alerts since the return are expected); indices with fewer than at the freeze: {less[:5]}")
bad += bool(less)
print("back: compare with the 4.x truth: %d difference(s)" % bad)
sys.exit(1 if bad else 0)
EOF
}
back_manifest() { # everything the return reads must equal the frozen bundle; drift elsewhere is reported, not fatal
  local out bad
  out=$( cd "$BUNDLE_DIR" && sha256sum --quiet -c MANIFEST.sha256 2>&1 ) && return 0
  bad=$(grep -E '^\./(v4|history|indexer-security/backup|indexer-security/shipped|dashboard|truth4|fingerprint|preflight)/.*: FAILED' <<<"$out" || true)
  if [ -n "$bad" ]; then echo "$bad" | head -n 10; return 1; fi
  echo "note: bundle files changed since the freeze in parts the return does not read: $(grep -c FAILED <<<"$out") ($(grep FAILED <<<"$out" | head -n 3 | tr '\n' ' '))"
}
abandoned_secrets() { # E2-deb G11 / E2-rpm gap 5: a bundle that will not be used again keeps no secret. Going back is over
  # (the 4.x manager runs from the restored files) or the bundle was abandoned before 4.x was removed. First what the
  # 4.x reinstall left in the work directory (its wazuh-install-files.tar: the reinstall's CA and admin private keys and
  # passwords, gzip inside a .tar name, unseen by the search; and the copy of the offline package set, 1.7 GB the
  # finish's search then read for 395 s), then the bundle's carried secrets by value. The 4.x install files the user
  # keeps are not named: 4.x is in use again.
  if [ -d "$WORK_DIR/v4-install" ]; then
    # E4-rpm gap 4: only the files that hold credentials are overwritten (the install files, their unpacked passwords
    # and keys); the public package set beside them (about 1.7 GB, 237 s of shredding) is a plain delete
    find "$WORK_DIR/v4-install" -type f \( -name 'wazuh-install-files*' -o -name '*.tar' -o -name '*passwords*' -o -name '*.pem' \
         -o -name '*.key' -o -name 'credentials*' -o -name '*.env' \) ! -name '*.rpm' ! -name '*.deb' -exec shred -u {} + 2>/dev/null || true
    rm -rf "${WORK_DIR:?}/v4-install"
    echo "deleted $WORK_DIR/v4-install (the 4.x reinstall's credential files shredded, its copy of the package set deleted)"
  fi
  # E3 fold (E3-rpm 7): the 4.x package set kept for an offline way back (1.7 GB on RHEL 9) has no use once the host is
  # back on 4.x or the bundle is abandoned; it holds no secret, and leaving it made every later sweep read it (283 s)
  if [ -d "$BUNDLE_DIR/v4/offline" ]; then
    echo "deleted $BUNDLE_DIR/v4/offline (the 4.x package set kept for an offline way back, $(du -sh "$BUNDLE_DIR/v4/offline" | cut -f1); no secret in it)"
    rm -rf "${BUNDLE_DIR:?}/v4/offline"
  fi
  python3 "$HERE/bundle_secrets.py" sweep --bundle "$BUNDLE_DIR" --search "$WORK_DIR"
}
bk_retention() { # E3 fold (E3-deb N4): the reinstalled 4.x indexer has no ISM policy and the alerts came back as new
  # indices, so the site lost its retention and the next bundle's pre-copy read "none" and loaded 365 days. The policies
  # and each alert index's attachment, recorded at the pre-copy (ism-4x.json), are put back; a policy already there is kept
  export V4_INDEXER_ADMIN_PASSWORD; V4_INDEXER_ADMIN_PASSWORD=$(v4pw "$BUNDLE_DIR/v4/rollback/wazuh-install-files.tar" admin)
  python3 "$HELPER" ism-restore4 "$BUNDLE_DIR/ism-4x.json"
}
bk_secrets() { abandoned_secrets; echo "this bundle records a finished return and its secrets are deleted: to migrate again, use a new BUNDLE_DIR"; }
cmd_discard() { # E2-deb G11: the secret cleanup for a bundle that never reaches the finish and did not go back
  [ -d "$STATE" ] || die "no migration is recorded in $BUNDLE_DIR"
  if done_ replace.remove4x && ! done_ back.done && ! done_ phase.finish; then
    die "4.x was removed by this run and the host has not gone back: this bundle is the way back and the only copy of the 4.x data. Run '$0 back' (or finish the migration) instead"
  fi
  local p; p=$(pgrep -f 'migrate\.sh (run|back|agents|finish)' | tr '\n' ' ' || true)
  [ -z "$p" ] || die "a migrate.sh command is running (pid $p): stop it first"
  CUR=discard; log "=== DISCARD $BUNDLE_DIR BEGIN (host state $(host_state))"
  step discard.secrets "delete this abandoned bundle's secrets, then search for their values" abandoned_secrets
  mark discarded; jr discarded end
  if [ "$(host_state)" = v4 ] && ! systemctl is-active -q wazuh-manager 2>/dev/null; then
    log "    note: the 4.x manager is not running (the freeze stops it): 'systemctl enable --now wazuh-manager filebeat' if you are not migrating now"
  fi
  log "=== DISCARD END: $BUNDLE_DIR holds no secret any more and cannot be used to migrate; use a new BUNDLE_DIR"
}
cmd_back() {
  [ -d "$STATE" ] || die "no migration is recorded in $BUNDLE_DIR"
  done_ confirm.no_return && die "the point of no return was confirmed at $(cat "$STATE/confirm.no_return"): going back is not offered"
  done_ replace.remove4x || die "4.x was not removed by this tool: there is nothing to go back from (before phase 5, start the 4.x manager and Filebeat again)"
  [ ! -e "$STATE/discarded" ] || die "this bundle was discarded (its secrets are deleted): it cannot be used to go back"
  # once the agents are back (back.verify) the return reads nothing more from the bundle, and back.secrets deletes it
  done_ back.verify || back_manifest || die "the bundle does not match its manifest in a part the return reads: cannot go back from it"
  CUR=back; log "=== GOING BACK to 4.x from $BUNDLE_DIR BEGIN (host state $(host_state))"; local t0=$SECONDS
  jr back begin
  step back.stop5    "stop the 5.0 manager"                                           bk_stop5
  step back.remove5  "remove 5.0 with the 5.0 assistant (-u), then the tool's cleanup" bk_remove5
  step back.install4 "reinstall 4.14.x with the 4.x assistant"                        bk_install4
  step back.restore  "restore configuration, registry, security, alerts, dashboards"  bk_restore
  step back.verify   "agents reconnect with ids, keys and groups; compare with the truth" bk_verify
  step back.retention "the 4.x ISM policies and the alert indices' attachments put back (E3-deb N4)" bk_retention
  step back.secrets  "delete the bundle's secrets and the reinstall's credentials (E2-deb G11)" bk_secrets
  mark back.done; jr back end "$((SECONDS - t0)) s"
  log "=== GOING BACK END ($((SECONDS - t0)) s): this host runs 4.x again. Agent outage: $(cat "$STATE/T_back_begin") to $(cat "$STATE/T_back_agents")"
  log "    to migrate again, use a new BUNDLE_DIR (this one records a finished return; its secrets are deleted)."
}

########################################################################## main
if [ "$CMD" = __step ]; then   # internal: one step body, called by step() in a fresh process (errexit cannot be switched off by the caller)
  declare -F "${1:-}" >/dev/null || { echo "__step: no such step function '${1:-}'" >&2; exit 2; }
  trap - ERR; set -Eeuo pipefail; "$1"; exit 0
fi
case "$CMD" in run|status|confirm-no-return|agents|finish|back|discard|image-prepare|image-agent-back|guard|dashboards-rollback) ;; *) sed -n '2,16p' "$0"; exit 2;; esac
bundle_path_check
if [ "$CMD" = status ]; then
  echo "host state: $(host_state)"; [ -d "$STATE" ] || { echo "no run recorded in $BUNDLE_DIR"; exit 0; }
  for f in "$STATE"/*; do [ -e "$f" ] && echo "$(basename "$f") $(cat "$f")"; done; exit 0
fi
mkdir -p "$STATE" "$LOGS" "$RESULTS" "$WORK_DIR"; chmod 700 "$BUNDLE_DIR"
exec > >(tee -a "$LOGS/migrate.log") 2>&1
trap 'rc=$?; log "ERROR: line $LINENO exited $rc during ${CUR:-startup}; markers in $STATE and results in $RESULTS show what completed"; jr "${CUR:-startup}" error "line $LINENO exit $rc"; exit $rc' ERR
RUN_T0=$SECONDS
log "migrate.sh $CMD: host state $(host_state), bundle $BUNDLE_DIR, from=${FROM:-} only=${ONLY:-} through=${THROUGH:-}"
jr "command.$CMD" begin "host state $(host_state)"
[ "$CMD" = guard ] || guard_resume   # F5
case "$CMD" in
  confirm-no-return) cmd_confirm;;
  image-prepare) image_prepare;;
  image-agent-back) image_agent_back;;     # R2: after phase 7 on an image: its own agent enrolls again (new id)           # R2: on a new 5.0 image, before the 4.x freeze: the image's agent out, listeners closed
  guard) guard "${GUARD_ARG:-status}";;
  dashboards-rollback) # rule 20: reset only the attributes the dashboard step changed, where nobody changed them since
    python3 "$HELPER" rollback-saved-objects "$BUNDLE_DIR/dashboard/saved-objects-ledger.json";;
  agents) cmd_agents;;
  finish) cmd_finish;;
  back) cmd_back;;
  discard) cmd_discard;;
  run)
    [ ! -e "$STATE/back.done" ] || die "this bundle records a finished return to 4.x: use a new BUNDLE_DIR to migrate again"
    [ ! -e "$STATE/discarded" ] || die "this bundle was discarded (its secrets are deleted): use a new BUNDLE_DIR to migrate again"
    started=0; [ -z "$FROM" ] && started=1
    n=0
    for CUR in "${PHASES[@]}"; do
      n=$((n + 1))
      [ "$CUR" = "$FROM" ] && started=1
      [ "$started" = 1 ] || continue
      if [ -n "$ONLY" ] && [ "$ONLY" != "$CUR" ]; then continue; fi
      # F6: verify_bundle too: it must run again right before the removal, and its own early return covers "already removed"
      if done_ "phase.$CUR" && [ "$CUR" != assess ] && [ "$CUR" != verify ] && [ "$CUR" != verify_bundle ] && [ -z "$ONLY" ] && [ -z "$FROM" ]; then
        log "=== PHASE $n $CUR: already complete ($(cat "$STATE/phase.$CUR")), skipped"
      else
        log "=== PHASE $n $CUR BEGIN"; jr "phase.$CUR" begin
        t0=$SECONDS
        "phase_$CUR"
        if [ "$CUR" = verify ] && [ "${VERIFY_REPORT_ONLY:-0}" = 1 ]; then jr "phase.$CUR" report "$((SECONDS - t0)) s"   # E3 fold (N3): the pass's mark stays
        else mark "phase.$CUR"; jr "phase.$CUR" end "$((SECONDS - t0)) s"; fi
        log "=== PHASE $n $CUR END ($((SECONDS - t0)) s)"
      fi
      [ "$THROUGH" = "$CUR" ] && { log "stopped after phase $CUR as asked (--through)"; break; }
    done
    if done_ phase.verify && ! done_ confirm.no_return; then banner_phase9; fi;;
esac
log "migrate.sh $CMD finished in $((SECONDS - RUN_T0)) s; host state $(host_state)"
jr "command.$CMD" end "$((SECONDS - RUN_T0)) s"
