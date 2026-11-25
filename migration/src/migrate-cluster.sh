#!/usr/bin/env bash
# migrate-cluster.sh - the Wazuh 4.14.x -> 5.0 migration of a CLUSTER (indexer nodes, a master, workers, a dashboard) as
# one re-runnable command (CL1). It runs on a control host that reaches every node over SSH, reads an inventory
# (cluster/inventory.py says its format) and runs the same contract as migrate.sh, with the same state machinery
# (markers, journal, one result file per step, resume, --from/--only/--through), the same decisions files and the same
# stop messages. Every node action is a node step (cluster/node/*.sh) run detached on the node (cluster/node/run-step.sh),
# so a controller that dies does not kill a step half way, and each step decides from the node's real state.
#
#   ./migrate-cluster.sh --inventory FILE run [--from PHASE] [--only PHASE] [--through PHASE]   phases 1-8 and the history
#   ./migrate-cluster.sh --inventory FILE confirm-no-return     phase 9: the explicit confirmation
#   ./migrate-cluster.sh --inventory FILE agents                phase 10: upgrade the agents (needs phase 9); FLEET_ARGS
#                                                               passes options to the fleet step (--node-address NODE=ADDR)
#   ./migrate-cluster.sh --inventory FILE finish                phase 11: legacy ports, group files, raw off, history data, secrets
#   ./migrate-cluster.sh --inventory FILE back [master]         go back to 4.14.x: the whole cluster, or the master alone while
#                                                               every worker is still 4.x (offered until confirm-no-return)
#   ./migrate-cluster.sh --inventory FILE status
#   phases: assess precopy freeze verify_bundle indexers master import open workers verify history
#   (also: ./migrate.sh cluster --inventory FILE ...)
#
# The order is the design's order C: the managers keep serving while the indexers and the dashboard are replaced; the
# master goes first (a 5.0 worker cannot join a 4.x master), then each worker; the old alerts load after the openings.
set -Eeuo pipefail
SELF="$(readlink -f "$0")"; HERE="$(dirname "$SELF")"
INVENTORY="${INVENTORY:-}"; args=()
while [ $# -gt 0 ]; do case "$1" in --inventory) INVENTORY="${2:-}"; shift 2;; --inventory=*) INVENTORY="${1#*=}"; shift;; *) args+=("$1"); shift;; esac; done
set -- ${args[@]+"${args[@]}"}
CCMD="${1:-}"; [ $# -gt 0 ] && shift
if [ -z "$INVENTORY" ] || [ ! -f "$INVENTORY" ]; then sed -n '2,23p' "$SELF"; echo "usage: migrate-cluster.sh --inventory FILE <command> (no inventory${INVENTORY:+ at $INVENTORY})"; exit 2; fi
INVENTORY="$(readlink -f "$INVENTORY")"; export INVENTORY
invq() { local c=$1; shift; python3 "$HERE/cluster/inventory.py" "$c" "$INVENTORY" "$@"; }

# The inventory's settings, unless the environment sets the same name (migrate.sh's names). Read before migrate.sh's
# defaults are loaded, so its defaults apply only to what neither sets. Never a development-build address by default: WPK_REPO empty unless
# set (the fleet step then takes it from the 5.0 manifest the inventory names, or the manager's own default).
while IFS= read -r kv; do [ -n "$kv" ] || continue; k=${kv%%=*}; [ -n "${!k+x}" ] || eval "export $kv"; done < <(invq settings)
: "${WPK_REPO=}"; export WPK_REPO

# migrate.sh's functions (up to its dispatcher): the step machinery (step, mark, jr, result), log, mask_passwords. The
# controller's own state replaces the bundle's.
load_aio() { set --; eval "$(sed '/^if \[ "\$CMD" = __step \]; then/,$d' "$HERE/migrate.sh")"; }
_hp_given=${HISTORY_PROCS+x}
load_aio
# E5 fold: migrate.sh's default HISTORY_PROCS is half of THIS host's CPUs; the history is shaped on the master, which
# takes its own default (history5-master.sh) unless the inventory or the environment set one
[ -n "$_hp_given" ] || unset HISTORY_PROCS
SELF="$(readlink -f "$0")"; HERE="$(dirname "$SELF")"; HELPER="$HERE/mig_helper.py"
CST="$(invq get state_dir)"; MIG_HOME_N="$(invq get work_dir)"; BUNDLE_N="$(invq get bundle_dir)"
STATE="$CST/state"; LOGS="$CST/logs"; RESULTS="$CST/results"; JOURNAL="$CST/journal.ndjson"; DEC="$CST/decisions"
BUNDLE_DIR="$CST"   # migrate.sh's functions that name the bundle mean this controller's state here
CPHASES=(assess precopy freeze verify_bundle indexers master import open workers verify history)
FROM=""; ONLY=""; THROUGH=""
[ "$CCMD" = __step ] || while [ $# -gt 0 ]; do case "$1" in
  --from) FROM="$2"; shift;; --only) ONLY="$2"; shift;; --through) THROUGH="$2"; shift;;
  master) BACK_WHAT=master;;
  -h|--help) sed -n '2,23p' "$SELF"; exit 0;; *) echo "unknown option $1" >&2; exit 2;; esac; shift; done
BACK_WHAT="${BACK_WHAT:-cluster}"

# ------------------------------------------------------------------------------------------------ the nodes
declare -A ADDR SSHADDR ROLE SUSER SKEY SPORT
NODES=(); INDEXERS=(); WORKERS=(); MASTER=""; SETUP=""; DASH=""
while read -r n r a s u k p; do
  [ -n "$n" ] || continue; NODES+=("$n"); ROLE[$n]=$r; ADDR[$n]=$a; SSHADDR[$n]=$s; SUSER[$n]=$u; SKEY[$n]=$k; SPORT[$n]=$p
  case "$r" in indexer) INDEXERS+=("$n");; master) MASTER=$n;; worker) WORKERS+=("$n");; dashboard) DASH=$n;; esac
done < <(invq nodes)
SETUP="$(invq nodes setup | awk '$2=="indexer"{print $1; exit}')"
MANAGERS=(${MASTER:+"$MASTER"} ${WORKERS[@]+"${WORKERS[@]}"})
BUNDLE_NODES=(${MANAGERS[@]+"${MANAGERS[@]}"} ${SETUP:+"$SETUP"})   # the nodes whose bundle holds something
I4="https://${ADDR[$SETUP]:-unset}:9200"; I5="$I4"                    # one indexer node; the same address on 4.x and 5.0
DASH_URL="${DASH:+https://${ADDR[$DASH]}:443}"

# ------------------------------------------------------------------------------------------------ SSH
SSH_USER="$(invq get ssh.user)"; SSH_KEY="$(invq get ssh.key)"   # the inventory's; a node may name its own (SUSER, SKEY, SPORT)
mapfile -t SSH_XOPTS < <(python3 -c 'import json,sys; [print(x) for x in json.loads(sys.argv[1] or "[]")]' "$(invq get ssh.options)")
MIG_SSH="${MIG_SSH:-ssh}"   # the SSH client; a test or a site wrapper may name another one taking the same arguments
SUDO="sudo -n"; [ "$SSH_USER" = root ] && SUDO=""   # every node's user must be root, or none (sudo without a password)
rsh() { local n=$1; shift
  "$MIG_SSH" -i "${SKEY[$n]}" -p "${SPORT[$n]}" -o BatchMode=yes -o ConnectTimeout=20 -o ServerAliveInterval=30 ${SSH_XOPTS[@]+"${SSH_XOPTS[@]}"} "${SUSER[$n]}@${SSHADDR[$n]}" "$@"; }
q() { printf '%q' "$1"; }
NODE_ENV_NAMES=(HISTORY_RETENTION HISTORY_ARCHIVES ACCEPT_ROLE_LOSS IDENTITY_LIMIT_MODE CARRY_SETTINGS CARRY_INDEXER_SECURITY CARRY_SAVED_OBJECTS
                UNCLASSIFIED_DECISION FEED_WAIT_MAX NEVER_CONNECTED_AT_FINISH WPK_REPO RMIG_ENGINE_HELPERS RMIG_SAMPLES RMIG_ACTIVATE_ARGS
                HISTORY_PROCS AGENT_ADDRESSES AGENT_WAIT_SECS LISTENER_HOST)
nenv() { # the environment of every node step: the inventory's paths, the cluster's facts, the settings
  local v m a=(); for m in "${MANAGERS[@]}"; do a+=("${ADDR[$m]}"); done
  printf 'BUNDLE_DIR=%q MIG_HOME=%q IDX5_HOST=%q CLUSTER_NODES=%q CLUSTER_ADDRESSES=%q ' "$BUNDLE_N" "$MIG_HOME_N" "${ADDR[$SETUP]:-}" "$(IFS=,; echo "${MANAGERS[*]}")" "$(IFS=,; echo "${a[*]}")"
  for v in "${NODE_ENV_NAMES[@]}"; do [ -z "${!v+x}" ] || printf '%s=%q ' "$v" "${!v}"; done; }
nstep() { # nstep <node> [VAR=val ...] <step> [args...]: one node step, run detached on the node by run-step.sh and
  # followed; the output prefixed with the node's name and kept, masked, in $LOGS/<node>/<id>.log; the step's exit code
  local n=$1 extra="" a cmd rc id s; shift
  while [[ "${1:-}" == *=* ]]; do extra+="$(q "$1") "; shift; done
  s=$1; shift; id="${CUR_STEP:-adhoc}.${s%.sh}"; for a in "$@"; do [[ "$a" == *://* ]] || { id+=".${a:0:24}"; break; }; done; id=${id//[^A-Za-z0-9_.-]/_}
  cmd="$SUDO env $(nenv)${extra}bash $(q "$MIG_HOME_N/src/cluster/node/run-step.sh") $(q "$id") $(q "$s")"
  for a in "$@"; do cmd+=" $(q "$a")"; done
  mkdir -p "$LOGS/$n"; rc=0
  rsh "$n" "$cmd" < /dev/null 2>&1 | mask_passwords | tee -a "$LOGS/$n/$id.log" | sed -u "s/^/  [$n] /" || rc=${PIPESTATUS[0]}
  return "$rc"; }
npar() { # npar "<node> <step> [args]"...: node steps in parallel, each on its own node; every one must exit 0
  local x i rc=0 pids=() what=()
  for x in "$@"; do ( set -f; nstep $x ) & pids+=($!); what+=("$x"); done
  for i in "${!pids[@]}"; do wait "${pids[$i]}" || { rc=1; echo "FAILED: ${what[$i]}"; }; done
  return "$rc"; }
put() { # put <node> <controller-file> <node-path>: mode 600, whole or absent
  rsh "$1" "$SUDO sh -c $(q "umask 077; mkdir -p \"\$(dirname '$3')\" && cat > '$3.part' && mv -f '$3.part' '$3'")" < "$2"; }
fetch_on() { # fetch_on <node> <url> <node-path>: the node downloads an input itself
  rsh "$1" "$SUDO sh -c $(q "umask 077; mkdir -p \"\$(dirname '$3')\" && curl -fsSL --retry 3 -o '$3.part' '$2' && mv -f '$3.part' '$3'")" < /dev/null; }
putdir() { # putdir <node> <controller-dir> <node-dir>: replaced whole
  tar -C "$2" -czf - --exclude=__pycache__ . | rsh "$1" "$SUDO sh -c $(q "rm -rf '$3.part' && mkdir -p '$3.part' && tar -xzf - -C '$3.part' && rm -rf '$3' && mv '$3.part' '$3'")"; }
xfer() { # xfer <src-node> <src-path> <dst-path> <dst-node...>: host to host through this controller's memory only (E3-cluster
  # fix 00: the 5.0 install files hold every 5.0 password and the CA key; no file on the controller ever holds them)
  local s=$1 sp=$2 dp=$3 r rc=0; shift 3
  for r in "$@"; do
    rsh "$s" "$SUDO cat $(q "$sp")" < /dev/null | rsh "$r" "$SUDO sh -c $(q "umask 077; mkdir -p \"\$(dirname '$dp')\" && cat > '$dp.part' && mv -f '$dp.part' '$dp' && echo \"$r $dp \$(sha256sum '$dp' | cut -c1-12)\"")" || { rc=1; echo "FAILED: $sp from $s to $r"; }
  done; return "$rc"; }
nget() { rsh "$1" "$SUDO cat $(q "$2")" < /dev/null; }   # nget <node> <path>: a file that holds no secret, to stdout
dec_push() { local f="$DEC/$1.json"; [ -s "$f" ] || return 0; put "$1" "$f" "$BUNDLE_N/decisions.json"; }
dec_pull() { # the node's decisions file comes back to $DEC/<node>.json, the file the user answers
  local t; mkdir -p "$DEC"; chmod 700 "$DEC"; t=$(mktemp "$DEC/.$1.XXXXXX")
  if nget "$1" "$BUNDLE_N/decisions.json" > "$t" 2>/dev/null && [ -s "$t" ]; then chmod 600 "$t"; mv -f "$t" "$DEC/$1.json"; else rm -f "$t"; fi; }
asked() { # asked <node> <rc>: exit 3 of a planning step means open questions: say which file to answer
  [ "$2" = 3 ] && echo "the run stops here: answer the open entries (\"action\": null) in $DEC/$1.json (node $1) and run again"
  return "$2"; }
nstep_dec() { local n=$1 rc=0; dec_push "$n"; nstep "$@" || rc=$?; dec_pull "$n"; asked "$n" "$rc"; }

# ------------------------------------------------------------------------------------------------ 1. ASSESS (read-only on 4.x)
a_inventory() { local p; if p=$(invq check); then ok "inventory: ${#NODES[@]} node(s): master $MASTER, worker(s) ${WORKERS[*]:-none}, indexer(s) ${INDEXERS[*]} (setup $SETUP), dashboard ${DASH:-none}"
  else while IFS= read -r l; do bad "$l"; done <<<"$p"; fi; }
a_reach() { local n; for n in "${NODES[@]}"; do
  if rsh "$n" "$SUDO true" < /dev/null >/dev/null 2>&1; then ok "node $n (${ROLE[$n]}, ${SSHADDR[$n]}): reachable over SSH as ${SUSER[$n]}${SUDO:+ with sudo}"
  else bad "node $n (${ROLE[$n]}, ${SSHADDR[$n]}): not reachable over SSH as ${SUSER[$n]} (key ${SKEY[$n]})${SUDO:+, or sudo asks for a password}"; fi; done; }
# E5 fold (E5-cluster-deb gap 7): one fingerprint form. The tree's paths as "src/<path>" in C-locale order, which is the
# LC_ALL=C form SRC-FINGERPRINT.txt records for the tool (before: "./<path>", a third value that matched neither)
FP_CMD='find . -type f ! -path "*/__pycache__/*" -print0 | LC_ALL=C sort -z | xargs -0 sha256sum | sed "s#  \./#  src/#" | sha256sum | cut -c1-16'
src_fp() { ( cd "$1" && eval "$FP_CMD" ); }
a_push() { # the tool's src/ tree, whole, on every node (it changes nothing of Wazuh)
  local n f want; want=$(src_fp "$HERE")
  for n in "${NODES[@]}"; do
    putdir "$n" "$HERE" "$MIG_HOME_N/src" || { bad "node $n: the tool could not be copied to $MIG_HOME_N/src"; continue; }
    f=$(rsh "$n" "cd $(q "$MIG_HOME_N/src") && $SUDO sh -c '$FP_CMD'" < /dev/null 2>/dev/null || true)
    [ "$f" = "$want" ] && ok "node $n: the tool is in $MIG_HOME_N/src ($want)" || bad "node $n: the tool copied to $MIG_HOME_N/src reads ${f:-nothing}, not $want"
  done; }
a_moved() { # a_moved <node>: the marker of the step that removed 4.x on this node in this run, when it is done
  local m; case "${ROLE[$1]}" in indexer|dashboard) m=indexers.remove4x;; master) m=master.remove4x;; worker) m=workers.$1.remove4x;; *) return 1;; esac
  done_ "$m" && echo "$m"; }
a_source() { # OF1 item 12: only the latest 4.14.x, every node, and every manager node connected to the master
  # E5 fold (E5-cluster-rpm 03 = E5-cluster-deb 03): assess runs again on every 'run'; a node this run already moved to
  # 5.0 is no 4.14 source any more, and refusing it stopped every 'run' after phase 5 ("nothing was changed", untrue).
  # Such a node is skipped by name; every node still on 4.x is checked as before. (The deb run skipped the source and
  # facts checks on every node once any removal was done, which leaves a worker changed since unchecked.)
  local n m
  for n in "${NODES[@]}"; do
    if m=$(a_moved "$n"); then ok "node $n: 4.x already removed by this run ($m at $(cat "$STATE/$m")): its source version was checked before"; continue; fi
    CUR_STEP=assess.source nstep "$n" source-version.sh > /dev/null && ok "node $n: 4.x is the latest 4.14.x" || bad "node $n: SOURCE VERSION REFUSED (see $LOGS/$n/assess.source.source-version.log)"; done
  if done_ master.freeze; then ok "the master's 4.x was frozen by this run ($(cat "$STATE/master.freeze")): the cluster view was checked before"; return 0; fi
  # E5 fold (E5-cluster-deb 02 = E5-cluster-rpm 02): the master's cluster check logs in to the 4.x Server API with the
  # password in the 4.x install files, which only the pre-copy staged: on a first run the login failed (HTTP 401) and
  # assess refused with "not the latest 4.14.x". They are staged on the master (host to host, as the pre-copy does) first
  in_put "$MASTER" v4_install_files "$MIG_HOME_N/v4/wazuh-install-files.tar" || { bad "the 4.x install files could not be staged on the master $MASTER (inputs.v4_install_files) for its cluster check"; return 0; }
  CUR_STEP=assess.cluster nstep "$MASTER" source-version.sh cluster > /dev/null && ok "the master sees every manager node of the inventory connected, at the latest 4.14.x" \
    || bad "the master's view of the cluster refused (see $LOGS/$MASTER/assess.cluster.source-version.cluster.log)"; }
a_facts() { local n out; for n in "${NODES[@]}"; do
  if out=$(CUR_STEP=assess.facts nstep "$n" node-facts.sh "${ROLE[$n]}" 2>&1); then
    while IFS= read -r l; do case "$l" in *facts:*) log "  info  ${l#*] }";; *WARN*) warn "${l#*] }";; esac; done <<<"$out"
  else bad "node $n: $( { grep -E 'FATAL|BLOCKER' <<<"$out" || echo "node-facts.sh failed"; } | head -n 3 | tr '\n' ' ')"; fi; done; }
phase_assess() {
  FAILS=0; WARNS=0
  a_inventory; [ "$FAILS" = 0 ] || die "assess failed: the inventory must be fixed first; nothing was changed on any node"
  a_reach;     [ "$FAILS" = 0 ] || die "assess failed: nothing was changed on any node"
  a_push; a_source; a_facts
  log "  assess: $FAILS blocker(s), $WARNS warning(s)"
  [ "$FAILS" = 0 ] || die "assess failed: nothing was changed on any node (the tool's copy in $MIG_HOME_N/src aside)"
}

# ------------------------------------------------------------------------------------------------ 2. PRE-COPY (4.x live)
in_put() { # in_put <node> <input-name> <node-path>
  local v; v=$(invq get "inputs.$2"); [ -n "$v" ] || return 0
  if [[ "$v" =~ ^https?:// ]]; then fetch_on "$1" "$v" "$3"
  elif [[ "$v" == node:* ]]; then local s=${v#node:}; s=${s%%:*}; [ "$s" = "$1" ] && [ "${v#node:$s:}" = "$3" ] || xfer "$s" "${v#node:$s:}" "$3" "$1" > /dev/null
  elif [ -d "$v" ]; then putdir "$1" "$v" "$3"; else put "$1" "$v" "$3"; fi; }
pc_stage_inputs() { # every node gets what its steps read, under the inventory's work_dir; the install files go only from
  # the controller's own copy (the user's file), never through another file here
  local n W="$MIG_HOME_N"
  for n in "${NODES[@]}"; do
    in_put "$n" v4_assistant "$W/v4/wazuh-install.sh"; in_put "$n" v4_install_files "$W/v4/wazuh-install-files.tar"
    in_put "$n" v5_assistant "$W/v5/wazuh-install.sh"; in_put "$n" v5_artifact_urls "$W/v5/artifact_urls.yaml"
    echo "$n: 4.x and 5.0 assistants and the 4.x install files staged in $W"
  done
  in_put "$SETUP" v5_config "$W/v5/config.yml"; echo "$SETUP: the 5.0 config.yml staged (it runs -g)"
  for n in "${MANAGERS[@]}"; do in_put "$n" identity_tool "$W/tools/wazuh-migrate-identity.py"; done
  in_put "$MASTER" ruleset_tool "$W/tools/ruleset-migration"; echo "the identity tool on every manager, the ruleset tool on the master"
}
pc_retention() { nstep "$MASTER" retention-4x.sh read "$I4"; }
pc_history() { nstep "$MASTER" history-dump.sh "$I4"; }
pc_indexer_security() { [ "$CARRY_INDEXER_SECURITY" = 1 ] || { echo "CARRY_INDEXER_SECURITY=0"; return 0; }; nstep "$SETUP" indexer-security.sh export; }
pc_saved_objects() { [ "$CARRY_SAVED_OBJECTS" = 1 ] && [ -n "$DASH" ] || { echo "no dashboard node, or CARRY_SAVED_OBJECTS=0: no saved objects"; return 0; }; nstep "$MASTER" dashboard-objects.sh export "$DASH_URL"; }
pc_settings() { # every manager: its settings files, then the conversion planned against the 5.0 files this build installs;
  # every open question lands in that node's decisions file, asked while 4.x still serves (as the all-in-one's pre-copy)
  local n rc=0; for n in "${MANAGERS[@]}"; do nstep "$n" settings-node.sh collect4 || return 1; nstep_dec "$n" settings-node.sh plan-precopy "$n" "${ROLE[$n]}" "${ADDR[$MASTER]}" || rc=$?; done; return "$rc"; }
pc_ruleset() { nstep_dec "$MASTER" ruleset-node.sh precopy; }
pc_fleet() { # the 4.x fleet facts and the certificate plan: names agents dial that no node certificate would carry (-as)
  nstep "$MASTER" fleet-facts.sh || return 1
  nget "$MASTER" "$BUNDLE_N/preflight/agent-san-extra.txt" > "$STATE/agent-san-extra.txt" 2>/dev/null || : > "$STATE/agent-san-extra.txt"
  echo "certificate plan: names to add with -as at the 5.0 -g: $(tr '\n' ' ' < "$STATE/agent-san-extra.txt")"; }
pc_gate() { nstep "$MASTER" bundle-check.sh precopy; [ "$CARRY_INDEXER_SECURITY" = 1 ] || return 0; nstep "$SETUP" bundle-check.sh manifest; }
phase_precopy() {
  step precopy.stage            "stage the inputs on every node (work_dir)"                         pc_stage_inputs
  step precopy.retention        "history: the 4.x retention (ISM delete policies; decision 5b)"     pc_retention
  step precopy.history          "history: dump the alerts while 4.x is live, through one indexer node" pc_history
  step precopy.indexer_security "indexer security configuration (REST, backup, indexer stage)"     pc_indexer_security
  step precopy.saved_objects    "dashboard saved objects"                                           pc_saved_objects
  step precopy.settings         "settings: every manager's files and the planned conversion (C4)"   pc_settings
  step precopy.ruleset          "ruleset: copy, scan, plan and build offline on the master"         pc_ruleset
  step precopy.fleet            "fleet facts and the certificate plan"                              pc_fleet
  step precopy.gate             "gate: the master's history dump and the setup node's bundle"       pc_gate
}

# ------------------------------------------------------------------------------------------------ 3. FREEZE (of the 4.x indexer tier; agents still served)
fz_filebeat() { local n x=(); for n in "${MANAGERS[@]}"; do x+=("$n filebeat-stop.sh"); done; npar "${x[@]}"; }
fz_delta() { nstep "$MASTER" history-dump.sh "$I4"; }
phase_freeze() {
  step freeze.filebeat      "Filebeat drained and stopped on every manager; the managers keep serving" fz_filebeat
  step freeze.history_delta "history: the delta dump (nothing is written to the 4.x indexers any more)" fz_delta
}

# ------------------------------------------------------------------------------------------------ 4. VERIFY BUNDLE
vb_history() { nstep "$MASTER" bundle-check.sh history; }
vb_setup() { [ "$CARRY_INDEXER_SECURITY" = 1 ] || return 0; nstep "$SETUP" bundle-check.sh manifest; }
phase_verify_bundle() {   # runs again on every run: it must hold right before the indexers are removed
  rm -f "$STATE/verify_bundle.history" "$STATE/verify_bundle.setup"
  step verify_bundle.history "the master's history dump: every index complete, every file equal to its checksum" vb_history
  step verify_bundle.setup   "the setup node's bundle (indexer security) equal to its manifest"                  vb_setup
}

# ------------------------------------------------------------------------------------------------ 5. INDEXERS (no agent outage)
ix_remove() { local n x=(); for n in "${INDEXERS[@]}" ${DASH:+"$DASH"}; do x+=("$n remove4x.sh"); done; npar "${x[@]}"; }
ix_generate() { local a=() l; while IFS= read -r l; do [ -n "$l" ] && a+=(-as "$l"); done < "$STATE/agent-san-extra.txt" 2>/dev/null || true
  nstep "$SETUP" install5.sh -g ${a[@]+"${a[@]}"}; }
ix_files() { local n o=(); for n in "${NODES[@]}"; do [ "$n" = "$SETUP" ] || o+=("$n"); done
  [ ${#o[@]} = 0 ] || xfer "$SETUP" "$MIG_HOME_N/v5/wazuh-install-files.tar" "$MIG_HOME_N/v5/wazuh-install-files.tar" "${o[@]}"; }
ix_install() { local n x=(); for n in "${INDEXERS[@]}"; do x+=("$n install5.sh -wi $n"); done; npar "${x[@]}"; }
ix_start() { nstep "$SETUP" install5.sh -s; }
ix_security() { [ "$CARRY_INDEXER_SECURITY" = 1 ] || return 0; nstep "$SETUP" indexer-security.sh import; }
ix_dashboard() { [ -n "$DASH" ] || { echo "no dashboard node"; return 0; }; nstep "$DASH" install5.sh -wd "$DASH"; }
phase_indexers() {
  step indexers.remove4x  "remove 4.x on every indexer node and the dashboard (the managers keep serving)" ix_remove
  step indexers.generate  "the 5.0 configuration and certificates, once, on the setup node (-g)"         ix_generate
  step indexers.files     "the 5.0 install files from the setup node to every node, host to host"        ix_files
  step indexers.install   "5.0 on every indexer node (-wi), in parallel"                                 ix_install
  step indexers.start     "start the 5.0 indexer cluster, once (-s)"                                     ix_start
  step indexers.security  "the indexer users, roles and mappings into 5.0"                              ix_security
  step indexers.dashboard "5.0 on the dashboard node (-wd)"                                              ix_dashboard
}

# ------------------------------------------------------------------------------------------------ 6. MASTER (its agents' outage starts)
mgr_guard() { nstep "$1" guard.sh on agent; }   # rule 5 (guide point b): from before the 4.x removal to the node's opening
mgr_freeze() { nstep "$1" NO_DRAIN=1 freeze-manager.sh; }
mgr_export() { nstep "$1" export-manager.sh "$2"; }
mgr_remove() { nstep "$1" remove4x.sh; }
mgr_install() { nstep "$1" install5.sh -wm "$1"; }
mgr_check() { nstep "$1" check5-manager.sh; }
ma_guard() { mgr_guard "$MASTER"; }; ma_freeze() { mgr_freeze "$MASTER"; }; ma_export() { mgr_export "$MASTER" master; }
ma_remove() { mgr_remove "$MASTER"; }; ma_check() { mgr_check "$MASTER"; }
ma_install() { mgr_install "$MASTER" && return 0
  # E5 fold (E5-cluster-deb gap 12): the stop named the result file but not the way out
  if [ ${#WORKERS[@]} -gt 0 ]; then echo "the master's 5.0 install failed; its workers still serve their agents on 4.x. To return the master alone to 4.x: '$0 --inventory $INVENTORY back master'; or fix the cause and run '$0 --inventory $INVENTORY run' again"
  else echo "the master's 5.0 install failed. To return the cluster to 4.x: '$0 --inventory $INVENTORY back'; or fix the cause and run '$0 --inventory $INVENTORY run' again"; fi
  return 1; }
phase_master() {
  [ -z "$(ls "$STATE"/back.* 2>/dev/null)" ] || die "this cluster went back to 4.x (markers back.* in $STATE): use a new state_dir and bundle_dir to migrate again"
  step master.guard    "the agent guard on the master (1514, 1515, 1517 refused but to loopback)"   ma_guard
  step master.freeze   "freeze the master: its agents' outage starts (the workers keep serving theirs)" ma_freeze
  step master.export   "the master's export: identity, configuration, settings, what going back needs" ma_export
  step master.remove4x "remove 4.x on the master (refused without a verified export)"              ma_remove
  step master.install5 "5.0 on the master (-wm), listeners closed"                                ma_install
  step master.check    "the master's 5.0 install: cluster, listeners, certificate names"           ma_check
}

# ------------------------------------------------------------------------------------------------ 7. IMPORT (the master)
im_c_plan() { [ "$CARRY_SETTINGS" = 1 ] || return 0; nstep_dec "$MASTER" settings-node.sh plan-installed; }
im_c_identity() { nstep "$MASTER" identity-stage-master.sh; }
im_c_groups() { nstep "$MASTER" settings-node.sh groups-pre; }
im_c_ruleset() { nstep_dec "$MASTER" ruleset-node.sh import; }
im_c_roles() { nstep "$MASTER" history5-master.sh "$I5" audit-roles $( [ "$ACCEPT_ROLE_LOSS" = 1 ] && echo --accept-role-loss ); }
phase_import() {
  step import.settings_plan "settings: the plan against the installed 5.0 files (a new question stops here)" im_c_plan
  step import.identity "identity stage, the master's settings staged (cross-node check), one restart, passwords, verify" im_c_identity
  step import.groups_pre "group files: the pre-upgrade pass (C4), carried files installed"         im_c_groups
  step import.ruleset   "ruleset: apply to the test space and verify with the 4.x alerts"           im_c_ruleset
  step import.history_roles "history: role audit (the aliases go on in the history phase)"          im_c_roles
}

# ------------------------------------------------------------------------------------------------ 8. OPEN (the master)
op_c_decision() { nstep_dec "$MASTER" ruleset-node.sh decision; }
op_c_fold() { nstep "$MASTER" fold-alertsjson.sh "$MASTER"; }
op_c_open() { nstep "$MASTER" open-node.sh; }
phase_open() {
  step open.decision  "the decision on events 5.0 cannot classify (decision 3 default: verified+raw)" op_c_decision
  step open.fold      "the master's alerts.json past Filebeat's offset into the history bundle (shaped with the rest)" op_c_fold
  step open.listeners "decision in force, firewall, guard off, listeners open (THE MASTER'S OUTAGE ENDS)" op_c_open
}

# ------------------------------------------------------------------------------------------------ 9. WORKERS (one after another)
wk_guard() { mgr_guard "$W"; }; wk_freeze() { mgr_freeze "$W"; }; wk_export() { mgr_export "$W" worker; }
wk_remove() { mgr_remove "$W"; }; wk_install() { mgr_install "$W"; }; wk_check() { mgr_check "$W"; }
regsum() { nget "$1" /etc/wazuh-manager/client.keys 2>/dev/null | sha256sum | cut -c1-16; }
wk_registry() { # the worker's registry must equal the master's before anything opens on it
  local i a b; for i in $(seq 1 "${REGISTRY_TRIES:-60}"); do a=$(regsum "$MASTER"); b=$(regsum "$W"); [ "$a" = "$b" ] && [ "$a" != "$(printf '' | sha256sum | cut -c1-16)" ] && { echo "registry of $W equals the master's ($a)"; return 0; }; sleep "${REGISTRY_WAIT:-5}"; done
  echo "the registry of $W ($b) does not equal the master's ($a) after the wait: not opening it"; return 1; }
wk_settings() { # converted against the worker's installed base, checked against every node already on 5.0 (their live
  # wazuh-manager.conf, streamed host to host), staged, checked, and restarted while the worker is still closed
  [ "$CARRY_SETTINGS" = 1 ] || return 0
  local p; for p in "$MASTER" ${WORKERS[@]+"${WORKERS[@]}"}; do
    [ "$p" = "$W" ] && break
    xfer "$p" /etc/wazuh-manager/wazuh-manager.conf "$BUNDLE_N/settings/peers/$p/wazuh-manager.conf" "$W" || return 1
  done
  nstep_dec "$W" settings-node.sh plan-installed || return $?
  nstep "$W" settings-node.sh apply-worker; }
wk_decision() { # the master's decision and its time, so the worker waits for it in force before it opens
  local f; for f in unclassified.applied T_decision_logtime; do xfer "$MASTER" "$BUNDLE_N/state/$f" "$BUNDLE_N/state/$f" "$W" > /dev/null 2>&1 || echo "no $f on the master (no decision applied)"; done; }
wk_fold() { # the worker's alerts.json past Filebeat's offset: into the master's history bundle, loaded and shaped with it
  nstep "$W" fold-alertsjson.sh "$W" || return 1
  xfer "$W" "$BUNDLE_N/history-fold/fold-$W.tar" "$BUNDLE_N/history-fold/in/fold-$W.tar" "$MASTER" || return 1
  nstep "$MASTER" fold-alertsjson.sh --merge "$BUNDLE_N/history-fold/in/fold-$W.tar"; }
wk_open() { nstep "$W" open-node.sh; }
phase_workers() {
  local w; for w in ${WORKERS[@]+"${WORKERS[@]}"}; do
    export W=$w
    step "workers.$w.guard"    "$w: the agent guard on"                                    wk_guard
    step "workers.$w.freeze"   "$w: freeze (this worker's agents' outage starts)"           wk_freeze
    step "workers.$w.export"   "$w: export"                                                 wk_export
    step "workers.$w.remove4x" "$w: remove 4.x"                                             wk_remove
    step "workers.$w.install5" "$w: 5.0 (-wm), listeners closed"                            wk_install
    step "workers.$w.registry" "$w: gate: its registry equals the master's"                 wk_registry
    step "workers.$w.check"    "$w: the 5.0 install"                                        wk_check
    step "workers.$w.settings" "$w: settings: plan, convert, cross-node check, stage, restart (closed)" wk_settings
    step "workers.$w.decision" "$w: the unclassified-events decision the master applied"    wk_decision
    step "workers.$w.fold"     "$w: its alerts.json past Filebeat's offset into the history bundle" wk_fold
    step "workers.$w.open"     "$w: decision in force, firewall, guard off, listeners open (ITS OUTAGE ENDS)" wk_open
  done; }

# ------------------------------------------------------------------------------------------------ 10. VERIFY
phase_verify() {
  local n a b ref="" bad=0
  for n in "${MANAGERS[@]}"; do CUR_STEP=verify.check nstep "$n" check5-manager.sh | grep -E 'package|listening|client.keys' || true; done
  ref=$(regsum "$MASTER"); for n in "${WORKERS[@]+"${WORKERS[@]}"}"; do [ -n "$n" ] || continue; b=$(regsum "$n"); [ "$b" = "$ref" ] && log "  PASS  $n registry equals the master's ($ref)" || { log "  FAIL  $n registry $b, the master's $ref"; bad=1; }; done
  CUR_STEP=verify.identity nstep "$MASTER" identity-verify.sh || bad=1
  [ "$bad" = 0 ] || die "the cluster differs from the bundle: see above"
  log "  verify: the master's registry equals the identity bundle and every worker holds the same registry"
}

# ------------------------------------------------------------------------------------------------ 11. HISTORY (after the openings)
hi_apply() { nstep "$MASTER" history5-master.sh "$I5" apply; }
hi_prove() { nstep "$MASTER" history5-master.sh "$I5" prove; }
hi_on() { nstep "$MASTER" history5-master.sh "$I5" on $( [ "$ACCEPT_ROLE_LOSS" = 1 ] && echo --accept-role-loss ); }
hi_dash() { [ "$CARRY_SAVED_OBJECTS" = 1 ] && [ -n "$DASH" ] || { echo "no dashboard node, or CARRY_SAVED_OBJECTS=0"; return 0; }; nstep "$MASTER" dashboard-objects.sh import5 "$DASH_URL" "${ADDR[$SETUP]}"; }
phase_history() {
  step history.apply      "history: load every dump and every fold through the shaping (agents are served meanwhile)" hi_apply
  step history.prove      "history: proof per source index"                                     hi_prove
  step history.on         "history: role audit again, then the aliases on"                      hi_on
  step history.dashboards "the custom dashboards as a view of the history"                      hi_dash
}
cbanner_phase9() {
  log "=== PHASE 9: POINT OF NO RETURN. Stopped here on purpose."
  log "    5.0 serves the agents of every manager as 4.x agents. Until you confirm, '$0 --inventory $INVENTORY back' returns the"
  log "    whole cluster to 4.14.x from the bundles; after the confirmation going back is refused (decision 11)."
  log "    To go on: '$0 --inventory $INVENTORY confirm-no-return', then 'agents' and 'finish'."
}

# ------------------------------------------------------------------------------------------------ confirm, agents, finish
cmd_c_confirm() {
  done_ phase.verify || die "phases 1 to 8 are not complete: nothing to confirm"
  [ -z "$(ls "$STATE"/back.* 2>/dev/null)" ] || die "this cluster went back to 4.x"
  mark confirm.no_return; jr confirm.no_return end "explicit confirmation"
  log "POINT OF NO RETURN confirmed at $(cat "$STATE/confirm.no_return"). Going back to 4.x from the bundles is no longer offered: an upgraded agent cannot return to a 4.x manager."
  done_ phase.history || log "    the old alerts are not switched on yet: run '$0 --inventory $INVENTORY run' to complete the history phase (the finish waits for it)"; }
ag_c() { nstep "$MASTER" agents-node.sh "$@"; }
ag_c_pre() { ag_c preflight ${FLEET_ARGS:-}; }; ag_c_run() { ag_c run ${FLEET_ARGS:-}; }; ag_c_trust() { ag_c trust; }
ag_c_feed() { # rule 14: every manager of the cluster, before the gate (E4-cluster gap 3)
  local n x=(); for n in "${MANAGERS[@]}"; do x+=("$n feed-node.sh"); done; npar "${x[@]}"; }
ag_c_gate() { ag_c gate; }
cmd_c_agents() {
  done_ confirm.no_return || die "the point of no return is not confirmed: run '$0 --inventory $INVENTORY confirm-no-return' first"
  CUR=agents; log "=== PHASE 10 agents BEGIN"; local t0=$SECONDS
  rm -f "$STATE/agents.preflight" "$STATE/agents.run" "$STATE/agents.trust" "$STATE/agents.feed" "$STATE/agents.gate"   # every call asks again for the late agents
  step agents.preflight "agents: preflight (read-only; certificate names per node)"        ag_c_pre
  step agents.run       "agents: upgrade in waves, verdicts from evidence"                  ag_c_run
  step agents.trust     "agents: trust audit from the indexer"                              ag_c_trust
  step agents.feed      "agents: the vulnerability feed's initial load on every manager (rule 14)" ag_c_feed
  step agents.gate      "gate: a verdict from evidence for every agent"                     ag_c_gate
  mark phase.agents; log "=== PHASE 10 agents END ($((SECONDS - t0)) s)"; }
fi_c_legacy() {
  # E5 fold (E5-cluster-rpm gap 5, E5-cluster-deb gap 10): closed once on every manager is closed; a later finish (after
  # the raw-at-finish answer) restarted every manager again for nothing
  if done_ legacy.closed; then rm -f "$STATE/legacy.open"; echo "the legacy ports were closed on every manager at $(cat "$STATE/legacy.closed"): not closed again"; return 0; fi
  local rc=0 n; nstep "$MASTER" finish-node.sh legacy-decide || rc=$?
  case "$rc" in
    0) for n in "${MANAGERS[@]}"; do nstep "$n" finish-node.sh legacy-close decided || return 1; done; rm -f "$STATE/legacy.open"; mark legacy.closed;;
    3) echo "legacy ports kept open on every node (see the master's legacy-status above)" > "$STATE/legacy.open"; cat "$STATE/legacy.open";;
    *) return "$rc";;
  esac; }
fi_c_raw() { nstep_dec "$MASTER" finish-node.sh raw-off; }   # decision 3 follow-up: may ask (exit 3)
fi_c_groups() { nstep "$MASTER" finish-node.sh groups-post; }
fi_c_hdata() { nstep "$MASTER" finish-node.sh history-data "$I5"; }
fi_c_secrets() { local n; for n in "${BUNDLE_NODES[@]}"; do nstep "$n" finish-node.sh secrets || return 1; done; }
cmd_c_finish() {
  done_ phase.agents || die "the agents phase is not complete"
  done_ history.on || die "the history is not loaded, proven and switched on yet: finish would delete its only copy (history/data). Run '$0 --inventory $INVENTORY run' to complete the history phase first"
  CUR=finish; log "=== PHASE 11 finish BEGIN"; local t0=$SECONDS
  rm -f "$STATE/finish.legacy" "$STATE/finish.raw_off" "$STATE/finish.groups_post"
  step finish.legacy      "close the legacy ports on every manager (only when no agent below 5.0 remains, or as decided)" fi_c_legacy
  step finish.raw_off     "switch raw event indexing off once no 4.x agent remains"         fi_c_raw
  step finish.groups_post "group files: the post-upgrade pass for every group whose agents all run 5.0 (C4)" fi_c_groups
  step finish.history_data "history: delete the alert files once proven, keep manifest and journal (H5)" fi_c_hdata
  step finish.secrets     "every bundle's secrets: deleted, then searched for by value"     fi_c_secrets
  if [ -e "$STATE/legacy.open" ]; then rm -f "$STATE/finish.secrets"; log "=== PHASE 11 finish END ($((SECONDS - t0)) s): secrets deleted; LEGACY PORTS STILL OPEN; run finish again when that changes"
  else mark phase.finish; log "=== PHASE 11 finish END ($((SECONDS - t0)) s)"; fi; }

# ------------------------------------------------------------------------------------------------ going back
bk_check() { # E5 fold (E5-cluster-deb gap 2): every node's bundle and refusals, read-only, before anything is removed
  # anywhere. back.remove5 runs on every node in parallel and only then checked each bundle: the master's refusal left
  # the worker, the indexers and the dashboard already without Wazuh, and the cluster half removed.
  local n x=(); for n in "${NODES[@]}"; do x+=("$n goback-remove5.sh check ${ROLE[$n]}"); done
  npar "${x[@]}" || { echo "GOING BACK REFUSED before anything was changed on any node: the node(s) above say why. Fix it and run 'back' again"; return 1; }; }
bk_guard() { local n; for n in "${MANAGERS[@]}"; do nstep "$n" guard.sh on agent || return 1; done; }
bk_remove5() { local n x=(); for n in "${NODES[@]}"; do x+=("$n goback-remove5.sh"); done; npar "${x[@]}"; }
bk_idx4() { local n x=(); for n in "${INDEXERS[@]}"; do x+=("$n goback-install4.sh --wazuh-indexer $n"); done; npar "${x[@]}" && nstep "$SETUP" goback-install4.sh --start-cluster; }
bk_history() { nstep "$MASTER" history-load-4x.sh "$I4"; }
bk_folds() { local n; for n in "${MANAGERS[@]}"; do nstep "$n" goback-fold-4x.sh "$I4" || return 1; done; }
bk_mgr4() { local n; for n in "${MANAGERS[@]}"; do nstep "$n" goback-install4.sh --wazuh-server "$n" || return 1; done
  [ -z "$DASH" ] || nstep "$DASH" goback-install4.sh --wazuh-dashboard "$DASH"; }
bk_restore() { local n; nstep "$MASTER" goback-restore-manager.sh master || return 1; for n in ${WORKERS[@]+"${WORKERS[@]}"}; do nstep "$n" goback-restore-manager.sh worker || return 1; done; }
bk_security() {
  if [ "$CARRY_INDEXER_SECURITY" = 1 ]; then nstep "$SETUP" indexer-security.sh restore4 && nstep "$SETUP" indexer-security.sh verify4 || return 1; fi
  if [ "$CARRY_SAVED_OBJECTS" = 1 ] && [ -n "$DASH" ]; then nstep "$MASTER" dashboard-objects.sh import4 "$DASH_URL" || return 1; fi
  nstep "$MASTER" retention-4x.sh restore4 "$I4"; }
bk_unguard() { local n; for n in "${MANAGERS[@]}"; do nstep "$n" guard.sh off agent || return 1; done; }
bk_secrets() { local n; for n in "${BUNDLE_NODES[@]}"; do nstep "$n" finish-node.sh secrets || return 1; done; }
bm_check() { nstep "$MASTER" goback-remove5.sh check master || { echo "GOING BACK REFUSED on the master before anything was changed: see above"; return 1; }; }
bm_guard() { nstep "$MASTER" guard.sh on agent && nstep "$MASTER" guard.sh on cluster; }
bm_remove5() { nstep "$MASTER" goback-remove5.sh; }
bm_install4() { nstep "$MASTER" goback-install4.sh --wazuh-server "$MASTER"; }
bm_restore() { nstep "$MASTER" NO_FILEBEAT=1 goback-restore-manager.sh master; }
bm_gate() { # K5: 1516 opens first, then the gate (a worker connected, the same registry), then the agent ports
  nstep "$MASTER" guard.sh off cluster || return 1
  local i a b; for i in $(seq 1 "${REGISTRY_TRIES:-60}"); do a=$(nget "$MASTER" /var/ossec/etc/client.keys | sha256sum | cut -c1-16); b=$(nget "${WORKERS[0]}" /var/ossec/etc/client.keys | sha256sum | cut -c1-16)
    [ "$a" = "$b" ] && { echo "the master's registry equals ${WORKERS[0]}'s ($a)"; return 0; }; sleep "${REGISTRY_WAIT:-5}"; done
  echo "the master's registry ($a) does not equal ${WORKERS[0]}'s ($b): the agent guard stays on"; return 1; }
bm_unguard() { nstep "$MASTER" guard.sh off agent; }
bm_generation() { nstep "$MASTER" generation.sh keep; }   # the next attempt's freeze must not overwrite this one's alerts
cmd_c_back() {
  done_ back.done && { log "this cluster already went back to 4.x ($(cat "$STATE/back.done")): nothing to do"; return 0; }
  done_ confirm.no_return && die "the point of no return was confirmed at $(cat "$STATE/confirm.no_return"): going back is not offered"
  done_ indexers.remove4x || done_ master.remove4x || die "4.x was not removed on any node by this tool: there is nothing to go back from (start Filebeat again on the managers if the freeze ran)"
  CUR=back; local t0=$SECONDS
  # E5 fold (E5-cluster-deb gap 3, E5-cluster-rpm gap 7): the tool goes to every node first, as assess does, so the way
  # back runs the copy this controller holds (a fix made after the last assess reached the nodes only through
  # 'run --only assess'). It changes nothing of Wazuh; a node it cannot reach stops the way back before anything else.
  FAILS=0; WARNS=0; a_push
  [ "$FAILS" = 0 ] || die "going back refused: the tool could not be copied to every node (above); nothing was changed"
  if [ "$BACK_WHAT" = master ]; then
    [ ${#WORKERS[@]} -gt 0 ] || die "back master is the master's way back while its workers still serve on 4.x: this cluster has no worker"
    local w; for w in "${WORKERS[@]}"; do done_ "workers.$w.freeze" && die "worker $w was already frozen: only the whole cluster can go back ('back' without 'master')"; done
    log "=== GOING BACK: the master alone (its workers keep serving on 4.x) BEGIN"
    step back.master.check    "the master's bundle and what its way back needs, before anything changes" bm_check
    step back.master.guard    "the agent and cluster guards on the master (K5: 1516 too)"      bm_guard
    step back.master.remove5  "remove 5.0 on the master (a failed install's leftovers too)"    bm_remove5
    step back.master.install4 "reinstall 4.14.x on the master with the original install files" bm_install4
    step back.master.restore  "restore the master's registry and configuration; Filebeat stays stopped (the indexers are 5.0)" bm_restore
    step back.master.gate     "1516 opens; gate: a worker connected with the same registry"    bm_gate
    step back.master.unguard  "the agent ports open on the master"                             bm_unguard
    step back.master.generation "this attempt's bundle kept as a generation (folded with the next)" bm_generation
    log "=== the master is back on 4.x ($((SECONDS - t0)) s): the cluster holds (4.x managers, 5.0 indexers). Go forward with"
    log "    'run' (the master's markers are cleared now) or go back the whole cluster with 'back'."
    rm -f "$STATE"/master.* "$STATE/phase.master" "$STATE"/back.master.*; return 0
  fi
  log "=== GOING BACK: the whole cluster to 4.x from the bundles BEGIN"; jr back begin
  step back.check    "every node's bundle and what its way back needs, before anything is removed anywhere" bk_check
  step back.guard    "the agent guard on every manager, before anything stops"              bk_guard
  step back.remove5  "remove 5.0 on every node that has it"                                 bk_remove5
  step back.indexers "reinstall the 4.x indexers with the original install files; start the cluster once" bk_idx4
  step back.history  "the old alerts back into 4.x from the master's bundle (their original creation dates)" bk_history
  step back.folds    "each manager's alerts.json past the Filebeat offset back into 4.x"    bk_folds
  step back.managers "reinstall the 4.x managers (master first) and the dashboard"          bk_mgr4
  step back.restore  "restore each manager's registry and configuration; Filebeat checked against the bundle" bk_restore
  step back.security "indexer security, saved objects and the ISM policies put back"       bk_security
  step back.unguard  "the agent guard off on every manager"                                 bk_unguard
  step back.secrets  "every bundle's secrets deleted (this bundle records a finished return)" bk_secrets
  mark back.done; jr back end "$((SECONDS - t0)) s"
  log "=== GOING BACK END ($((SECONDS - t0)) s): the cluster runs 4.x again; to migrate later use a new state_dir and bundle_dir"; }

# ------------------------------------------------------------------------------------------------ main
if [ "$CCMD" = __step ]; then
  declare -F "${1:-}" >/dev/null || { echo "__step: no such step function '${1:-}'" >&2; exit 2; }
  CUR_STEP="$1"; trap - ERR; set -Eeuo pipefail; "$1"; exit 0
fi
case "$CCMD" in run|status|confirm-no-return|agents|finish|back) ;; *) sed -n '2,23p' "$SELF"; exit 2;; esac
if [ "$CCMD" = status ]; then
  [ -d "$STATE" ] || { echo "no run recorded in $CST"; exit 0; }
  for f in "$STATE"/*; do [ -e "$f" ] && echo "$(basename "$f") $(cat "$f")"; done; exit 0
fi
mkdir -p "$STATE" "$LOGS" "$RESULTS" "$DEC"; chmod 700 "$CST" "$DEC"
exec > >(tee -a "$LOGS/migrate-cluster.log") 2>&1
trap 'rc=$?; log "ERROR: line $LINENO exited $rc during ${CUR:-startup}; markers in $STATE and results in $RESULTS show what completed"; jr "${CUR:-startup}" error "line $LINENO exit $rc"; exit $rc' ERR
log "migrate-cluster.sh $CCMD: inventory $INVENTORY, state $CST, from=${FROM:-} only=${ONLY:-} through=${THROUGH:-}"
jr "command.$CCMD" begin "$INVENTORY"
case "$CCMD" in
  confirm-no-return) cmd_c_confirm;;
  agents) cmd_c_agents;;
  finish) cmd_c_finish;;
  back) cmd_c_back;;
  run)
    [ ! -e "$STATE/back.done" ] || die "this cluster records a finished return to 4.x: use a new state_dir and bundle_dir to migrate again"
    started=0; [ -z "$FROM" ] && started=1; n=0
    [ -z "$FROM$ONLY$THROUGH" ] || for p in $FROM $ONLY $THROUGH; do [[ " ${CPHASES[*]} " == *" $p "* ]] || die "no phase '$p' (phases: ${CPHASES[*]})"; done
    for CUR in "${CPHASES[@]}"; do
      n=$((n + 1))
      [ "$CUR" = "$FROM" ] && started=1
      [ "$started" = 1 ] || continue
      if [ -n "$ONLY" ] && [ "$ONLY" != "$CUR" ]; then continue; fi
      if done_ "phase.$CUR" && [ "$CUR" != assess ] && [ "$CUR" != verify ] && [ "$CUR" != verify_bundle ] && [ -z "$ONLY" ] && [ -z "$FROM" ]; then
        log "=== PHASE $n $CUR: already complete ($(cat "$STATE/phase.$CUR")), skipped"
      else
        log "=== PHASE $n $CUR BEGIN"; jr "phase.$CUR" begin; t0=$SECONDS
        "phase_$CUR"
        mark "phase.$CUR"; jr "phase.$CUR" end "$((SECONDS - t0)) s"; log "=== PHASE $n $CUR END ($((SECONDS - t0)) s)"
      fi
      [ "$THROUGH" = "$CUR" ] && { log "stopped after phase $CUR as asked (--through)"; break; }
    done
    if done_ phase.history && ! done_ confirm.no_return && [ -z "$ONLY" ] && [ -z "$THROUGH" ]; then cbanner_phase9; fi;;
esac
jr "command.$CCMD" end
