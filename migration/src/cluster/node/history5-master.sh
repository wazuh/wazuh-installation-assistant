#!/usr/bin/env bash
# history5-master.sh <indexer-url> <plan|apply|prove|audit-roles|on|status|remove-bundle> [args] : E2-cluster wiring (new
# node step). On the node that holds the history bundle (the master): the merged history stage (src/history_load.py, H5 +
# S5 over RD2's M3) against the 5.0 indexer cluster through ONE node, with the group stamp. The registry for the stamp is
# written once from the frozen master's identity export (id, name, groups), in mig_helper.py agent-registry's format; on
# the all-in-one migrate.sh takes it from the fingerprint, which a cluster node cannot take (it reads a local indexer).
. "$(dirname "$(readlink -f "$0")")/common.sh"
URL=$1; cmd=$2; shift 2; S="$SRC"
export INDEXER_PASSWORD; INDEXER_PASSWORD=$(v5cred WAZUH_INDEXER_ADMIN_PASSWORD)
ca=/etc/wazuh-manager/certs/indexer-ca.pem; [ -s "$ca" ] || { tar -xOf "$V5_TAR" wazuh-install-files/root-ca.pem > "$STATE/root-ca-5x.pem"; ca="$STATE/root-ca-5x.pem"; }
cn=$(sed -n '/<cluster>/,/<\/cluster>/s/.*<name>\(.*\)<\/name>.*/\1/p' /etc/wazuh-manager/wazuh-manager.conf | head -n1)
reg="$BUNDLE_DIR/history-registry.json"
if [ ! -s "$reg" ]; then python3 - "$BUNDLE_DIR/identity/manifest.json" "$reg" <<'PY'
import json, sys
m = json.load(open(sys.argv[1]))
reg = {"source": "4.x registry at the master's freeze (identity export manifest.json)",
       "agents": {"%03d" % a["id"]: {"name": a["name"], "groups": list(a.get("groups") or [])} for a in m["agents"]}}
json.dump(reg, open(sys.argv[2], "w"), indent=1); print("agent-registry: %d agent(s) written to %s" % (len(reg["agents"]), sys.argv[2]))
PY
fi
mkdir -p "$BUNDLE_DIR/indexer-security"
history_retention() { # F4 (decision 5b): migrate.sh history_retention on the cluster: an explicit HISTORY_RETENTION, else
  # the 4.x deployment's own (retention-4x.json, written by retention-4x.sh read at the pre-copy), else 365 days; the
  # value and the reason in $STATE/history.retention, printed with every history command
  local v why n f="$BUNDLE_DIR/retention-4x.json"
  if [ -n "${HISTORY_RETENTION:-}" ]; then v=$HISTORY_RETENTION; why="set explicitly (HISTORY_RETENTION=$HISTORY_RETENTION)"
  elif n=$(python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); n=d.get("retention_days"); print(n) if n is not None else sys.exit(1)' "$f" 2>/dev/null); then
    v="${n}d"; why="the 4.x deployment's own retention: $(python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); print("; ".join("ISM policy %s deletes alert indices after %s days" % (p["policy_id"], p["delete_after_days"]) for p in d["policies"] if p["delete_after_days"] is not None))' "$f")"
  elif [ -s "$f" ]; then v=365d; why="no ISM policy deleted the 4.x alert indices (read at the pre-copy): the default, 365 days"
  else v=365d; why="the 4.x retention was not read at the pre-copy (retention-4x.sh read did not run for this bundle): the default, 365 days"; fi
  echo "history retention: $v: $why" > "$STATE/history.retention.tmp" && mv -f "$STATE/history.retention.tmp" "$STATE/history.retention"
  echo "$v"
}
ret=$(history_retention); log "$(cat "$STATE/history.retention")"
# the shaping in worker processes, as the all-in-one's load (migrate.sh HISTORY_PROCS):
# HISTORY_PROCS from the inventory's settings, else half this node's CPUs, 1 to 8; 0 uses threads. Before, the cluster's
# history ran in threads only (E5-aio CL-L15: processes 1.9 times faster on the same month, the same documents)
if [ "$cmd" = apply ]; then
  if [ -z "${HISTORY_PROCS:-}" ]; then np=$(nproc 2>/dev/null || echo 2); HISTORY_PROCS=$(( np / 2 )); [ "$HISTORY_PROCS" -ge 1 ] || HISTORY_PROCS=1; [ "$HISTORY_PROCS" -le 8 ] || HISTORY_PROCS=8; fi
  log "history shaping: --procs $HISTORY_PROCS$( [ "$HISTORY_PROCS" = 0 ] && echo ' (threads)')"
  set -- --procs "$HISTORY_PROCS" "$@"
fi
t0=$SECONDS
python3 "$S/history_load.py" "$cmd" --bundle "$BUNDLE_DIR/history" --url "$URL" --cacert "$ca" --cluster-name "${cn:-wazuh}" \
  --agent-ids carried --agent-registry "$reg" --retention "$ret" "$@" 2>&1 | tee -a "$LOGS/history5-$cmd.log" | tail -n 30
rc=${PIPESTATUS[0]}; log "history_load.py $cmd exit $rc in $((SECONDS - t0)) s"; exit $rc
