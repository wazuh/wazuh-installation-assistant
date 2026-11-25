#!/usr/bin/env bash
# agents-node.sh <preflight|run|trust|gate|raw CMD> [fleet-upgrade.py options] : CL1, on the 5.0 MASTER, phase 10 by the
# all-in-one's own steps (migrate.sh ag_preflight, ag_run, ag_trust, ag_gate) with the cluster's connection: one
# indexer node of the inventory (IDX5_HOST), the fleet facts the pre-copy took, the per-node certificate preflight
# (fleet-upgrade.py reads every node; --node-address NODE=ADDR passes through). The agent upgrade packages: WPK_REPO
# when set, else the 5.0 manifest the inventory staged (development builds; its wazuh_wpk_* entries), else the
# default of the manager for a published release; never a development-build address by default.
. "$(dirname "$(readlink -f "$0")")/common.sh"
aio_lib
cmd=${1:-}; shift || true
if [ -z "$WPK_REPO" ] && [ -s "$V5_DIR/artifact_urls.yaml" ]; then WPK_REPO=$(python3 "$SRC/mig_helper.py" wpk-repo "$V5_DIR/artifact_urls.yaml") || die "the 5.0 manifest names no single agent package repository"; fi
echo "agent upgrade packages: ${WPK_REPO:-the default of the manager (a published release)}"
XARGS=("$@"); [ -z "${LISTENER_HOST:-}" ] || XARGS+=(--listener-host "$LISTENER_HOST")
fu() { # migrate.sh fu with the cluster's indexer and the extra options
  local ca=$V5ETC/certs/root-ca.pem; [ -s "$ca" ] || ca=$V5ETC/export/ca.pem   # the API's CA: where the all-in-one has it, else the cluster export's
  local a=(--api https://localhost:55000 --ca "$ca" --fleet-facts "$BUNDLE_DIR/preflight/fleet-facts.json" --state "$BUNDLE_DIR/fleet/upgrade-state.json"
           --indexer "https://$(idxhost):9200" --indexer-ca "$IDX5_CA" --manager-log $V5/logs/wazuh-manager.log --tasks-db $V5/queue/tasks/tasks.db)
  [ -z "$WPK_REPO" ] || a+=(--wpk-repo "$WPK_REPO")
  WAZUH_API_PASSWORD="$(v5env $V5ETC/export/credentials.env WAZUH_MANAGER_API_PASSWORD)" WAZUH_INDEXER_PASSWORD="$(idx5pw)" python3 "$HERE/fleet-upgrade.py" "$@" "${a[@]}" ${XARGS[@]+"${XARGS[@]}"}
}
mkdir -p "$BUNDLE_DIR/fleet"
case "$cmd" in
preflight) ag_preflight;;
run) ag_run;;
trust) ag_trust;;
gate) XARGS=(); ag_gate;;
raw) # any other fleet-upgrade.py command (legacy-status, status, report) with the same connection. E5 fold (E5-cluster-rpm
     # 08 = E5-cluster-deb 09): XARGS held every argument, the command too, so fu passed it twice ("unrecognized
     # arguments: legacy-status") and the cluster finish could never start; rebuilt here as gate does
     XARGS=(); [ -z "${LISTENER_HOST:-}" ] || XARGS+=(--listener-host "$LISTENER_HOST")
     fu "$@";;
*) die "usage: agents-node.sh preflight|run|trust|gate [fleet-upgrade.py options]";;
esac
