#!/usr/bin/env bash
# settings-node.sh <step> : CL1, the settings stage (rules 21 and 22) on one manager node of a cluster, by the
# all-in-one's own functions (migrate.sh, loaded by aio_lib; E4-cluster's lab wrapper tools/settings-cluster.sh was the
# reference). The node's decisions file is $BUNDLE_DIR/decisions.json; migrate-cluster.sh brings it from and back to
# the controller ($state_dir/decisions/<node>.json) around every step that can ask.
#   collect4        4.x node (pre-copy, and again at every freeze through export-manager.sh): pc_settings into this
#                   attempt's v4/config (E4-cluster gap 2b: a second forward attempt moved v4/ away and the cluster
#                   export wrote no v4/config, so plan was refused); the indexer and dashboard files only where they exist
#   plan-precopy <name> <master|worker> <master-address>
#                   4.x node: pc_settings_plan against the 5.0 files this build installs, with this node's <cluster> as
#                   the 5.0 install writes it (E5 fold: the all-in-one base asked three false questions per node); exit
#                   3: open questions
#   plan-installed  5.0 node, closed: collect_base, then the plan against the installed files (exit 3: a new question)
#   stage           5.0 MASTER, inside the identity step before its restart: im_settings (convert, validate, cross-node
#                   check, save, stage, wazuh-manager-control check); the master is the first 5.0 node of the cluster
#                   (order C), so its candidate is checked alone; the restart that applies it is the identity step's own
#   apply-worker    5.0 WORKER, closed: im_settings against every node already on 5.0 (settings/peers/<node>/, their
#                   live wazuh-manager.conf streamed host to host), then its restart while it is still closed; a 5.0
#                   worker runs no Server API, so ready is the cluster daemon answering. A restart
#                   that fails puts the saved files back (rule 22)
#   restore         the saved installed files back (rule 22)
#   groups-pre      MASTER: im_groups_pre (the pre-upgrade group pass, while 4.x agents remain)
#   groups-post     MASTER (finish): fi_groups_post (every group whose agents all run 5.0)
. "$(dirname "$(readlink -f "$0")")/common.sh"
aio_lib
cmd=${1:-}; rc=0
case "$cmd" in
collect4)
  [ -d /var/ossec/etc ] || die "no 4.x manager on this node"
  rm -rf "$BUNDLE_DIR/v4/config"; pc_settings || rc=$?
  [ "$rc" = 0 ] || die "the 4.x settings could not be collected"
  mark settings.collect4;;   # the stock reference line was printed once by pc_settings
plan-precopy) # <node name> <master|worker> <master address>: planned against a cluster base, not the all-in-one's
  if [ -n "${2:-}" ] && [ -n "${3:-}" ] && [ -n "${4:-}" ]; then
    PRECOPY_BASE="$BUNDLE_DIR/settings/base-precopy-cluster"
    python3 "$HERE/settings_stage.py" cluster-base --base-from "$HERE/converter/refs/base-5.0.0-aio" --out "$PRECOPY_BASE" \
      --node-name "$2" --node-type "$3" --master "$4" || die "the cluster base for the pre-copy plan could not be made"
  fi
  pc_settings_plan || rc=$?; exit $rc;;
plan-installed) rp_settings_plan || rc=$?; exit $rc;;
stage)
  CLUSTER_CANDIDATES=first-node; im_settings || rc=$?
  [ "$rc" = 0 ] || exit $rc; mark settings.staged;;
apply-worker)
  [ "$CARRY_SETTINGS" = 1 ] || { echo "CARRY_SETTINGS=0: the installed 5.0 settings are kept"; exit 0; }
  peers=$(ls -d "$BUNDLE_DIR"/settings/peers/*/ 2>/dev/null | tr '\n' ' ' || true)
  [ -n "$peers" ] || die "no other node's wazuh-manager.conf in settings/peers: the cross-node check cannot run"
  CLUSTER_CANDIDATES="$peers"; im_settings || exit $?
  systemctl restart wazuh-manager; ts > "$STATE/T_settings_restart"
  if ! wait_clusterd; then
    echo "the worker did not come back on the converted settings: putting the saved installed files back"
    python3 "$HERE/settings_stage.py" restore --saved "$BUNDLE_DIR/settings/saved" --targets "$(cat "$BUNDLE_DIR/settings/targets.json")"
    systemctl restart wazuh-manager; wait_clusterd || true; die "the converted settings were refused on this worker: the installed ones are back"
  fi
  echo "worker restarted on its converted settings (closed); cluster daemon answering ($( [ "$($V5/bin/wazuh-manager-conf get cluster.node_type 2>/dev/null || echo worker)" = master ] && echo master || echo 'no Server API on a 5.0 worker'))"
  mark settings.applied;;
restore) python3 "$HERE/settings_stage.py" restore --saved "$BUNDLE_DIR/settings/saved" --targets "$(cat "$BUNDLE_DIR/settings/targets.json")";;
groups-pre) im_groups_pre || exit $?;;
groups-post) fi_groups_post || exit $?;;
*) die "usage: settings-node.sh collect4|plan-precopy|plan-installed|stage|apply-worker|restore|groups-pre|groups-post";;
esac
