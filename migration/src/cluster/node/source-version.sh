#!/usr/bin/env bash
# source-version.sh [cluster] : OF1 item 12 (decision of 2026-11-24): only the latest 4.14.x is a migration source. On ANY node:
# this node's installed wazuh-manager, wazuh-indexer and wazuh-dashboard against manifest/builds.json (source_min_version,
# or a newer 4.14.x published after the tool); older is refused (upgrade to the latest 4.14.x first), 4.15+ and 5.x are
# not a 4.14 source. "cluster" (on the master, 4.x API up): also every manager node the 4.x cluster lists in
# /cluster/nodes, so a mixed-version cluster is refused naming the node before anything is changed anywhere. E3 fold
# (E3-cluster gap 1): a worker of another version cannot join, so /cluster/nodes hid it; every node CLUSTER_NODES (the
# inventory, comma separated) or the agent registry names must be connected, else it is refused by name.
. "$(dirname "$(readlink -f "$0")")/common.sh"
source_version_gate
if [ "${1:-}" = cluster ]; then
  V4_API_PASSWORD="$(pw4 wazuh)" python3 "$SRC/mig_helper.py" source-version-cluster || die "a manager node of the 4.x cluster is not the latest 4.14.x: nothing changed"
fi
log "source version: this node's 4.x components are the latest 4.14.x${1:+ (and every manager node of the cluster)}"
