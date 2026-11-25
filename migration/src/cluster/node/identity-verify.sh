#!/usr/bin/env bash
# identity-verify.sh : CL1, on the 5.0 MASTER (phase 8 of the cluster): the registry, groups, memberships and API users
# against the identity bundle (identity_stage.py verify), and the Server API limit back to the original (rule 15).
. "$(dirname "$(readlink -f "$0")")/common.sh"
V5=/var/wazuh-manager; py=$V5/framework/python/bin/python3
exp=(); [ -s "$BUNDLE_DIR/settings/groups-pre/uploaded.json" ] && exp=(--expected-conf "$BUNDLE_DIR/settings/groups-pre/uploaded.json")
$py "$SRC/identity_stage.py" verify "$BUNDLE_DIR/identity" --state "$BUNDLE_DIR/identity-stage" ${exp[@]+"${exp[@]}"} > "$LOGS/identity-verify-phase8.json" 2>&1 \
  || { head -c 2000 "$LOGS/identity-verify-phase8.json"; echo; die "the master's registry differs from the identity bundle"; }
head -c 600 "$LOGS/identity-verify-phase8.json"; echo
log "identity: the master's registry equals the identity bundle"
