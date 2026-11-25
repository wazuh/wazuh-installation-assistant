#!/usr/bin/env bash
# open-node.sh : CL1, on a 5.0 MANAGER node of a cluster, after its registry is verified (the master's identity step, or
# a worker's registry gate): the all-in-one's opening (migrate.sh op_in_force, op_listeners): the unclassified-events
# decision seen in force by this node's engine first (rule 8: a worker waits for the decision the master applied; its
# time and answer come from the master's state), then the host firewall (1517 added where firewalld or ufw is active,
# recorded for the way back), the agent guard off, the listeners open, one restart. The outage of this node's agents
# ends here. A 5.0 worker runs no Server API: ready is the cluster daemon answering.
. "$(dirname "$(readlink -f "$0")")/common.sh"
aio_lib
if [ -e "$STATE/unclassified.applied" ]; then op_in_force || die "the decision on unclassified events is not in force on this node's engine"
else echo "no decision on unclassified events recorded for this node (CARRY of the ruleset off, or nothing to apply)"; fi
op_listeners || die "the listeners could not be opened"
wait_clusterd || die "the cluster daemon does not answer after the opening"
mark open.done; log "listeners open on $(nodelabel)"
