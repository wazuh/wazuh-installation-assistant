#!/usr/bin/env bash
# feed-node.sh : CL1, on EVERY 5.0 manager node, phase 10 before its gate (rule 14 on every manager of a cluster;
# the cluster's agents step had no wait and two agents were upgraded six minutes before the master's
# feed loaded). The all-in-one's feed_wait: FEED_WAIT_MAX seconds (0: only report).
. "$(dirname "$(readlink -f "$0")")/common.sh"
aio_lib
feed_wait || die "the vulnerability feed's initial load did not complete on $(nodelabel)"
