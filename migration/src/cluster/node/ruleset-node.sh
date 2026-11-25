#!/usr/bin/env bash
# ruleset-node.sh <precopy|import|decision> : CL1, on the MASTER, the all-in-one's custom-rule migration (rmig) and the
# unclassified-events decision (rule 8, decision 3), by migrate.sh's own functions (aio_lib). The rmig content is
# cluster-wide (it lives in the indexer): the master applies, verifies and activates it once for every node; the
# indexer is the inventory's setup node (IDX5_HOST), with the CA the manager holds for it.
#   precopy   4.x live: pc_ruleset_src (custom and stock content), pc_ruleset_build (scan, plan, build offline; open
#             questions go into the "ruleset" section of this node's decisions file, exit 1 and the run stops)
#   import    5.0 master: im_ruleset (rebuilt for the installed engine when needed, apply to the test space, verify
#             with the 4.x alerts of the master's bundle)
#   decision  5.0 master, before it opens: op_decision (default verified+raw, decision 3; UNCLASSIFIED_DECISION=ask
#             stops with exit 3 and the listeners closed); the time it was applied is what each node's opening waits on
. "$(dirname "$(readlink -f "$0")")/common.sh"
aio_lib
rmig_dialect_planned() { [ -n "$RMIG_ENGINE_HELPERS" ] && { echo "$RMIG_ENGINE_HELPERS"; return; }   # the assistant staged in work_dir
  dialect_for_stage "$(sed -n 's/^staging_url_stage="\(.*\)"/\1/p' "$V5_DIR/wazuh-install.sh" 2>/dev/null | head -n1)"; }
[ -d "$RMIG_DIR" ] || die "the ruleset tool is not at $RMIG_DIR (inputs.ruleset_tool)"
rc=0
case "${1:-}" in
precopy) [ -d /var/ossec/etc ] || die "no 4.x manager on this node"; pc_ruleset_src && pc_ruleset_build || rc=$?
         [ "$rc" = 0 ] || exit 3; mark ruleset.precopy;;
import) im_ruleset || exit $?; mark ruleset.import;;
decision) op_decision || exit $?; mark unclassified.decided;;
*) die "usage: ruleset-node.sh precopy|import|decision";;
esac
