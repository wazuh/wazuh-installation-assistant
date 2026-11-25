#!/usr/bin/env bash
# fleet-facts.sh : CL1, on the 4.x MASTER at the pre-copy, read-only. The all-in-one's pc_fleet: every agent's facts from
# the 4.x API (fleet-facts-4x.py) into the bundle (preflight/fleet-facts.json, where the fleet step reads them), and the
# certificate plan: the names agents dial (and AGENT_ADDRESSES) that are none of the inventory's manager node addresses
# or names, which the 5.0 -g must add with -as (preflight/agent-san-extra.txt). A per-node name is checked by the fleet
# preflight against that node only (E2 fold).
. "$(dirname "$(readlink -f "$0")")/common.sh"
d="$BUNDLE_DIR/preflight"; mkdir -p "$d"
WAZUH_API_PASSWORD="$(pw4 wazuh)" python3 "$SRC/fleet-facts-4x.py" --insecure --out "$d/fleet-facts.json" || die "the 4.x fleet facts could not be read"
python3 - "$d" "${AGENT_ADDRESSES:-}" "${CLUSTER_NODES:-}" "${CLUSTER_ADDRESSES:-}" <<'PY'
import json, os, sys
d, extra, nodes, addrs = sys.argv[1:5]
facts = json.load(open(os.path.join(d, "fleet-facts.json")))
dial = sorted({x for a in facts["agents"].values() for x in a.get("dialed", [])} | {x for x in extra.replace(",", " ").split() if x})
own = set(nodes.split(",")) | set(addrs.split(",")) | {"localhost", "127.0.0.1", "::1"}
add = [x for x in dial if x not in own]
open(os.path.join(d, "dialed-addresses.txt"), "w").write("".join(x + "\n" for x in dial))
open(os.path.join(d, "agent-san-extra.txt"), "w").write("".join(x + "\n" for x in add))
print("certificate plan: dialled %s; to add with -as at the 5.0 -g: %s" % (" ".join(dial) or "none", " ".join(add) or "none"))
PY
chmod -R go= "$d"; mark precopy.fleet
