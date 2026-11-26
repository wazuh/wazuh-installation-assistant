#!/usr/bin/env bash
# goback-fold-4x.sh <4.x-indexer-url> : going back, on EACH reinstalled 4.x manager node. Loads the part of this node's
# final 4.x alerts.json that Filebeat never shipped (the same fold that went to 5.0) into the 4.x indexer, in the daily
# index the 4.x Filebeat would have used. Together with the history bundle this gives 4.x back every 4.x alert.
# every generation of this node's bundle (v4.gen*/, v4/); the bulk file is built from the recorded offset when the
# fold never ran on 5.0 (the hold, after the master's way back alone). A fold the history reload already put back
# (merged into the master's history bundle) has the same ids: its documents come back "already there", never twice.
. "$(dirname "$(readlink -f "$0")")/common.sh"
# the whole-cluster way back runs this step before any 4.x manager exists, so ossec.conf is
# absent; under errexit and pipefail the failed sed killed the step with an empty transcript. The name is only needed to
# build a bulk file the forward fold never wrote; the node's host name stands in for it
URL=$1; NODE=$( { sed -n 's#.*<node_name>[[:space:]]*\([^<[:space:]]*\)[[:space:]]*</node_name>.*#\1#p' /var/ossec/etc/ossec.conf 2>/dev/null || true; } | head -n1)
export IDX_PASS; IDX_PASS=$(pw4 admin)
ca=/etc/filebeat/certs/root-ca.pem; [ -s "$ca" ] || ca=$(ca4)
n=0
for G in $(cd "$BUNDLE_DIR" && ls -d v4.gen* 2>/dev/null | sort -V) v4; do
  src="$BUNDLE_DIR/$G/alertsjson-fold.ndjson.gz"; dst="$BUNDLE_DIR/$G/alertsjson-fold-4x-daily.ndjson.gz"; p="$BUNDLE_DIR/$G/filebeat-not-shipped.json"
  if [ ! -s "$src" ]; then
    [ -s "$p" ] && [ -s "$BUNDLE_DIR/$G/alerts/alerts.json" ] || continue
    off=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["filebeat_offset"])' "$p")
    python3 "$SRC/cluster/alertsjson-fold.py" bulk "$BUNDLE_DIR/$G/alerts/alerts.json" "$off" "${NODE:-$(hostname -s)}" "$src"
  fi
  python3 - "$src" "$dst" <<'PY'
import gzip, json, sys
n = 0
with gzip.open(sys.argv[1], "rt") as i, gzip.open(sys.argv[2], "wt") as o:
    for k, line in enumerate(i):
        if k % 2 == 0:
            a = json.loads(line); m = a["create"]; day = m["_id"].split(":", 1)[0]
            m["_index"] = "wazuh-alerts-4.x-" + day; m["_id"] = m["_id"].split(":", 1)[1]; n += 1
            line = json.dumps(a) + "\n"
        o.write(line)
print(json.dumps({"documents": n, "bulk_file": sys.argv[2]}))
PY
  python3 "$SRC/cluster/alertsjson-fold.py" load "$dst" "$URL" admin "$ca"; n=$((n + 1))
done
[ "$n" -gt 0 ] || log "no alerts.json fold on this node (no freeze recorded an offset): nothing to put back"
log "$n generation(s) of this node's alerts.json fold put back into 4.x"
