#!/usr/bin/env bash
# filebeat-stop.sh : on EVERY 4.x manager node, before the 4.x indexer goes (orders where the 4.x managers keep serving
# agents while the indexers are replaced). Lets Filebeat ship what alerts.json holds, stops Filebeat only, and records the
# offset. From here this node's alerts exist only in alerts.json, and the delta dump taken next has no gap behind it:
# what the indexer holds and what alerts.json holds past the offset add up to everything, with nothing in between.
. "$(dirname "$(readlink -f "$0")")/common.sh"
V4=/var/ossec; f=$V4/logs/alerts/alerts.json
for i in $(seq 1 60); do
  size=$(stat -c %s "$f"); off=$(grep -F "\"source\":\"$f\"" /var/lib/filebeat/registry/filebeat/log.json 2>/dev/null | tail -n1 | grep -o '"offset":[0-9]*' | cut -d: -f2)
  [ "${off:-0}" -ge "$size" ] && break; sleep 2
done
systemctl stop filebeat; systemctl disable filebeat >/dev/null 2>&1 || true
ts > "$STATE/T_filebeat_stopped"
mkdir -p "$BUNDLE_DIR/v4"; python3 "$SRC/cluster/alertsjson-fold.py" plan "$f" /var/lib/filebeat/registry/filebeat/log.json | tee "$BUNDLE_DIR/v4/filebeat-at-stop.json"
log "Filebeat stopped; the 4.x manager keeps running ($(systemctl is-active wazuh-manager))"
