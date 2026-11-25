#!/usr/bin/env bash
# freeze-manager.sh : on EVERY 4.x manager node. Stops the manager, lets this node's Filebeat ship the rest of
# this node's alerts.json, then stops Filebeat. The outage of the agents this node serves starts here.
. "$(dirname "$(readlink -f "$0")")/common.sh"
V4=/var/ossec
# OF1 item 12: before this node's outage starts. E3 fold (E3-cluster gap 5): on every attempt, not only the first: a
# second forward attempt after a way back (the 4.x reinstall may be of another build) kept T_manager4_stop_begin and
# skipped the check. The packages are read from the package database, so a manager stopped by the first attempt is fine.
source_version_gate
ts > "$STATE/T_manager4_stop_begin"
systemctl stop wazuh-manager; systemctl disable wazuh-manager >/dev/null 2>&1 || true
# E2-cluster fix: the identity export refuses while pid files remain under var/run (it checks presence only); after
# `systemctl stop` the master still had 2 a second later. Wait for every pid file whose process lives; a pid file whose
# process is gone is stale: recorded and removed. A process still alive after 60 s stops the freeze.
for i in $(seq 1 60); do
  alive=""; for f in $V4/var/run/*.pid; do [ -e "$f" ] || continue; p=$(cat "$f" 2>/dev/null); if [ -n "$p" ] && kill -0 "$p" 2>/dev/null; then alive="$alive $(basename "$f")"; fi; done
  [ -z "$alive" ] && break; sleep 1
done
[ -z "$alive" ] || die "manager processes still alive 60 s after the stop:$alive"
for f in $V4/var/run/*.pid; do [ -e "$f" ] && { log "stale pid file after the stop (process gone): $(basename "$f"), removed"; rm -f "$f"; }; done
ts > "$STATE/T_manager4_stopped"; log "4.x manager stopped ($(sed -n '/<cluster>/,/<\/cluster>/s/.*<node_type>\(.*\)<.*/\1/p' $V4/etc/ossec.conf))"
f=$V4/logs/alerts/alerts.json
if [ "${NO_DRAIN:-0}" = 1 ]; then
  # Order B: no 4.x indexer is left to take the alerts. Record where Filebeat stopped, so the rest can be folded in from the file.
  mkdir -p "$BUNDLE_DIR/v4"; python3 "$SRC/cluster/alertsjson-fold.py" plan "$f" /var/lib/filebeat/registry/filebeat/log.json | tee "$BUNDLE_DIR/v4/filebeat-not-shipped.json"
  systemctl stop filebeat; systemctl disable filebeat >/dev/null 2>&1 || true
  mark freeze.done; log "Filebeat stopped without draining (NO_DRAIN=1)"; exit 0
fi
for i in $(seq 1 60); do
  size=$(stat -c %s "$f"); off=$(grep -F "\"source\":\"$f\"" /var/lib/filebeat/registry/filebeat/log.json 2>/dev/null | tail -n1 | grep -o '"offset":[0-9]*' | cut -d: -f2)
  [ "${off:-0}" -ge "$size" ] && break; sleep 2
done
log "Filebeat offset ${off:-?} of $size bytes of alerts.json"
[ "${off:-0}" -ge "$size" ] || log "WARN Filebeat had not shipped all of alerts.json after 120 s"
sleep 3; systemctl stop filebeat; systemctl disable filebeat >/dev/null 2>&1 || true
mark freeze.done; log "Filebeat stopped; alerts.json lines today: $(wc -l < "$f")"
