#!/usr/bin/env bash
# finish-node.sh <legacy-decide|legacy-close|history-data|secrets> [args] : the cluster's phase 11, per node. E2 fold,
# the cluster flow had no finish (the lab controller closed the legacy listeners by hand; no step removed
# the history data or the bundles' secrets). The all-in-one's finish (migrate.sh cmd_finish), split by where it runs:
#   legacy-decide               on the 5.0 MASTER, after the fleet upgrade: fleet-upgrade.py legacy-status for the whole
#                               cluster and migrate.sh fi_legacy's rule: exit 0 = close; exit 3 = keep open, the
#                               reason in state/legacy.open (agents below 5.0 that reported a version, open legacy
#                               sessions, or never-connected agents with NEVER_CONNECTED_AT_FINISH=keep, the default);
#                               NEVER_CONNECTED_AT_FINISH=remove deletes those agents through the API first
#   legacy-close decided        on EVERY 5.0 manager, only after legacy-decide exited 0 on the master: <legacy> off,
#                               validated, restarted; 1514 and 1515 must be closed, 1517 open
#   history-data <indexer-url>  on the MASTER: the alert files leave the bundle after the proof passes (H5 remove-bundle)
#   secrets                     on EVERY node with a bundle (managers, and indexer node-1 since indexer-security.sh):
#                               bundle_secrets.py, the all-in-one's sweep by value (CL1: the node's work directory)
#   raw-off                     on the MASTER: migrate.sh fi_raw_off, raw event indexing off once no
#                               4.x agent that reported a version remains (the content is cluster-wide)
#   groups-post                 on the MASTER: the post-upgrade group pass (settings-node.sh)
. "$(dirname "$(readlink -f "$0")")/common.sh"
N="$(dirname "$(readlink -f "$0")")"; V5=/var/wazuh-manager; c=/etc/wazuh-manager/wazuh-manager.conf
NEVER_CONNECTED_AT_FINISH="${NEVER_CONNECTED_AT_FINISH:-keep}"
apipw() { sed -n "s/^WAZUH_MANAGER_API_PASSWORD=//p" /etc/wazuh-manager/export/credentials.env | head -n1 | sed "s/^'\(.*\)'$/\1/"; }
case "${1:-}" in
legacy-decide)
  st="$LOGS/legacy-status.txt"; rm -f "$STATE/legacy.open" "$STATE/legacy.close_ok"
  bash "$N/fleet-upgrade.sh" legacy-status > "$st" 2>&1 || { cat "$st"; die "legacy-status failed"; }
  cat "$st"
  if ! grep -q 'legacy channel can be closed: YES' "$st"; then
    old=$(sed -n 's/^agents not on 5.x in the registry: [0-9]*: //p' "$st" | sed 's/), /)\n/g')
    nc=$(grep -E '\(None, never_connected\)' <<<"$old" | awk '{print $1}' | tr '\n' ' ' || true)
    others=$(grep -v -E '\(None, never_connected\)' <<<"$old" | grep . || true)
    sess=$(sed -n 's/^legacy TCP sessions per node: //p' "$st" | tr ',' '\n' | awk -F= '$2 != 0' | grep . || true)
    if [ -n "$others" ] || [ -n "$sess" ]; then
      echo "keep legacy: $(echo $others $sess)" > "$STATE/legacy.open"
      log "LEGACY PORTS KEPT OPEN on every node: agents below 5.0 that reported a version, or open legacy sessions: $(echo $others $sess)"; exit 3
    fi
    log "the only agents below 5.0 on record never connected: $nc"
    case "$NEVER_CONNECTED_AT_FINISH" in
      keep) echo "keep never-connected: $nc" > "$STATE/legacy.open"
            log "LEGACY PORTS KEPT OPEN for them; to close them, answer \"close\" or \"remove\" in the controller's decisions file (section \"never-connected\", entry \"at-finish\") and run again"; exit 3;;
      remove) tok=$(curl -sk -u "wazuh:$(apipw)" -X POST "https://localhost:55000/security/user/authenticate?raw=true")
              curl -sk -X DELETE "https://localhost:55000/agents?agents_list=$(echo $nc | tr ' ' ',')&status=all&older_than=0s" -H "Authorization: Bearer $tok"; echo
              log "removed from the registry by the user's decision: $nc";;
      close) log "closing the legacy ports by the user's decision; still registered: $nc";;
      *) die "NEVER_CONNECTED_AT_FINISH: unknown answer '$NEVER_CONNECTED_AT_FINISH' (keep, close, remove)";;
    esac
  fi
  mark legacy.close_ok; log "the legacy listeners can be closed on every node";;
legacy-close)
  [ "${2:-}" = decided ] || die "legacy-close runs only after legacy-decide exited 0 on the master: pass 'decided'"
  # this node's own record and its live state. Closed here before, <legacy> still off and neither 1514 nor 1515
  # listening: no second restart (a controller that lost the step's end runs it again)
  if [ -e "$STATE/finish.legacy" ] && [ -e "$c.before-legacy-off" ] && ! sed -n '/<legacy>/,/<\/legacy>/p' "$c" | grep -q '<enabled>yes</enabled>' \
     && ! { ss -ltnH 2>/dev/null || true; } | awk '{print $4}' | grep -qE ':(1514|1515)$'; then
    log "the legacy listener was closed on this node at $(cat "$STATE/finish.legacy"): not closed again"; exit 0; fi
  # rule 14: the restart below would throw away this node's vulnerability feed load in progress; wait for it first
  # (FEED_WAIT_MAX seconds, 0 = only report), before the configuration is touched
  if [ "${FEED_WAIT_MAX:-3600}" = 0 ]; then python3 "$SRC/mig_helper.py" feed-status "$V5/logs/wazuh-manager.log" || true
  else python3 "$SRC/mig_helper.py" feed-wait "$V5/logs/wazuh-manager.log" "${FEED_WAIT_MAX:-3600}" "$c" || die "the vulnerability feed did not load: see above"; fi
  [ -e "$c.before-legacy-off" ] || cp -p "$c" "$c.before-legacy-off"     # a rerun keeps the first copy
  sed -i '/<legacy>/,/<\/legacy>/ s#<enabled>yes</enabled>#<enabled>no</enabled>#' "$c"
  $V5/bin/wazuh-manager-conf validate || die "the configuration with <legacy> off does not validate"
  systemctl restart wazuh-manager; ts > "$STATE/T_legacy_closed"; sleep 20
  l=$(ss -ltnH | awk '{print $4}' | grep -E ':(1514|1515|1516|1517)$' | sort | tr '\n' ' ')
  log "listening after the legacy listener closed: $l"
  ! grep -qE ':(1514|1515) ' <<<"$l " || die "a legacy port is still open"
  grep -q ':1517 ' <<<"$l " || die "1517 is not listening after the restart"
  # the host firewall as the all-in-one's finish leaves it (1514 and 1515 removed where opened as ports; ufw too)
  ( aio_lib; fw_close_legacy ) || log "WARN the host firewall could not be changed: remove 1514/tcp and 1515/tcp yourself"
  mark finish.legacy;;
raw-ask) rc=0; ( aio_lib; raw_ask ) || rc=$?; exit "$rc";;   # the point-of-no-return stop asks the finish's raw question (exit 3)
raw-off) rc=0; ( aio_lib; fi_raw_off ) || rc=$?; [ "$rc" = 0 ] || { [ "$rc" = 3 ] && exit 3; die "raw event indexing could not be switched off"; };;
groups-post) bash "$N/settings-node.sh" groups-post || die "the post-upgrade group pass failed";;
history-data)
  URL=${2:?the indexer URL}
  [ -d "$BUNDLE_DIR/history" ] || { log "no history in this node's bundle"; exit 0; }
  # the finish runs again after the last upgrade (legacy-decide exit 3 the first time); by then the
  # first finish's secret sweep has deleted identity/ and history-registry.json, which history5-master.sh needs to
  # start, so a second remove-bundle crashed. Done once is done.
  [ -e "$STATE/finish.history_data" ] && { log "history data already removed after its proof ($(cat "$STATE/finish.history_data"))"; exit 0; }
  bash "$N/history5-master.sh" "$URL" remove-bundle || die "the history data stays: its proof did not pass"
  mark finish.history_data;;
secrets)
  # a way back run before goback-install4.sh removed its own copy left the 4.x install files here
  f="$WORK_DIR/v4-reinstall/wazuh-install-files.tar"
  [ -e "$f" ] && { shred -u "$f" 2>/dev/null || rm -f "$f"; log "removed the way back's working copy of the 4.x install files ($f)"; }
  python3 "$SRC/bundle_secrets.py" sweep --bundle "$BUNDLE_DIR" --search "$WORK_DIR" --outside "$V4_TAR" --outside "$V5_TAR" \
    $( [ "${2:-}" = keep-sample ] && echo --keep-sample ) || die "a carried secret is still on this node"
  mark finish.secrets;;
*) die "usage: finish-node.sh legacy-decide | legacy-close decided | history-data <indexer-url> | secrets | raw-ask | raw-off | groups-post";;
esac
