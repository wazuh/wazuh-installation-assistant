#!/usr/bin/env bash
# history-dump.sh <indexer-url> : on the node that holds the bundle (the master here). First run with 4.x live is the
# pre-copy; a second run after the freeze takes only the delta. Needs HTTPS to ONE 4.x indexer node, nothing shared.
. "$(dirname "$(readlink -f "$0")")/common.sh"
URL=$1; export IDX_PASS; IDX_PASS=$(pw4 admin)
ca=/etc/filebeat/certs/root-ca.pem; [ -s "$ca" ] || ca=$(ls /etc/wazuh-indexer/certs/root-ca.pem /etc/wazuh-dashboard/certs/root-ca.pem 2>/dev/null | head -n1 || true)
t0=$SECONDS
python3 "$SRC/dump.py" --url "$URL" --user admin --password-env IDX_PASS --cafile "$ca" --out "$BUNDLE_DIR/history" 2>&1 | tail -n 12
log "history dump run finished in $((SECONDS - t0)) s; bundle $(du -sh "$BUNDLE_DIR/history" | cut -f1)"
