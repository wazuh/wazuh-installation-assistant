#!/usr/bin/env bash
# history-load-4x.sh <4.x-indexer-url> : going back. Loads the history bundle into the reinstalled 4.x indexer cluster, daily layout as it was.
# the shipped src/load_unchanged.py (the all-in-one's back reload; it replaced the lab's own loader),
# which creates each index with the creation date dump.py recorded, so the 4.x ISM policies retention-4x.sh restore4 puts
# back count each index's age from its first creation, not from this load.
. "$(dirname "$(readlink -f "$0")")/common.sh"
URL=$1; shift; export IDX_PASS; IDX_PASS=$(pw4 admin)
ca=/etc/filebeat/certs/root-ca.pem; [ -s "$ca" ] || ca=$(ca4)
t0=$SECONDS
python3 "$SRC/load_unchanged.py" --bundle "$BUNDLE_DIR/history" --url "$URL" --user admin --password-env IDX_PASS --cafile "$ca" --state-dir "$BUNDLE_DIR/history-load-state-goback" "$@" 2>&1 | tail -n 12
log "history load into 4.x finished in $((SECONDS - t0)) s"
