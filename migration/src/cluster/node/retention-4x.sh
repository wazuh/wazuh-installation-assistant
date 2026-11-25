#!/usr/bin/env bash
# retention-4x.sh <read|restore4> <4.x-indexer-url> : on the MASTER (the node whose bundle holds the history), through ONE
# 4.x indexer node, as history-dump.sh. F4 (decision 5b and the E3 fold's item 8 on the cluster): the all-in-one's
# precopy.retention and back.retention steps, which the cluster flow did not have (history5-master.sh loaded 365 days
# unless retention-4x.json was placed by hand, and the whole-cluster way back left 4.x with no ISM policy).
#   read      (pre-copy, 4.x live, before the first dump)  mig_helper.py retention-4x: the ISM policies that cover the
#             alert indices and their delete age into retention-4x.json, every policy's body and each alert index's policy
#             into ism-4x.json (a secret part: an error_notification can hold a webhook). A refused read stops (rule 19).
#             export-manager.sh's manifest then covers both files.
#   restore4  (whole-cluster way back, after the history and the folds are back in 4.x and the go-back verify)
#             mig_helper.py ism-restore4: each policy put back (one already there is kept), each restored alert index
#             attached to the policy it had; the indices already past their delete age, or whose age counts from a later
#             date, are named. A bundle without the record goes back and says so.
. "$(dirname "$(readlink -f "$0")")/common.sh"
cmd=${1:?read or restore4}; URL=${2:?the 4.x indexer URL, https://<node-1>:9200}
export V4_INDEXER_ADMIN_PASSWORD MIG_IDX_URL="$URL" MIG_IDX_CAFILE
V4_INDEXER_ADMIN_PASSWORD=$(pw4 admin)
[ -n "$V4_INDEXER_ADMIN_PASSWORD" ] || die "no 4.x admin password in $V4_TAR"
case "$cmd" in
read)
  MIG_IDX_CAFILE=/etc/filebeat/certs/root-ca.pem; [ -s "$MIG_IDX_CAFILE" ] || MIG_IDX_CAFILE=$(ca4)
  rc=0; python3 "$SRC/mig_helper.py" retention-4x "$BUNDLE_DIR/retention-4x.json" 2>&1 | tee "$LOGS/retention-4x.log" || rc=$?
  [ "$rc" = 0 ] || die "the 4.x retention could not be read (rule 19): nothing written"
  chmod 600 "$BUNDLE_DIR/retention-4x.json" "$BUNDLE_DIR/ism-4x.json"
  mark retention.read;;
restore4)
  MIG_IDX_CAFILE=$(ca4)   # the reinstalled 4.x indexers use the original 4.x certificates
  rc=0; python3 "$SRC/mig_helper.py" ism-restore4 "$BUNDLE_DIR/ism-4x.json" 2>&1 | tee "$LOGS/goback-retention.log" || rc=$?
  [ "$rc" = 0 ] || die "the 4.x ISM policies or their attachments could not all be put back (see above)"
  mark goback.retention;;
*) die "usage: retention-4x.sh read|restore4 <4.x-indexer-url>";;
esac
