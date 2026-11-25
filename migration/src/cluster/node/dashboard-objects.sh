#!/usr/bin/env bash
# dashboard-objects.sh <export|import5|import4> <dashboard-url> [5.0 indexer address] : on the MASTER (the node whose bundle
# the cluster flow goes back from). E2 fold, E2-cluster gap 4: the cluster bundle held no saved objects, so the whole-
# cluster go-back lost every custom dashboard ("ACME payments overview") and nothing carried them to 5.0. The
# all-in-one's steps, with the dashboard and the indexer on other hosts (mig_helper.py's MIG_DASH*_URL, MIG_IDX5_* inputs):
#   export  (pre-copy, 4.x live)  migrate.sh pc_saved_objects: the custom dashboards, visualizations and searches into
#           dashboard/saved-objects.ndjson (export-manager.sh's manifest then covers it)
#   import5 (after the master's history `on`)  migrate.sh im_saved_objects: as a view of the history through its aliases,
#           never overwriting an existing object, every changed attribute recorded for rule 20's rollback
#   import4 (whole-cluster go-back, 4.x dashboard reinstalled)  migrate.sh bk_restore step 6
. "$(dirname "$(readlink -f "$0")")/common.sh"
cmd=${1:?export, import5 or import4}; DASH=${2:?the dashboard URL, https://<dashboard>:443}
F="$BUNDLE_DIR/dashboard/saved-objects.ndjson"
case "$cmd" in
export)
  mkdir -p "$BUNDLE_DIR/dashboard"
  V4_INDEXER_ADMIN_PASSWORD=$(pw4 admin) MIG_DASH4_URL="$DASH" python3 "$SRC/mig_helper.py" export-saved-objects "$F" || die "saved objects export failed"
  chmod -R go= "$BUNDLE_DIR/dashboard"; mark dashboard.export
  log "saved objects exported: $(grep -c . "$F") object(s) in $F";;
import5)
  IDX=${3:?the address of one 5.0 indexer node}
  [ -s "$F" ] || die "no saved objects in this node's bundle (run 'export' at the pre-copy)"
  MIG_DASH5_URL="$DASH" MIG_IDX5_HOST="$IDX" MIG_IDX5_PASSWORD="$(v5cred WAZUH_INDEXER_ADMIN_PASSWORD)" \
    python3 "$SRC/mig_helper.py" import-saved-objects "$F" || die "saved objects import failed (is the history switched on?)"
  mark dashboard.import5;;
import4)
  [ -s "$F" ] || die "no saved objects in this node's bundle"
  pw=$(pw4 admin); code=""
  for i in $(seq 1 40); do   # refused while the 4.x dashboard starts (R2: curl exit 7)
    code=$(curl -sk -o "$LOGS/goback-saved-objects.out" -w '%{http_code}' -u "admin:$pw" -X POST "$DASH/api/saved_objects/_import?overwrite=true" \
           -H 'osd-xsrf: true' --form "file=@$F;filename=v4.ndjson" || true)
    [ "$code" = 200 ] && break; sleep 5
  done
  log "saved objects import into the 4.x dashboard: HTTP $code $(cut -c1-160 "$LOGS/goback-saved-objects.out")"
  [ "$code" = 200 ] || die "the 4.x dashboard refused the saved objects"; mark goback.dashboard;;
*) die "usage: dashboard-objects.sh export|import5|import4 <dashboard-url> [indexer]";;
esac
