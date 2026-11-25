#!/usr/bin/env bash
# fold-alertsjson.sh <node-name> | --merge <fold.tar> : on EACH manager node after its freeze (orders B and C). The part
# of this node's 4.x alerts.json that Filebeat never shipped (offset recorded at the freeze), for every generation of
# this node's bundle (v4.gen*/ of earlier attempts, then v4/: K5, every generation is folded).
# CL1 (the guide's point a): no longer loaded unshaped into wazuh-alerts-4.x-YYYY.MM on 5.0, which the history's aliases
# do not cover (those alerts did not show in the 5.0 screens). They are written in the history dump's format and merged
# into the master's history bundle, loaded, shaped, proven and switched on with the rest by the history phase:
#   on the node that holds the history bundle (the master): merged at once
#   on a worker: packed into history-fold/fold-<node>.tar, which migrate-cluster.sh streams to the master, and the
#   master runs  fold-alertsjson.sh --merge <tar>
# The bundle's MANIFEST.sha256 is refreshed for what the merge wrote, so the way back's manifest check still holds. The
# way back's bulk file (alertsjson-fold.ndjson.gz, goback-fold-4x.sh) is written too.
. "$(dirname "$(readlink -f "$0")")/common.sh"
F="$SRC/cluster/alertsjson-fold.py"; H="$BUNDLE_DIR/history"; O="$BUNDLE_DIR/history-fold"; mkdir -p "$O"
refresh_manifest() { # the bundle-relative paths on stdin: their MANIFEST.sha256 lines replaced (export-manager.sh's format)
  local p; [ -s "$BUNDLE_DIR/MANIFEST.sha256" ] || return 0
  while IFS= read -r p; do [ -n "$p" ] || continue
    ( cd "$BUNDLE_DIR" && grep -v -F "  ./$p" MANIFEST.sha256 > MANIFEST.sha256.tmp; sha256sum "./$p" >> MANIFEST.sha256.tmp; mv -f MANIFEST.sha256.tmp MANIFEST.sha256 )
  done; }
merge() { # merge <fold-dir>
  local out; out=$(python3 "$F" merge "$1" "$H") || die "the fold could not be merged into the history bundle"
  head -n 1 <<<"$out"; tail -n +2 <<<"$out" | refresh_manifest; }
if [ "${1:-}" = --merge ]; then
  t=${2:?the fold tar}; [ -s "$H/manifest.json" ] || die "this node holds no history bundle: merge on the master"
  d="$O/in/$(basename "$t" .tar)"; rm -rf "$d"; mkdir -p "$d"; tar -xf "$t" -C "$d"
  for f in "$d"/*/fold.json; do [ -e "$f" ] || continue; merge "$(dirname "$f")"; done
  mark "fold.merged.$(basename "$t" .tar)"; exit 0
fi
NODE=${1:?the node name}; n=0
for G in $(cd "$BUNDLE_DIR" && ls -d v4.gen* 2>/dev/null | sort -V) v4; do
  p="$BUNDLE_DIR/$G/filebeat-not-shipped.json"; a="$BUNDLE_DIR/$G/alerts/alerts.json"
  [ -s "$p" ] || { [ "$G" = v4 ] && die "no Filebeat offset recorded at the freeze ($p)"; continue; }
  [ -s "$a" ] || { log "$G: no alerts.json in the bundle: nothing to fold"; continue; }
  off=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["filebeat_offset"])' "$p"); label="$NODE-$G"
  python3 "$F" dumpfold "$a" "$off" "$NODE" "$label" "$O/$label" || die "the fold of $G could not be written"
  [ -s "$BUNDLE_DIR/$G/alertsjson-fold.ndjson.gz" ] || python3 "$F" bulk "$a" "$off" "$NODE" "$BUNDLE_DIR/$G/alertsjson-fold.ndjson.gz" > /dev/null
  n=$((n + 1))
  if [ -s "$H/manifest.json" ]; then merge "$O/$label"; fi
done
if [ ! -s "$H/manifest.json" ]; then
  ( cd "$O" && tar -cf "fold-$NODE.tar" $(ls -d "$NODE"-v4* 2>/dev/null) ) || die "the fold could not be packed"
  log "$n generation(s) folded: history-fold/fold-$NODE.tar, for the master's history bundle"
else log "$n generation(s) folded into the history bundle"; fi
mark fold.done
