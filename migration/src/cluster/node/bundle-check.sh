#!/usr/bin/env bash
# bundle-check.sh <precopy|history|manifest> : CL1, read-only, on a node with a bundle (the all-in-one's pre-copy gate and
# verify_bundle, per node). precopy: the history dump exists and every file reads back equal to its checksum (the dump
# may still be incomplete: 4.x is live). history: the same, and every index complete (the delta after the Filebeat stop).
# manifest: the node's MANIFEST.sha256 reads back equal.
. "$(dirname "$(readlink -f "$0")")/common.sh"
case "${1:-}" in
precopy|history)
  [ -s "$BUNDLE_DIR/history/manifest.json" ] || die "no history dump in this node's bundle ($BUNDLE_DIR/history)"
  python3 - "$SRC" "$BUNDLE_DIR/history" "$1" <<'PY' || die "the history dump is not usable: see above"
import sys
sys.path.insert(0, sys.argv[1])
import history_load as h
b = h.Bundle(sys.argv[2]); n, bad = b.verify(allow_incomplete=(sys.argv[3] == "precopy"))
for x in bad[:20]: print("  " + x)
print("history dump: %d file(s) checked, %d month(s), %d document(s) expected%s" % (n, len(b.months), b.total(), "" if not bad else ", %d problem(s)" % len(bad)))
sys.exit(1 if bad else 0)
PY
  ;;
manifest)
  [ -s "$BUNDLE_DIR/MANIFEST.sha256" ] || die "no MANIFEST.sha256 in this node's bundle"
  bundle_verify || die "the bundle does not match its manifest"
  log "every one of $(grep -c . "$BUNDLE_DIR/MANIFEST.sha256") bundle file(s) reads back equal to its checksum";;
*) die "usage: bundle-check.sh precopy|history|manifest";;
esac
