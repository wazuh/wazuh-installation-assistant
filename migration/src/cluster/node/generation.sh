#!/usr/bin/env bash
# generation.sh keep : CL1, on the MASTER after its way back alone (back master). The next forward attempt's freeze and
# export write v4/ and identity/ again; this attempt's are kept as v4.gen<N>/ and identity.gen<N>/ first, so its
# alerts.json past the Filebeat offset is still folded (K5: overwriting the first generation lost 26 alerts). It was a
# lab step in k5.sh (forward2 newgen).
. "$(dirname "$(readlink -f "$0")")/common.sh"
[ "${1:-}" = keep ] || die "usage: generation.sh keep"
[ -d "$BUNDLE_DIR/v4" ] || { log "no v4/ in the bundle: nothing to keep"; exit 0; }
i=1; while [ -e "$BUNDLE_DIR/v4.gen$i" ]; do i=$((i + 1)); done
mv "$BUNDLE_DIR/v4" "$BUNDLE_DIR/v4.gen$i"; [ ! -d "$BUNDLE_DIR/identity" ] || mv "$BUNDLE_DIR/identity" "$BUNDLE_DIR/identity.gen$i"
rm -f "$STATE/export.done" "$STATE/freeze.done" "$STATE/remove4x.done" "$STATE/fold.done"
log "this attempt's v4/ and identity/ kept as generation $i; the next freeze starts generation $((i + 1))"
