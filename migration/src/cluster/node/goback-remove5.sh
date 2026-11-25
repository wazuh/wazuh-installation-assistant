#!/usr/bin/env bash
# goback-remove5.sh [check <role>] : on EVERY node, going back to 4.x before the point of no return. Removes 5.0 with the
# 5.0 assistant (-u).
#   check <role>  E5 fold (E5-cluster-deb gap 2): read-only, run on every node BEFORE the way back removes anything
#                 anywhere. back.remove5 runs on every node in parallel, and one node's refusal (the master's bundle
#                 check) left the others already without Wazuh and the cluster half removed. Refuses when this node's
#                 bundle does not match its manifest, when the files the way back needs are not here (the 5.0 assistant
#                 for the removal, the 4.x assistant and the original 4.x install files for the reinstall, the master's
#                 history bundle), or when 4.x is still installed here with no export in this bundle: the 5.0 assistant's
#                 -u removes packages by name, so it would remove this 4.x node with nothing to restore it from.
. "$(dirname "$(readlink -f "$0")")/common.sh"
if [ "${1:-}" = check ]; then
  role=${2:-unknown}; why=()
  if [ -s "$BUNDLE_DIR/MANIFEST.sha256" ]; then bundle_verify > "$LOGS/goback-check-manifest.log" 2>&1 || why+=("the bundle does not match its manifest ($(head -n 3 "$LOGS/goback-check-manifest.log" | tr '\n' ' '))")
  elif [ -e "$STATE/export.done" ]; then why+=("export.done is recorded but MANIFEST.sha256 is missing from the bundle"); fi
  [ -s "$V5_DIR/wazuh-install.sh" ] || why+=("the 5.0 assistant is not at $V5_DIR/wazuh-install.sh (the removal needs it)")
  [ -s "$V4_ASSISTANT_FILE" ] || why+=("the 4.x assistant is not at $V4_ASSISTANT_FILE (the reinstall needs it)")
  [ -s "$V4_TAR" ] || why+=("the original 4.x install files are not at $V4_TAR (the reinstall needs them)")
  if [ "$role" = master ] && [ ! -s "$BUNDLE_DIR/history/manifest.json" ]; then why+=("no history dump in this bundle ($BUNDLE_DIR/history): the old alerts could not go back into 4.x"); fi
  for p in wazuh-manager wazuh-indexer wazuh-dashboard; do v=$(pkgver "$p")
    if [[ "$v" == 4.* ]] && [ ! -e "$STATE/export.done" ]; then why+=("$p $v (4.x) is still installed on this node and this bundle holds no export of it: the 5.0 assistant's -u would remove it with nothing to restore it from")
    fi; done
  if [ ${#why[@]} -gt 0 ]; then for w in "${why[@]}"; do log "REFUSED: $w"; done; die "going back is refused on this node ($(nodelabel), $role): nothing was removed"; fi
  log "this node can go back ($role): bundle$( [ -s "$BUNDLE_DIR/MANIFEST.sha256" ] && echo " verified" || echo " without a manifest (no export on this node)"), the 5.0 and 4.x assistants and the 4.x install files are here"
  exit 0
fi
if [ -s "$BUNDLE_DIR/MANIFEST.sha256" ]; then bundle_verify || die "the bundle does not match its manifest: not removing 5.0"; log "bundle verified"; fi
d="$WORK_DIR/v5"; mkdir -p "$d"; cp -f "$V5_DIR/wazuh-install.sh" "$d/"
ts > "$STATE/T_goback_remove5_begin"
( cd "$d" && bash ./wazuh-install.sh -u ) > "$LOGS/goback-remove-5.0.log" 2>&1 || { tail -n 20 "$LOGS/goback-remove-5.0.log"; die "5.0 uninstall failed"; }
grep -E 'INFO|WARNING|ERROR' "$LOGS/goback-remove-5.0.log" | tail -n 4
{ for p in /var/wazuh-manager /etc/wazuh-manager /var/lib/wazuh-indexer /etc/wazuh-indexer /usr/share/wazuh-indexer /etc/wazuh-dashboard /usr/share/wazuh-dashboard /var/lib/wazuh-dashboard; do [ -e "$p" ] && echo "path $p"; done
  pkgs | sed 's/^/package /'; getent passwd wazuh wazuh-manager wazuh-indexer wazuh-dashboard | cut -d: -f1 | sed 's/^/user /'; } > "$LOGS/leftovers-after-5.0-removal.txt" || true
log "left after the 5.0 uninstall: $(tr '\n' ';' < "$LOGS/leftovers-after-5.0-removal.txt")"
rm -f "$STATE"/install5-*.ok   # E5 fold: 5.0 is gone from this node; its install markers no longer describe it
if [ -s "$BUNDLE_DIR/MANIFEST.sha256" ]; then bundle_verify || die "the bundle changed during the 5.0 removal"; fi
mark goback.remove5.done
