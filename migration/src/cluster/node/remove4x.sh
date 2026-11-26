#!/usr/bin/env bash
# remove4x.sh : on EVERY node. Removes 4.x with the 4.x assistant (-u), after verifying this node's bundle (if it has one).
# rpm: the 4.x assistant's -u leaves a Filebeat process running from a deleted binary (arm f1b); it is recorded, then stopped.
. "$(dirname "$(readlink -f "$0")")/common.sh"
# a MANAGER node is removed only with its export done and verified. The check was "verify the manifest
# if there is one", so a manager whose identity export had failed (no manifest) was removed with nothing exported.
if [ -x /var/ossec/bin/wazuh-control ] && [ -e /var/ossec/etc/ossec.conf ]; then
  [ -e "$STATE/export.done" ] && [ -s "$BUNDLE_DIR/MANIFEST.sha256" ] || die "this is a manager node and its bundle has no completed export (export.done, MANIFEST.sha256): not removing 4.x"
fi
if [ -s "$BUNDLE_DIR/MANIFEST.sha256" ]; then bundle_verify || die "the bundle does not match its manifest: not removing 4.x"; log "bundle verified"; fi
v4_assistant_check || die "not removing 4.x with an assistant of another version"
mkdir -p "$WORK_DIR/v4-uninstall"; cp -f "$V4_ASSISTANT_FILE" "$WORK_DIR/v4-uninstall/wazuh-install.sh"
ts > "$STATE/T_remove4x_begin"
( cd "$WORK_DIR/v4-uninstall" && bash ./wazuh-install.sh -u ) > "$LOGS/remove-4x.log" 2>&1 || { tail -n 20 "$LOGS/remove-4x.log"; die "4.x uninstall failed"; }
tail -n 3 "$LOGS/remove-4x.log"
leftovers > "$LOGS/leftovers-after-4x-removal.txt"; log "left after the 4.x uninstall: $(grep -c . "$LOGS/leftovers-after-4x-removal.txt") item(s)"; sed 's/^/    /' "$LOGS/leftovers-after-4x-removal.txt"
if pgrep -x filebeat >/dev/null; then
  log "orphan Filebeat process after the removal: $(for p in $(pgrep -x filebeat); do echo "pid $p exe $(readlink /proc/$p/exe)"; done | tr '\n' ' ')"
  systemctl stop filebeat 2>/dev/null || true; pkill -x filebeat || true; sleep 2
  pgrep -x filebeat >/dev/null && die "Filebeat still running" || log "orphan Filebeat stopped"
fi
# the 4.x repository the assistant left, on deb or rpm (the all-in-one's REPO_FILES)
# wazuh.gpg~, the keyring's backup copy, was left on every deb node
rm -f /etc/apt/sources.list.d/wazuh.list /etc/apt/sources.list.d/wazuh.sources /usr/share/keyrings/wazuh.gpg /usr/share/keyrings/wazuh.gpg~ /etc/yum.repos.d/wazuh.repo 2>/dev/null || true
systemctl daemon-reload
[ -z "$(pkgver wazuh-manager)$(pkgver wazuh-indexer)$(pkgver wazuh-dashboard)$(pkgver filebeat)" ] || die "a 4.x package is still installed"
if [ -s "$BUNDLE_DIR/MANIFEST.sha256" ]; then bundle_verify || die "the bundle changed during the 4.x removal"; fi
mark remove4x.done
