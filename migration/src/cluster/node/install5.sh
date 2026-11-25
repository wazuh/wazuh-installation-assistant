#!/usr/bin/env bash
# install5.sh <-wi|-wm|-wd|-s|-g> [node-name] [extra assistant args...] : runs the 5.0 assistant on this node from
# $WORK_DIR/v5 (never from a directory that holds anything else). For -wm the agent listeners are installed
# CLOSED unless LISTENERS_OPEN=1. CL1: the assistant, config.yml and install files from the node's work_dir ($V5_DIR);
# -d local (a development build's artifact_urls.yaml) only when the inventory staged one, never for a release.
. "$(dirname "$(readlink -f "$0")")/common.sh"
flag=$1; shift
# E5 fold (E5-cluster-rpm 05, E5-cluster-deb 04 and 08, amended): this step decides from the node's real state. The
# controller can lose a step's exit code (killed while the step ran); a rerun then starts it again, and the 5.0 assistant
# refuses a component that is already installed ("already installed ... Use option -o"), so the run could never pass a
# node where the first run had succeeded. A success-only marker of THIS bundle (written on exit 0 only, removed when a
# new run of the assistant starts) says the assistant succeeded here: an earlier success cannot stand for a later run
# that failed, and the end-time marker (written on failure too) is never trusted for it.
ok5="install5${flag}.ok"
case "$flag" in -wi) comp=wazuh-indexer;; -wm) comp=wazuh-manager;; -wd) comp=wazuh-dashboard;; *) comp="";; esac
if [ -n "$comp" ] && [ -s "$STATE/$ok5" ] && [[ "$(pkgver "$comp")" == 5.* ]]; then
  log "$comp $(pkgver "$comp") was installed here by this step at $(cat "$STATE/$ok5") (service $(systemctl is-active "$comp" 2>/dev/null || true)): the assistant is not run again"; exit 0
fi
if [ "$flag" = -g ] && [ -s "$STATE/$ok5" ] && [ -s "$V5_TAR" ]; then
  log "the 5.0 install files are already in $V5_TAR (this bundle's -g succeeded at $(cat "$STATE/$ok5")): not generated again"; exit 0
fi
rm -f "$STATE/$ok5"; sync "$STATE" 2>/dev/null || true
d="$WORK_DIR/v5"; mkdir -p "$d"; chmod 700 "$WORK_DIR"; cp -f "$V5_DIR/wazuh-install.sh" "$d/"
if [ "$flag" = -g ] && { [ -e "$d/wazuh-install-files.tar" ] || [ -d "$d/wazuh-ca" ]; }; then
  # E5 fold (E5-cluster-deb 08): a work_dir used again (a second migration after going back keeps the work_dir) holds an
  # earlier -g's install files and CA, and the 5.0 assistant refuses -g ("File ... already exists"). This bundle has no
  # successful -g of its own (checked above), so they are another attempt's, or a failed one's: removed, shredded
  log "an earlier attempt's 5.0 install files are in $d (no successful -g of this bundle): removed before -g"
  find "$d/wazuh-ca" -type f -exec shred -u {} + 2>/dev/null || true; rm -rf "$d/wazuh-ca"
  shred -u "$d/wazuh-install-files.tar" 2>/dev/null || rm -f "$d/wazuh-install-files.tar"
fi
dev=0; rm -f "$d/artifact_urls.yaml"; if [ -s "$V5_DIR/artifact_urls.yaml" ]; then cp -f "$V5_DIR/artifact_urls.yaml" "$d/"; dev=1; fi
if [ "$flag" = -g ]; then cp -f "$V5_DIR/config.yml" "$d/config.yml"; else cp -f "$V5_TAR" "$d/wazuh-install-files.tar"; fi
envs=(XNONE=1)
if [ "$flag" = -wm ] && [ "${LISTENERS_OPEN:-0}" != 1 ]; then envs=(WAZUH_REMOTE_HTTPS_BIND_ADDR=127.0.0.1 WAZUH_REMOTE_LEGACY_ENABLED=no); fi
args=("$flag" "$@"); case "$flag" in -wi|-wm|-wd) args+=(-id);; esac
[ "$dev" = 1 ] && case "$flag" in -wi|-wm|-wd|-s) args+=(-d local);; esac
log "env ${envs[*]} bash wazuh-install.sh ${args[*]}"
ts > "$STATE/T_install5${flag}_begin"; rc=0
( cd "$d" && env "${envs[@]}" bash ./wazuh-install.sh "${args[@]}" ) > "$LOGS/install-5.0$flag.$(date -u +%H%M%S).log" 2>&1 || rc=$?
l=$(ls -t "$LOGS"/install-5.0$flag.*.log | head -n1)
{ grep -E 'INFO|WARNING|ERROR' "$l" || true; } | sed -E 's/(Password|password|token)[:=].*/\1: MASKED/I' | tail -n 14
ts > "$STATE/T_install5${flag}_end"
if [ "$flag" = -g ] && [ "$rc" = 0 ]; then install -m 600 "$d/wazuh-install-files.tar" "$V5_TAR"; ls -la "$d"; fi
[ "$rc" != 0 ] || mark "$ok5"   # the success-only marker (whole or absent), after everything the step wrote
log "assistant exit $rc"; exit $rc
