#!/usr/bin/env bash
# goback-install4.sh <--wazuh-indexer|--wazuh-server|--wazuh-dashboard|--start-cluster> [name] : reinstalls 4.14 on this node with the
# ORIGINAL 4.x wazuh-install-files.tar (same certificates, cluster key and passwords as before the migration).
. "$(dirname "$(readlink -f "$0")")/common.sh"
flag=$1; shift
# E5 fold (with install5.sh's success-only rule): from the node's real state. A way back cut inside
# the 4.x reinstall (a reboot during the assistant's Filebeat step) left the packages installed, and the assistant
# refuses "already installed ... use -o" on every rerun, so the way back could never go on.
#   - this bundle's success marker (written on exit 0 only) and the packages there: done, not run again;
#   - the server's packages all at 4.14.x without the marker (the cut above): not run again; the restore that follows
#     puts back the node's configuration and registry from the bundle and the Filebeat repair compares /etc/filebeat
#     with it (the lab's case, E5-cluster-rpm CL-L9);
#   - any other part-installed state (an indexer or dashboard package without the marker, or the server's packages only
#     in part): run again with -o, which overwrites; nothing on this node is kept at this point of the way back (the
#     alerts are loaded into the indexers after this step, the registry restored after it)
#   - a 5.0 package still here: the 5.0 removal did not finish; stop.
ok4="goback-install4${flag}.ok"; over=()
case "$flag" in --wazuh-server) need="wazuh-manager filebeat";; --wazuh-indexer) need=wazuh-indexer;; --wazuh-dashboard) need=wazuh-dashboard;; *) need="";; esac
if [ -n "$need" ]; then
  have=""; all=1; v4=1
  for p in $need; do v=$(pkgver "$p")
    if [ -z "$v" ]; then all=0; continue; fi
    have="$have $p $v"; [[ "$p" == filebeat || "$v" == 4.14.* ]] || v4=0
    [[ "$p" == filebeat || "$v" != 5.* ]] || die "$p $v is still installed: the 5.0 removal did not finish on this node (run the way back again)"
  done
  if [ -s "$STATE/$ok4" ] && [ "$all" = 1 ]; then log "already reinstalled here by this step at $(cat "$STATE/$ok4") ($have ): the 4.x assistant is not run again"; exit 0; fi
  if [ "$flag" = --wazuh-server ] && [ "$all" = 1 ] && [ "$v4" = 1 ]; then
    log "the packages are installed ($have ) but this step did not record a success (a cut during the reinstall): the 4.x assistant is not run again; the restore puts back the configuration and registry from the bundle, and the Filebeat repair /etc/filebeat"
    exit 0
  fi
  if [ -n "$have" ]; then over=(-o); log "part-installed by an earlier attempt that did not finish ($have ): reinstalled with -o (overwrite; nothing on this node is kept at this point of the way back)"; fi
fi
v4_assistant_check || die "not reinstalling 4.x with an assistant of another version"
rm -f "$STATE/$ok4"
d="$WORK_DIR/v4-reinstall"; mkdir -p "$d"; cp -f "$V4_ASSISTANT_FILE" "$d/wazuh-install.sh"; cp -f "$V4_TAR" "$d/wazuh-install-files.tar"
args=("$flag" "$@" ${over[@]+"${over[@]}"}); [ "$flag" = --wazuh-dashboard ] && args+=(-i)
log "bash wazuh-install.sh ${args[*]}"; rc=0
( cd "$d" && bash ./wazuh-install.sh "${args[@]}" ) 2>&1 | mask_passwords > "$LOGS/goback-install-4x$flag.log" || rc=${PIPESTATUS[0]}   # the summary prints the admin password
grep -E 'INFO|WARNING|ERROR' "$LOGS/goback-install-4x$flag.log" | sed -E 's/(Password|password): .*/\1: MASKED/' | tail -n 5
# the working copy of the 4.x install files (every 4.x password and the cluster key) is needed only
# while the assistant runs; left here it fails the finish's secret sweep of the work directory (the all-in-one's back.secrets)
shred -u "$d/wazuh-install-files.tar" 2>/dev/null || rm -f "$d/wazuh-install-files.tar"
[ "$rc" != 0 ] || mark "$ok4"   # the success-only marker
log "4.x assistant exit $rc (its copy of the install files removed)"; exit $rc
