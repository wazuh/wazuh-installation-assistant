#!/usr/bin/env bash
# guard.sh - the host firewall guard, one implementation for the all-in-one (migrate.sh) and the cluster node steps.
#
#   guard.sh on|off|status <agent|cluster> <state-dir>
#   guard.sh reapply <state-dir>            (run by the wazuh-manager drop-in before any manager starts)
#
#   agent   : TCP 1514, 1515, 1517 refused to everything but loopback (R2's guard; necessary and sufficient on the way
#             back; phases 5 to 7 hold both halves of rule 5 whatever the manager configuration says)
#   cluster : TCP 1516 refused to everything but loopback (K5: a reinstalled 4.x master rejoined the live 4.x worker within
#             seconds, emptied its registry and re-keyed an agent; the master's way back guards 1516 until its registry
#             equals the bundle)
#
# Merged from R2/F5 (`migrate.sh guard()`: a chain of its own, nft where iptables is missing, re-applied from its record on
# every resume) and K5 (`tools/node/guard.sh`: named guards, a state file per guard, and a wazuh-manager drop-in whose
# ExecStartPre puts back every recorded guard before any manager starts, so the guard is node state that survives a
# reboot; an iptables-only guard vanished at K5's reboot and the takeover happened again). Rule 11.
set -uo pipefail
ACT=${1:-status}; NAME=${2:-agent}; SD=${3:-${MIG_GUARD_STATE:-}}
[ "$ACT" = reapply ] && SD=${2:-${MIG_GUARD_STATE:-}}
[ -n "$SD" ] || { echo "guard.sh: no state directory" >&2; exit 2; }
DROPIN_DIR=${MIG_GUARD_DROPIN_DIR:-/etc/systemd/system/wazuh-manager.service.d}   # the env names are for tests and packaging
DROPIN=$DROPIN_DIR/zz-wazuh-migration-guard.conf
COPY=${MIG_GUARD_COPY:-/usr/local/sbin/wazuh-migration-guard.sh}   # outside every directory an installer deletes; the drop-in runs this copy
ts() { date -u +%Y-%m-%dT%H:%M:%SZ; }

ports_for() { case "$1" in agent) echo "1514,1515,1517";; cluster) echo "1516";; *) echo "guard name: agent or cluster" >&2; return 2;; esac; }
chain_for() { case "$1" in agent) echo MIGGUARD;; cluster) echo MIGGUARD_CLUSTER;; esac; }
tool() { if command -v iptables >/dev/null 2>&1; then echo iptables; elif command -v nft >/dev/null 2>&1; then echo nft; else echo none; fi; }

rule_on() { # rule_on <name>
  local n=$1 p c; p=$(ports_for "$n") || return 2; c=$(chain_for "$n")
  case "$(tool)" in
    iptables) iptables -N "$c" 2>/dev/null || iptables -F "$c"
              iptables -A "$c" -i lo -j RETURN
              iptables -A "$c" -p tcp -m multiport --dports "$p" -j REJECT --reject-with tcp-reset
              iptables -C INPUT -j "$c" 2>/dev/null || iptables -I INPUT 1 -j "$c";;
    nft) nft add table inet migguard 2>/dev/null || true
         nft "add chain inet migguard $n { type filter hook input priority -10 ; policy accept ; }" 2>/dev/null || true
         nft flush chain inet migguard "$n"; nft add rule inet migguard "$n" iifname lo accept
         nft add rule inet migguard "$n" tcp dport "{ ${p//,/, } }" reject with tcp reset;;
    none) return 3;;
  esac
}
rule_off() {
  local n=$1 c; c=$(chain_for "$n")
  case "$(tool)" in
    iptables) while iptables -C INPUT -j "$c" 2>/dev/null; do iptables -D INPUT -j "$c"; done
              iptables -F "$c" 2>/dev/null || true; iptables -X "$c" 2>/dev/null || true;;
    nft) nft delete chain inet migguard "$n" 2>/dev/null || true
         nft list table inet migguard 2>/dev/null | grep -q 'chain ' || nft delete table inet migguard 2>/dev/null || true;;
  esac
  return 0
}
rule_status() {
  local n=$1 c; c=$(chain_for "$n")
  case "$(tool)" in
    iptables) iptables -C INPUT -j "$c" 2>/dev/null && echo on || echo off;;
    nft) nft list chain inet migguard "$n" >/dev/null 2>&1 && echo on || echo off;;
    none) echo unavailable;;
  esac
}
persist() { # the drop-in that re-applies every recorded guard before any wazuh-manager unit starts (4.x or 5.0)
  mkdir -p "$DROPIN_DIR"; cp -f "$(readlink -f "$0")" "$COPY"; chmod 755 "$COPY"
  command -v restorecon >/dev/null 2>&1 && restorecon "$COPY" 2>/dev/null || true   # SELinux enforcing
  # "+" runs this one command with full privileges, outside the unit's sandbox. The 5.0 unit sets
  # ProtectHome=yes (a bundle under /root is invisible: the reapply found no record and exited 0) and a capability bounding
  # set without CAP_NET_ADMIN (iptables could not write). systemd 231 or later (RHEL 8+, Ubuntu 18.04+). K5 had proven the
  # drop-in on a 4.x unit only, which has no sandbox.
  printf '[Service]\nExecStartPre=+/bin/bash %s reapply %s\n' "$COPY" "$SD" > "$DROPIN"
  systemctl daemon-reload 2>/dev/null || true
}
# the copy the drop-in ran goes with the drop-in (it was left in /usr/local/sbin after the finish)
unpersist() { rm -f "$DROPIN" "$COPY"; rmdir "$DROPIN_DIR" 2>/dev/null || true; systemctl daemon-reload 2>/dev/null || true; }

case "$ACT" in
  on)
    mkdir -p "$SD"
    if ! rule_on "$NAME"; then
      echo "WARNING: no iptables or nft on this host: no $NAME guard; the listeners are held closed by the manager configuration only (use the cloud security group or hypervisor network to hold agents off)"
      exit 3
    fi
    ts > "$SD/guard.required.$NAME"; persist
    echo "$NAME guard ON ($(ports_for "$NAME") refused to everything but loopback; re-applied before any manager start)";;
  off)
    rule_off "$NAME"; rm -f "$SD/guard.required.$NAME"
    ls "$SD"/guard.required.* >/dev/null 2>&1 || unpersist
    echo "$NAME guard OFF";;
  status) rule_status "$NAME";;
  reapply)
    for g in agent cluster; do
      [ -e "$SD/guard.required.$g" ] || continue
      [ "$(rule_status $g)" = on ] && continue
      rule_on "$g" && echo "$g guard RE-APPLIED before the manager starts (recorded on since $(cat "$SD/guard.required.$g"))"
    done; exit 0;;
  *) echo "usage: guard.sh on|off|status agent|cluster STATE_DIR | reapply STATE_DIR" >&2; exit 2;;
esac
