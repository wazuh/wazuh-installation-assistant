#!/usr/bin/env bash
# guard.sh <on|off|show|reapply|persist|unpersist> <agent|cluster> : on a manager node (K5's node step).
# The rules, their record and the wazuh-manager drop-in that re-applies them before any manager starts are the shared
# implementation in ../../guard.sh (also used by migrate.sh): agent = 1514, 1515, 1517; cluster = 1516; refused to
# everything but loopback. `on` records and persists at once (K5 needed a separate `persist`: kept as a no-op alias).
. "$(dirname "$(readlink -f "$0")")/common.sh"
G="$(dirname "$(readlink -f "$0")")/../../guard.sh"; [ -f "$G" ] || die "the shared guard is not at $G: push the whole src/ tree"
case $1 in
  on|off) bash "$G" "$1" "${2:-agent}" "$STATE"; ts > "$STATE/T_guard_${2:-agent}_$1"; log "${2:-agent} guard $1" ;;
  reapply) bash "$G" reapply "$STATE"; exit 0 ;;
  persist|unpersist) log "guard.sh $1: the shared guard persists itself on 'on' and removes its drop-in when no guard is recorded" ;;
  show|*) for g in agent cluster; do echo "$g guard: $(bash "$G" status $g "$STATE")"; done ;;
esac
