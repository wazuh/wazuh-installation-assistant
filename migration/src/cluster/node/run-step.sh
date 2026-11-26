#!/usr/bin/env bash
# run-step.sh <id> <step> [args...] : CL1, on a node, as root, called by migrate-cluster.sh over SSH. Runs the node step
# cluster/node/<step> DETACHED from the SSH session (setsid, nohup), its transcript and exit code in the node's bundle
# (logs/steps/<id>.log, <id>.rc), and follows it until it ends; this script exits with the step's exit code. The design's
# K5 rule: node steps run detached from the controller, so a controller that dies (or an SSH session that drops) does
# not kill a step half way. When migrate-cluster.sh runs again, a step of the same id still running on the node is
# followed, never started twice; one that finished after its caller died (pid file and exit code left, uncollected) is
# reported with its exit code; one already collected is run again and decides from the node's real state, as
# every node step does (a marker on the controller is never trusted for that). The exit code stays on the node after it
# is collected (<id>.rc, replaced only when the step starts again): a follower left running under the SSH session of a
# killed controller collected it itself and removed the pid file, so the rerun started the step again. When the
# controller says its own step was cut (RUN_STEP_RESUME=1), a node step whose last run ended with exit 0 is reported
# from that record and not started again; one that failed is started again.
set -uo pipefail
N="$(dirname "$(readlink -f "$0")")"
if [ "${1:-}" = __run ]; then   # the detached runner itself
  step=$2; log=$3; rcf=$4; shift 4
  bash "$N/$step" "$@" >> "$log" 2>&1; rc=$?
  echo "$rc" > "$rcf.tmp"; sync "$rcf.tmp" 2>/dev/null || sync; mv -f "$rcf.tmp" "$rcf"; sync "$(dirname "$rcf")" 2>/dev/null || sync; exit 0
fi
id=${1:?id}; step=${2:?step}; shift 2
BUNDLE_DIR="${BUNDLE_DIR:-/root/wazuh-migration-bundle}"
D="$BUNDLE_DIR/logs/steps"; mkdir -p "$D"; chmod 700 "$BUNDLE_DIR" 2>/dev/null || true
case "$id" in */*|.*|"") echo "run-step.sh: bad id '$id'"; exit 2;; esac
[ -f "$N/$step" ] || { echo "run-step.sh: no node step $step in $N"; exit 2; }
log="$D/$id.log"; rcf="$D/$id.rc"; pidf="$D/$id.pid"
alive() { local p; p=$(cat "$pidf" 2>/dev/null) && [ -n "$p" ] && kill -0 "$p" 2>/dev/null && grep -q "run-step" "/proc/$p/cmdline" 2>/dev/null; }
if alive; then
  echo "[run-step] $id ($step) is still running on this node (pid $(cat "$pidf"), started by an earlier call): following it, not starting it again"
  off=$(grep -b "^### " "$log" 2>/dev/null | tail -n1 | cut -d: -f1 || true); off=${off:-0}
elif [ -e "$pidf" ] && [ -s "$rcf" ]; then
  # the call that started this step ended before the step did (the controller was killed)
  # and the step then finished on its own. Its exit code is still here, uncollected: the pid file goes only when a
  # follower collects it. It is reported with its transcript, not started again: a second start ran the 5.0 assistant
  # again on an installed manager, which refused ("already installed") and stopped the run on a working node.
  echo "[run-step] $id ($step) finished on this node after the call that started it had ended: exit $(cat "$rcf"); not started again"
  off=$(grep -b "^### " "$log" 2>/dev/null | tail -n1 | cut -d: -f1 || true); off=${off:-0}
  tail -c +"$((off + 1))" "$log"; rc=$(cat "$rcf"); rm -f "$pidf"; exit "$rc"
elif [ "${RUN_STEP_RESUME:-0}" = 1 ] && [ "$(cat "$rcf" 2>/dev/null)" = 0 ]; then
  # the controller's step was cut and this node step's last run ended with exit 0 (collected or not)
  echo "[run-step] $id ($step) finished on this node with exit 0 during the controller's earlier, cut run: not started again"
  off=$(grep -b "^### " "$log" 2>/dev/null | tail -n1 | cut -d: -f1 || true); off=${off:-0}
  tail -c +"$((off + 1))" "$log"; rm -f "$pidf"; exit 0
else
  rm -f "$rcf" "$rcf.tmp"; touch "$log"; off=$(stat -c %s "$log")
  echo "### $(date -u +%FT%TZ) $step $*" >> "$log"
  setsid nohup bash "$0" __run "$step" "$log" "$rcf" "$@" < /dev/null > /dev/null 2>&1 &
  echo $! > "$pidf"
fi
show() { local sz; sz=$(stat -c %s "$log"); if [ "$sz" -gt "$off" ]; then tail -c +"$((off + 1))" "$log" | head -c "$((sz - off))"; off=$sz; fi; }
while :; do
  show
  if [ -s "$rcf" ]; then show; rm -f "$pidf"; exit "$(cat "$rcf")"; fi
  if ! alive; then
    sleep 1; [ -s "$rcf" ] && continue
    echo "[run-step] $id ($step): the runner is gone without an exit code (killed, or the node rebooted)"; rm -f "$pidf"; exit 125
  fi
  sleep "${RUN_STEP_POLL:-1}"
done
