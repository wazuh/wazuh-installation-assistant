#!/usr/bin/env bash
# identity-stage-master.sh : E2-cluster wiring (new node step). On the 5.0 MASTER, running, listeners closed: the merged
# identity stage (src/identity_stage.py) in place of the identity tool's import (import-master.sh), followed by
# what migrate.sh phase 6 does after it on an all-in-one: import.restart (clean stop and start, cluster daemon answering,
# rule 4), import.passwords, the identity part of import.reconcile (identity_stage.py verify; run again on a difference)
# and the limit gate of im_gate (rule 15). Mirrors migrate.sh im_identity, im_restart, im_passwords, im_reconcile, im_gate.
. "$(dirname "$(readlink -f "$0")")/common.sh"
V5=/var/wazuh-manager; V5ETC=/etc/wazuh-manager; py=$V5/framework/python/bin/python3; S="$SRC"
MODE=${IDENTITY_LIMIT_MODE:-raise}; W=1; [ "$MODE" = raise ] && W=4
v5env() { sed -n "s/^$2=//p" "$1" | head -n1 | sed "s/^'\(.*\)'$/\1/"; }
wait_api() { local i; for i in $(seq 1 60); do curl -sk -o /dev/null -m 5 https://localhost:55000/ && return 0; sleep 3; done; return 1; }
wait_clusterd() { local i out; for i in $(seq 1 30); do out=$(timeout 30 $V5/bin/cluster_control -l 2>&1) && { echo "$out" | tail -n 3; return 0; }; sleep 15; done; echo "cluster daemon not answering: $out"; return 1; }
passwords() { local i; for i in 1 2 3 4 5 6 7 8; do
    if v5env $V5ETC/export/credentials.env WAZUH_MANAGER_API_PASSWORD | $V5/bin/rbac_control change-password -u wazuh -p - \
       && v5env $V5ETC/export/credentials.env WAZUH_MANAGER_WUI_PASSWORD | $V5/bin/rbac_control change-password -u wazuh-internal-client -p -; then
      curl -sk -u "wazuh:$(v5env $V5ETC/export/credentials.env WAZUH_MANAGER_API_PASSWORD)" -X POST "https://localhost:55000/security/user/authenticate?raw=true" | grep -q '^ey' \
        && { log "wazuh and wazuh-internal-client are back on the 5.0 passwords; login as wazuh works"; return 0; }
    fi; sleep 10; done; return 1; }
# E4-breaker fix 02 on the cluster: a 4.x source enrolling without a password (the 4.x assistant's default) has no
# authd.pass in the identity bundle, and --with-password then blocks the import; carried only when the source had one
pwflag() { [ -s "$BUNDLE_DIR/identity/authd.pass" ] && echo --with-password || true; }
run_stage() { $py "$S/identity_stage.py" run "$BUNDLE_DIR/identity" --state "$BUNDLE_DIR/identity-stage" --limit-mode "$MODE" \
      --workers "$W" $(pwflag) --with-rbac >> "$LOGS/identity-stage-run.log" 2>&1; }
[ -e "$STATE/T_import_begin" ] || ts > "$STATE/T_import_begin"
log "identity stage run (limit mode $MODE, $W worker(s))"
run_stage || { tail -n 30 "$LOGS/identity-stage-run.log"; die "identity stage failed"; }
grep -E 'GATE|REFUSE|cut import|preflight:|limit|inserted|repair' "$LOGS/identity-stage-run.log" | cut -c1-300 | tail -n 12
[ -z "${MIG_TEST_STOP_AFTER_STAGE:-}" ] || { log "MIG_TEST_STOP_AFTER_STAGE is set (unit tests only): stopping after the identity stage"; exit 0; }
# CL1 (parity with the all-in-one's import.settings): the master's converted settings are staged now,
# after the identity stage's own restarts and before the clean restart below, which applies them (one restart, inside
# the master's outage, as migrate.sh's import.restart); a manager that does not come up on them gets the saved files back
N="$(dirname "$(readlink -f "$0")")"; staged=0
if [ "${CARRY_SETTINGS:-1}" = 1 ] && [ ! -e "$STATE/settings.staged" ]; then
  bash "$N/settings-node.sh" stage || die "the settings stage refused (nothing staged): see above"; staged=1
elif [ -e "$STATE/settings.staged" ]; then staged=1; fi
t0=$SECONDS; systemctl stop wazuh-manager; log "clean stop of the 5.0 master took $((SECONDS - t0)) s"
if ! { systemctl restart wazuh-manager && wait_api; }; then
  if [ "$staged" = 1 ]; then log "the master did not come up on the converted settings: putting the saved installed files back"
    bash "$N/settings-node.sh" restore; rm -f "$STATE/settings.staged"; systemctl restart wazuh-manager; wait_api || true; fi
  die "the Server API did not come back"
fi
wait_clusterd || die "cluster daemon"; sleep 10
passwords || die "password resets failed"
if ! $py "$S/identity_stage.py" verify "$BUNDLE_DIR/identity" --state "$BUNDLE_DIR/identity-stage" > "$LOGS/identity-verify-1.json" 2>&1; then
  log "differences from the identity bundle after the restart: running the identity stage again"; cat "$LOGS/identity-verify-1.json" | head -c 1500; echo
  run_stage || { tail -n 20 "$LOGS/identity-stage-run.log"; die "identity stage rerun failed"; }
  passwords || die "password resets failed"
  $py "$S/identity_stage.py" verify "$BUNDLE_DIR/identity" --state "$BUNDLE_DIR/identity-stage" > "$LOGS/identity-verify-2.json" 2>&1 || { cat "$LOGS/identity-verify-2.json"; die "the registry still differs from the identity bundle"; }
fi
head -c 1200 "$LOGS/identity-verify-1.json"; echo
python3 - "$BUNDLE_DIR/identity-stage/state.json" <<'PY' || die "the API limit gate"
import json, sys
st = json.load(open(sys.argv[1])); lim = (st.get("limit") or {}).get("state")
if lim in ("raised", "restored-pending-restart"):
    print("the Server API limit raised for the identity import is not restored (state %s)" % lim); sys.exit(1)
print("the Server API limit is the original (identity stage state: %s)" % (lim or "never raised"))
PY
grep -E 'max_request_per_minute' $V5/api/configuration/api.yaml 2>/dev/null | head -n 3 || true; ls -la "$BUNDLE_DIR/identity-stage/" | tail -n +2 | cut -c1-120
mark import.done; log "identity stage done"
