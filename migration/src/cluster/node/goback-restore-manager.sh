#!/usr/bin/env bash
# goback-restore-manager.sh <master|worker> : on a freshly reinstalled 4.x manager node. Puts back etc/, the API configuration
# (rbac.db), the agent registry (global.db), the group membership files and the message counters from this node's bundle.
# NO_FILEBEAT=1 (the master's way back alone while the indexers are already 5.0): Filebeat is stopped and disabled
# and stays so; this node's alerts then exist only in alerts.json, as on the 4.x workers after order C's step 2.
. "$(dirname "$(readlink -f "$0")")/common.sh"
ROLE=$1; R="$BUNDLE_DIR/v4/rollback"
[ -s "$R/var-ossec.tar.gz" ] || die "no rollback archive in this node's bundle"
systemctl stop wazuh-manager filebeat
tar -xzf "$R/var-ossec.tar.gz" -C /
tar -xzf "$R/etc-filebeat.tar.gz" -C / 2>/dev/null || true
for a in filebeat-keystore filebeat-module-wazuh; do [ -s "$R/$a.tar.gz" ] && tar -xzf "$R/$a.tar.gz" -C /; done  # fix 06
/var/ossec/bin/wazuh-keystore -f indexer -k username -v admin
/var/ossec/bin/wazuh-keystore -f indexer -k password -v "$(pw4 admin)"
systemctl enable wazuh-manager >/dev/null 2>&1 || true
if [ "${NO_FILEBEAT:-0}" = 1 ]; then
  systemctl disable filebeat >/dev/null 2>&1 || true; systemctl start wazuh-manager; fb="Filebeat stopped and disabled (NO_FILEBEAT=1)"
else
  systemctl start wazuh-manager; bash "$(dirname "$(readlink -f "$0")")/filebeat-repair.sh" || true; fb="Filebeat $(systemctl is-active filebeat)"  # fix 06
fi
for i in $(seq 1 60); do curl -sk -o /dev/null -u "wazuh:$(pw4 wazuh)" -X POST "https://localhost:55000/security/user/authenticate?raw=true" && break; sleep 3; done
# the host firewall as it was: the ports the opening added (open-node.sh records them in fw.added, as the
# all-in-one's op_listeners does) are removed again, as migrate.sh's way back does
if [ -s "$STATE/fw.added" ]; then ( aio_lib; for fp in $(sort -u "$STATE/fw.added"); do fw_port remove "$fp" || true; echo "$(fw_kind): $fp/tcp removed again (the migration had added it)"; done ) || true; rm -f "$STATE/fw.added"; fi
sleep 5; ts > "$STATE/T_goback_manager_started"; mark goback.restore.done
log "4.x manager ($ROLE) restored and started: client.keys $(grep -c . /var/ossec/etc/client.keys) line(s); listening $(ss -ltnH | awk '{print $4}' | grep -E ':(1514|1515|1516|55000)$' | sort | tr '\n' ' '); $fb"
