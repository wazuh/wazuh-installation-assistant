#!/usr/bin/env bash
# export-manager.sh <master|worker> : on a stopped 4.x manager node. Identity export (the master's is the one the
# flow imports; the worker's is taken to compare), raw copy of etc/ and ruleset/, and what going back needs.
. "$(dirname "$(readlink -f "$0")")/common.sh"
ROLE=$1; V4=/var/ossec
systemctl is-active -q wazuh-manager && die "the 4.x manager is running: freeze first"
py=python3; [ -x $V4/framework/python/bin/python3 ] && py=$V4/framework/python/bin/python3
if [ -d "${BUNDLE_DIR:?}/identity" ]; then mv "${BUNDLE_DIR:?}/identity" "${BUNDLE_DIR:?}/identity.old.$(date +%s)"; fi
$py "$IDENTITY_TOOL" export "$BUNDLE_DIR/identity" --with-password --with-rbac > "$LOGS/identity-export.log" 2>&1 || { tail -n 30 "$LOGS/identity-export.log"; die "identity export failed"; }
grep -v '^$' "$LOGS/identity-export.log" | head -n 14
d="${BUNDLE_DIR:?}/v4"; mkdir -p "$d/rollback" "$d/alerts" "$d/etc" "$d/ruleset"
cp -a $V4/etc/. "$d/etc/"; cp -a $V4/ruleset/. "$d/ruleset/"
find $V4/logs/alerts -name '*.json' -o -name '*.json.gz' | while read -r f; do cp -f "$f" "$d/alerts/$(echo "${f#$V4/logs/alerts/}" | tr / _)"; done
# OF1 (E2-deb G4): this node's per-agent databases (inventory, FIM baselines, SCA state) too, listed with their sizes
find $V4/queue/db -maxdepth 1 -type f -regextype posix-extended -regex '.*/[0-9]+\.db(-wal|-shm)?' -printf '%f %s\n' 2>/dev/null | sort > "$d/rollback/agent-dbs.txt" || true
tar -czf "$d/rollback/var-ossec.tar.gz" -C / var/ossec/etc var/ossec/api/configuration var/ossec/queue/db/global.db var/ossec/queue/agent-groups var/ossec/queue/rids \
    $(sed 's|^\([^ ]*\) .*|var/ossec/queue/db/\1|' "$d/rollback/agent-dbs.txt") 2>/dev/null || true
n=$(tar -tzf "$d/rollback/var-ossec.tar.gz" | grep -cE '/queue/db/[0-9]+\.db(-wal|-shm)?$' || true)
[ "$n" = "$(grep -c . "$d/rollback/agent-dbs.txt" || true)" ] || die "the rollback archive holds $n of the $(grep -c . "$d/rollback/agent-dbs.txt") per-agent databases"
log "per-agent databases in the rollback archive: $n ($(awk '{s+=$2} END{print int(s/1048576)}' "$d/rollback/agent-dbs.txt") MB)"
tar -czf "$d/rollback/etc-filebeat.tar.gz" -C / etc/filebeat 2>/dev/null || true
# fix 06: Filebeat's keystore and wazuh module are outside /etc/filebeat; a reinstall cut before its Filebeat step lacks both
[ -s /var/lib/filebeat/filebeat.keystore ] && tar -czf "$d/rollback/filebeat-keystore.tar.gz" -C / var/lib/filebeat/filebeat.keystore
[ -d /usr/share/filebeat/module/wazuh ] && tar -czf "$d/rollback/filebeat-module-wazuh.tar.gz" -C / usr/share/filebeat/module/wazuh
cp -f "$V4_TAR" "$d/rollback/wazuh-install-files.tar"
# CL1 (E4-cluster gap 2b): this attempt's own settings collection, from the stopped 4.x node, into this attempt's v4/:
# a second forward attempt (the first one's v4/ kept as v4.gen1) still has v4/config for its settings plan
if [ "${CARRY_SETTINGS:-1}" = 1 ]; then bash "$(dirname "$(readlink -f "$0")")/settings-node.sh" collect4 | tail -n 3 || die "the 4.x settings could not be collected"; fi
pkgs > "$d/rollback/packages.txt"
echo "$ROLE" > "$d/rollback/role"
# E5 fold (E5-cluster-deb 06): decisions.json is the user's answers, rewritten by later steps: not part of the manifest
( cd "$BUNDLE_DIR" && find . -type f ! -path './state/*' ! -path './logs/*' ! -path './identity.old.*' ! -name MANIFEST.sha256 ! -path ./decisions.json -print0 | sort -z | xargs -0 sha256sum > MANIFEST.sha256 )
mark export.done; log "bundle on this node: $(wc -l < "$BUNDLE_DIR/MANIFEST.sha256") file(s), $(du -sh "$BUNDLE_DIR" | cut -f1)"
