#!/usr/bin/env bash
# check5-manager.sh : on EVERY 5.0 manager node. The gate after the install: cluster view, listeners, certificate names, registry.
. "$(dirname "$(readlink -f "$0")")/common.sh"
V5=/var/wazuh-manager; E=/etc/wazuh-manager
log "package wazuh-manager $(pkgver wazuh-manager), service $(systemctl is-active wazuh-manager)"
sed -n '/<cluster>/,/<\/cluster>/p' $E/wazuh-manager.conf | sed -E 's|<key>.*</key>|<key>MASKED</key>|' | tr -s ' \n' ' '; echo
$V5/bin/cluster_control -l 2>&1 || true
log "listening: $(ss -ltnH | awk '{print $4}' | grep -E ':(1514|1515|1516|1517|55000)$' | sort | tr '\n' ' ')"
log "remoted certificate SAN: $(openssl x509 -in $E/certs/remoted.pem -noout -ext subjectAltName 2>/dev/null | tail -n1 | tr -d ' ')"
log "remoted certificate issuer: $(openssl x509 -in $E/certs/remoted.pem -noout -issuer -fingerprint -sha256 | tr '\n' ' ')"
log "CA: $(openssl x509 -in $E/ca/root-ca.pem -noout -fingerprint -sha256) ; CA key on this node: $([ -e $E/ca/root-ca.key ] && echo yes || echo no)"
n=$( { grep -c . $E/client.keys 2>/dev/null || true; } | head -n1)   # E5 fold: grep -c prints 0 AND fails on an empty file ("0" then "0 line(s)")
log "client.keys: ${n:-0} line(s), sha256 $(sha256sum $E/client.keys 2>/dev/null | cut -c1-16)"
log "authd.pass: $(wc -c < $E/authd.pass 2>/dev/null || echo none) bytes, sha256 $(sha256sum $E/authd.pass 2>/dev/null | cut -c1-16)"
log "groups: $(ls $E/shared 2>/dev/null | tr '\n' ' ')"
for g in $E/shared/*/; do [ -e "$g/agent.conf" ] && echo "    $(basename "$g")/agent.conf $(sed 's/^[ \t]*//;s/[ \t]*$//' "$g/agent.conf" | grep -v '^$' | sha256sum | cut -c1-16) $(ls "$g" | grep -v -E 'agent.conf|merged.mg' | tr '\n' ' ')"; done
grep -E 'indexer|<host>' $E/wazuh-manager.conf | grep '<host>' | tr -s ' \n' ' '; echo
tail -n 400 $V5/logs/wazuh-manager.log 2>/dev/null | grep -i -E 'error|critical' | tail -n 5 | cut -c1-220 || true
