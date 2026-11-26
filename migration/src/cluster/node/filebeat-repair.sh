#!/usr/bin/env bash
# filebeat-repair.sh : on a 4.x manager node that is going back to shipping alerts. The rollback archive
# carries /etc/filebeat only; the Filebeat keystore (/var/lib/filebeat/filebeat.keystore: the indexer user and password the
# configuration reads as ${username}/${password}) and the wazuh module (/usr/share/filebeat/module/wazuh) live elsewhere.
# When the 4.x reinstall was cut before the assistant's Filebeat step (a reboot), both are missing and Filebeat refuses to
# start ("missing field accessing 'output.elasticsearch.username'"). Put back each one from the bundle when it holds it
# (bundles exported with fix 06), else rebuild it as the 4.x assistant does; then start Filebeat and test the output.
. "$(dirname "$(readlink -f "$0")")/common.sh"
R="$BUNDLE_DIR/v4/rollback"
pkg_installed filebeat || die "filebeat is not installed: rerun the 4.x assistant's Filebeat step"
if [ ! -s /var/lib/filebeat/filebeat.keystore ]; then
  if [ -s "$R/filebeat-keystore.tar.gz" ]; then tar -xzf "$R/filebeat-keystore.tar.gz" -C /; how="from the bundle"
  else filebeat keystore create --force >/dev/null 2>&1; echo admin | filebeat keystore add username --force --stdin >/dev/null
       pw4 admin | filebeat keystore add password --force --stdin >/dev/null; how="rebuilt (admin, password from the 4.x install files)"; fi
  log "Filebeat keystore was missing: $how"
fi
# a reboot during the reinstall left /etc/filebeat/filebeat.yml at 0 bytes and the module
# directory with 10 zero-byte files; presence is not enough. neither is size: a cut earlier in
# the Filebeat step left the PACKAGE's own default filebeat.yml (9,982 bytes, no certs/), which passed the size check,
# and Filebeat failed. /etc/filebeat is compared file by file with the bundle's etc-filebeat.tar.gz (what this node had
# at its export); any file missing or different puts the bundle's copy back. Without the archive, the size check stays.
empty() { { find "$1" -type f -size 0 2>/dev/null || true; } | head -n 20 | tr '\n' ' '; }
if [ -s "$R/etc-filebeat.tar.gz" ]; then
  d=$(python3 - "$R/etc-filebeat.tar.gz" "${MIG_TEST_ROOT:-}/" <<'PY'
import hashlib, os, sys, tarfile
out = []
with tarfile.open(sys.argv[1]) as t:
    for m in t.getmembers():
        if not m.isfile():
            continue
        p = os.path.join(sys.argv[2], m.name.lstrip("/"))
        want = hashlib.sha256(t.extractfile(m).read()).hexdigest()
        try:
            have = hashlib.sha256(open(p, "rb").read()).hexdigest()
        except OSError:
            out.append("/" + m.name.lstrip("/") + " (missing)"); continue
        if have != want:
            out.append("/" + m.name.lstrip("/") + " (differs from the bundle's)")
print(" ".join(out[:20]) + (" and %d more" % (len(out) - 20) if len(out) > 20 else ""))
PY
) || die "the bundle's etc-filebeat.tar.gz cannot be read"
  if [ -n "$d" ]; then
    tar -xzf "$R/etc-filebeat.tar.gz" -C /
    log "Filebeat configuration was not this node's (a package default or a cut reinstall): $d: the bundle's /etc/filebeat put back"
  fi
else
  e=$(empty /etc/filebeat)
  if [ ! -s /etc/filebeat/filebeat.yml ] || [ -n "$e" ]; then
    die "Filebeat's configuration is missing or empty (${e:-/etc/filebeat/filebeat.yml}) and the bundle has no etc-filebeat.tar.gz: rerun the 4.x assistant's Filebeat step"
  fi
  log "WARN the bundle has no etc-filebeat.tar.gz: /etc/filebeat checked for empty files only"
fi
[ -s /etc/filebeat/filebeat.yml ] || die "/etc/filebeat/filebeat.yml is still empty after the bundle's copy"
m=/usr/share/filebeat/module/wazuh
if [ -d "$m" ] && { [ -n "$(empty "$m")" ] || [ -z "$({ find "$m" -type f 2>/dev/null || true; } | head -n1)" ]; }; then
  log "Filebeat wazuh module is damaged (empty: $(empty "$m")): replaced"; rm -rf "$m"
fi
if [ ! -d /usr/share/filebeat/module/wazuh ]; then
  if [ -s "$R/filebeat-module-wazuh.tar.gz" ]; then tar -xzf "$R/filebeat-module-wazuh.tar.gz" -C /; how="from the bundle"
  else u=$(sed -n 's/^filebeat_wazuh_module="\${repobaseurl}\(.*\)"$/\1/p' "$V4_ASSISTANT_FILE" | head -n1)
       b=$(sed -n 's/^readonly repobaseurl="\(.*\)"$/\1/p; s/^repobaseurl="\(.*\)"$/\1/p' "$V4_ASSISTANT_FILE" | head -n1)
       curl -sS --fail --max-time 300 "${b}${u}" | tar -xz -C /usr/share/filebeat/module || die "could not fetch the wazuh module (${b}${u})"
       how="downloaded as the 4.x assistant does (${b}${u})"; fi
  log "Filebeat wazuh module was missing: $how"
  [ -z "$(empty "$m")" ] || log "WARN the wazuh module still has empty files after the repair (empty in its source too?): $(empty "$m")"
fi
systemctl enable filebeat >/dev/null 2>&1 || true; systemctl restart filebeat; sleep 5
# the output test's result is said whether it passes or not (it printed nothing when the
# test failed: x509 against 5.0 indexers on the master's way back alone)
to=$(filebeat test output 2>&1) && tr=ok || tr=failed
log "filebeat $(systemctl is-active filebeat); filebeat test output $tr: $( { grep -E 'talk to server|version' <<<"$to" || grep -iE 'error|fail|x509|refused' <<<"$to" | tail -n 2 || echo "no output"; } | sed 's/^[[:space:]]*//' | tr -s ' ' | tr '\n' ' ')"
systemctl is-active -q filebeat
