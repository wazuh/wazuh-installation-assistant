#!/bin/sh
# agent-conf-5x.sh - bring an upgraded agent's own ossec.conf to the 5.0 shape, with nothing but /bin/sh and awk.
#
# Experiment arm MAC1 of the 4.x -> 5.0 migration lab. A port of AG1's agent-conf-5x.py for endpoints that have no
# python3 (stock macOS: /usr/bin/python3 is only a stub that asks to install the Command Line Tools). Same decisions:
#   - refuses unless the installed agent is 5.x (a 4.x agent does not start with an <agent> block),
#   - rewrites the first <client> block as <agent>: <manager><endpoint> (one address), <config-profile>,
#     <notify_time>, <auto_restart>, and the <enrollment> options 5.0 still reads,
#   - drops what 5.0 ignores: <client_buffer>, <time-reconnect>, <crypto_method>, <ip_update_interval>,
#     <force_reconnect_interval>, <remote_conf>, the 4.x <enrollment> transport options and the 4.x default
#     authorization_pass_path, the cis-cat and osquery wodles, syscheck <scan_on_start>/<max_eps> (top level),
#     rootcheck <check_files>/<check_trojans>/<rootkit_files>/<rootkit_trojans>,
#   - keeps a backup, validates with the agent's own parser (wazuh-agentd -t), restores the backup on failure,
#     restarts the agent with --restart (launchd on macOS through wazuh-control, systemd on Linux).
# Idempotent: a file with <agent><manager> and no <client> is left alone.
# Limit (stated, not hidden): tags are read line by line, as every packaged ossec.conf writes them; a <client> block
# folded onto one line, or comments opening and closing inside it on the same line as a value, are not handled.
#
# Exit codes: 0 converted or nothing to do; 2 refused; 3 validation failed and backup restored; 1 other error.
#   sudo sh agent-conf-5x.sh --home /Library/Ossec --restart
#   sh agent-conf-5x.sh --file ossec.conf --out ossec.conf.5x --assume-5x      # offline
set -u
HOME_DIR=""; FILE=""; OUT=""; ENDPOINT=""; POLICY=""; ASSUME=0; RESTART=0
while [ $# -gt 0 ]; do
  case "$1" in
    --home) HOME_DIR=$2; shift 2 ;;
    --file) FILE=$2; shift 2 ;;
    --out) OUT=$2; shift 2 ;;
    --endpoint) ENDPOINT=$2; shift 2 ;;
    --endpoint-policy) POLICY=$2; shift 2 ;;
    --assume-5x) ASSUME=1; shift ;;
    --restart) RESTART=1; shift ;;
    -h|--help) sed -n '2,22p' "$0"; exit 0 ;;
    *) echo "unknown option $1"; exit 1 ;;
  esac
done
if [ -z "$HOME_DIR" ]; then
  if [ "$(uname)" = "Darwin" ]; then HOME_DIR=/Library/Ossec; else HOME_DIR=/var/ossec; fi
fi
[ -n "$FILE" ] || FILE="$HOME_DIR/etc/ossec.conf"
[ -r "$FILE" ] || { echo "error: cannot read $FILE"; exit 1; }

if [ "$ASSUME" = 0 ] && [ -z "$OUT" ]; then
  V=""
  for f in "$HOME_DIR/VERSION.json" "$HOME_DIR/VERSION"; do
    [ -r "$f" ] && V=$(sed -n 's/.*\([0-9][0-9]*\.[0-9][0-9]*\.[0-9][0-9]*\).*/\1/p' "$f" | head -1) && [ -n "$V" ] && break
  done
  MAJOR=${V%%.*}
  case "$MAJOR" in
    ''|*[!0-9]*) echo "refused: the installed agent version is unknown; a 4.x agent does not start with an <agent> block. Convert after the upgrade."; exit 2 ;;
  esac
  if [ "$MAJOR" -lt 5 ]; then
    echo "refused: the installed agent is $V; a 4.x agent does not start with an <agent> block. Convert after the upgrade."; exit 2
  fi
fi

TMP=$(mktemp "${TMPDIR:-/tmp}/agentconf5x.XXXXXX") || exit 1
REPORT=$(mktemp "${TMPDIR:-/tmp}/agentconf5x-report.XXXXXX") || exit 1
trap 'rm -f "$TMP" "$REPORT"' EXIT

awk -v endpoint="$ENDPOINT" -v policy="$POLICY" -v report="$REPORT" '
function val(s, t,   a, b) {   # value of <t>...</t> in s, "" if absent; sets FOUND
  FOUND = 0
  if (match(s, "<" t ">")) { a = substr(s, RSTART + RLENGTH); if (match(a, "</" t ">")) { FOUND = 1; b = substr(a, 1, RSTART - 1); gsub(/^[ \t\n]+|[ \t\n]+$/, "", b); return b } }
  return ""
}
function rep(s) { print s >> report }
BEGIN { state = "out"; done_client = 0; in_comment = 0; in_sync = 0 }
{
  line = $0
  # comment tracking (whole-line comments, as packaged files have them); inside a dropped block they go with it
  if (state == "skip") { if (line ~ endtag) state = "out"; next }
  if (in_comment) { if (state == "client") { cbody_raw = cbody_raw line "\n" } else print line; if (line ~ /-->/) in_comment = 0; next }
  if (line ~ /<!--/ && line !~ /-->/) { in_comment = 1; if (state == "client") { cbody_raw = cbody_raw line "\n" } else print line; next }
  if (line ~ /^[ \t]*<!--.*-->[ \t]*$/) { if (state == "client") { cbody_raw = cbody_raw line "\n" } else print line; next }

  if (state == "out" && !done_client && line ~ /^[ \t]*<client>[ \t]*$/) {
    state = "client"; indent = line; sub(/<client>.*/, "", indent); cbody = ""; cbody_raw = ""; next
  }
  if (state == "client") {
    if (line ~ /<\/client>/) { state = "out"; done_client = 1; emit_agent(); next }
    cbody = cbody line "\n"; cbody_raw = cbody_raw line "\n"; next
  }
  if (state == "out" && line ~ /<client_buffer>/) { state = "skip"; endtag = "</client_buffer>"; dropped["client_buffer"]++; if (line ~ endtag) state = "out"; next }
  if (state == "out" && line ~ /<wodle name="(cis-cat|osquery)">/) { w = line; sub(/.*name="/, "", w); sub(/".*/, "", w); dropped["wodle " w]++; state = "skip"; endtag = "</wodle>"; if (line ~ endtag) state = "out"; next }
  if (state == "skip") { if (line ~ endtag) state = "out"; next }

  if (line ~ /<syscheck>/) in_syscheck = 1
  if (line ~ /<\/syscheck>/) in_syscheck = 0
  if (line ~ /<synchronization>/) in_sync = 1
  if (line ~ /<\/synchronization>/) in_sync = 0
  if (in_syscheck && !in_sync && line ~ /^[ \t]*<(scan_on_start|max_eps)>[^<]*<\/(scan_on_start|max_eps)>[ \t]*$/) { t = line; sub(/^[ \t]*</, "", t); sub(/>.*/, "", t); dropped["syscheck/" t]++; next }
  if (line ~ /<rootcheck>/) in_rootcheck = 1
  if (line ~ /<\/rootcheck>/) in_rootcheck = 0
  if (in_rootcheck && line ~ /^[ \t]*<(check_files|check_trojans|rootkit_files|rootkit_trojans)>[^<]*<\/(check_files|check_trojans|rootkit_files|rootkit_trojans)>[ \t]*$/) { t = line; sub(/^[ \t]*</, "", t); sub(/>.*/, "", t); dropped["rootcheck/" t]++; next }
  print line
}
function emit_agent(   s, n, addrs, chosen, i, k, v, enr, sub_, keepk, dropk, ports, p) {
  s = cbody; n = 0
  while (match(s, /<server>/)) {
    s = substr(s, RSTART + RLENGTH)
    if (!match(s, /<\/server>/)) break
    blk = substr(s, 1, RSTART - 1); s = substr(s, RSTART + RLENGTH)
    a = val(blk, "address"); if (FOUND && a != "") { n++; addrs[n] = a; p = val(blk, "port"); ports[n] = p; rep("kept servers_4x: " a " port=" p " protocol=" val(blk, "protocol")) }
  }
  if (endpoint != "") chosen = endpoint
  else if (n == 1) chosen = addrs[1]
  else if (n > 1 && policy == "first") chosen = addrs[1]
  else if (n > 1 && policy == "last") chosen = addrs[n]
  else if (n > 1) { REFUSED = n " manager addresses: 5.0 has no failover and dials only the last one (" addrs[n] "). Name the one address that reaches every manager node with --endpoint, or accept --endpoint-policy last or first"; print indent "<client>"; printf "%s", cbody_raw; print indent "</client>"; return }
  else { REFUSED = "the <client> block names no <server><address>"; print indent "<client>"; printf "%s", cbody_raw; print indent "</client>"; return }
  for (i = 1; i <= n; i++) { if (addrs[i] != chosen) rep("dropped other_manager: " addrs[i]); if (ports[i] != "" && ports[i] != "1514") rep("dropped server_port: " ports[i] " (a 4.x legacy port; 5.0 dials the HTTPS port)") }
  print indent "<agent>"
  print indent "  <manager>"
  print indent "    <endpoint>" chosen "</endpoint>"
  print indent "  </manager>"
  split("config-profile notify_time auto_restart", keepk, " ")
  for (i = 1; i <= 3; i++) { v = val(cbody, keepk[i]); if (FOUND) { print indent "  <" keepk[i] ">" v "</" keepk[i] ">"; rep("kept " keepk[i] ": " v) } }
  split("time-reconnect crypto_method ip_update_interval force_reconnect_interval remote_conf", dropk, " ")
  for (i = 1; i <= 5; i++) { v = val(cbody, dropk[i]); if (FOUND) rep("dropped " dropk[i] ": " v) }
  enr = val(cbody, "enrollment")
  if (FOUND) {
    sub_ = ""
    split("enabled agent_name groups agent_address delay_after_enrollment use_source_ip authorization_pass_path", keepk, " ")
    for (i = 1; i <= 7; i++) {
      v = val(enr, keepk[i])
      if (!FOUND) continue
      if (keepk[i] == "authorization_pass_path" && (v == "etc/authd.pass" || v == "authd.pass")) { rep("dropped enrollment/authorization_pass_path: " v " (4.x default, file removed by the 5.0 upgrade)"); continue }
      sub_ = sub_ indent "    <" keepk[i] ">" v "</" keepk[i] ">\n"; rep("kept enrollment/" keepk[i] ": " v)
    }
    split("manager_address port ssl_cipher server_ca_path agent_certificate_path agent_key_path auto_method", dropk, " ")
    for (i = 1; i <= 7; i++) { v = val(enr, dropk[i]); if (FOUND) rep("dropped enrollment/" dropk[i] ": " v) }
    if (sub_ != "") { print indent "  <enrollment>"; printf "%s", sub_; print indent "  </enrollment>" }
  }
  print indent "</agent>"
  rep("changed: <client> rewritten as <agent> with <manager><endpoint>" chosen "</endpoint>")
}
END {
  for (k in dropped) rep("dropped " k ": " dropped[k])
  if (REFUSED != "") { rep("REFUSED: " REFUSED); exit 2 }
  if (!done_client) rep("nothing: no <client> block")
}' "$FILE" > "$TMP"
RC=$?
if [ $RC = 2 ]; then grep REFUSED "$REPORT" | sed 's/^REFUSED/refused/'; exit 2; fi
[ $RC = 0 ] || { echo "error: awk failed ($RC)"; exit 1; }
if cmp -s "$FILE" "$TMP"; then
  if grep -q "<agent>" "$FILE" && grep -q "<manager>" "$FILE"; then echo "already in the 5.0 shape (<agent><manager>, no <client>): nothing to do"; else echo "no <client> block: nothing to do"; fi
  exit 0
fi
echo "file: $FILE"; sed 's/^/  /' "$REPORT"
if [ -n "$OUT" ]; then cp "$TMP" "$OUT"; echo "written: $OUT"; exit 0; fi

BACKUP="$FILE.4x-backup-$(date +%Y%m%d%H%M%S)"
cp -p "$FILE" "$BACKUP" || exit 1
# keep owner, group and mode: write into the existing inode
cat "$TMP" > "$FILE" || { cp -p "$BACKUP" "$FILE"; exit 1; }
echo "backup: $BACKUP"
AGENTD="$HOME_DIR/bin/wazuh-agentd"
if [ -x "$AGENTD" ]; then
  OUTV=$("$AGENTD" -t 2>&1); VRC=$?
  echo "validation: rc=$VRC $(printf '%s' "$OUTV" | tail -c 400)"
  if [ $VRC != 0 ]; then cp -p "$BACKUP" "$FILE"; echo "restored: the backup is back in place"; exit 3; fi
fi
if [ "$RESTART" = 1 ]; then
  if command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then systemctl restart wazuh-agent; RRC=$?
  else "$HOME_DIR/bin/wazuh-control" restart >/dev/null 2>&1; RRC=$?; fi
  echo "restart: rc=$RRC"
fi
exit 0
