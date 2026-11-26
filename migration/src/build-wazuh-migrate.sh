#!/usr/bin/env bash
# build-wazuh-migrate.sh [--out FILE] [--identity FILE | --fetch-identity] : the migration tool as one file,
# wazuh-migrate.sh, from this tree (the directory this script is in).
#
# The file is a short bash launcher followed by the tool (this tree, and the identity tool when given) as a base64
# gzip tar. On start it checks the tar against the sha256 written in the launcher, extracts it to a private directory
# (mode 700, under /root, never under /tmp: the 4.x removal, the 5.0 assistant's rollback and a reboot clean /tmp while
# the tool runs), runs migrate.sh from there with the same arguments, and removes the directory at exit.
#   wazuh-migrate.sh --version     the tool fingerprint, the ruleset tool commit and the identity tool it carries
#   wazuh-migrate.sh --self-test   extracts, checks the sha256 and the fingerprint, parses every script; changes nothing
#
# The identity tool (wazuh/wazuh, tools/migration/wazuh-migrate-identity.py) is embedded at the commit the build
# manifest pins (manifest/builds.json "identity_tool"): --identity takes a local copy, --fetch-identity downloads it
# read-only from GitHub; either must match the pinned sha256. Without either, the file carries no identity tool and the
# run needs IDENTITY_TOOL (it asks for its path). The ruleset tool (rmig) lives in a private repository and is never
# embedded: the run needs RMIG_DIR, and asks for its path when it is not found.
# Python 3 standard library and coreutils only.
set -euo pipefail
HERE="$(cd "$(dirname "$(readlink -f "$0")")" && pwd)"
OUT="$PWD/wazuh-migrate.sh"; IDENT=""; FETCH=0
while [ $# -gt 0 ]; do case "$1" in
  --out) OUT="$2"; shift;; --identity) IDENT="$2"; shift;; --fetch-identity) FETCH=1;;
  -h|--help) sed -n '2,19p' "$0"; exit 0;; *) echo "unknown option $1" >&2; exit 2;; esac; shift; done
mf() { python3 -c 'import json,sys; d=json.load(open(sys.argv[1]));
for k in sys.argv[2].split("."): d=(d or {}).get(k)
print(d or "")' "$HERE/manifest/builds.json" "$1"; }
RMIG_COMMIT=$(mf ruleset_tool.commit); ID_COMMIT=$(mf identity_tool.commit); ID_SHA=$(mf identity_tool.sha256)
ID_REPO=$(mf identity_tool.repository); ID_PATH=$(mf identity_tool.path)

STAGE=$(mktemp -d); trap 'rm -rf "$STAGE"' EXIT
mkdir -p "$STAGE/p/src"
tar -C "$HERE" --exclude=__pycache__ --exclude='*.pyc' -cf - . | tar -C "$STAGE/p/src" -xf -
if [ "$FETCH" = 1 ] && [ -z "$IDENT" ]; then
  IDENT="$STAGE/wazuh-migrate-identity.py"
  curl -fsSL --retry 3 -o "$IDENT" "https://raw.githubusercontent.com/$ID_REPO/$ID_COMMIT/$ID_PATH" || { echo "the identity tool could not be downloaded from $ID_REPO at $ID_COMMIT" >&2; exit 1; }
fi
IDENTITY="not embedded: the run asks where the identity tool is (wazuh/wazuh $ID_PATH at $ID_COMMIT)"
if [ -n "$IDENT" ]; then
  got=$(sha256sum "$IDENT" | cut -d' ' -f1)
  [ "$got" = "$ID_SHA" ] || { echo "the identity tool $IDENT has sha256 $got, not the pinned $ID_SHA ($ID_REPO $ID_PATH at $ID_COMMIT)" >&2; exit 1; }
  mkdir -p "$STAGE/p/identity"; cp "$IDENT" "$STAGE/p/identity/wazuh-migrate-identity.py"
  IDENTITY="embedded: $ID_REPO $ID_PATH at $ID_COMMIT (sha256 ${ID_SHA:0:16})"
fi
FP=$(cd "$STAGE/p/src" && find . -type f ! -path "*/__pycache__/*" -print0 | LC_ALL=C sort -z | xargs -0 sha256sum | sed "s#  \./#  src/#" | sha256sum | cut -c1-16)
( cd "$STAGE/p" && tar --sort=name --mtime=@0 --owner=0 --group=0 --numeric-owner -cf - * ) | gzip -n -9 > "$STAGE/payload.tgz"
SHA=$(sha256sum "$STAGE/payload.tgz" | cut -d' ' -f1)

{
cat <<'LAUNCHER' | sed -e "s|@FP@|$FP|" -e "s|@RMIG@|$RMIG_COMMIT|" -e "s|@SHA@|$SHA|" -e "s|@IDENTITY@|$IDENTITY|" -e "s|@IDSHA@|$ID_SHA|"
#!/usr/bin/env bash
# wazuh-migrate.sh - the Wazuh 4.14.x -> 5.0 migration tool as one file. Run it as root on the 4.x host (on the master
# of a cluster): it stops with exit 3 on each question, printing it and the decisions file to answer it in; run it again
# after answering. It ends with "MIGRATION FINISHED". `wazuh-migrate.sh back` returns to 4.x until the point of no return.
#   --version     the tool fingerprint, the ruleset tool commit and the identity tool it carries
#   --self-test   checks the embedded tool (sha256, fingerprint, syntax); changes nothing
#   --help        the tool's own help (every command, the advanced ones included)
set -euo pipefail
WM_TOOL_FINGERPRINT="@FP@"
WM_RMIG_COMMIT="@RMIG@"
WM_IDENTITY="@IDENTITY@"
WM_IDENTITY_SHA256="@IDSHA@"
WM_PAYLOAD_SHA256="@SHA@"
WM_FILE="$(readlink -f "$0")"
wm_extract() { # wm_extract <dir>: the embedded tool, checked against its sha256, into <dir>
  awk 'f{print} $0=="__WAZUH_MIGRATE_PAYLOAD__"{f=1}' "$WM_FILE" | base64 -d > "$1/payload.tgz"
  if [ "$(sha256sum "$1/payload.tgz" | cut -d' ' -f1)" != "$WM_PAYLOAD_SHA256" ]; then
    echo "wazuh-migrate.sh: the embedded tool does not match its sha256 ($WM_PAYLOAD_SHA256): the file is damaged or was changed; download it again" >&2
    return 1
  fi
  tar -xzf "$1/payload.tgz" -C "$1"; rm -f "$1/payload.tgz"; }
wm_fp() { ( cd "$1" && find . -type f ! -path "*/__pycache__/*" -print0 | LC_ALL=C sort -z | xargs -0 sha256sum | sed "s#  \./#  src/#" | sha256sum | cut -c1-16 ); }
case "${1:-}" in
  --version)
    echo "wazuh-migrate.sh $WM_TOOL_FINGERPRINT (tool fingerprint)"
    echo "ruleset tool commit $WM_RMIG_COMMIT: not embedded (private repository); the run asks where the ruleset tool is"
    echo "identity tool $WM_IDENTITY"
    exit 0;;
  --self-test)
    d=$(mktemp -d); trap 'rm -rf "$d"' EXIT
    wm_extract "$d" || exit 1
    echo "payload: sha256 $WM_PAYLOAD_SHA256 matches"
    fp=$(wm_fp "$d/src")
    [ "$fp" = "$WM_TOOL_FINGERPRINT" ] || { echo "self-test FAILED: the extracted tool's fingerprint is $fp, not $WM_TOOL_FINGERPRINT" >&2; exit 1; }
    echo "tool: fingerprint $fp matches"
    for f in $(cd "$d/src" && find . -name '*.sh'); do bash -n "$d/src/$f" || { echo "self-test FAILED: $f does not parse" >&2; exit 1; }; done
    python3 -c 'import ast,sys; [ast.parse(open(f).read(), f) for f in sys.argv[1:]]' $(find "$d/src" -name '*.py') || { echo "self-test FAILED: a Python file does not parse" >&2; exit 1; }
    echo "scripts: every bash and Python file parses ($(find "$d/src" -name '*.sh' -o -name '*.py' | wc -l) files)"
    if [ -f "$d/identity/wazuh-migrate-identity.py" ]; then
      [ "$(sha256sum "$d/identity/wazuh-migrate-identity.py" | cut -d' ' -f1)" = "$WM_IDENTITY_SHA256" ] || { echo "self-test FAILED: the identity tool's sha256 differs from the pinned one" >&2; exit 1; }
      echo "identity tool: $WM_IDENTITY"
    else echo "identity tool: $WM_IDENTITY"; fi
    echo "self-test passed"; exit 0;;
esac
base="${WAZUH_MIGRATE_TMP:-/root}"   # never /tmp: the 4.x removal, the 5.0 assistant's rollback and a reboot clean it
{ [ -d "$base" ] && [ -w "$base" ]; } || base="$HOME"
for old in "$base"/.wazuh-migrate.*; do   # the directories of runs killed before their exit (kill -9, a reboot)
  [ -d "$old" ] || continue; p=$(cat "$old/.pid" 2>/dev/null || echo 0); [ "$p" -gt 0 ] && kill -0 "$p" 2>/dev/null || rm -rf "$old"
done
WM_DIR=$(mktemp -d "$base/.wazuh-migrate.XXXXXX"); chmod 700 "$WM_DIR"; echo $$ > "$WM_DIR/.pid"
trap 'rm -rf "$WM_DIR"' EXIT
trap 'exit 130' INT; trap 'exit 143' TERM; trap 'exit 129' HUP
wm_extract "$WM_DIR"
[ ! -f "$WM_DIR/identity/wazuh-migrate-identity.py" ] || export WM_IDENTITY_TOOL="$WM_DIR/identity/wazuh-migrate-identity.py"
export WM_SELF="${WM_SELF:-$0}" WM_ORIGIN_DIR="$(dirname "$WM_FILE")"
rc=0; bash "$WM_DIR/src/migrate.sh" "$@" || rc=$?
exit "$rc"
LAUNCHER
echo "__WAZUH_MIGRATE_PAYLOAD__"
base64 -w 76 "$STAGE/payload.tgz"
} > "$OUT.part"
chmod 755 "$OUT.part"; mv -f "$OUT.part" "$OUT"
echo "built $OUT: tool fingerprint $FP, payload sha256 ${SHA:0:16}, $(du -h "$OUT" | cut -f1); identity tool $IDENTITY; rmig $RMIG_COMMIT (not embedded)"
