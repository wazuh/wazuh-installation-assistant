#!/usr/bin/env bash
# indexer-security.sh <export|import|restore4|verify4> : on indexer NODE-1 (the node the assistants run -s / securityadmin
# on). the cluster bundle had no indexer security, so going back lost the site's indexer users,
# roles and mappings (acme-reader, acme_alerts_ro) and nothing carried them to 5.0. The all-in-one's steps, per node:
#   export   (pre-copy, 4.x live)  migrate.sh pc_indexer_security: the REST export and the securityadmin backup (what going
#            back restores) into indexer-security/, and C23's indexer stage export (users with their hashes, roles,
#            mappings, authentication backends, settings) into indexer/; this node's bundle gets a manifest, which
#            remove4x.sh verifies before it removes 4.x
#   import   (5.0 indexer tier up, before the history's role audit)  migrate.sh im_indexer_security: indexer stage import
#            and verify with the 5.0 admin certificate
#   restore4 (whole-cluster go-back, after goback-install4.sh --start-cluster)  migrate.sh bk_restore step 3: the backup's
#            files into opensearch-security/, then securityadmin (cluster wide)
#   verify4  (after restore4)  migrate.sh bk_verify: every object of the REST export against the live 4.x indexer
# Certificates: the node's own /etc/wazuh-indexer/certs when it holds the admin pair, else the install files tar (4.x
# for export, restore4 and verify4; 5.0 for import), extracted into the state directory for the call and removed.
. "$(dirname "$(readlink -f "$0")")/common.sh"
cmd=${1:?export, import, restore4 or verify4}
D="$BUNDLE_DIR/indexer-security"; C=/etc/wazuh-indexer/certs
url() { echo "https://$(idxhost):9200"; }
certs() { # certs <tar>: prints --cacert/--cert/--key, from the node or from the tar
  if [ -s "$C/admin.pem" ] && [ -s "$C/admin-key.pem" ] && [ -s "$C/root-ca.pem" ]; then echo "--cacert $C/root-ca.pem --cert $C/admin.pem --key $C/admin-key.pem"; return; fi
  local d="$STATE/certs-tmp"; rm -rf "$d"; mkdir -m 700 "$d"
  for f in root-ca.pem admin.pem admin-key.pem; do tar -xOf "$1" "wazuh-install-files/$f" > "$d/$f" 2>/dev/null || die "no $f in $1"; done
  echo "--cacert $d/root-ca.pem --cert $d/admin.pem --key $d/admin-key.pem"; }
cleanup() { rm -rf "$STATE/certs-tmp"; }
trap cleanup EXIT
case "$cmd" in
export)
  case "$(pkgver wazuh-indexer)" in 4.*) ;; *) die "this node does not run a 4.x indexer";; esac
  source_version_gate   # OF1 item 12
  mkdir -p "$D/rest" "$D/backup"
  V4_INDEXER_ADMIN_PASSWORD=$(pw4 admin) python3 "$SRC/mig_helper.py" export-security-rest "$D/rest" || die "REST export failed"
  t=$(mktemp -d /var/lib/wazuh-indexer/security-backup.XXXXXX); chown wazuh-indexer "$t"
  /usr/share/wazuh-indexer/bin/indexer-security-init.sh --options "-backup $t -icl -nhnv" > "$LOGS/indexer-security-backup.log" 2>&1 \
    || { tail -n 20 "$LOGS/indexer-security-backup.log"; rm -rf "$t"; die "securityadmin backup failed"; }
  cp -f "$t"/*.yml "$D/backup/"; rm -rf "$t"
  [ -s "$D/backup/internal_users.yml" ] && [ -s "$D/backup/roles.yml" ] || die "the securityadmin backup is incomplete"
  ca=$(certs "$V4_TAR")
  # shellcheck disable=SC2086
  python3 "$SRC/indexer_stage.py" export --bundle "$BUNDLE_DIR" --url "$(url)" $ca > "$LOGS/indexer-stage-export.log" 2>&1 \
    || { tail -n 20 "$LOGS/indexer-stage-export.log"; die "indexer stage export failed"; }
  tail -n 3 "$LOGS/indexer-stage-export.log"
  chown -R root:root "$D" "$BUNDLE_DIR/indexer"; chmod -R go= "$D" "$BUNDLE_DIR/indexer"
  ( cd "$BUNDLE_DIR" && find indexer-security indexer -type f -print0 | sort -z | xargs -0 sha256sum > MANIFEST.sha256 )
  mark indexer_security.export; log "indexer security exported: $(ls "$D/backup" | tr '\n' ' '); bundle manifest $(wc -l < "$BUNDLE_DIR/MANIFEST.sha256") file(s)";;
import)
  [ -d "$BUNDLE_DIR/indexer" ] || die "no indexer stage export in this node's bundle (run 'export' at the pre-copy)"
  ca=$(certs "$V5_TAR")
  # shellcheck disable=SC2086
  python3 "$SRC/indexer_stage.py" import --bundle "$BUNDLE_DIR" --url "$(url)" $ca > "$LOGS/indexer-stage-import.log" 2>&1 \
    || { tail -n 30 "$LOGS/indexer-stage-import.log"; die "indexer stage import failed"; }
  tail -n 5 "$LOGS/indexer-stage-import.log"
  # shellcheck disable=SC2086
  python3 "$SRC/indexer_stage.py" verify --bundle "$BUNDLE_DIR" --url "$(url)" $ca > "$LOGS/indexer-stage-verify.log" 2>&1 \
    || { tail -n 20 "$LOGS/indexer-stage-verify.log"; die "indexer stage verify failed"; }
  tail -n 1 "$LOGS/indexer-stage-verify.log"; mark indexer_security.import;;
restore4)
  ls "$D"/backup/*.yml >/dev/null 2>&1 || die "no securityadmin backup in this node's bundle"
  ( cd "$BUNDLE_DIR" && grep '  indexer-security/' MANIFEST.sha256 | sha256sum --quiet -c - ) || die "the backup in this node's bundle does not match its manifest"
  cp -f "$D"/backup/*.yml /etc/wazuh-indexer/opensearch-security/; chown -R wazuh-indexer:wazuh-indexer /etc/wazuh-indexer/opensearch-security
  /usr/share/wazuh-indexer/bin/indexer-security-init.sh > "$LOGS/goback-securityadmin.log" 2>&1 || { tail -n 15 "$LOGS/goback-securityadmin.log"; die "securityadmin failed"; }
  mark goback.indexer_security; log "4.x security configuration restored (users, roles, mappings) from the backup taken at the pre-copy";;
verify4)
  V4_INDEXER_ADMIN_PASSWORD=$(pw4 admin) IDX_URL="$(url)" python3 - "$D/rest" <<'PY' || die "the 4.x indexer security differs from the export"
import base64, json, os, ssl, sys, urllib.request
ctx = ssl._create_unverified_context(); bad = 0
def live(kind):
    r = urllib.request.Request(os.environ["IDX_URL"] + "/_plugins/_security/api/" + kind)
    r.add_header("Authorization", "Basic " + base64.b64encode(("admin:" + os.environ["V4_INDEXER_ADMIN_PASSWORD"]).encode()).decode())
    return json.load(urllib.request.urlopen(r, context=ctx, timeout=60))
strip = lambda o: {k: v for k, v in o.items() if k != "hash"} if isinstance(o, dict) else o
for kind in ("internalusers", "roles", "rolesmapping"):
    x = {k: strip(v) for k, v in json.load(open(os.path.join(sys.argv[1], kind + ".json"))).items()}
    y = {k: strip(v) for k, v in live(kind).items()}
    diff = sorted(k for k in set(x) | set(y) if x.get(k) != y.get(k)); bad += bool(diff)
    print("indexer %-14s %s  %d in the export, %d now%s" % (kind, "SAME" if not diff else "DIFFERENT", len(x), len(y), "; differing: %s" % diff[:6] if diff else ""))
sys.exit(1 if bad else 0)
PY
  ;;
*) die "usage: indexer-security.sh export|import|restore4|verify4";;
esac
