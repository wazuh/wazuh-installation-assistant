#!/usr/bin/env python3
"""bundle_secrets.py - delete a migration bundle's secrets, then search for them by value (rule 13). Python 3.8+,
standard library only.

    bundle_secrets.py sweep --bundle DIR [--search DIR]... [--outside FILE]... [--keep-parts]

One implementation for every place a bundle's secrets are cleaned: the all-in-one finish (migrate.sh
fi_secrets), going back (migrate.sh back.secrets, E2-deb G11: before, only a bundle that reached the finish was
cleaned, so a bundle abandoned after going back kept every carried secret), `migrate.sh discard` (an abandoned bundle),
and the cluster finish (cluster/node/finish-node.sh secrets, E2-cluster gap 6: the cluster flow had no finish).

1. Every secret value the bundle carried is read first (nothing printed): the 4.x passwords from the bundle's copy of
   wazuh-install-files.tar, the cluster key and integration hook URLs and API keys from the 4.x ossec.conf, the
   enrollment password, every agent key. Cluster bundles keep ossec.conf, client.keys and authd.pass only inside
   v4/rollback/var-ossec.tar.gz: they are read from there too.
2. The parts that hold them are deleted (each file overwritten, then removed).
3. What is kept, and every --search directory, is searched for each value, for private keys and for password hashes,
   inside tar archives too (E2-rpm gap 5: the way back's wazuh-install-files.tar in the work directory was not seen).
   A value found fails the sweep (exit 1).
4. Outside the bundle, files that hold credentials nothing uses any more, archives of installer credentials, and other
   migration bundles on the host that still hold secret parts are named for the user (never deleted: they are not this
   bundle's). Bundles already cleaned (discarded, gone back, finished) are listed apart, as holding no secret.
5. before the parts are deleted, a salted SHA-256 of every value of 16
   characters or more is recorded in state/secret-digests.json, so a rerun (the cluster finish always runs twice when a
   4.x agent remains) still searches for them: windows of each recorded length over runs of the values' characters.
   Shorter values (a weak enrollment password could be guessed from its digest) are not recorded and the rerun says so.
"""
import hashlib
import argparse
import glob
import io
import json
import os
import re
import shutil
import subprocess
import sys
import tarfile

# Parts of a bundle that hold carried secrets: the all-in-one layout (migrate.sh) and the cluster node layout
# (cluster/node/export-manager.sh, bundle generations of K5's fold). Globs are relative to the bundle.
PARTS = ["settings", "identity", "identity-noagents", "identity-stage", "indexer", "v4/etc", "v4/config", "v4/rollback",
         "v4/alerts", "indexer-security", "history/data", "history-registry.json", "ruleset-src", "ism-4x.json",
         "identity.old.*", "identity.gen*", "v4.gen*"]
PEM = re.compile(rb"BEGIN (RSA |EC |ENCRYPTED )?PRIVATE KEY")
BCRYPT = re.compile(rb"\$2[aby]\$[0-9]{2}\$")
CRED_MEMBERS = re.compile(r"(^|/)(wazuh-passwords\.txt|credentials\.env|[^/]*-key\.pem|admin-key\.pem)$")
TAR_MAX = 200 * 1024 * 1024        # archives larger than this are package sets, not credentials: not opened
MEMBER_MAX = 20 * 1024 * 1024
CHUNK = 8 * 1024 * 1024


def _read(path):
    try:
        with open(path, errors="replace") as f:
            return f.read()
    except OSError:
        return ""


def _tar_member(tar_path, suffix):
    """Text of the first member of tar_path whose name ends with suffix, or ''."""
    try:
        with tarfile.open(tar_path) as t:
            for m in t.getmembers():
                if m.isfile() and m.name.endswith(suffix):
                    return t.extractfile(m).read().decode(errors="replace")
    except (OSError, tarfile.TarError, EOFError):
        pass
    return ""


def carried_values(b):
    """{label: value} of every secret the bundle carried (values shorter than 8 characters are not searched)."""
    vals = {}
    pw = _tar_member(os.path.join(b, "v4/rollback/wazuh-install-files.tar"), "wazuh-install-files/wazuh-passwords.txt")
    for u, v in re.findall(r"(?:indexer|api)_username: '([^']*)'\s*\n\s*(?:indexer|api)_password: '([^']*)'", pw):
        vals["4.x password of " + u] = v
    rb = os.path.join(b, "v4/rollback/var-ossec.tar.gz")
    confs = [_read(os.path.join(b, f)) for f in ("v4/config/ossec.conf", "v4/etc/ossec.conf")] + [_tar_member(rb, "var/ossec/etc/ossec.conf")]
    for c in confs:
        for k in re.findall(r"<cluster>.*?<key>([^<]+)</key>", c, re.S):
            vals["4.x cluster key"] = k
        for i, u in enumerate(re.findall(r"<hook_url>([^<]+)</hook_url>", c)):
            vals["4.x integration hook_url %d" % i] = u
        for i, u in enumerate(re.findall(r"<api_key>([^<]+)</api_key>", c)):
            vals["4.x integration api_key %d" % i] = u
    e = (_read(os.path.join(b, "identity/authd.pass")).strip() or _read(os.path.join(b, "v4/etc/authd.pass")).strip()
         or _tar_member(rb, "var/ossec/etc/authd.pass").strip())
    if e:
        vals["enrollment password"] = e
    for keys in (_read(os.path.join(b, "v4/etc/client.keys")), _tar_member(rb, "var/ossec/etc/client.keys")):
        for line in keys.splitlines():
            f = line.split()
            if len(f) >= 4 and not line.startswith("#") and not f[1].startswith("!"):
                vals["key of agent " + f[0]] = f[3]
    return {k: v for k, v in vals.items() if len(v) >= 8}


DIGESTS = "state/secret-digests.json"
DIGEST_MIN = 16


def _digest(salt, value):
    return hashlib.sha256(salt + value).hexdigest()


def record_digests(b, vals):
    """Merge the values' salted digests into state/secret-digests.json (written to a temporary file, synced, renamed).
    Returns the record. Values shorter than DIGEST_MIN are only counted."""
    path = os.path.join(b, DIGESTS)
    rec = load_digests(b) or {"salt": os.urandom(16).hex(), "values": {}, "short": []}
    salt = bytes.fromhex(rec["salt"])
    for k, v in vals.items():
        if len(v) >= DIGEST_MIN:
            rec["values"][k] = {"length": len(v.encode()), "digest": _digest(salt, v.encode())}
        elif k not in rec["short"]:
            rec["short"].append(k)
    chars = set(rec.get("alphabet", ""))
    for v in vals.values():
        if len(v) >= DIGEST_MIN:
            chars |= set(v)
    rec["alphabet"] = "".join(sorted(chars))
    os.makedirs(os.path.dirname(path), exist_ok=True)
    tmp = path + ".tmp"
    # CL1 (E4-cluster note 8): mode 600 from the start (it was 644): salted digests of secret values are still not for
    # every reader of the host
    with os.fdopen(os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600), "w") as f:
        os.fchmod(f.fileno(), 0o600)
        json.dump(rec, f, indent=1, sort_keys=True)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, path)
    return rec


def load_digests(b):
    try:
        with open(os.path.join(b, DIGESTS)) as f:
            rec = json.load(f)
        return rec if isinstance(rec, dict) and rec.get("salt") else None
    except (OSError, ValueError):
        return None


class Digests:
    """Search bytes for recorded values by digest: every window of a recorded length inside a run of the values'
    characters is hashed with the salt and looked up."""

    def __init__(self, rec, labels):
        self.salt = bytes.fromhex(rec["salt"])
        self.by_len = {}
        for k in labels:
            e = rec["values"][k]
            self.by_len.setdefault(int(e["length"]), {})[e["digest"]] = k
        alpha = rec.get("alphabet", "").encode()
        self.longest = max(self.by_len) if self.by_len else 0
        self.run = re.compile(rb"[" + b"".join(re.escape(bytes([c])) for c in sorted(set(alpha))) + rb"]{%d,}" % min(self.by_len)) \
            if self.by_len and alpha else None

    def find(self, buf):
        found = set()
        if self.run is None:
            return found
        for m in self.run.finditer(buf):
            r = m.group(0)
            for n, table in self.by_len.items():
                for i in range(len(r) - n + 1):
                    k = table.get(_digest(self.salt, r[i:i + n]))
                    if k:
                        found.add(k)
        return found


def shred(path):
    """Overwrite, then remove, every file under path (shred -u where it exists)."""
    files = [path] if os.path.isfile(path) or os.path.islink(path) else \
        [os.path.join(r, f) for r, _, fs in os.walk(path) for f in fs]
    for f in files:
        if os.path.islink(f):
            os.unlink(f)
            continue
        if shutil.which("shred"):
            subprocess.run(["shred", "-u", f], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        if os.path.exists(f):
            try:
                with open(f, "r+b") as h:
                    n = os.path.getsize(f)
                    while n > 0:
                        w = min(n, CHUNK)
                        h.write(b"\0" * w)
                        n -= w
                    h.flush()
                    os.fsync(h.fileno())
            except OSError:
                pass
            os.unlink(f)
    if os.path.isdir(path):
        shutil.rmtree(path, ignore_errors=True)


def _scan_bytes(stream, needles, digests=None):
    """Labels of `needles` ({label: bytes}) found in the stream, plus 'private key' / 'password hash'; with `digests`
    (a Digests), the values recorded by an earlier sweep too."""
    found, tail = set(), b""
    longest = max([len(v) for v in needles.values()] + [64] + [digests.longest if digests else 0])
    while True:
        chunk = stream.read(CHUNK)
        if not chunk:
            break
        buf = tail + chunk
        for k, v in needles.items():
            if k not in found and v in buf:
                found.add(k)
        if digests:
            found |= digests.find(buf)
        if PEM.search(buf):
            found.add("a private key")
        if BCRYPT.search(buf):
            found.add("a password hash")
        tail = buf[-longest:]
    return found


def scan_file(path, needles, digests=None):
    """[(label, where, inside_an_archive)] for one file; tar archives are opened and their members scanned too."""
    out = []
    try:
        with open(path, "rb") as f:
            out += [(k, path, False) for k in sorted(_scan_bytes(f, needles, digests))]
    except OSError:
        return out
    try:
        if os.path.getsize(path) <= TAR_MAX and tarfile.is_tarfile(path):
            with tarfile.open(path) as t:
                for m in t.getmembers():
                    if not m.isfile():
                        continue
                    where = "%s:%s" % (path, m.name)
                    if CRED_MEMBERS.search(m.name):
                        out.append(("installer credentials", where, True))
                    if m.size <= MEMBER_MAX:
                        out += [(k, where, True) for k in sorted(_scan_bytes(t.extractfile(m), needles, digests))]
    except (OSError, tarfile.TarError, EOFError):
        pass
    return out


def walk(*dirs):
    for d in dirs:
        if os.path.isfile(d):
            yield d
        for r, _, fs in os.walk(d):
            for f in fs:
                yield os.path.join(r, f)


def holds_parts(d):
    """E3 fold: a bundle still holds secrets while any of its secret parts is there; a bundle that
    was discarded, went back or finished has had them deleted."""
    return any(glob.glob(os.path.join(d, pat)) for pat in PARTS)


def other_bundles(b, roots=("/root", "/home", "/srv", "/opt", "/var/backups")):
    """Migration bundles elsewhere on the host: a directory with state/ and a journal, a manifest or v4/. The identity
    stage's own state directory inside a bundle (it has a journal.ndjson too) is not one."""
    me, out = os.path.realpath(b), []
    for root in roots:
        for d in glob.glob(os.path.join(root, "*")) + glob.glob(os.path.join(root, "*", "*")):
            if not os.path.isdir(os.path.join(d, "state")):
                continue
            rd = os.path.realpath(d)
            if rd == me or rd.startswith(me + os.sep) or os.path.basename(rd) == "identity-stage":
                continue
            if any(os.path.exists(os.path.join(d, x)) for x in ("journal.ndjson", "MANIFEST.sha256", "v4")):
                out.append(rd)
    return sorted(set(out))


SAMPLE = "v4/alerts-sample"


def sweep(bundle, search=(), outside=(), keep_parts=False, roots=None, keep_sample=False):
    """keep_sample (the way back): the 4.x alerts copied at the freeze are moved to v4/alerts-sample instead of deleted,
    so a new attempt's ruleset verification has 4.x samples (a reinstalled 4.x has few alerts of its own). They are
    searched like the rest; a sample file that holds a carried value is deleted, never kept."""
    b = os.path.abspath(bundle)
    if keep_sample and not keep_parts and os.path.isdir(os.path.join(b, "v4", "alerts")):
        shutil.rmtree(os.path.join(b, SAMPLE), ignore_errors=True)
        os.rename(os.path.join(b, "v4", "alerts"), os.path.join(b, SAMPLE))
        print("kept %s: the 4.x alerts copied at the freeze, the next attempt's verification samples" % SAMPLE)
    vals = carried_values(b)
    rec = record_digests(b, vals) if vals else load_digests(b)
    by_digest = sorted(k for k in (rec or {}).get("values", {}) if k not in vals)
    digests = Digests(rec, by_digest) if by_digest else None
    kinds = lambda ks: ", ".join(sorted({re.sub(r" (of|\d).*", "", k) for k in ks}))
    print("secret values this bundle carried: %d (%s)" % (len(vals) + len(by_digest), kinds(list(vals) + by_digest)))
    if by_digest:
        print("  %d of them searched by the digest an earlier sweep recorded (%s): their parts are already deleted"
              % (len(by_digest), DIGESTS))
    short = [k for k in (rec or {}).get("short", []) if k not in vals]
    if short:
        print("  not searched again: %s (shorter than %d characters: no digest is kept of a value that could be guessed from it)"
              % (", ".join(sorted(short)), DIGEST_MIN))
    if not keep_parts:
        for pat in PARTS:
            for p in sorted(glob.glob(os.path.join(b, pat))):
                shred(p)
                print("deleted %s" % os.path.relpath(p, b))
        if os.path.exists(os.path.join(b, "MANIFEST.sha256")):
            os.unlink(os.path.join(b, "MANIFEST.sha256"))
    needles = {k: v.encode() for k, v in vals.items()}
    left, named = [], []
    for f in walk(b, *[s for s in search if s and os.path.exists(s)]):
        inside = f.startswith(b + os.sep)
        if os.path.realpath(f) in (os.path.realpath(os.path.join(b, DIGESTS)), os.path.realpath(os.path.join(b, DIGESTS + ".tmp"))):
            continue        # the record itself: digests, not values
        for label, where, archived in scan_file(f, needles, digests):
            if not inside and archived and label not in vals:
                # an installer's credentials archive in the work directory (the 5.0 install's own, which the live
                # deployment uses, or a 4.x reinstall's): not this bundle's secret, named for the user
                named.append("%s (holds installer credentials or private keys; not a value this bundle carried)" % f)
            elif not inside and label == "a private key":
                # a loose private key in the work directory that is no value this bundle carried is
                # the 5.0 installer's own output (on a cluster, `-g` on indexer node-1 leaves wazuh-ca/root-ca.key, the
                # key of the CA it generated): named for the user, not a failure. Carried values still fail
                # (scan_file gives them their own label, so the same file still lands in `left`).
                # E4-deb wording: the message no longer claims what the key signed (not
                # checked here, and not true of every key found)
                named.append("%s (a private key, not a value this bundle carried: the 5.0 installer's -g leaves its CA "
                             "key in its work directory, and whoever holds a CA key can issue certificates its clients "
                             "trust; keep it offline or delete it)" % f)
            elif inside and keep_sample and f.startswith(os.path.join(b, SAMPLE) + os.sep):
                shred(f)
                print("deleted %s from the kept samples: it holds %s" % (os.path.relpath(f, b), label))
            else:
                left.append("%s in %s" % (label, where))
    for f in outside:
        if f and os.path.exists(f):
            named.append(f)
    cleaned = []
    for d in other_bundles(b, roots or ("/root", "/home", "/srv", "/opt", "/var/backups")):
        if not holds_parts(d):
            cleaned.append(d)
            continue
        named.append("%s (another migration bundle on this host: an earlier or abandoned run, with its own secrets; "
                     "BUNDLE_DIR=%s migrate.sh discard deletes them)" % (d, d))
    if left:
        print("still holding secrets:\n  " + "\n  ".join(sorted(set(left))))
        return 1
    # worded without "password" before a colon, which the controller's mask takes for a credential's name
    print("kept (checked: none of the carried secret values, no private key and no credential hash in them): %s"
          % " ".join(sorted(os.listdir(b))))
    if named:
        print("outside the bundle, yours to delete (credentials nothing uses any more):\n  " + "\n  ".join(sorted(set(named))))
    if cleaned:
        print("other migration bundles on this host, their secrets already deleted (discarded, gone back or finished): %s"
              % " ".join(cleaned))
    return 0


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("sweep")
    p.add_argument("--bundle", required=True)
    p.add_argument("--search", action="append", default=[], help="another directory to search (the work directory)")
    p.add_argument("--outside", action="append", default=[], help="a credentials file outside the bundle to name if present")
    p.add_argument("--keep-parts", action="store_true", help="search only, delete nothing")
    p.add_argument("--keep-sample", action="store_true", help="the way back: keep the 4.x alerts as v4/alerts-sample")
    p.add_argument("--roots", action="append", help="where other bundles are looked for (default /root /home /srv /opt "
                                                       "/var/backups, or MIG_BUNDLE_ROOTS, colon separated: tests)")
    a = ap.parse_args(argv)
    roots = a.roots or [r for r in os.environ.get("MIG_BUNDLE_ROOTS", "").split(":") if r] or None
    return sweep(a.bundle, a.search, a.outside, a.keep_parts, roots, a.keep_sample)


if __name__ == "__main__":
    sys.exit(main())
