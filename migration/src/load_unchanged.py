#!/usr/bin/env python3
"""load.py - load a migration bundle written by dump.py into a 5.0 indexer (or any OpenSearch >= 2).

Python standard library only. Oldest Python needed: 3.6 (f-strings, http.client, concurrent.futures);
tested on 3.9 (RHEL 9) and 3.12.

What it does: verify the bundle (sha256 of every file, completeness flags) -> check the shard budget ->
create every index with the 4.x mappings and settings (replicas 0 and refresh off during the load) ->
bulk `create` every document with its original _id -> restore replicas and refresh -> compare
_count with the manifest.  Exactly-once: `create` on an existing _id answers 409, which is counted as
"already loaded", so a rerun after a kill never duplicates and never overwrites.

The merged tool uses it to reload the 4.x alerts into a reinstalled 4.x when going back. F4: each index is created with
the source index's creation date (recorded by dump.py; else the end of the day in its name), because ISM's min_index_age
counts from it: created with today's date, a restored index was kept up to its own age longer than the source would have
kept it. An indexer that refuses the setting gets the index without it, named in the log and in the summary line.

  load.py --bundle /srv/bundle --url https://v5.indexer:9200 --user admin --password-env IDX_PASS --cafile ca.pem
"""
import argparse
import concurrent.futures
import datetime
import getpass
import gzip
import hashlib
import http.client
import json
import os
import ssl
import sys
import threading
import time
import urllib.parse
import base64


RETRY = {"requests": 0, "slept": 0.0}


def log(msg):
    sys.stderr.write("%s load: %s\n" % (datetime.datetime.now().strftime("%H:%M:%S"), msg))
    sys.stderr.flush()


class Client(object):
    def __init__(self, url, user, password, cafile=None, insecure=False, timeout=300):
        u = urllib.parse.urlparse(url)
        self.scheme, self.host, self.port = u.scheme, u.hostname, u.port or 9200
        self.timeout = timeout
        self.auth = "Basic " + base64.b64encode(("%s:%s" % (user, password)).encode()).decode()
        self.ctx = None
        if self.scheme == "https":
            self.ctx = ssl.create_default_context(cafile=cafile)
            if insecure:
                self.ctx.check_hostname = False
                self.ctx.verify_mode = ssl.CERT_NONE
        self.conn = None

    def _connect(self):
        if self.scheme == "https":
            self.conn = http.client.HTTPSConnection(self.host, self.port, context=self.ctx, timeout=self.timeout)
        else:
            self.conn = http.client.HTTPConnection(self.host, self.port, timeout=self.timeout)

    def request(self, method, path, body=None, ok=(200,), retries=10, raw_body=None, ctype="application/json"):
        data = raw_body if raw_body is not None else (None if body is None else json.dumps(body).encode())
        headers = {"Authorization": self.auth, "Content-Type": ctype, "Accept-Encoding": "identity"}
        delay = 1.0
        for attempt in range(retries + 1):
            try:
                if self.conn is None:
                    self._connect()
                self.conn.request(method, path, body=data, headers=headers)
                resp = self.conn.getresponse()
                raw = resp.read()
                status = resp.status
            except (OSError, http.client.HTTPException) as e:
                self.conn = None
                if attempt == retries:
                    raise
                log("connection problem (%s), retry in %.0fs" % (e, delay))
                time.sleep(delay)
                delay = min(delay * 2, 30)
                continue
            if status in ok:
                return status, (json.loads(raw) if raw else {})
            if status in (429, 502, 503, 504) and attempt < retries:
                RETRY["requests"] += 1
                RETRY["slept"] += delay
                time.sleep(delay)
                delay = min(delay * 2, 30)
                continue
            raise RuntimeError("%s %s -> HTTP %s: %s" % (method, path, status, raw[:600]))


def q(name):
    return urllib.parse.quote(name, safe=",*")


def write_json(path, obj):
    tmp = path + ".tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        json.dump(obj, f, indent=1, sort_keys=True)
        f.flush()
        os.fsync(f.fileno())
    os.rename(tmp, path)


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while True:
            b = f.read(1 << 20)
            if not b:
                break
            h.update(b)
    return h.hexdigest()


def py_transform(index, meta_line, src_line):
    """Trivial per-document transform, for measuring: add where the document came from."""
    src = json.loads(src_line)
    m = json.loads(meta_line)
    src["legacy"] = {"source_index": index, "source_id": m["_id"]}
    return json.dumps(src, ensure_ascii=False, separators=(",", ":")).encode("utf-8")


class State(object):
    def __init__(self, path):
        self.path, self.lock = path, threading.Lock()
        self.d = json.load(open(path)) if os.path.exists(path) else {"files": {}, "indices": {}}

    def save(self):
        with self.lock:
            write_json(self.path, self.d)


def bulk_batch(c, index, pairs, pipeline, stats):
    """pairs: list of (action_line, source_line) as bytes. Sends, retries 429 items, counts 409."""
    path = "/%s/_bulk?filter_path=errors,items.*.status,items.*.error.type,items.*.error.reason" % q(index)
    if pipeline:
        path += "&pipeline=" + urllib.parse.quote(pipeline)
    delay = 1.0
    while pairs:
        body = b"".join(a + s for a, s in pairs)
        _, r = c.request("POST", path, raw_body=body, ctype="application/x-ndjson")
        if not r.get("errors"):
            stats["created"] += len(pairs)
            return
        retry = []
        for pair, item in zip(pairs, r["items"]):
            st = item["create"]["status"] if "create" in item else item.get("index", {}).get("status", 500)
            if st in (200, 201):
                stats["created"] += 1
            elif st == 409:
                stats["existing"] += 1
            elif st in (429, 503):
                retry.append(pair)
            else:
                err = (item.get("create") or item.get("index") or {}).get("error", {})
                raise RuntimeError("document rejected: status %s %s %s" % (st, err.get("type"), str(err.get("reason"))[:300]))
        pairs = retry
        if retry:
            stats["retried"] += len(retry)
            time.sleep(delay)
            delay = min(delay * 2, 20)


def load_file(conn, bundle, entry, target_index, args, state, tid_stats):
    c = Client(**conn)
    stats = {"created": 0, "existing": 0, "retried": 0, "docs": 0}
    path = os.path.join(bundle, entry["file"])
    pairs, nbytes = [], 0
    with gzip.open(path, "rb") as f:
        while True:
            m = f.readline()
            if not m:
                break
            s = f.readline()
            if not s:
                raise RuntimeError("%s: odd number of lines (truncated)" % entry["file"])
            if args.py_transform:
                s = py_transform(entry["index"], m, s) + b"\n"
            if args.rollup == "month":
                m = m.replace(b'{"_id":"', b'{"_id":"' + entry["index"][-10:].encode() + b":", 1)
            a = b'{"create":' + m.rstrip(b"\n") + b"}\n"
            pairs.append((a, s))
            nbytes += len(a) + len(s)
            stats["docs"] += 1
            if len(pairs) >= args.bulk_docs or nbytes >= args.bulk_bytes:
                bulk_batch(c, target_index, pairs, args.pipeline, stats)
                pairs, nbytes = [], 0
    if pairs:
        bulk_batch(c, target_index, pairs, args.pipeline, stats)
    if stats["docs"] != entry["docs"]:
        raise RuntimeError("%s: %d documents read, manifest says %d" % (entry["file"], stats["docs"], entry["docs"]))
    return stats


def _day_end_ms(index):
    """End of the UTC day in a daily index's name (wazuh-alerts-4.x-YYYY.MM.DD), epoch ms; None without a date."""
    import calendar
    import re
    m = re.search(r"(\d{4})\.(\d{2})\.(\d{2})$", index)
    if not m:
        return None
    try:
        return calendar.timegm((int(m.group(1)), int(m.group(2)), int(m.group(3)), 23, 59, 59)) * 1000 + 999
    except ValueError:
        return None


def creation_ms(name, ent):
    """F4: the creation date a reloaded source index is created with, so ISM's min_index_age (counted from the index's
    creation date) keeps it as long as the source would have. The date dump.py recorded; never later than the end of the
    day in the index's name (an index the source itself had reloaded counted from its reload); that day's end for a
    bundle dumped before dump.py recorded it. None when neither is known (the age then counts from this load)."""
    rec, end = ent.get("creation_date"), _day_end_ms(name)
    try:
        rec = int(rec) if rec is not None else None
    except (TypeError, ValueError):
        rec = None
    if rec is not None and end is not None:
        return min(rec, end)
    return rec if rec is not None else end


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--bundle", required=True)
    ap.add_argument("--url", required=True, help="https://host:9200 of the target indexer")
    ap.add_argument("--user", required=True)
    ap.add_argument("--password-env")
    ap.add_argument("--password-file")
    ap.add_argument("--cafile")
    ap.add_argument("--insecure", action="store_true")
    ap.add_argument("--workers", type=int, default=4, help="parallel bulk connections (one file each)")
    ap.add_argument("--bulk-docs", type=int, default=5000)
    ap.add_argument("--bulk-bytes", type=int, default=8 << 20)
    ap.add_argument("--state-dir", help="where finished files are recorded (default: <bundle>/load-state)")
    ap.add_argument("--verify-only", action="store_true", help="check the bundle against its manifest and stop")
    ap.add_argument("--allow-incomplete", action="store_true", help="load indices that were still being written during the dump")
    ap.add_argument("--no-mappings", action="store_true", help="EXPERIMENT: create indices without the 4.x mappings")
    ap.add_argument("--py-transform", action="store_true", help="EXPERIMENT: trivial Python per-document transform")
    ap.add_argument("--pipeline", help="EXPERIMENT: ingest pipeline name applied by _bulk")
    ap.add_argument("--rollup", choices=["none", "month"], default="none",
                    help="month: load the daily indices of a month into one monthly index (wazuh-alerts-4.x-YYYY.MM); _id becomes YYYY.MM.DD:<original _id>")
    ap.add_argument("--shards", type=int, help="primary shards per target index (default: as in the source)")
    ap.add_argument("--index-prefix", default="", help="prefix for target index names (default none)")
    ap.add_argument("--remove-bundle", action="store_true", help="delete the bundle files after a fully verified load")
    ap.add_argument("--no-creation-date", action="store_true",
                    help="create the target indices with today's creation date (default: the source's, so ISM ages count from it)")
    ap.add_argument("--stop-after-files", type=int, help="TEST ONLY: exit hard after N files")
    a = ap.parse_args()

    pw = os.environ[a.password_env] if a.password_env else (open(a.password_file).read().strip() if a.password_file else getpass.getpass("indexer password: "))
    bundle = os.path.abspath(a.bundle)
    man = json.load(open(os.path.join(bundle, "manifest.json")))
    sdir = a.state_dir or os.path.join(bundle, "load-state")
    os.makedirs(sdir, mode=0o700, exist_ok=True)
    state = State(os.path.join(sdir, "state.json"))

    # 1. verify the bundle
    t0 = time.time()
    bad = []
    nfiles = 0
    for n, ent in man["indices"].items():
        if not ent["complete"] and not a.allow_incomplete:
            bad.append("%s: dumped while still being written (run dump.py again after the write stop)" % n)
        for f in ent["files"]:
            p = os.path.join(bundle, f["file"])
            nfiles += 1
            if not os.path.exists(p):
                bad.append("missing: " + f["file"])
            elif os.path.getsize(p) != f["bytes"] or sha256_file(p) != f["sha256"]:
                bad.append("corrupt or truncated: " + f["file"])
    log("verified %d files in %.1fs, %d problems" % (nfiles, time.time() - t0, len(bad)))
    if bad:
        for b in bad[:20]:
            log("  " + b)
        sys.exit(2)
    if a.verify_only:
        return

    conn = {"url": a.url, "user": a.user, "password": pw, "cafile": a.cafile, "insecure": a.insecure}
    c = Client(**conn)
    _, info = c.request("GET", "/")
    log("target: %s %s" % (info["version"].get("distribution", "?"), info["version"]["number"]))

    # 2. targets: one per source index, or one per month
    def target_of(n):
        return a.index_prefix + (n[:-3] if a.rollup == "month" else n)

    groups = {}
    for n in sorted(man["indices"]):
        groups.setdefault(target_of(n), []).append(n)
    ents = {n: json.load(open(os.path.join(bundle, "indices", n + ".json"))) for n in man["indices"]}
    # ask for every target by name (a wildcard _cat listing can still show an index deleted a moment ago)
    existing = set(t for t in groups if c.request("HEAD", "/%s" % q(t), ok=(200, 404))[0] == 200)
    new_shards = sum((a.shards or ents[m[0]]["shards"]) for t, m in groups.items() if t not in existing)
    _, h = c.request("GET", "/_cluster/health")
    _, cs = c.request("GET", "/_cluster/settings?include_defaults=true&flat_settings=true&filter_path=**.cluster.max_shards_per_node")
    merged = dict(cs.get("defaults", {}))
    merged.update(cs.get("persistent", {}))
    merged.update(cs.get("transient", {}))
    limit = int(next(iter(merged.values()), 1000)) * h["number_of_data_nodes"]
    have = h["active_shards"] + h["unassigned_shards"] + h["initializing_shards"]
    log("shards: %d now + %d new, limit %d" % (have, new_shards, limit))
    if have + new_shards > limit:
        sys.exit("refusing: %d + %d shards exceed cluster.max_shards_per_node x nodes = %d; every index creation and rollover on this cluster would fail afterwards (use --rollup month and/or --shards)" % (have, new_shards, limit))

    def merge_props(dst, src, path):
        for k, v in src.items():
            if k not in dst:
                dst[k] = json.loads(json.dumps(v))
            elif isinstance(v, dict) and isinstance(dst[k], dict):
                if k == "properties" or "properties" in v or "properties" in dst[k]:
                    merge_props(dst[k], v, path + "." + k)
                elif v != dst[k] and "type" in v and "type" in dst[k]:
                    raise SystemExit("mapping conflict at %s.%s: %s vs %s" % (path, k, dst[k], v))
            elif dst[k] != v and k == "type":
                raise SystemExit("mapping conflict at %s: type %s vs %s" % (path, dst[k], v))

    # 3. create the target indices
    originals, created_at = {}, {}
    for t, members in sorted(groups.items()):
        ent = ents[members[0]]
        st = dict(ent["settings"]["index"])
        originals[t] = {"number_of_replicas": st.get("number_of_replicas", "1"), "refresh_interval": st.get("refresh_interval")}
        if t in existing:
            _, cur = c.request("GET", "/%s/_mapping?filter_path=*.mappings._meta" % q(t))
            if cur.get(t, {}).get("mappings", {}).get("_meta", {}).get("wazuh_migration_bundle") != man["bundle_id"]:
                sys.exit("refusing: index %s exists and was not created by this bundle" % t)
            continue
        mp = {} if a.no_mappings else json.loads(json.dumps(ent["mappings"]))
        if len(members) > 1 and not a.no_mappings:
            for m in members[1:]:
                merge_props(mp.setdefault("properties", {}), ents[m]["mappings"].get("properties", {}), t)
            fields = []
            for m in members:
                for f in ents[m]["settings"]["index"].get("query", {}).get("default_field", []):
                    if f not in fields:
                        fields.append(f)
            if fields:
                st["query"] = dict(st.get("query", {}), default_field=fields)
        if a.shards:
            st["number_of_shards"] = str(a.shards)
        st["number_of_replicas"] = "0"
        st["refresh_interval"] = "-1"
        mp.setdefault("_meta", {})["wazuh_migration_bundle"] = man["bundle_id"]
        cds = [creation_ms(m, ents[m]) for m in members]
        cd = None if a.no_creation_date or None in cds else max(cds)   # a monthly target: its newest day (never earlier)
        if cd is not None:
            st["creation_date"] = str(cd)
        try:
            c.request("PUT", "/%s" % q(t), {"settings": {"index": st}, "mappings": mp})
            created_at[t] = cd
        except RuntimeError as e:
            if cd is None or "creation_date" not in str(e) or "HTTP 400" not in str(e):
                raise
            # F4: an indexer that refuses the setting at creation: the index is created anyway, its ISM age counted from now
            log("%s: the indexer refused index.creation_date (%s): created without it, its ISM age counts from this load" % (t, str(e)[:200]))
            st.pop("creation_date", None)
            c.request("PUT", "/%s" % q(t), {"settings": {"index": st}, "mappings": mp})
            created_at[t] = None
    if created_at:
        kept = sorted(t for t, v in created_at.items() if v is not None)
        lost = sorted(t for t, v in created_at.items() if v is None)
        log("creation dates: %d new target index(es) created with the source's, %d counted from this load%s" % (
            len(kept), len(lost), (": " + " ".join(lost[:10]) + (" ..." if len(lost) > 10 else "")) if lost else ""))
        state.d.setdefault("creation_dates", {}).update({t: created_at[t] for t in created_at})
    state.d["targets"] = originals
    state.save()

    # 4. load files, smallest work unit = one file
    todo = []
    for n, ent in sorted(man["indices"].items()):
        for f in ent["files"]:
            if f["file"] not in state.d["files"]:
                todo.append((n, f))
    todo.sort(key=lambda x: -x[1]["docs"])
    log("%d files to load, %d already loaded" % (len(todo), nfiles - len(todo)))
    totals = {"created": 0, "existing": 0, "retried": 0, "docs": 0}
    t1 = time.time()
    done_files = 0
    with concurrent.futures.ThreadPoolExecutor(a.workers) as ex:
        futs = {ex.submit(load_file, conn, bundle, f, target_of(n), a, state, None): (n, f) for n, f in todo}
        try:
            for fu in concurrent.futures.as_completed(futs):
                n, f = futs[fu]
                s = fu.result()
                for k in totals:
                    totals[k] += s[k]
                state.d["files"][f["file"]] = s
                state.save()
                done_files += 1
                if a.stop_after_files and done_files >= a.stop_after_files:
                    log("TEST: hard exit after %d files" % done_files)
                    os._exit(99)
        except Exception:
            for fu in futs:
                fu.cancel()
            raise
    el = time.time() - t1
    log("429/503 retries of whole requests: %d, slept %.0fs in total across workers" % (RETRY["requests"], RETRY["slept"]))
    log("loaded %d docs (%d created, %d already there, %d retried after 429) in %.1fs = %.0f docs/s" % (
        totals["docs"], totals["created"], totals["existing"], totals["retried"], el, totals["docs"] / el if el else 0))

    # 5. restore settings, verify counts
    fails = []
    for t, members in sorted(groups.items()):
        o = originals[t]
        c.request("PUT", "/%s/_settings" % q(t), {"index": {"number_of_replicas": o["number_of_replicas"], "refresh_interval": o["refresh_interval"]}})
    for t, members in sorted(groups.items()):
        c.request("POST", "/%s/_refresh" % q(t))
        _, r = c.request("GET", "/%s/_count" % q(t))
        want = sum(man["indices"][m]["docs_expected"] for m in members)
        if r["count"] != want:
            fails.append("%s: %d documents in the target, manifest expects %d" % (t, r["count"], want))
    state.d["verified"] = not fails
    state.save()
    if fails:
        for x in fails:
            log("COUNT MISMATCH " + x)
        sys.exit(3)
    log("verified: every index holds exactly the manifest count (%d target indices)" % len(groups))
    if a.remove_bundle:
        import shutil
        shutil.rmtree(bundle)
        log("bundle removed")
    print(json.dumps({"docs": totals["docs"], "seconds": round(el, 2), "docs_per_s": round(totals["docs"] / el) if el else 0, "existing": totals["existing"],
                      "age_from_load": sorted(t for t, v in (state.d.get("creation_dates") or {}).items() if v is None)}))


if __name__ == "__main__":
    main()
