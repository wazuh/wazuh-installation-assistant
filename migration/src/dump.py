#!/usr/bin/env python3
"""dump.py - export Wazuh 4.x indexed alerts from the indexer into a migration bundle directory.

Python standard library only. Oldest Python needed: 3.6 (f-strings, http.client, concurrent.futures);
tested on 3.9 (RHEL 9) and 3.12.  Linux only (uses fork-based multiprocessing and os.fsync).

Bundle layout (all files mode 0600, directories 0700):
  manifest.json                 what is in the bundle, per file counts and sha256, completeness per index
  indices/<index>.json          settings (filtered), mappings, aliases, creation version and creation date of every index
  templates.json                the index templates of the source that match the exported indices
  runs/run-NNN.json             plan of every dump run (baseline seq_no per shard, for deltas)
  data/<index>/rNNN-<k>.ndjson.gz   documents: two lines each, {"_id":..[,"_routing":..]} then the _source
  data/<index>/rNNN-<k>.meta.json   sidecar of a finished file (docs, bytes, sha256)

Re-running into the same directory resumes an interrupted run (finished files are skipped, a file is only
renamed into place when complete) or, when the previous run completed, takes a DELTA: only documents whose
_seq_no is above the checkpoint recorded before the previous run's scan.  That is how a live pre-copy plus a
final delta after the write stop works.

  dump.py --url https://127.0.0.1:9200 --user admin --password-env IDX_PASS --cafile root-ca.pem --out /srv/bundle
"""
import argparse
import base64
import datetime
import getpass
import gzip
import hashlib
import http.client
import json
import multiprocessing
import os
import re
import ssl
import sys
import time
import urllib.parse

FORMAT = 1
DROP_SETTINGS = {"uuid", "creation_date", "provided_name", "version", "resize", "routing", "history",
                 "blocks", "verified_before_close", "creation_date_string"}


def log(msg):
    sys.stderr.write("%s dump: %s\n" % (datetime.datetime.now().strftime("%H:%M:%S"), msg))
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

    def request(self, method, path, body=None, ok=(200,), retries=10):
        data = None if body is None else json.dumps(body).encode()
        headers = {"Authorization": self.auth, "Content-Type": "application/json", "Accept-Encoding": "identity"}
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
                time.sleep(delay)
                delay = min(delay * 2, 30)
                continue
            raise RuntimeError("%s %s -> HTTP %s: %s" % (method, path, status, raw[:500]))


def q(name):
    return urllib.parse.quote(name, safe=",*")


def dumps(o):
    try:
        return json.dumps(o, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    except UnicodeEncodeError:  # lone surrogates in a source value
        return json.dumps(o, ensure_ascii=True, separators=(",", ":")).encode("ascii")


class HashingFile(object):
    """File wrapper that hashes and counts what is written to disk (the gzip bytes)."""
    def __init__(self, f):
        self.f, self.h, self.n = f, hashlib.sha256(), 0

    def write(self, b):
        self.h.update(b)
        self.n += len(b)
        return self.f.write(b)

    def flush(self):
        self.f.flush()


def open_private(path, mode):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    return os.fdopen(fd, mode)


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for b in iter(lambda: f.read(1 << 20), b""):
            h.update(b)
    return h.hexdigest()


def write_json(path, obj):
    tmp = path + ".tmp"
    with open_private(tmp, "w") as f:
        json.dump(obj, f, indent=1, sort_keys=True)
        f.flush()
        os.fsync(f.fileno())
    os.rename(tmp, path)


# ----------------------------------------------------------------------------------------- worker

def scan_scroll(c, index, query, extra, size, preference):
    body = {"size": size, "sort": ["_doc"], "_source": True, "query": query}
    body.update(extra)
    fp = "filter_path=_scroll_id,hits.hits._id,hits.hits._routing,hits.hits._source"
    path = "/%s/_search?scroll=10m&%s%s" % (q(index), fp, ("&preference=" + preference) if preference else "")
    _, r = c.request("POST", path, body)
    sid = r.get("_scroll_id")
    try:
        while True:
            hits = r.get("hits", {}).get("hits", [])
            if not hits:
                break
            yield hits
            _, r = c.request("POST", "/_search/scroll?" + fp, {"scroll": "10m", "scroll_id": sid})
            sid = r.get("_scroll_id", sid)
    finally:
        if sid:
            try:
                c.request("DELETE", "/_search/scroll", {"scroll_id": sid}, ok=(200, 404), retries=1)
            except Exception:
                pass


def scan_pit(c, index, query, size, slice_):
    """Point in time + search_after on _doc, one slice (= one shard when slices == shards) per call.
    OpenSearch 2.19 has no _shard_doc sort, so _doc is only a unique tiebreaker inside a single shard."""
    _, r = c.request("POST", "/%s/_search/point_in_time?keep_alive=10m" % q(index))
    pit = r["pit_id"]
    try:
        after = None
        while True:
            body = {"size": size, "query": query, "pit": {"id": pit, "keep_alive": "10m"},
                    "sort": [{"_doc": "asc"}], "_source": True}
            if slice_:
                body["slice"] = slice_
            if after is not None:
                body["search_after"] = after
            _, r = c.request("POST", "/_search?filter_path=pit_id,hits.hits._id,hits.hits._routing,hits.hits._source,hits.hits.sort", body)
            hits = r.get("hits", {}).get("hits", [])
            if not hits:
                break
            after = hits[-1]["sort"]
            pit = r.get("pit_id", pit)
            yield hits
    finally:
        try:
            c.request("DELETE", "/_search/point_in_time", {"pit_id": [pit]}, ok=(200, 404), retries=1)
        except Exception:
            pass


def run_unit(u):
    c = Client(**u["conn"])
    path = u["path"]
    if u["kind"] == "delta":
        query = {"range": {"_seq_no": {"gt": u["gt"]}}}
        gen = scan_scroll(c, u["index"], query, {}, u["size"], "_shards:%d" % u["shard"])
    elif u["method"] == "pit":
        gen = scan_pit(c, u["index"], {"match_all": {}}, u["size"], {"id": u["slice"], "max": u["slices"]} if u["slices"] > 1 else None)
    else:
        extra = {"slice": {"id": u["slice"], "max": u["slices"]}} if u["slices"] > 1 else {}
        gen = scan_scroll(c, u["index"], {"match_all": {}}, extra, u["size"], None)
    os.makedirs(os.path.dirname(path), mode=0o700, exist_ok=True)
    tmp = path + ".part"
    docs = raw = 0
    f = open_private(tmp, "wb")
    hf = HashingFile(f)
    gz = gzip.GzipFile(fileobj=hf, mode="wb", compresslevel=u["level"], mtime=0)
    for hits in gen:
        buf = []
        for h in hits:
            meta = {"_id": h["_id"]}
            if "_routing" in h:
                meta["_routing"] = h["_routing"]
            a, b = dumps(meta), dumps(h["_source"])
            buf.append(a)
            buf.append(b)
            raw += len(a) + len(b) + 2
        gz.write(b"\n".join(buf) + b"\n")
        docs += len(hits)
    gz.close()
    f.flush()
    os.fsync(f.fileno())
    f.close()
    os.rename(tmp, path)
    meta = {"file": os.path.relpath(path, u["out"]), "docs": docs, "bytes": hf.n, "raw_bytes": raw,
            "sha256": hf.h.hexdigest(), "index": u["index"], "kind": u["kind"], "run": u["run"]}
    write_json(path[:-len(".ndjson.gz")] + ".meta.json", meta)
    return meta


# ---------------------------------------------------------------------------------------- planning

def date_of(index):
    m = re.search(r"(\d{4})\.(\d{2})\.(\d{2})$", index)
    return "%s-%s-%s" % m.groups() if m else None


def shard_checkpoints(c, index):
    _, r = c.request("GET", "/%s/_stats?level=shards&filter_path=indices.*.shards.*.routing.primary,indices.*.shards.*.seq_no" % q(index))
    out = {}
    for name, ind in r.get("indices", {}).items():
        out[name] = {}
        for sh, copies in ind["shards"].items():
            for cp in copies:
                if cp["routing"]["primary"]:
                    out[name][sh] = {"local": cp["seq_no"]["local_checkpoint"], "max": cp["seq_no"]["max_seq_no"]}
    return out


def clean_settings(s):
    s = dict(s.get("index", {}))
    for k in DROP_SETTINGS:
        s.pop(k, None)
    return {"index": s}


def index_entry(m):
    """What indices/<index>.json records of one source index. F4 (going back): the index's creation date too, outside
    "settings" (a load into 5.0 never sends it): ISM's min_index_age counts from it, so the reload into a reinstalled 4.x
    (load_unchanged.py) creates the index with it and the 4.x policy keeps the index as long as it would have."""
    s = m["settings"]["index"]
    ent = {"version_created": s["version"]["created"], "shards": int(s["number_of_shards"]),
           "settings": clean_settings(m["settings"]), "mappings": m["mappings"], "aliases": m.get("aliases", {})}
    try:
        ent["creation_date"] = int(s["creation_date"])
    except (KeyError, TypeError, ValueError):
        pass
    return ent


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--url", required=True, help="https://host:9200 of the 4.x indexer")
    ap.add_argument("--user", required=True)
    ap.add_argument("--password-env", help="name of the environment variable holding the password")
    ap.add_argument("--password-file", help="file holding the password")
    ap.add_argument("--cafile", help="CA certificate that signed the indexer certificate")
    ap.add_argument("--insecure", action="store_true", help="do not verify the TLS certificate")
    ap.add_argument("--out", required=True, help="bundle directory (created, mode 0700)")
    ap.add_argument("--indices", default="wazuh-alerts-4.x-*", help="comma separated index patterns")
    ap.add_argument("--include-archives", action="store_true", help="also wazuh-archives-4.x-*")
    ap.add_argument("--since", help="YYYY-MM-DD first day to export (by index name)")
    ap.add_argument("--until", help="YYYY-MM-DD last day to export (by index name)")
    ap.add_argument("--workers", type=int, default=3, help="parallel scan processes")
    ap.add_argument("--slices", type=int, default=0, help="slices per index (default: its shard count, max 6)")
    ap.add_argument("--page", type=int, default=2000, help="documents per search page")
    ap.add_argument("--level", type=int, default=6, help="gzip level 1-9")
    ap.add_argument("--method", choices=["scroll", "pit"], default="scroll")
    ap.add_argument("--full", action="store_true", help="ignore a previous completed run and export everything again into a new run")
    a = ap.parse_args()

    if a.password_env:
        pw = os.environ[a.password_env]
    elif a.password_file:
        pw = open(a.password_file).read().strip()
    else:
        pw = getpass.getpass("indexer password: ")
    os.umask(0o077)
    out = os.path.abspath(a.out)
    for bad in ("/var/lib/wazuh-indexer", "/var/ossec", "/usr/share/wazuh-indexer"):
        if out == bad or out.startswith(bad + "/"):
            sys.exit("refusing: %s is removed by the 4.x uninstall or the 5.0 installer rollback" % out)
    for d in ("", "indices", "runs", "data"):
        os.makedirs(os.path.join(out, d), mode=0o700, exist_ok=True)
    conn = {"url": a.url, "user": a.user, "password": pw, "cafile": a.cafile, "insecure": a.insecure}
    c = Client(**conn)

    _, info = c.request("GET", "/")
    log("source: %s %s (cluster %s)" % (info["version"].get("distribution", "?"), info["version"]["number"], info["cluster_name"]))

    pats = a.indices + (",wazuh-archives-4.x-*" if a.include_archives else "")
    _, cat = c.request("GET", "/_cat/indices/%s?format=json&h=index,pri,docs.count,store.size&bytes=b&expand_wildcards=open" % q(pats))
    names = sorted(x["index"] for x in cat if not x["index"].startswith("."))
    if a.since or a.until:
        names = [n for n in names if (date_of(n) or "") >= (a.since or "") and (date_of(n) or "9999") <= (a.until or "9999")]
    log("%d indices selected" % len(names))
    if not names:
        sys.exit("no index matches")

    mpath = os.path.join(out, "manifest.json")
    manifest = json.load(open(mpath)) if os.path.exists(mpath) else {"format": FORMAT, "indices": {}, "runs": []}

    # run planning: continue an interrupted run, else start a new one
    runs = sorted(x for x in os.listdir(os.path.join(out, "runs")) if x.endswith(".json"))
    plan = None
    if runs:
        last = json.load(open(os.path.join(out, "runs", runs[-1])))
        if not last.get("done"):
            plan = last
            log("resuming interrupted run %d" % plan["run"])
    if plan is None:
        run = len(runs) + 1
        for n in names:  # make every document visible, then take the checkpoints
            c.request("POST", "/%s/_refresh" % q(n), ok=(200,))
        cps = shard_checkpoints(c, pats)
        prev = {}
        for rn in runs:
            pr = json.load(open(os.path.join(out, "runs", rn)))
            if pr.get("done"):
                prev.update(pr["baseline"])
        plan = {"run": run, "started": time.time(), "baseline": {n: cps[n] for n in names if n in cps},
                "prev_baseline": {} if a.full else {n: prev[n] for n in names if n in prev},
                "count_start": {n: int(c.request("GET", "/%s/_count" % q(n))[1]["count"]) for n in names}}  # not docs.count
        write_json(os.path.join(out, "runs", "run-%03d.json" % run), plan)
    run = plan["run"]

    # per index: metadata, then the units
    units = []
    for n in names:
        _, meta = c.request("GET", "/%s" % q(n))
        ent = index_entry(meta[n])
        write_json(os.path.join(out, "indices", n + ".json"), ent)
        shards = ent["shards"]
        prevb = plan["prev_baseline"].get(n)
        if prevb is None:
            ns = a.slices or min(shards, 6)
            for k in range(ns):
                units.append({"conn": conn, "index": n, "kind": "full", "method": a.method, "slice": k, "slices": ns,
                              "size": a.page, "level": a.level, "run": run, "out": out,
                              "path": os.path.join(out, "data", n, "r%03d-%d.ndjson.gz" % (run, k))})
        else:
            for sh, cp in plan["baseline"][n].items():
                if cp["max"] > prevb[sh]["local"]:
                    units.append({"conn": conn, "index": n, "kind": "delta", "shard": int(sh), "gt": prevb[sh]["local"],
                                  "method": "scroll", "slices": 1, "size": a.page, "level": a.level, "run": run, "out": out,
                                  "path": os.path.join(out, "data", n, "r%03d-s%s.ndjson.gz" % (run, sh))})

    todo, done = [], []
    for u in units:
        mp = u["path"][:-len(".ndjson.gz")] + ".meta.json"
        if os.path.exists(mp) and os.path.exists(u["path"]):
            md = json.load(open(mp))
            if md["bytes"] == os.path.getsize(u["path"]) and md["sha256"] == sha256_file(u["path"]):
                done.append(md)
                continue
        for stale in (u["path"], u["path"] + ".part", mp):
            if os.path.exists(stale):
                os.remove(stale)
        todo.append(u)
    log("run %d: %d files to write, %d already finished" % (run, len(todo), len(done)))

    t0 = time.time()
    results = list(done)
    if todo:
        ctx = multiprocessing.get_context("fork")
        # largest indices first
        with ctx.Pool(a.workers) as pool:
            for md in pool.imap_unordered(run_unit, todo):
                results.append(md)
                log("wrote %s docs=%d bytes=%d" % (md["file"], md["docs"], md["bytes"]))
    el = time.time() - t0

    # completeness: refresh, then check nothing moved while we were scanning
    for n in names:
        c.request("POST", "/%s/_refresh" % q(n), ok=(200,))
    end_cps = shard_checkpoints(c, pats)
    # _cat/indices docs.count also counts nested sub-documents (the 4.x template maps data.ms-graph.evidence,
    # resources, managedDevices, ... as nested), so it is not the number of alerts; _count is.
    counts = {}
    for n in names:
        _, cc = c.request("GET", "/%s/_count" % q(n))
        counts[n] = int(cc["count"])
    for n in names:
        ent = manifest["indices"].setdefault(n, {"files": []})
        files = [f for f in ent["files"] if f["run"] != run]
        files += [r for r in results if r["index"] == n]
        files.sort(key=lambda r: r["file"])
        quiet = all(end_cps[n][sh]["max"] == plan["baseline"][n][sh]["max"] for sh in plan["baseline"][n])
        ent.update({"files": files, "docs_expected": counts[n], "complete": bool(quiet),
                    "version_created": json.load(open(os.path.join(out, "indices", n + ".json")))["version_created"]})
    _, tpl = c.request("GET", "/_template/wazuh?filter_path=*.index_patterns,*.order,*.settings,*.mappings,*.aliases", ok=(200, 404))
    write_json(os.path.join(out, "templates.json"), tpl)
    manifest.setdefault("bundle_id", hashlib.sha1((info["cluster_uuid"] + repr(plan["started"])).encode()).hexdigest()[:16])
    manifest.update({"format": FORMAT, "source": {"version": info["version"]["number"], "distribution": info["version"].get("distribution"),
                                                  "cluster_name": info["cluster_name"], "cluster_uuid": info["cluster_uuid"]},
                     "updated": time.time(), "last_run": run})
    manifest.setdefault("runs", [])
    manifest["runs"] = [r for r in manifest["runs"] if r["run"] != run] + [
        {"run": run, "files": len(results), "docs": sum(r["docs"] for r in results), "seconds": round(el, 2)}]
    write_json(mpath, manifest)
    plan["done"] = True
    write_json(os.path.join(out, "runs", "run-%03d.json" % run), plan)
    tot = sum(r["docs"] for r in results)
    incomplete = [n for n in names if not manifest["indices"][n]["complete"]]
    log("run %d finished: %d docs in %d files, %.1fs scan (%.0f docs/s); indices still changing: %d%s" % (
        run, tot, len(results), el, tot / el if el else 0, len(incomplete),
        (" -> stop the writers and run dump.py again for a final delta" if incomplete else "")))
    print(json.dumps({"run": run, "docs": tot, "files": len(results), "seconds": round(el, 2), "incomplete_indices": incomplete}))


if __name__ == "__main__":
    main()
